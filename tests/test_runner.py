# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Proof and ownership failure paths, without provider accounts."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

from sandbox_provider_spec.driver import (
    Differs,
    Driver,
    Inputs,
    NativeFailure,
    NotRun,
    Observation,
    Unsupported,
)
from sandbox_provider_spec.runner import Runner, asserted, matches, resolve
from sandbox_provider_spec.suite import Suite, read_suite
from sandbox_provider_spec.suite import Test as Scenario


class NativeDriver(Driver):
    unsupported = {"terminal.open": "SDK has no PTY operation"}

    def __init__(self, *, cleanup_failure: bool = False) -> None:
        super().__init__()
        self.cleanup_failure = cleanup_failure
        self.closed: list[str] = []

    def create(self, target: object, inputs: Inputs) -> Observation:
        del target, inputs
        owned = self.own("sandbox", object(), self.cleanup)
        return {"resource": owned, "state": "active"}

    def cleanup(self) -> Observation:
        self.closed.append("sandbox")
        if self.cleanup_failure:
            raise OSError("untrusted upstream data that must not enter the report")
        return {"result": "deleted"}


def test_allocation_is_released_when_its_creation_assertion_differs() -> None:
    driver = NativeDriver()
    test = Scenario(
        "candidate",
        "example",
        ({"op": "create", "as": "box", "expect": {"equals": {"state": "destroyed"}}},),
        (),
    )
    result = Runner(driver).run_test(test)
    assert result["result"] == "differs"
    assert result["reason"] == "state"
    assert driver.closed == ["sandbox"]
    assert result["cleanup"] == [{"kind": "sandbox", "result": "deleted"}]


def test_cleanup_failures_are_retained_without_upstream_payloads() -> None:
    driver = NativeDriver(cleanup_failure=True)
    test = Scenario("candidate", "example", ({"op": "create", "as": "box"},), ())
    result = Runner(driver).run_test(test)
    assert result["cleanup"] == [{"kind": "sandbox", "result": "error", "reason": "OSError"}]
    assert "untrusted" not in str(result)


@pytest.mark.parametrize(
    "operation,expected", [("terminal.open", "unsupported"), ("process.start", "not_run")]
)
def test_missing_native_capability_differs_from_missing_driver_mapping(
    operation: str, expected: str
) -> None:
    result = Runner(NativeDriver()).run_test(
        Scenario("candidate", "example", ({"op": operation},), ())
    )
    assert result["result"] == expected


@pytest.mark.parametrize("inputs", [{"image": "$runner.image"}, "$runner.options"])
def test_missing_fixture_proves_nothing(inputs: object) -> None:
    result = Runner(NativeDriver()).run_test(
        Scenario("candidate", "example", ({"op": "create", "in": inputs},), ())
    )
    assert result["result"] == "not_run"
    assert result["reason"] == "fixture_missing"
    assert result["cleanup"] == []


@pytest.mark.parametrize(
    "value",
    [
        "http://example.com/",
        "https://user:secret@example.com/",
        "https://exa\tmple.com/",
        "https://exa\nmple.com/",
        "https://exa\rmple.com/",
        "https://",
        "https://exa mple.com/",
        "https://example.com:99999/",
        "not-a-url",
        "",
        None,
        443,
    ],
)
def test_reachable_url_must_be_https(value: object) -> None:
    with pytest.raises(NotRun, match="^proof_fixture_invalid$"):
        resolve("$runner.reachable_url", {}, {"reachable_url": value})


def test_https_reachable_url_is_passed_through() -> None:
    assert (
        resolve("$runner.reachable_url", {}, {"reachable_url": "https://example.com/health"})
        == "https://example.com/health"
    )


def test_mapping_can_extend_a_resolved_runner_fixture() -> None:
    assert resolve(
        {"<<": "$runner.test_size", "size_is_ceiling": True},
        {},
        {"test_size": {"cpu_min": 2, "memory_min_mib": 1024}},
    ) == {"cpu_min": 2, "memory_min_mib": 1024, "size_is_ceiling": True}


def test_invalid_fixture_is_rejected_before_sandbox_creation() -> None:
    driver = NativeDriver()
    result = Runner(driver, {"reachable_url": "http://example.com/"}).run_test(
        Scenario(
            "candidate",
            "invalid fixture before allocation",
            (
                {"op": "create", "as": "box"},
                {"op": "probe.http", "in": {"url": "$runner.reachable_url"}},
            ),
            (),
        )
    )
    assert result["result"] == "not_run"
    assert result["reason"] == "proof_fixture_invalid"
    assert driver.resources == []
    assert result["cleanup"] == []


def test_plain_http_reachable_url_does_not_reach_the_guest() -> None:
    result = Runner(NativeDriver(), {"reachable_url": "http://example.com/"}).run_test(
        Scenario(
            "baseline.outbound_network",
            "https fixture",
            (
                {
                    "op": "probe.http",
                    "in": {"url": "$runner.reachable_url"},
                    "expect": {"equals": {"served": True}},
                },
                {"op": "run", "in": {"environment": {"TARGET": "$runner.reachable_url"}}},
            ),
            (),
        )
    )
    assert result["result"] == "not_run"
    assert result["reason"] == "proof_fixture_invalid"
    assert result["steps"] == [
        {"operation": "probe.http", "result": "not_run", "reason": "proof_fixture_invalid"}
    ]


def test_idle_observation_cannot_use_an_expiring_sandbox() -> None:
    driver = NativeDriver()
    scenario = Scenario(
        "idle",
        "expiry is not idle shutdown",
        (
            {"op": "create", "in": {"lifetime_seconds": "$runner.idle_lifetime_seconds"}},
            {"wait_ms": "$runner.idle_after_wait_ms"},
        ),
        (),
    )
    result = Runner(driver, {"idle_lifetime_seconds": 60, "idle_after_wait_ms": 65000}).run_test(
        scenario
    )
    assert result["result"] == "not_run"
    assert result["reason"] == "idle_fixture_window_invalid"
    assert result["steps"] == [
        {"operation": "prepare", "result": "not_run", "reason": "idle_fixture_window_invalid"}
    ]
    assert driver.resources == []


def test_idle_observation_overrun_cannot_prove_ordinary_expiry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ticks = iter((0.0, 235.0, 236.0))
    monkeypatch.setattr("sandbox_provider_spec.runner.time.monotonic", lambda: next(ticks))
    driver = NativeDriver()
    scenario = Scenario(
        "idle",
        "expired observation window",
        ({"op": "create", "in": {"lifetime_seconds": "$runner.idle_lifetime_seconds"}},),
        (),
    )
    result = Runner(driver, {"idle_lifetime_seconds": 240}).run_test(scenario)
    assert result["result"] == "not_run"
    assert result["reason"] == "idle_observation_deadline_near"
    assert driver.resources == []


def test_classified_native_failures_keep_the_fixed_public_code() -> None:
    class Timeout(NativeDriver):
        def run(self, target: object, inputs: Inputs) -> Observation:
            del target, inputs
            raise NativeFailure("timeout")

    result = Runner(Timeout()).run_test(
        Scenario("native_timeout", "classified failure", ({"op": "run"},), ())
    )
    assert result["result"] == "error"
    assert result["reason"] == "timeout"
    assert result["steps"] == [{"operation": "run", "result": "error", "reason": "timeout"}]


def test_suite_rejects_mutation_retries_before_allocation(tmp_path: Path) -> None:
    path = tmp_path / "suite.yaml"
    path.write_text("""spec: sandbox-provider-spec/0.1
tests:
- id: example
  title: example
  steps:
  - op: create
    expect: {eventually_ms: 1000}
""")
    with pytest.raises(ValueError, match="^example: cannot retry a mutation$"):
        read_suite(path)


def test_proof_targets_are_explicit_and_require_a_passing_result() -> None:
    proof = ({"gate": "pause_resume", "knob": "keeps", "value": "files_only"},)
    test = Scenario("candidate", "example", ({"op": "create", "as": "box"},), proof)
    result = Runner(NativeDriver()).run_test(test)
    assert result["proves"] == list(proof)
    failed = Scenario("candidate", "example", ({"op": "process.start"},), proof)
    incomplete = Runner(NativeDriver()).run_test(failed)
    assert incomplete["proves"] == list(proof)
    assert incomplete["result"] == "not_run"


def test_cleanup_continues_after_a_dependent_resource_fails() -> None:
    order: list[str] = []

    class Dependents(NativeDriver):
        def create(self, target: object, inputs: Inputs) -> Mapping[str, object]:
            result = super().create(target, inputs)
            self.own("observer", object(), fail)
            return result

    def fail() -> Observation:
        order.append("observer")
        raise OSError("cleanup failed")

    driver = Dependents()
    result = Runner(driver).run_test(Scenario("candidate", "example", ({"op": "create"},), ()))
    assert order == ["observer"]
    assert driver.closed == ["sandbox"]
    assert result["cleanup"] == [
        {"kind": "observer", "result": "error", "reason": "OSError"},
        {"kind": "sandbox", "result": "deleted"},
    ]


@pytest.mark.parametrize("data", [b"hello", bytearray(b"hello"), memoryview(b"hello")])
def test_native_byte_buffers_compare_without_changing_the_payload(data: object) -> None:
    assert matches(data, {"utf8": "hello"})
    assert not matches(data, {"utf8": "other"})


@pytest.mark.parametrize("data", [b"/usr/bin/bash\n", bytearray(b"/usr/bin/bash\n")])
def test_controlled_environment_observations_accept_native_byte_buffers(data: object) -> None:
    assert asserted({"stdout": data}, {"record": ["stdout"]}) == {"stdout": "/usr/bin/bash\n"}


def test_absence_assertion_applies_only_to_the_named_operation() -> None:
    proof = ({"gate": "snapshots", "knob": "deletable", "value": False},)
    test = Scenario(
        "absence",
        "native absence",
        ({"op": "terminal.open", "expect": {"unsupported": True}},),
        proof,
    )
    result = Runner(NativeDriver()).run_test(test)
    assert result["result"] == "passed"
    assert result["steps"] == [
        {"operation": "terminal.open", "result": "passed", "native_absence": True}
    ]
    # An absent prerequisite never turns the later absence assertion into proof.
    prerequisite = Scenario(
        "prerequisite",
        "missing prerequisite",
        (
            {"op": "terminal.open"},
            {"op": "process.start", "expect": {"unsupported": True}},
        ),
        proof,
    )
    assert Runner(NativeDriver()).run_test(prerequisite)["result"] == "unsupported"


def test_environment_absence_assertion_does_not_record_untrusted_environment() -> None:
    with pytest.raises(Differs) as caught:
        asserted(
            {"stdout": "OTHER_ACCOUNT_KEY=sensitive\nfixture=needle"},
            {"equals": {"stdout": {"utf8_absent": "needle"}}},
        )
    assert "sensitive" not in str(caught.value.observation)


@pytest.mark.parametrize(
    "field", ["exists", "served", "status", "exit_code", "observed_cpu", "observed_memory_mib"]
)
def test_typed_observations_cannot_record_an_upstream_message(field: str) -> None:
    with pytest.raises(ValueError, match="record value must"):
        asserted({field: "account or credential data"}, {"record": [field]})


def test_an_observed_allocation_records_fractional_cpus_and_whole_mib() -> None:
    assert asserted(
        {"observed_cpu": 0.5, "observed_memory_mib": 3950},
        {"record": ["observed_cpu", "observed_memory_mib"]},
    ) == {"observed_cpu": 0.5, "observed_memory_mib": 3950}
    with pytest.raises(ValueError, match="record value must"):
        asserted({"observed_cpu": float("nan")}, {"record": ["observed_cpu"]})
    with pytest.raises(ValueError, match="record value must"):
        asserted({"observed_memory_mib": 3950.5}, {"record": ["observed_memory_mib"]})


def test_guest_precondition_skip_is_not_a_pass() -> None:
    class Guest(NativeDriver):
        def run(self, target: object, inputs: Inputs) -> Observation:
            del target, inputs
            return {"exit_code": 77}

    result = Runner(Guest()).run_test(
        Scenario(
            "privilege",
            "guest privilege",
            (
                {
                    "op": "run",
                    "expect": {"equals": {"exit_code": 0}, "not_run_if": {"exit_code": 77}},
                },
            ),
            (),
        )
    )
    assert result["result"] == "not_run"
    assert result["reason"] == "guest_fixture_unavailable"


def test_receiver_allocation_is_cleaned_when_startup_fails() -> None:
    class ReceiverDriver(NativeDriver):
        def files_write(self, target: object, inputs: Inputs) -> Observation:
            del target, inputs
            return {}

        def process_start(self, target: object, inputs: Inputs) -> Observation:
            del target, inputs
            raise RuntimeError("receiver startup failed")

    driver = ReceiverDriver()
    result = Runner(driver).run_test(
        Scenario(
            "receiver",
            "failed fixture startup",
            ({"op": "fixture.secret_receiver", "in": {"value": "sps-generated-test-secret"}},),
            (),
        )
    )
    assert result["result"] == "error"
    assert result["cleanup"] == [{"kind": "sandbox", "result": "deleted"}]
    assert driver.closed == ["sandbox"]


@pytest.mark.parametrize("buffered", [False, True])
def test_stream_proof_rejects_output_delivered_only_after_self_exit(
    monkeypatch: pytest.MonkeyPatch,
    buffered: bool,
) -> None:
    clock = [0.0]
    monkeypatch.setattr("sandbox_provider_spec.runner.time.monotonic", lambda: clock[0])

    class StreamDriver(NativeDriver):
        def process_start(self, target: object, inputs: Inputs) -> Observation:
            del target
            assert "read " not in str(inputs["bash_script"])
            assert "timeout_ms" not in inputs  # Execution limits are outside the baseline.
            return {"resource": self.own("process", object(), lambda: {"result": "deleted"})}

        def process_output(self, target: object, inputs: Inputs) -> Observation:
            del target, inputs
            clock[0] += 15.1 if buffered else 0.1
            return {"stdout": "stream-marker\n" + ("released" if buffered else "")}

        def process_wait(self, target: object, inputs: Inputs) -> Observation:
            del target, inputs
            return {"exit_code": 0}

    test = next(t for t in read_suite().tests if t.id == "baseline.process_stream")
    result = Runner(StreamDriver()).run_test(test)
    assert result["result"] == ("differs" if buffered else "passed")
    cleanup = result["cleanup"]
    assert isinstance(cleanup, list)
    assert all(row["result"] == "deleted" for row in cleanup)


class LifetimeDriver(NativeDriver):
    def __init__(self, clock: list[float], *, dynamic_absence: bool = False) -> None:
        super().__init__()
        self.clock = clock
        self.dynamic_absence = dynamic_absence
        self.peak = 0
        self.events: list[tuple[str, float]] = []

    def create(self, target: object, inputs: Inputs) -> Observation:
        result = dict(super().create(target, inputs))
        result["born"] = self.clock[0]
        result["until"] = self.clock[0] + cast(int, inputs.get("lifetime_seconds", 300))
        self.peak = max(self.peak, sum(not owned.released for owned in self.resources))
        self.events.append(("create", self.clock[0]))
        return result

    def lifetime_extend(self, target: object, inputs: Inputs) -> Observation:
        if self.dynamic_absence:
            raise Unsupported("native extension absent")
        assert isinstance(target, dict)
        target["until"] = self.clock[0] + cast(int, inputs["lifetime_seconds"])
        return {}

    def get(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        assert isinstance(target, dict)
        assert not target["resource"].released
        return {"state": "active" if self.clock[0] < target["until"] else "destroyed"}

    def run(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        assert self.get(target, {})["state"] == "active"
        self.events.append(("run", self.clock[0]))
        return {"exit_code": 0}


@pytest.fixture
def lifetime_clock(monkeypatch: pytest.MonkeyPatch) -> tuple[list[float], list[float]]:
    clock, sleeps = [0.0], []

    def sleep(seconds: float) -> None:
        sleeps.append(seconds)
        clock[0] += seconds

    monkeypatch.setattr("sandbox_provider_spec.runner.time.monotonic", lambda: clock[0])
    monkeypatch.setattr("sandbox_provider_spec.runner.time.sleep", sleep)
    return clock, sleeps


def _lifetime_check(identifier: str) -> Scenario:
    return next(test for test in read_suite().tests if test.id == identifier)


@pytest.mark.parametrize("limit,seconds", [(1, 610), (2, 305)])
def test_extension_control_and_candidate_share_time_only_with_capacity(
    lifetime_clock: tuple[list[float], list[float]], limit: int, seconds: int
) -> None:
    clock, sleeps = lifetime_clock
    driver = LifetimeDriver(clock)
    row = Runner(driver, {"max_live_sandboxes": limit}).run_test(
        _lifetime_check("facts.extendable_lifetime")
    )
    assert row["result"] == "passed"
    assert sum(sleeps) == seconds
    assert row["duration_ms"] == seconds * 1000
    assert driver.peak == limit
    assert len(cast(list[object], row["cleanup"])) == 2
    assert all(owned.released for owned in driver.resources)


def test_declared_absence_and_fast_checks_precede_all_long_waits(
    lifetime_clock: tuple[list[float], list[float]],
) -> None:
    clock, sleeps = lifetime_clock
    driver = LifetimeDriver(clock)
    driver.unsupported = {"lifetime.extend": "native extension absent"}
    timer = _lifetime_check("lifetime_timer.at_end.destroyed")
    fast = Scenario(
        "fast", "fast", ({"op": "create", "as": "box"}, {"op": "run", "target": "box"}), ()
    )
    rows = Runner(driver).run(
        Suite("", (timer, _lifetime_check("facts.extendable_lifetime"), fast))
    )
    assert [row["result"] for row in rows] == ["passed", "unsupported", "passed"]
    assert rows[1]["cleanup"] == []
    assert driver.events[1] == ("run", 0)
    assert sum(sleeps) == 305


def test_dynamic_extension_absence_does_not_wait_on_control(
    lifetime_clock: tuple[list[float], list[float]],
) -> None:
    clock, sleeps = lifetime_clock
    driver = LifetimeDriver(clock, dynamic_absence=True)
    row = Runner(driver).run_test(_lifetime_check("facts.extendable_lifetime"))
    assert row["result"] == "unsupported"
    assert sleeps == []
    assert len(driver.resources) == 1
    assert all(owned.released for owned in driver.resources)


@pytest.mark.parametrize("limit,seconds", [(1, 915), (2, 610), (3, 305)])
def test_independent_timer_check_shares_the_extension_window_within_limit(
    lifetime_clock: tuple[list[float], list[float]], limit: int, seconds: int
) -> None:
    clock, sleeps = lifetime_clock
    driver = LifetimeDriver(clock)
    rows = Runner(driver, {"max_live_sandboxes": limit}).run(
        Suite(
            "",
            (
                _lifetime_check("lifetime_timer.at_end.destroyed"),
                _lifetime_check("facts.extendable_lifetime"),
            ),
        )
    )
    assert [row["result"] for row in rows] == ["passed", "passed"]
    assert sum(sleeps) == seconds
    assert driver.peak <= limit
    assert [len(cast(list[object], row["cleanup"])) for row in rows] == [1, 2]
    assert all(owned.released for owned in driver.resources)


@pytest.mark.parametrize("fault", ["no_extension", "no_timer"])
def test_overlapping_lifetime_proof_rejects_each_broken_branch(
    lifetime_clock: tuple[list[float], list[float]], fault: str
) -> None:
    class Faulty(LifetimeDriver):
        def create(self, target: object, inputs: Inputs) -> Observation:
            result = dict(super().create(target, inputs))
            if fault == "no_timer":
                result["until"] = float("inf")
            return result

        def lifetime_extend(self, target: object, inputs: Inputs) -> Observation:
            if fault == "no_extension":
                return {}
            return super().lifetime_extend(target, inputs)

        def run(self, target: object, inputs: Inputs) -> Observation:
            del inputs
            return {"exit_code": 0 if self.get(target, {})["state"] == "active" else 1}

    clock, _ = lifetime_clock
    driver = Faulty(clock)
    row = Runner(driver, {"max_live_sandboxes": 2}).run_test(
        _lifetime_check("facts.extendable_lifetime")
    )
    assert row["result"] == "differs"
    assert len(cast(list[object], row["cleanup"])) == 2
    assert all(owned.released for owned in driver.resources)


@pytest.mark.parametrize("limit", [0, -1, True, "2"])
def test_invalid_overlap_limit_allocates_nothing(limit: object) -> None:
    driver = NativeDriver()
    with pytest.raises(ValueError, match="max_live_sandboxes"):
        Runner(driver, {"max_live_sandboxes": limit}).run_test(
            _lifetime_check("lifetime_timer.at_end.destroyed")
        )
    assert driver.resources == []


def test_core_suite_discovers_dynamic_extension_absence_before_timer_wait(
    lifetime_clock: tuple[list[float], list[float]],
) -> None:
    clock, sleeps = lifetime_clock
    driver = LifetimeDriver(clock, dynamic_absence=True)
    selected = tuple(
        test
        for test in read_suite().tests
        if test.id in {"facts.extendable_lifetime", "lifetime_timer.at_end.destroyed"}
    )
    assert selected[0].id == "facts.extendable_lifetime"
    rows = Runner(driver).run(Suite("", selected))
    assert [row["result"] for row in rows] == ["unsupported", "passed"]
    assert driver.events == [("create", 0), ("create", 0)]
    assert sum(sleeps) == 305
    assert driver.peak == 1


def test_unconfirmed_cleanup_does_not_free_a_timer_capacity_slot(
    lifetime_clock: tuple[list[float], list[float]],
) -> None:
    driver = NativeDriver(cleanup_failure=True)
    test = Scenario("timer", "timer", ({"op": "create"}, {"wait_ms": 1000}), ())
    rows = Runner(driver).run(Suite("", (test, Scenario("next", "next", test.steps, ()))))
    assert rows[0]["cleanup"] == [{"kind": "sandbox", "result": "error", "reason": "OSError"}]
    assert rows[1]["result"] == "not_run"
    assert rows[1]["reason"] == "runner_sandbox_capacity_unavailable"
    assert len(driver.resources) == 1
    assert lifetime_clock[1] == [1]
