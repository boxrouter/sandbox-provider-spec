# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Independent native idle experiments cannot accidentally prove each other."""

from __future__ import annotations

import pytest

from sandbox_provider_spec import coverage_lifecycle as probe
from sandbox_provider_spec.driver import Driver, Inputs, NativeFailure, Observation
from sandbox_provider_spec.runner import Runner
from sandbox_provider_spec.suite import read_suite, suite_path


class LifetimeDriver(Driver):
    """A native idle clock is refreshed by a command, never by a metadata read."""

    def __init__(self, clock: list[float], *, ending: str | None = None) -> None:
        super().__init__()
        self.clock = clock
        self.last_activity = 0.0
        self.ending = ending
        self.calls: list[tuple[str, float]] = []

    def create(self, target: object, inputs: Inputs) -> Observation:
        del target, inputs
        return {"resource": self.own("sandbox", object(), lambda: {"result": "deleted"})}

    def run(self, target: object, inputs: Inputs) -> Observation:
        del target, inputs
        self.last_activity = self.clock[0]
        self.calls.append(("run", self.clock[0]))
        return {"exit_code": 0}

    def get(self, target: object, inputs: Inputs) -> Observation:
        del target, inputs
        self.calls.append(("get", self.clock[0]))
        state = self.ending if self.clock[0] >= 10 and self.ending else "active"
        if self.clock[0] - self.last_activity >= 15:
            state = "paused"
        return {"state": state}


@pytest.fixture
def lifetime_clock(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    clock = [0.0]
    monkeypatch.setattr("sandbox_provider_spec.coverage_lifecycle.time.monotonic", lambda: clock[0])
    monkeypatch.setattr(
        "sandbox_provider_spec.coverage_lifecycle.time.sleep",
        lambda seconds: clock.__setitem__(0, clock[0] + seconds),
    )
    return clock


def test_core_max_lifetime_uses_activity_without_claiming_long_running(
    lifetime_clock: list[float],
) -> None:
    core = next(test for test in read_suite().tests if test.id == "facts.max_lifetime")
    supplementary = next(
        test
        for test in read_suite(suite_path().with_name("coverage.yaml")).tests
        if test.id == "coverage.facts.max_lifetime.active"
    )
    fixtures = {"max_lifetime_seconds": 100, "max_lifetime_wait_ms": 35000}
    core_driver = LifetimeDriver(lifetime_clock)
    core_result = Runner(core_driver, fixtures).run_test(core)
    assert core_result["result"] == "passed"
    assert lifetime_clock[0] >= 35
    assert core_result["proves"] == [
        {"fact": "resources.max_lifetime_seconds", "value": {"at_least": 35}}
    ]
    assert core_driver.calls[-2:] == [("run", 35), ("get", 35)]
    lifetime_clock[0] = 0
    driver = LifetimeDriver(lifetime_clock)
    result = Runner(driver, fixtures).run_test(supplementary)
    assert result["result"] == "passed"
    assert lifetime_clock[0] >= 35
    assert result["proves"] == [
        {"fact": "resources.max_lifetime_seconds", "value": {"at_least": 35}}
    ]
    assert driver.calls[-2:] == [("run", 35), ("get", 35)]
    assert all(item.released for item in driver.resources)


@pytest.mark.parametrize("ending", ["paused", "destroyed"])
def test_activity_cannot_hide_a_native_lifetime_ending(
    lifetime_clock: list[float], ending: str
) -> None:
    assert probe.active_lifetime(
        LifetimeDriver(lifetime_clock, ending=ending), {}, {"wait_ms": 35000}
    ) == {"state": ending, "window_completed": False}
    assert lifetime_clock[0] < 35


def test_failed_activity_command_cannot_prove_a_lifetime(lifetime_clock: list[float]) -> None:
    class FailedCommand(LifetimeDriver):
        def run(self, target: object, inputs: Inputs) -> Observation:
            del target, inputs
            return {"exit_code": 1}

    with pytest.raises(NativeFailure, match="active_lifetime_command_failed"):
        probe.active_lifetime(FailedCommand(lifetime_clock), {}, {"wait_ms": 35000})


def test_invalid_activity_window_allocates_nothing(lifetime_clock: list[float]) -> None:
    scenario = next(
        test
        for test in read_suite(suite_path().with_name("coverage.yaml")).tests
        if test.id == "coverage.facts.max_lifetime.active"
    )
    driver = LifetimeDriver(lifetime_clock)
    result = Runner(driver, {"max_lifetime_seconds": 30, "max_lifetime_wait_ms": 30000}).run_test(
        scenario
    )
    assert result["result"] == "not_run"
    assert result["proves"] == []
    assert not driver.resources
