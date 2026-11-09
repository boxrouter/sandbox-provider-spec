# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Public bounds stay tied to exercised inputs and observations."""

from __future__ import annotations

import base64
import json
import subprocess
from collections.abc import Mapping

import pytest

from sandbox_provider_spec.driver import Driver, Inputs, NotRun, Observation
from sandbox_provider_spec.proofs import proof_fixtures
from sandbox_provider_spec.runner import Runner
from sandbox_provider_spec.suite import Test as Scenario
from sandbox_provider_spec.suite import read_suite, suite_path


def scenario(identifier: str) -> Scenario:
    return next(test for test in read_suite().tests if test.id == identifier)


def coverage_scenario(identifier: str) -> Scenario:
    suite = read_suite(suite_path().with_name("coverage.yaml"))
    return next(test for test in suite.tests if test.id == identifier)


def live_resize_scenario(identifier: str) -> Scenario:
    # The proof helper remains testable without keeping a waitlisted case in coverage.yaml.
    return Scenario(identifier, "Synthetic waitlisted proof fixture.", (), ())


class Allocations(Driver):
    def __init__(self) -> None:
        super().__init__()
        self.inputs: list[Inputs] = []

    def create(self, target: object, inputs: Inputs) -> Observation:
        del target
        self.inputs.append(inputs)
        return {"state": "active"}

    def allocation_observe(self, target: object, inputs: Inputs) -> Observation:
        del target, inputs
        return {"allocation": {"cpu_min": 2, "memory_min_mib": 1024}}


def test_size_proof_is_one_concrete_point_without_other_fixture_data() -> None:
    driver = Allocations()
    result = Runner(
        driver,
        {
            "test_size": {"cpu_min": 2, "memory_min_mib": 1024},
            "test_size_value": "sensitive forged proof",
            "authorization": "sensitive header",
        },
    ).run_test(scenario("facts.sizes"))
    assert result["result"] == "passed"
    assert result["proves"] == [
        {"fact": "resources.sizes", "value": [{"cpu": 2, "memory_mib": 1024}]}
    ]
    assert "sensitive" not in str(result)


def test_an_allocation_rounded_to_a_different_point_is_not_proof() -> None:
    result = Runner(Allocations(), {"test_size": {"cpu_min": 1, "memory_min_mib": 1024}}).run_test(
        scenario("facts.sizes")
    )
    assert result["result"] == "differs"


@pytest.mark.parametrize(
    "size",
    [
        {"cpu_min": True},
        {"cpu_min": float("inf")},
        {"cpu_min": "secret"},
        {"authorization": "secret"},
    ],
)
def test_invalid_size_fixture_cannot_allocate_or_serialize_a_proof(size: object) -> None:
    driver = Allocations()
    result = Runner(driver, {"test_size": size}).run_test(scenario("facts.sizes"))
    assert result["result"] == "not_run"
    assert result["proves"] == []
    assert driver.inputs == []
    assert "secret" not in str(result)


class Ceiling(Driver):
    """Bounds probe plus the optional measured-use fallback.

    `use` is the `size_ceiling_use` guest payload, `hog` the memory run's exit
    code or an exception the run raises. `state` answers `get` after a failed
    hog. When `use` is None the measured path cannot run.
    """

    def __init__(
        self,
        observed: bool,
        *,
        use: object = None,
        hog: object = None,
        state: str = "active",
    ) -> None:
        super().__init__()
        self.observed = observed
        self.use = use
        self.hog = hog
        self.state = state
        self.bounds: dict[str, object] | None = None
        self.created: list[Inputs] = []
        self.arguments: object = None

    def create(self, target: object, inputs: Inputs) -> Observation:
        del target
        self.created.append(dict(inputs))
        return {"state": "active"}

    def get(self, target: object, inputs: Inputs) -> Observation:
        del target, inputs
        return {"state": self.state}

    def files_write(self, target: object, inputs: Inputs) -> Observation:
        del target
        script = base64.b64decode(str(inputs["data"]))
        assert b"def observe_ceiling_bounds" in script
        return {}

    def run(self, target: object, inputs: Inputs) -> Observation:
        del target
        environment = inputs.get("environment")
        arguments = (
            json.loads(str(environment["SPS_FACT_ARGUMENTS"]))
            if isinstance(environment, Mapping)
            else {}
        )
        probe = arguments.get("probe")
        if probe == "size_ceiling_bounds":
            self.arguments = arguments
            assert inputs["timeout_ms"] == 45000
            value = "1073741824" if self.observed else "2147483648"
            payload = self.bounds or {
                "membership": "0::/box",
                "files": {
                    "/sys/fs/cgroup/cpu.max": "200000 100000",
                    "/sys/fs/cgroup/memory.max": value,
                },
            }
            return {"exit_code": 0, "stdout": json.dumps(payload)}
        if probe == "size_ceiling_use":
            self.arguments = arguments
            assert inputs["timeout_ms"] == 120000
            if self.use is None:
                raise NotRun("use_measurement_unproven")
            return {"exit_code": 0, "stdout": json.dumps(self.use)}
        assert probe is None, probe
        if isinstance(self.hog, BaseException):
            raise self.hog
        assert isinstance(self.hog, int)
        return {"exit_code": self.hog, "stdout": ""}


def test_size_ceiling_uses_the_concrete_tested_size() -> None:
    driver = Ceiling(True)
    result = Runner(
        driver,
        {
            "test_size": {"cpu_min": 2, "memory_min_mib": 1024, "disk_min_mib": 2048},
            "test_size_value": "forged secret",
        },
    ).run_test(coverage_scenario("coverage.facts.size_is_ceiling.true"))
    assert result["result"] == "passed"
    assert result["proves"] == [{"fact": "resources.size_is_ceiling", "value": True}]
    assert driver.created[0]["resources"] == {
        "cpu_min": 2,
        "memory_min_mib": 1024,
        "disk_min_mib": 2048,
        "size_is_ceiling": True,
    }
    assert driver.arguments == {"probe": "size_ceiling_bounds"}
    assert "forged" not in str(result)


@pytest.mark.parametrize("version", [1, 2])
def test_ceiling_report_records_raw_controller_membership_and_ancestor_paths(version: int) -> None:
    driver = Ceiling(True)
    files = (
        {
            "/sys/fs/cgroup/cpu/box/cpu.cfs_quota_us": "200000",
            "/sys/fs/cgroup/cpu/cpu.cfs_period_us": "100000",
            "/sys/fs/cgroup/cpu/cpu.cfs_quota_us": "200000",
            "/sys/fs/cgroup/cpu/box/cpu.cfs_period_us": "100000",
            "/sys/fs/cgroup/memory/memory.limit_in_bytes": "1073741824",
        }
        if version == 1
        else {
            "/sys/fs/cgroup/cpu.max": "200000 100000",
            "/sys/fs/cgroup/box/memory.max": "1073741824",
        }
    )
    membership = "4:cpu,cpuacct:/box\n3:memory:/box" if version == 1 else "0::/box"
    driver.bounds = {"membership": membership, "files": files}
    result = Runner(driver, {"test_size": {"cpu_min": 2, "memory_min_mib": 1024}}).run_test(
        coverage_scenario("coverage.facts.size_is_ceiling.true")
    )
    assert result["result"] == "passed"
    steps = result["steps"]
    assert isinstance(steps, list)
    evidence = json.loads(steps[1]["observations"]["ceiling_evidence"])
    assert evidence["method"] == "enforced_cgroup_bounds"
    assert evidence["observation"] == driver.bounds
    assert evidence["cpu_bound"] == "2"
    assert evidence["memory_bound_bytes"] == 1073741824


def test_larger_bounds_do_not_prove_the_false_declaration() -> None:
    # Bounds stay unproven, so the measured-use fallback runs: an unbounded guest
    # burns past the request and proves the false declaration without the hog.
    driver = Ceiling(
        False,
        use={
            "processors": 8,
            "cpu_quota": None,
            "burn_threads": 8,
            "burn_wall_seconds": 4.0,
            "burn_cpu_seconds": 30.4,
        },
    )
    result = Runner(driver, {"test_size": {"cpu_min": 1, "memory_min_mib": 512}}).run_test(
        coverage_scenario("coverage.facts.size_is_ceiling.false")
    )
    assert result["result"] == "passed"
    assert result["proves"] == [{"fact": "resources.size_is_ceiling", "value": False}]
    assert driver.arguments == {"probe": "size_ceiling_use", "cpu": "1"}
    steps = result["steps"]
    assert isinstance(steps, list)
    assert steps[1]["observations"] == {"size_is_ceiling": {"matches": True}}


@pytest.mark.parametrize(
    ("size", "reason"),
    [
        (None, "fixture_missing"),
        ({"cpu_min": 1}, "proof_fixture_invalid"),
        ({"memory_min_mib": 512}, "proof_fixture_invalid"),
        ({"cpu_min": True, "memory_min_mib": 512}, "proof_fixture_invalid"),
    ],
)
def test_size_ceiling_does_not_run_without_cpu_and_memory(size: object, reason: str) -> None:
    driver = Ceiling(True)
    fixtures: dict[str, object] = {} if size is None else {"test_size": size}
    result = Runner(driver, fixtures).run_test(
        coverage_scenario("coverage.facts.size_is_ceiling.true")
    )
    assert result["result"] == "not_run"
    assert result["reason"] == reason
    assert result["proves"] == []
    assert driver.created == []


class Allocated(Driver):
    """A guest that reports the CPUs and memory it sees."""

    def __init__(self, cpu: float, memory_mib: int) -> None:
        super().__init__()
        self.seen = {"cpu": cpu, "memory_mib": memory_mib}
        self.created: list[Inputs] = []
        self.arguments: object = None

    def create(self, target: object, inputs: Inputs) -> Observation:
        del target
        self.created.append(dict(inputs))
        return {"state": "active"}

    def files_write(self, target: object, inputs: Inputs) -> Observation:
        del target
        assert b"def observe_allocation" in base64.b64decode(str(inputs["data"]))
        return {}

    def run(self, target: object, inputs: Inputs) -> Observation:
        del target
        environment = inputs["environment"]
        assert isinstance(environment, Mapping)
        self.arguments = json.loads(str(environment["SPS_FACT_ARGUMENTS"]))
        return {"exit_code": 0, "stdout": json.dumps(self.seen)}


LARGER = {"cpu_min": 2, "memory_min_mib": 4096}


def test_a_larger_size_is_delivered_when_the_guest_sees_it() -> None:
    driver = Allocated(2, 3950)
    result = Runner(driver, {"larger_size": LARGER}).run_test(
        coverage_scenario("coverage.facts.sizes.delivered")
    )
    assert result["result"] == "passed"
    assert result["proves"] == []
    assert driver.created[0]["resources"] == LARGER
    assert driver.arguments == {"probe": "allocation", "size": LARGER}
    assert '"observed_memory_mib": 3950' in json.dumps(result)


@pytest.mark.parametrize(("cpu", "memory_mib"), [(2, 1024), (1, 4096), (2, 3680)])
def test_the_default_size_is_not_a_delivered_larger_size(cpu: float, memory_mib: int) -> None:
    result = Runner(Allocated(cpu, memory_mib), {"larger_size": LARGER}).run_test(
        coverage_scenario("coverage.facts.sizes.delivered")
    )
    assert result["result"] == "differs"
    assert f'"observed_memory_mib": {memory_mib}' in json.dumps(result)


@pytest.mark.parametrize(
    ("size", "reason"),
    [
        (None, "fixture_missing"),
        ({"memory_min_mib": 4096}, "proof_fixture_invalid"),
        ({"cpu_min": 2, "memory_min_mib": 4096.5}, "proof_fixture_invalid"),
        ({"cpu_min": True, "memory_min_mib": 4096}, "proof_fixture_invalid"),
        ({"cpu_min": 2, "memory_min_mib": 4096, "disk_min_mib": 8192}, "proof_fixture_invalid"),
    ],
)
def test_a_larger_size_needs_exactly_cpu_and_memory(size: object, reason: str) -> None:
    driver = Allocated(2, 4096)
    fixtures: dict[str, object] = {} if size is None else {"larger_size": size}
    result = Runner(driver, fixtures).run_test(coverage_scenario("coverage.facts.sizes.delivered"))
    assert result["result"] == "not_run"
    assert result["reason"] == reason
    assert driver.created == []


@pytest.mark.parametrize("test_id", ["coverage.live_resize.grows", "coverage.live_resize.shrinks"])
def test_live_resize_fixtures_select_two_ordered_cpu_memory_sizes(test_id: str) -> None:
    fixtures = {
        "original_size": {"cpu_min": 1, "memory_min_mib": 512},
        "restored_size": {"cpu_min": 2, "memory_min_mib": 1024},
    }
    assert proof_fixtures(live_resize_scenario(test_id), fixtures) == {}


@pytest.mark.parametrize(
    ("original_size", "restored_size"),
    [
        ({"cpu_min": 1, "memory_min_mib": 512}, {"cpu_min": 2, "memory_min_mib": 512}),
        ({"cpu_min": 2, "memory_min_mib": 512}, {"cpu_min": 1, "memory_min_mib": 1024}),
        (
            {"cpu_min": 1, "memory_min_mib": 512},
            {"cpu_min": 2, "memory_min_mib": 1024, "disk_min_mib": 8192},
        ),
    ],
)
def test_live_resize_invalid_size_pair_is_not_run_before_create(
    original_size: Mapping[str, object], restored_size: Mapping[str, object]
) -> None:
    driver = Allocations()
    result = Runner(
        driver, {"original_size": original_size, "restored_size": restored_size}
    ).run_test(live_resize_scenario("coverage.live_resize.grows"))
    assert result["reason"] == "proof_fixture_invalid"
    assert driver.inputs == []


def test_missing_dynamic_proof_fixture_has_no_unresolved_report_target() -> None:
    result = Runner(Allocations()).run_test(scenario("previews.link_lifetime_seconds.public"))
    assert result["result"] == "not_run"
    assert result["proves"] == []
    assert "$runner" not in str(result)


def test_private_fixture_cannot_be_a_proof_value() -> None:
    test = Scenario(
        "private",
        "private",
        ({"op": "create"},),
        ({"fact": "resources.sizes", "value": "$runner.headers"},),
    )
    driver = Allocations()
    result = Runner(driver, {"headers": {"Authorization": "secret"}}).run_test(test)
    assert result["reason"] == "proof_fixture_not_public"
    assert driver.inputs == []
    assert "secret" not in str(result)


def test_gpu_alternatives_cannot_prove_every_requested_model() -> None:
    driver = Allocations()
    result = Runner(driver, {"test_gpu": {"gpu_model": ["nvidia:h100", "nvidia:h200"]}}).run_test(
        scenario("facts.gpus")
    )
    assert result["reason"] == "gpu_identity_mapping_unavailable"
    assert driver.inputs == []


def test_lifetime_proof_uses_waited_duration_and_rejects_expiry_as_success() -> None:
    driver = Allocations()
    result = Runner(driver, {"max_lifetime_seconds": 300, "max_lifetime_wait_ms": 300000}).run_test(
        scenario("facts.max_lifetime")
    )
    assert result["reason"] == "proof_fixture_window_invalid"
    assert driver.inputs == []


def test_allowlist_capacity_requires_an_endpoint_for_every_distinct_entry() -> None:
    driver = Allocations()
    result = Runner(
        driver,
        {"max_allow_entries": ["a.example", "b.example"], "max_allow_urls": ["https://a.example/"]},
    ).run_test(scenario("network_lockdown.max_allow"))
    assert result["reason"] == "proof_fixture_invalid"
    assert driver.inputs == []


def test_all_exercised_urls_must_succeed() -> None:
    class Network(Driver):
        def run(self, target: object, inputs: Inputs) -> Observation:
            del target
            environment = inputs["environment"]
            assert isinstance(environment, Mapping)
            return {"exit_code": 1 if environment["TARGET"] == "https://second.example/" else 0}

    test = Scenario(
        "entries",
        "entries",
        (
            {
                "op": "run.each_url",
                "in": {
                    "urls": ["https://first.example/", "https://second.example/"],
                    "bash_script": "probe",
                    "timeout_ms": 30000,
                },
                "expect": {"equals": {"exit_code": 0}},
            },
        ),
        (),
    )
    assert Runner(Network()).run_test(test)["result"] == "differs"


def test_multiple_mounts_cannot_pass_if_they_alias_one_volume() -> None:
    class Aliased(Driver):
        payload = b""

        def destroy(self, target: object, inputs: Inputs) -> Observation:
            del target, inputs
            return {}

        def create(self, target: object, inputs: Inputs) -> Observation:
            del target, inputs
            return {}

        def files_write(self, target: object, inputs: Inputs) -> Observation:
            del target
            assert isinstance(inputs["data"], str)
            self.payload = base64.b64decode(inputs["data"])
            return {}

        def files_read_bytes(self, target: object, inputs: Inputs) -> Observation:
            del target, inputs
            return {"data": self.payload}

    test = Scenario(
        "mounts",
        "mounts",
        (
            {
                "op": "volume.observe_mounts",
                "in": {"mounts": [{"path": "/first"}, {"path": "/second"}]},
                "expect": {"equals": {"all_writable": True}},
            },
        ),
        (),
    )
    assert Runner(Aliased(), {"volume_kind": "filesystem"}).run_test(test)["result"] == "differs"


@pytest.mark.parametrize(
    "model,wrong_name", [("nvidia:a10", "NVIDIA A100"), ("nvidia:l4", "NVIDIA L40S")]
)
def test_gpu_name_boundaries_do_not_accept_a_different_registry_model(
    model: str, wrong_name: str
) -> None:
    derived = proof_fixtures(scenario("facts.gpus"), {"test_gpu": {"gpu_model": [model]}})
    assert isinstance(derived["gpu_name_pattern"], str)
    result = subprocess.run(
        ["grep", "-E", derived["gpu_name_pattern"]],
        input=wrong_name + "\n",
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 1


def test_mounts_must_survive_in_a_fresh_sandbox() -> None:
    class Directories(Driver):
        payloads: dict[str, object] = {}

        def files_write(self, target: object, inputs: Inputs) -> Observation:
            del target
            self.payloads[str(inputs["path"])] = base64.b64decode(str(inputs["data"]))
            return {}

        def files_read_bytes(self, target: object, inputs: Inputs) -> Observation:
            del target
            return {"data": self.payloads.get(str(inputs["path"]), b"")}

        def destroy(self, target: object, inputs: Inputs) -> Observation:
            del target, inputs
            self.payloads = {}
            return {}

        def create(self, target: object, inputs: Inputs) -> Observation:
            del target, inputs
            return {}

    test = Scenario(
        "mounts",
        "mounts",
        (
            {
                "op": "volume.observe_mounts",
                "in": {"mounts": [{"path": "/ordinary-directory"}]},
                "expect": {"equals": {"all_writable": True}},
            },
        ),
        (),
    )
    assert (
        Runner(Directories(), {"volume_kind": "filesystem"}).run_test(test)["result"] == "differs"
    )


@pytest.mark.parametrize(
    "kind,output", [("default_user", b"guest\n"), ("default_cwd", b"/workspace with space\n")]
)
def test_environment_facts_come_from_successful_observation(kind: str, output: bytes) -> None:
    class Environment(Allocations):
        def run(self, target: object, inputs: Inputs) -> Observation:
            del target
            assert inputs == {"bash_script": "id -un" if kind == "default_user" else "pwd"}
            return {"exit_code": 0, "stdout": output}

    result = Runner(Environment(), {kind: "forged"}).run_test(scenario("facts." + kind))
    assert result["result"] == "passed"
    assert result["proves"] == [
        {"fact": "resources." + kind, "value": output.decode().removesuffix("\n")}
    ]
    assert "forged" not in str(result)


@pytest.mark.parametrize(
    "output,status", [(b"secret\nsecond\n", 0), (b"relative\n", 0), (b"/valid\n", 7)]
)
def test_invalid_or_failed_environment_observation_is_not_proof(output: bytes, status: int) -> None:
    class Environment(Allocations):
        def run(self, target: object, inputs: Inputs) -> Observation:
            del target, inputs
            return {"exit_code": status, "stdout": output}

    result = Runner(Environment()).run_test(scenario("facts.default_cwd"))
    assert result["result"] == "error"
    assert result["proves"] == []
    assert "secret" not in str(result)


@pytest.mark.parametrize(
    "surface,expected", [("absent", "passed"), ("implemented", "differs"), ("unmapped", "not_run")]
)
def test_false_process_proof_distinguishes_absence_from_missing_mapping(
    surface: str, expected: str
) -> None:
    class Surface(Driver):
        def process_cancel(self, target: object, inputs: Inputs) -> Observation:
            del target, inputs
            raise AssertionError("absence inspection must not invoke a supported operation")

    driver = Surface() if surface == "implemented" else Driver()
    if surface == "absent":
        driver.unsupported = {"process.cancel": "Pinned native SDK has no cancellation API"}
    result = Runner(driver).run_test(scenario("processes.cancel.false"))
    assert result["result"] == expected
    if expected == "passed":
        assert result["proves"] == [{"gate": "processes", "knob": "cancel", "value": False}]


def test_inject_host_count_is_derived_before_any_step() -> None:
    class Stops(Driver):
        def __init__(self) -> None:
            super().__init__()
            self.created: Inputs | None = None

        def secret_create(self, target: object, inputs: Inputs) -> Observation:
            del target, inputs
            return {"id": "secret"}

        def create(self, target: object, inputs: Inputs) -> Observation:
            del target
            self.created = inputs
            raise NotRun("stop_after_create")

    hosts = ["a.fixture", "b.fixture"]
    driver = Stops()
    result = Runner(
        driver,
        {
            "max_inject_into_hosts": hosts,
            "max_inject_into_urls": ["https://a.fixture/one", "https://b.fixture/two"],
            "max_inject_into_count": 999,
        },
    ).run_test(
        next(
            test
            for test in read_suite(suite_path().with_name("coverage.yaml")).tests
            if test.id == "coverage.hidden_secrets.max_inject_into"
        )
    )
    assert result["reason"] == "stop_after_create"
    assert result["proves"] == [
        {"gate": "hidden_secrets", "knob": "max_inject_into", "value": {"at_least": 2}}
    ]
    assert driver.created is not None
    requirements = driver.created["requirements"]
    assert isinstance(requirements, Mapping)
    secrets = requirements["hidden_secrets"]
    assert isinstance(secrets, Mapping)
    assert secrets["inject_into"] == hosts
    assert "999" not in str(result)


def test_inject_host_count_overwrites_an_independent_fixture() -> None:
    assert proof_fixtures(
        Scenario("coverage.hidden_secrets.max_inject_into", "inject count", (), ()),
        {
            "max_inject_into_hosts": ["a.fixture", "b.fixture"],
            "max_inject_into_urls": ["https://a.fixture/", "https://b.fixture/"],
            "max_inject_into_count": 999,
        },
    ) == {"max_inject_into_count": 2}


@pytest.mark.parametrize(
    "hosts,urls,reason",
    [
        (None, ["https://a.fixture/"], "fixture_missing"),
        (["a.fixture"], None, "fixture_missing"),
        ([], [], "proof_fixture_invalid"),
        (["a.fixture"], ["https://a.fixture/", "https://b.fixture/"], "proof_fixture_invalid"),
        (["a.fixture"], ["http://a.fixture/"], "proof_fixture_invalid"),
        (["a.fixture"], ["https://user@a.fixture/"], "proof_fixture_invalid"),
        (["a.fixture"], ["https://user:pass@a.fixture/"], "proof_fixture_invalid"),
        (["a.fixture"], ["https://a.fixture/#fragment"], "proof_fixture_invalid"),
        (["a.fixture"], ["https://other.fixture/"], "proof_fixture_invalid"),
        (
            ["a.fixture", "a.fixture"],
            ["https://a.fixture/", "https://a.fixture/"],
            "proof_fixture_invalid",
        ),
        (["*.fixture"], ["https://a.fixture/"], "proof_fixture_invalid"),
        (["192.0.2.1"], ["https://192.0.2.1/"], "proof_fixture_invalid"),
        (
            [f"host{index}.fixture" for index in range(129)],
            [f"https://host{index}.fixture/" for index in range(129)],
            "proof_fixture_invalid",
        ),
    ],
)
def test_inject_host_count_rejects_untested_destinations(
    hosts: object, urls: object, reason: str
) -> None:
    with pytest.raises(NotRun, match=reason):
        proof_fixtures(
            Scenario("coverage.hidden_secrets.max_inject_into", "inject count", (), ()),
            {"max_inject_into_hosts": hosts, "max_inject_into_urls": urls},
        )


def test_deny_limit_counts_only_distinct_exercised_entries() -> None:
    test = Scenario("coverage.network_lockdown.max_deny", "deny count", (), ())
    assert proof_fixtures(
        test,
        {
            "max_deny_entries": ["a.fixture", "192.0.2.0/24"],
            "max_deny_urls": [
                ["http://a.fixture/", "https://a.fixture/"],
                ["https://192.0.2.1/", "http://192.0.2.2/"],
            ],
            "max_deny_count": 999,
        },
    ) == {"max_deny_count": 2}


@pytest.mark.parametrize(
    "pairs",
    [
        [["http://a.fixture/", "https://other.fixture/"]],
        [["http://a.fixture/", "http://a.fixture/"]],
        [],
    ],
)
def test_deny_limit_rejects_untested_entries(pairs: list[list[str]]) -> None:
    with pytest.raises(NotRun, match="proof_fixture_invalid"):
        proof_fixtures(
            Scenario("coverage.network_lockdown.max_deny", "deny count", (), ()),
            {
                "max_deny_entries": ["a.fixture"],
                "max_deny_urls": pairs,
            },
        )


@pytest.mark.parametrize(
    "kind,entry,pair,valid",
    [
        ("names", "a.fixture", ["http://a.fixture/", "https://other.fixture/"], False),
        ("addresses", "192.0.2.0/24", ["http://192.0.2.1/", "https://192.0.2.2/"], True),
        ("addresses", "192.0.2.0/24", ["http://192.0.2.1/", "https://198.51.100.1/"], False),
        ("addresses", "192.0.2.1", ["http://192.0.2.1/", "https://192.0.2.1/"], True),
        ("names", "192.0.2.1", ["http://192.0.2.1/", "https://192.0.2.1/"], False),
    ],
)
def test_ordinary_denylist_proof_targets_the_actual_entry(
    kind: str, entry: str, pair: list[str], valid: bool
) -> None:
    test = Scenario("coverage.network_lockdown.denylist." + kind, "denied", (), ())
    prefix = "denylist_" + kind
    fixtures = {prefix + "_entries": [entry], prefix + "_urls": [pair]}
    if valid:
        assert proof_fixtures(test, fixtures) == {}
    else:
        with pytest.raises(NotRun, match="proof_fixture_invalid"):
            proof_fixtures(test, fixtures)


def test_mixed_denylist_proof_accepts_names_and_addresses_together() -> None:
    test = Scenario("coverage.network_lockdown.denylist.mixed", "denied", (), ())
    fixtures = {
        "denylist_mixed_entries": ["blocked.fixture", "192.0.2.0/24"],
        "denylist_mixed_urls": [
            ["http://blocked.fixture/", "https://blocked.fixture/"],
            ["http://192.0.2.1/", "https://192.0.2.2/"],
        ],
    }
    assert proof_fixtures(test, fixtures) == {}


def _range_fixtures(**overrides: object) -> dict[str, object]:
    fixtures: dict[str, object] = {
        "allowed_ip_range": "192.0.2.0/24",
        "allowed_ip_url": "http://192.0.2.10/",
        "allowed_ip_range_url": "http://192.0.2.20/",
        "denied_url": "http://198.51.100.10/",
    }
    fixtures.update(overrides)
    return fixtures


def test_ip_range_fixture_accepts_a_denied_address_outside_the_range() -> None:
    test = Scenario("coverage.network_lockdown.allowlist.range", "range", (), ())
    assert proof_fixtures(test, _range_fixtures()) == {}
    assert proof_fixtures(test, _range_fixtures(denied_url="http://blocked.example/")) == {}


@pytest.mark.parametrize(
    "overrides",
    [
        {"denied_url": "http://192.0.2.11/"},
        {"allowed_ip_range": "0.0.0.0/0", "denied_url": "http://198.51.100.10/"},
        {"allowed_ip_range": "192.0.2.0/25"},
        {"allowed_ip_url": "http://198.51.100.10/"},
        {"allowed_ip_url": "http://[::1"},
        {"denied_url": "http://[::1"},
        {"allowed_ip_range": "not-a-range"},
        {"allowed_ip_range_url": "http://192.0.2.10/"},
        {"allowed_ip_range_url": "http://198.51.100.20/"},
        {"allowed_ip_range_url": "https://192.0.2.20/"},
        {"allowed_ip_range_url": "http://range.example/"},
        {"allowed_ip_range": "192.0.2.10/32", "allowed_ip_range_url": "http://192.0.2.10/"},
    ],
)
def test_ip_range_fixture_rejects_a_denied_address_the_range_would_allow(
    overrides: dict[str, object],
) -> None:
    with pytest.raises(NotRun, match="proof_fixture_invalid"):
        proof_fixtures(
            Scenario("coverage.network_lockdown.allowlist.range", "range", (), ()),
            _range_fixtures(**overrides),
        )


def test_ip_range_fixture_is_missing_until_its_controls_are_supplied() -> None:
    with pytest.raises(NotRun, match="fixture_missing"):
        proof_fixtures(
            Scenario("coverage.network_lockdown.allowlist.range", "range", (), ()),
            {},
        )


def test_allowlist_range_reports_a_missing_second_address() -> None:
    fixtures = _range_fixtures()
    del fixtures["allowed_ip_range_url"]
    with pytest.raises(NotRun, match="fixture_missing"):
        proof_fixtures(
            Scenario("coverage.network_lockdown.allowlist.range", "range", (), ()),
            fixtures,
        )


def test_allowlist_range_coverage_probes_both_addresses() -> None:
    suite = read_suite(suite_path().with_name("coverage.yaml"))
    test = next(
        item for item in suite.tests if item.id == "coverage.network_lockdown.allowlist.range"
    )
    requests = test.steps[1]["in"]["requests"]
    assert [row["url"] for row in requests] == [
        "$runner.allowed_ip_url",
        "$runner.allowed_ip_range_url",
        "$runner.denied_url",
    ]
    assert [row["reachable"] for row in requests] == [True, True, False]
