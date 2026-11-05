# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Controlled probe output is validated before it enters report assertions."""

from __future__ import annotations

import json
import os
import runpy
import subprocess
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import cast

import pytest

from sandbox_provider_spec.coverage_probe import _MEMORY_EXHAUSTION_SCRIPT, guest
from sandbox_provider_spec.driver import Driver, Inputs, NativeFailure, NotRun, Observation
from sandbox_provider_spec.runner import Runner
from sandbox_provider_spec.suite import read_suite, suite_path


class GuestDriver(Driver):
    def __init__(self, output: object) -> None:
        super().__init__()
        self.output = output
        self.operations: list[str] = []
        self.inputs: list[tuple[str, Inputs]] = []

    def call(self, operation: str, target: object, inputs: Inputs) -> Observation:
        del target
        self.operations.append(operation)
        self.inputs.append((operation, dict(inputs)))
        return (
            {}
            if operation == "files.write"
            else {"exit_code": 0, "stdout": json.dumps(self.output)}
        )


class UntimedMetadataDriver(GuestDriver):
    """A baseline provider that does not offer per-command execution limits."""

    def call(self, operation: str, target: object, inputs: Inputs) -> Observation:
        if operation == "create":
            return {"resource": self.own("sandbox", "owned", lambda: {"result": "deleted"})}
        if operation == "run" and "timeout_ms" in inputs:
            raise NotRun("per_command_execution_limit_unavailable")
        return super().call(operation, target, inputs)


@pytest.mark.parametrize(("hidden", "expected"), [(True, "passed"), (False, "differs")])
def test_metadata_baseline_needs_no_per_command_execution_limit(
    hidden: bool, expected: str
) -> None:
    driver = UntimedMetadataDriver({"host_metadata_hidden": hidden})
    selected = read_suite(suite_path().with_name("coverage.yaml"))
    case = next(test for test in selected.tests if test.id == "baseline.no_metadata")
    result = Runner(driver).run_test(case)
    assert result["result"] == expected
    if not hidden:
        assert result["reason"] == "host_metadata_hidden"
    assert driver.operations == ["files.write", "files.write", "run"]
    assert "timeout_ms" not in driver.inputs[-1][1]
    assert result["cleanup"] == [{"kind": "sandbox", "result": "deleted"}]


@pytest.mark.parametrize(
    ("inputs", "output", "timeout_ms"),
    [
        ({"probe": "arch"}, {"arch": "amd64"}, 45000),
        ({"probe": "package_manager"}, {"installed": True}, 240000),
    ],
)
def test_supplementary_fact_probe_execution_limits_are_retained(
    inputs: dict[str, object], output: dict[str, object], timeout_ms: int
) -> None:
    driver = GuestDriver(output)
    assert guest(driver, None, inputs) == output
    assert driver.inputs[-1][1]["timeout_ms"] == timeout_ms


@pytest.mark.parametrize("value", ["arm64", "amd64"])
def test_architecture_probe_accepts_only_catalog_values(value: str) -> None:
    driver = GuestDriver({"arch": value})
    assert guest(driver, None, {"probe": "arch"}) == {"arch": value}
    assert driver.operations == ["files.write", "run"]


def test_per_command_root_uses_a_native_user_operation() -> None:
    driver = GuestDriver({"uid_zero": True})
    assert guest(driver, None, {"probe": "root", "way": "per_command"}) == {"uid_zero": True}
    assert driver.operations == ["files.write", "run.as_root"]


@pytest.mark.parametrize(
    "output", [{"uid_zero": "upstream-text"}, {"uid_zero": True, "unexpected": "payload"}]
)
def test_upstream_text_cannot_become_a_boolean_fact(output: Mapping[str, object]) -> None:
    with pytest.raises(NativeFailure, match="guest_fact_probe_invalid"):
        guest(GuestDriver(output), None, {"probe": "root", "way": "by_default"})


def test_ambiguous_memory_observation_proves_nothing() -> None:
    output = {
        "disk_in_memory": None,
        "wrote_bytes": 256 * 1024**2,
        "memory_source": "cgroup_shmem",
        "memory_before_bytes": 0,
        "memory_during_bytes": 0,
        "memory_after_bytes": 0,
    }
    with pytest.raises(NotRun, match="guest_fact_observation_ambiguous"):
        guest(
            GuestDriver(output),
            None,
            {"probe": "disk_in_memory"},
        )


def test_tmpfs_shmem_delta_is_memory_backed() -> None:
    facts = runpy.run_path(str(suite_path().parent / "fixtures/environment_facts.py"))
    classify = cast(Callable[[int, int, int, str], bool | None], facts["_disk_memory_value"])
    assert classify(0, 256 * 1024**2, 0, "cgroup_shmem") is True


def test_disk_page_cache_without_shmem_is_not_memory_backed() -> None:
    facts = runpy.run_path(str(suite_path().parent / "fixtures/environment_facts.py"))
    classify = cast(Callable[[int, int, int, str], bool | None], facts["_disk_memory_value"])
    assert classify(8 * 1024**2, 8 * 1024**2, 8 * 1024**2, "cgroup_shmem") is False


def test_cgroup_shmem_ignores_host_memavailable_noise() -> None:
    facts = runpy.run_path(str(suite_path().parent / "fixtures/environment_facts.py"))
    source = cast(Callable[..., str], facts["_memory_source"])
    classify = cast(Callable[[int, int, int, str], bool | None], facts["_disk_memory_value"])
    meminfo = "MemAvailable: 1000000 kB\nShmem: 10 kB\n"
    assert source("shmem 10485760\nfile 99999999\n", meminfo) == "cgroup_shmem"
    assert classify(10, 10, 10, "cgroup_shmem") is False


def test_disk_probe_falls_back_to_guest_shmem_then_memavailable() -> None:
    facts = runpy.run_path(str(suite_path().parent / "fixtures/environment_facts.py"))
    source = cast(Callable[..., str], facts["_memory_source"])
    assert source("", "Shmem: 32 kB\nMemAvailable: 999 kB\n") == "meminfo_shmem"
    assert source("", "MemAvailable: 999 kB\n") == "memavailable"
    assert source("", "MemTotal: 999 kB\n") == "unavailable"


def test_disk_memory_guest_observation_keeps_source_and_raw_samples() -> None:
    output = {
        "disk_in_memory": False,
        "wrote_bytes": 256 * 1024**2,
        "memory_source": "cgroup_shmem",
        "memory_before_bytes": 1024,
        "memory_during_bytes": 1024,
        "memory_after_bytes": 1024,
    }
    assert guest(GuestDriver(output), None, {"probe": "disk_in_memory"}) == {
        **output,
        "stdout": json.dumps(output),
    }


@pytest.mark.parametrize(
    "field_value",
    [(["cgroup_shmem"], "memory_source"), (2**63, "memory_during_bytes")],
)
def test_disk_memory_guest_rejects_unbounded_observation_fields(
    field_value: tuple[object, str],
) -> None:
    value, field = field_value
    output: dict[str, object] = {
        "disk_in_memory": False,
        "wrote_bytes": 256 * 1024**2,
        "memory_source": "cgroup_shmem",
        "memory_before_bytes": 0,
        "memory_during_bytes": 0,
        "memory_after_bytes": 0,
    }
    output[field] = value
    with pytest.raises(NativeFailure, match="guest_fact_probe_invalid"):
        guest(GuestDriver(output), None, {"probe": "disk_in_memory"})


class MemoryDriver(Driver):
    def __init__(
        self,
        *,
        state: str | None = "active",
        stdout: bytes | str = b"alive\n",
        exit_code: int = 0,
        start_error: Exception | None = None,
        echo_error: Exception | None = None,
        state_error: Exception | None = None,
        allocator_exit_code: int | None = 137,
        wait_error: Exception | None = None,
    ) -> None:
        super().__init__()
        self.state = state
        self.stdout = stdout
        self.exit_code = exit_code
        self.start_error = start_error
        self.echo_error = echo_error
        self.state_error = state_error
        self.allocator_exit_code = allocator_exit_code
        self.wait_error = wait_error
        self.operations: list[str] = []
        self.started = ""
        self.process_resource = object()

    def call(self, operation: str, target: object, inputs: Inputs) -> Observation:
        self.operations.append(operation)
        if operation == "process.start":
            assert target is None
            script = inputs.get("bash_script")
            self.started = script if isinstance(script, str) else ""
            if self.start_error is not None:
                raise self.start_error
            return {"resource": self.process_resource, "identity": "allocator"}
        if operation == "get":
            if self.state_error is not None:
                raise self.state_error
            assert target is None
            if self.state is None:
                return {}
            return {"state": self.state}
        if operation == "run":
            assert target is None
            if self.echo_error is not None:
                raise self.echo_error
            return {"exit_code": self.exit_code, "stdout": self.stdout}
        if operation == "process.wait":
            assert isinstance(target, Mapping) and target["resource"] is self.process_resource
            if self.wait_error is not None:
                raise self.wait_error
            return {"exit_code": self.allocator_exit_code}
        raise AssertionError(operation)


def test_memory_probe_reports_process_killed(monkeypatch: pytest.MonkeyPatch) -> None:
    slept: list[float] = []
    monkeypatch.setattr(
        "sandbox_provider_spec.coverage_probe.time.sleep", lambda seconds: slept.append(seconds)
    )
    driver = MemoryDriver(stdout="alive\n")
    assert guest(driver, None, {"probe": "on_memory_exhausted", "memory_mib": 512}) == {
        "on_memory_exhausted": "process_killed"
    }
    assert slept == [10]
    assert driver.operations == ["process.start", "get", "run", "process.wait"]
    assert driver.started.endswith(" 512")
    assert "64 * 1024 * 1024" in driver.started


@pytest.mark.parametrize(
    ("state", "exit_code", "stdout"),
    [
        ("destroyed", 0, b"alive\n"),
        ("stopped", 0, b"alive\n"),
    ],
)
def test_memory_probe_reports_sandbox_ended(
    monkeypatch: pytest.MonkeyPatch, state: str, exit_code: int, stdout: bytes
) -> None:
    monkeypatch.setattr("sandbox_provider_spec.coverage_probe.time.sleep", lambda _seconds: None)
    driver = MemoryDriver(state=state, exit_code=exit_code, stdout=stdout)
    assert guest(driver, None, {"probe": "on_memory_exhausted", "memory_mib": 512}) == {
        "on_memory_exhausted": "sandbox_ended"
    }
    if state != "active":
        assert driver.operations == ["process.start", "get"]


def test_memory_probe_treats_a_dead_sandbox_during_start_as_sandbox_ended(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("sandbox_provider_spec.coverage_probe.time.sleep", lambda _seconds: None)
    driver = MemoryDriver(state="destroyed", start_error=RuntimeError("sandbox gone"))
    assert guest(driver, None, {"probe": "on_memory_exhausted", "memory_mib": 512}) == {
        "on_memory_exhausted": "sandbox_ended"
    }
    assert driver.operations == ["process.start", "get"]


@pytest.mark.parametrize(
    "error", [RuntimeError("request failed"), NotRun("native_state_unobservable")]
)
def test_memory_probe_propagates_unknown_state_after_observation(
    monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    monkeypatch.setattr("sandbox_provider_spec.coverage_probe.time.sleep", lambda _seconds: None)

    class StateReadFailure(MemoryDriver):
        reads = 0

        def call(self, operation: str, target: object, inputs: Inputs) -> Observation:
            if operation == "get":
                self.reads += 1
                if self.reads == 1:
                    self.operations.append(operation)
                    raise error
            return super().call(operation, target, inputs)

    driver = StateReadFailure()
    with pytest.raises(type(error), match=str(error)):
        guest(driver, None, {"probe": "on_memory_exhausted", "memory_mib": 512})
    assert driver.operations == ["process.start", "get"]


def test_memory_probe_does_not_prove_an_outcome_when_start_fails_on_a_live_sandbox() -> None:
    driver = MemoryDriver(start_error=RuntimeError("process start failed"))
    with pytest.raises(RuntimeError, match="process start failed"):
        guest(driver, None, {"probe": "on_memory_exhausted", "memory_mib": 512})


def test_memory_probe_echo_failure_does_not_prove_sandbox_ended(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("sandbox_provider_spec.coverage_probe.time.sleep", lambda _seconds: None)
    driver = MemoryDriver(echo_error=NativeFailure("gone"))
    with pytest.raises(NotRun, match="memory_sandbox_liveness_unproven"):
        guest(driver, None, {"probe": "on_memory_exhausted", "memory_mib": 512})


@pytest.mark.parametrize(
    ("state", "state_error", "expected_error"),
    [
        (None, None, NotRun),
        ("active", RuntimeError("temporary get failure"), RuntimeError),
    ],
)
def test_memory_probe_does_not_claim_termination_when_state_is_unreadable(
    monkeypatch: pytest.MonkeyPatch,
    state: str | None,
    state_error: Exception | None,
    expected_error: type[Exception],
) -> None:
    monkeypatch.setattr("sandbox_provider_spec.coverage_probe.time.sleep", lambda _seconds: None)
    driver = MemoryDriver(state=state, state_error=state_error)
    with pytest.raises(expected_error):
        guest(driver, None, {"probe": "on_memory_exhausted", "memory_mib": 512})
    assert driver.operations == ["process.start", "get"]


@pytest.mark.parametrize("exit_code", [0, 1, 127, -1, None, True, "137"])
def test_memory_probe_requires_allocator_failure_to_report_process_killed(
    monkeypatch: pytest.MonkeyPatch, exit_code: object
) -> None:
    monkeypatch.setattr("sandbox_provider_spec.coverage_probe.time.sleep", lambda _seconds: None)
    driver = MemoryDriver(allocator_exit_code=cast(int | None, exit_code))
    with pytest.raises(NativeFailure, match="memory_allocator_exit_unproven"):
        guest(driver, None, {"probe": "on_memory_exhausted", "memory_mib": 512})
    assert driver.operations[-1] == "process.wait"


def test_memory_probe_does_not_claim_kill_when_allocator_is_still_running(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("sandbox_provider_spec.coverage_probe.time.sleep", lambda _seconds: None)
    driver = MemoryDriver(wait_error=NotRun("native_process_still_running"))
    with pytest.raises(NotRun, match="memory_allocator_still_running"):
        guest(driver, None, {"probe": "on_memory_exhausted", "memory_mib": 512})


@pytest.mark.parametrize("memory_mib", [None, True, False, 0, -1, "512"])
def test_memory_probe_rejects_a_bad_memory_size(memory_mib: object) -> None:
    with pytest.raises(ValueError, match="invalid on_memory_exhausted memory_mib"):
        guest(MemoryDriver(), None, {"probe": "on_memory_exhausted", "memory_mib": memory_mib})


def test_memory_exhaustion_script_allocates_one_step() -> None:
    completed = subprocess.run(
        [sys.executable, "-c", _MEMORY_EXHAUSTION_SCRIPT, "1"],
        check=False,
        capture_output=True,
        timeout=60,
    )
    assert completed.returncode == 0, completed.stderr


def test_size_ceiling_requires_the_tested_size_before_running() -> None:
    driver = GuestDriver({"size_is_ceiling": True})
    with pytest.raises(ValueError, match="tested size"):
        guest(driver, None, {"probe": "size_is_ceiling"})
    assert driver.operations == []


def _ceiling_script(
    arguments: Mapping[str, object], timeout: int
) -> subprocess.CompletedProcess[str]:
    script = suite_path().parent / "fixtures/environment_facts.py"
    return subprocess.run(
        [sys.executable, str(script)],
        env={**os.environ, "SPS_FACT_ARGUMENTS": json.dumps(arguments)},
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def test_ceiling_bounds_script_reads_without_allocating() -> None:
    result = _ceiling_script({"probe": "size_ceiling_bounds"}, 10)
    assert result.returncode == 0, result.stderr
    assert set(json.loads(result.stdout)) == {"membership", "files"}


def _facts() -> dict[str, object]:
    return runpy.run_path(str(suite_path().parent / "fixtures/environment_facts.py"))


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def test_allocation_takes_the_tightest_cgroup_v2_limit_up_to_the_mount(tmp_path: Path) -> None:
    root = tmp_path / "cgroup"
    _write(root / "cpu.max", "400000 100000\n")
    _write(root / "memory.max", "8589934592\n")
    _write(root / "box" / "cpu.max", "200000 100000\n")
    _write(root / "box" / "memory.max", "max\n")
    _write(root / "box" / "inner" / "cpu.max", "max 100000\n")
    _write(tmp_path / "self", "0::/box/inner\n")
    limits = cast(Callable[[Path, Path], tuple[object, object]], _facts()["cgroup_limits"])
    assert limits(root, tmp_path / "self") == (2.0, 8589934592)


def test_allocation_reads_cgroup_v1_and_a_host_path_the_mount_hides(tmp_path: Path) -> None:
    root = tmp_path / "cgroup"
    _write(root / "cpu,cpuacct" / "cpu.cfs_quota_us", "150000\n")
    _write(root / "cpu,cpuacct" / "cpu.cfs_period_us", "100000\n")
    _write(root / "memory" / "memory.limit_in_bytes", "4294967296\n")
    _write(tmp_path / "self", "4:cpu,cpuacct:/docker/abc\n3:memory:/docker/abc\n")
    limits = cast(Callable[[Path, Path], tuple[object, object]], _facts()["cgroup_limits"])
    assert limits(root, tmp_path / "self") == (1.5, 4294967296)


def test_allocation_without_cgroup_limits_is_none(tmp_path: Path) -> None:
    _write(tmp_path / "self", "0::/\n")
    limits = cast(Callable[[Path, Path], tuple[object, object]], _facts()["cgroup_limits"])
    assert limits(tmp_path / "cgroup", tmp_path / "self") == (None, None)


@pytest.mark.parametrize(
    ("control", "contents", "membership", "unreadable", "error"),
    [
        (
            "cpu.max",
            {"cpu.max": "200000 100000\n", "memory.max": "8589934592\n"},
            "0::/box/inner\n",
            "cpu.max",
            "cgroup cpu limit unreadable",
        ),
        (
            "memory.max",
            {"cpu.max": "200000 100000\n", "memory.max": "8589934592\n"},
            "0::/box/inner\n",
            "memory.max",
            "cgroup memory limit unreadable",
        ),
        (
            "cpu.cfs_quota_us",
            {"cpu.cfs_quota_us": "200000\n", "cpu.cfs_period_us": "100000\n"},
            "4:cpu,cpuacct:/box/inner\n",
            "cpu.cfs_quota_us",
            "cgroup CPU limit unreadable",
        ),
        (
            "cpu.cfs_period_us",
            {"cpu.cfs_quota_us": "200000\n", "cpu.cfs_period_us": "100000\n"},
            "4:cpu,cpuacct:/box/inner\n",
            "cpu.cfs_period_us",
            "cgroup CPU limit unreadable",
        ),
        (
            "memory.limit_in_bytes",
            {"memory.limit_in_bytes": "8589934592\n"},
            "3:memory:/box/inner\n",
            "memory.limit_in_bytes",
            "cgroup memory limit unreadable",
        ),
    ],
)
def test_allocation_rejects_unreadable_cgroup_limits(
    tmp_path: Path,
    control: str,
    contents: dict[str, str],
    membership: str,
    unreadable: str,
    error: str,
) -> None:
    root = tmp_path / "cgroup"
    if control in {"cpu.max", "memory.max"}:
        directories = (root, root / "box" / "inner")
    elif control.startswith("cpu."):
        directories = (root / "cpu,cpuacct", root / "cpu,cpuacct" / "box" / "inner")
    else:
        directories = (root / "memory", root / "memory" / "box" / "inner")
    for directory in directories:
        for filename, value in contents.items():
            _write(directory / filename, value)
    _write(tmp_path / "self", membership)
    facts = _facts()
    limits = cast(Callable[[Path, Path], tuple[object, object]], facts["cgroup_limits"])
    read = cast(Callable[[Path], str | None], facts["_read"])

    ancestor = directories[0]

    def unreadable_control(path: Path) -> str | None:
        return None if path.name == unreadable and path.parent == ancestor else read(path)

    limits.__globals__["_read"] = unreadable_control
    try:
        with pytest.raises(ValueError, match=error):
            limits(root, tmp_path / "self")
    finally:
        limits.__globals__["_read"] = read


def test_allocation_rejects_unreadable_cgroup_membership(tmp_path: Path) -> None:
    limits = cast(Callable[[Path, Path], tuple[object, object]], _facts()["cgroup_limits"])
    with pytest.raises(ValueError, match="cgroup membership unreadable"):
        limits(tmp_path / "cgroup", tmp_path / "missing-self")


def test_allocation_script_reports_positive_cpu_and_memory() -> None:
    result = _ceiling_script({"probe": "allocation"}, 10)
    assert result.returncode == 0, result.stderr
    seen = json.loads(result.stdout)
    assert set(seen) == {"cpu", "memory_mib"}
    assert seen["cpu"] > 0
    assert isinstance(seen["memory_mib"], int)
    assert seen["memory_mib"] > 0


def test_allocation_requires_the_requested_size_before_running() -> None:
    driver = GuestDriver({"cpu": 2, "memory_mib": 4096})
    with pytest.raises(ValueError, match="requested size"):
        guest(driver, None, {"probe": "allocation", "size": {"memory_min_mib": 4096}})
    assert driver.operations == []


def test_allocation_compares_what_the_guest_sees_with_the_request() -> None:
    size = {"cpu_min": 2, "memory_min_mib": 4096}
    assert guest(
        GuestDriver({"cpu": 2, "memory_mib": 1024}), None, {"probe": "allocation", "size": size}
    ) == {
        "observed_cpu": 2,
        "observed_memory_mib": 1024,
        "cpu_delivered": True,
        "memory_delivered": False,
    }
    assert guest(
        GuestDriver({"cpu": 1.999, "memory_mib": 3700}), None, {"probe": "allocation", "size": size}
    ) == {
        "observed_cpu": 1.999,
        "observed_memory_mib": 3700,
        "cpu_delivered": True,
        "memory_delivered": True,
    }


@pytest.mark.parametrize(
    "output",
    [
        {"cpu": "2", "memory_mib": 4096},
        {"cpu": 2, "memory_mib": 4096.5},
        {"cpu": 0, "memory_mib": 1},
    ],
)
def test_allocation_rejects_output_that_is_not_a_positive_size(output: object) -> None:
    with pytest.raises(NativeFailure, match="guest_fact_probe_invalid"):
        guest(
            GuestDriver(output),
            None,
            {"probe": "allocation", "size": {"cpu_min": 2, "memory_min_mib": 4096}},
        )
