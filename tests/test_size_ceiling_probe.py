# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Exact enforced bounds, with no inference from guest-visible allocation or CPU affinity."""

from __future__ import annotations

import json
import os
import runpy
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import cast

import pytest

from sandbox_provider_spec.coverage_probe import guest
from sandbox_provider_spec.driver import Driver, Inputs, NativeFailure, NotRun, Observation
from sandbox_provider_spec.suite import suite_path

SIZE = {"probe": "size_is_ceiling", "size": [{"cpu": 2, "memory_mib": 4096}]}
ROOT = "/sys/fs/cgroup"


class Ceiling(Driver):
    """Bounds probe plus the optional measured-use fallback.

    `use` is the `size_ceiling_use` guest payload, `hog` the memory run's exit
    code or an exception the run raises. `state` answers `get` after a failed
    hog. When `use` is None the measured path cannot run.
    """

    def __init__(
        self,
        files: dict[str, str],
        *,
        exit_code: object = 0,
        use: object = None,
        hog: object = None,
        state: str = "active",
    ) -> None:
        super().__init__()
        self.payload: object = {"membership": "0::/box\n", "files": files}
        self.exit_code = exit_code
        self.use = use
        self.hog = hog
        self.state = state
        self.operations: list[str] = []

    def call(self, operation: str, target: object, inputs: Inputs) -> Observation:
        del target
        self.operations.append(operation)
        if operation == "files.write":
            return {}
        if operation == "get":
            return {"state": self.state}
        environment = inputs.get("environment")
        probe = (
            json.loads(str(environment["SPS_FACT_ARGUMENTS"]))["probe"]
            if isinstance(environment, Mapping)
            else None
        )
        if probe == "size_ceiling_bounds":
            assert inputs["timeout_ms"] == 45000
            return {"exit_code": self.exit_code, "stdout": json.dumps(self.payload)}
        if probe == "size_ceiling_use":
            if self.use is None:
                raise NotRun("use_measurement_unproven")
            return {"exit_code": 0, "stdout": json.dumps(self.use)}
        assert probe is None, probe
        if isinstance(self.hog, BaseException):
            raise self.hog
        assert isinstance(self.hog, int)
        return {"exit_code": self.hog, "stdout": ""}


def burn(
    processors: int,
    used_cpus: float,
    *,
    threads: int = 8,
    quota: object = None,
    wall: float = 4.0,
) -> dict[str, object]:
    """A `size_ceiling_use` guest answer burning `used_cpus` for `wall` seconds."""
    return {
        "processors": processors,
        "cpu_quota": quota,
        "burn_threads": threads,
        "burn_wall_seconds": wall,
        "burn_cpu_seconds": used_cpus * wall,
    }


def bounds(cpu: str = "200000 100000", memory: str = "4294967296") -> dict[str, str]:
    return {f"{ROOT}/box/cpu.max": cpu, f"{ROOT}/box/memory.max": memory}


def test_exact_v2_limits_prove_true_and_retain_raw_provenance() -> None:
    driver = Ceiling(bounds())
    result = guest(driver, None, SIZE)
    assert result["size_is_ceiling"] is True
    assert json.loads(str(result["ceiling_evidence"]))["observation"] == driver.payload
    assert driver.operations == ["files.write", "run"]


def test_exact_v1_limits_prove_true() -> None:
    files = {
        f"{ROOT}/cpu/box/cpu.cfs_quota_us": "200000",
        f"{ROOT}/cpu/box/cpu.cfs_period_us": "100000",
        f"{ROOT}/memory/box/memory.limit_in_bytes": "4294967296",
    }
    driver = Ceiling(files)
    driver.payload = {
        "membership": "4:cpu,cpuacct:/box\n3:memory:/box",
        "files": files,
    }
    result = guest(driver, None, SIZE)
    assert result["size_is_ceiling"] is True


def test_fractional_cpu_is_compared_without_rounding() -> None:
    size = {"probe": "size_is_ceiling", "size": [{"cpu": 0.1, "memory_mib": 4096}]}
    assert guest(Ceiling(bounds("10000 100000")), None, size)["size_is_ceiling"] is True
    with pytest.raises(NotRun, match="unproven"):
        guest(Ceiling(bounds("10001 100000")), None, size)


@pytest.mark.parametrize(
    "files",
    [
        bounds("200001 100000"),
        bounds(memory="4294967297"),
        {},
        bounds("max 100000", "max"),
        {f"{ROOT}/box/cpu.max": "200000 100000"},
    ],
)
def test_missing_or_larger_limits_prove_neither_true_nor_false(files: dict[str, str]) -> None:
    with pytest.raises(NotRun, match="unproven"):
        guest(Ceiling(files), None, SIZE)


def test_tight_ancestor_bound_is_sufficient_despite_larger_child_limit() -> None:
    files = bounds("400000 100000", "8589934592")
    files.update({f"{ROOT}/cpu.max": "200000 100000", f"{ROOT}/memory.max": "4294967296"})
    assert guest(Ceiling(files), None, SIZE)["size_is_ceiling"] is True


@pytest.mark.parametrize("scenario", ["affinity", "markerless_container", "unobserved_reserve"])
def test_vm_guest_observations_are_not_enforced_bounds(
    scenario: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # All three worlds look identical to nproc/MemTotal: 2 CPUs and ~3.8 GiB.
    # The real VM can have eight CPUs, or >4 GiB installed with a larger reserve,
    # or this process can be in a markerless container on a VM host.
    original = Path.read_text

    def read_text(path: Path, encoding: str | None = None, errors: str | None = None) -> str:
        if str(path) == "/proc/meminfo":
            return "MemTotal: 4018460 kB\n"
        if str(path) == "/proc/cpuinfo":
            return "flags: hypervisor\n"
        return original(path, encoding=encoding, errors=errors)

    monkeypatch.setattr(Path, "read_text", read_text)
    monkeypatch.setattr(os, "sched_getaffinity", lambda _: {0, 1})
    monkeypatch.setattr(os, "cpu_count", lambda: 8 if scenario == "affinity" else 2)
    facts = runpy.run_path(str(suite_path().parent / "fixtures/environment_facts.py"))
    observe = cast(Callable[[Path, Path], object], facts["observe_ceiling_bounds"])
    root = tmp_path / "cgroup"
    root.mkdir()
    membership = tmp_path / "membership"
    membership.write_text("0::/\n")
    driver = Ceiling({})
    driver.payload = observe(root, membership)
    assert driver.payload == {"membership": "0::/", "files": {}}
    with pytest.raises(NotRun, match="unproven"):
        guest(driver, None, SIZE)


@pytest.mark.parametrize(
    "files",
    [
        bounds("0 100000"),
        bounds("-1 100000"),
        bounds("200000 0"),
        bounds("NaN 100000"),
        bounds("200000"),
        bounds(memory="0"),
        bounds(memory="-1"),
        bounds(memory="1.5"),
        {f"{ROOT}/cpu/cpu.cfs_quota_us": "200000"},
        {"/tmp/memory.max": "4294967296"},
    ],
)
def test_malformed_limits_are_errors(files: dict[str, str]) -> None:
    with pytest.raises(NativeFailure, match="guest_fact_probe_invalid"):
        guest(Ceiling(files), None, SIZE)


@pytest.mark.parametrize("exit_code", [1, 137, 0.0, False, None])
def test_unsuccessful_read_is_never_proof(exit_code: object) -> None:
    with pytest.raises(NativeFailure, match="guest_fact_probe_failed"):
        guest(Ceiling(bounds(), exit_code=exit_code), None, SIZE)


@pytest.mark.parametrize("error", [TimeoutError("timed out"), KeyboardInterrupt(), OSError("EOF")])
def test_timeout_cancel_and_transport_errors_are_never_proof(error: BaseException) -> None:
    class Failed(Driver):
        def call(self, operation: str, target: object, inputs: Inputs) -> Observation:
            if operation == "files.write":
                return {}
            raise error

    with pytest.raises(type(error)):
        guest(Failed(), None, SIZE)


def test_unrelated_sibling_limits_cannot_prove_current_membership() -> None:
    driver = Ceiling(
        {f"{ROOT}/other/cpu.max": "100000 100000", f"{ROOT}/other/memory.max": "1073741824"}
    )
    with pytest.raises(NativeFailure, match="guest_fact_probe_invalid"):
        guest(driver, None, SIZE)


def test_unbounded_guest_fails_the_ceiling_on_measured_use() -> None:
    # An over-subscribed burn on an unbounded container measures more CPU than
    # the request; the memory hog is not attempted once use is disproved.
    driver = Ceiling({}, use=burn(8, 7.6))
    result = guest(driver, None, SIZE)
    assert result["size_is_ceiling"] is False
    evidence = json.loads(str(result["ceiling_evidence"]))
    assert evidence["method"] == "measured_use"
    assert evidence["memory_outcome"] == "not_attempted"
    assert driver.operations == ["files.write", "run", "run"]


def test_bounded_guest_proves_the_ceiling_on_measured_use() -> None:
    driver = Ceiling({}, use=burn(2, 1.98), hog=-9)
    result = guest(driver, None, SIZE)
    assert result["size_is_ceiling"] is True
    assert json.loads(str(result["ceiling_evidence"]))["memory_outcome"] == "process_killed"


@pytest.mark.parametrize("exit_code", [-9, 137, -15, 1, 2])
def test_killed_or_refused_hog_proves_the_memory_ceiling(exit_code: int) -> None:
    driver = Ceiling({}, use=burn(2, 2.0), hog=exit_code)
    assert guest(driver, None, SIZE)["size_is_ceiling"] is True


def test_surviving_hog_proves_there_is_no_memory_ceiling() -> None:
    driver = Ceiling({}, use=burn(2, 2.0), hog=0)
    result = guest(driver, None, SIZE)
    assert result["size_is_ceiling"] is False
    assert json.loads(str(result["ceiling_evidence"]))["memory_outcome"] == "completed"


def test_hog_taking_the_sandbox_down_proves_the_ceiling() -> None:
    driver = Ceiling({}, use=burn(2, 2.0), hog=OSError("lost"), state="stopped")
    result = guest(driver, None, SIZE)
    assert result["size_is_ceiling"] is True
    assert json.loads(str(result["ceiling_evidence"]))["memory_outcome"] == "sandbox_ended"


def test_failed_hog_on_a_live_sandbox_proves_nothing() -> None:
    driver = Ceiling({}, use=burn(2, 2.0), hog=OSError("lost"), state="active")
    with pytest.raises(NativeFailure, match="memory_ceiling_unproven"):
        guest(driver, None, SIZE)


@pytest.mark.parametrize(
    "payload",
    [
        burn(8, -1),
        burn(0, 1),
        {**burn(2, 1), "extra": 1},
        {key: value for key, value in burn(2, 1).items() if key != "cpu_quota"},
        {**burn(2, 1), "burn_wall_seconds": 0},
    ],
)
def test_malformed_use_observations_are_errors(payload: dict[str, object]) -> None:
    driver = Ceiling({}, use=payload)
    with pytest.raises(NativeFailure, match="guest_fact_probe_invalid"):
        guest(driver, None, SIZE)
