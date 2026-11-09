# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Shared supplementary guest fixtures, invoked through native run and file APIs."""

from __future__ import annotations

import base64
import json
import math
import shlex
import time
from collections.abc import Mapping
from fractions import Fraction
from pathlib import PurePosixPath
from typing import cast

from sandbox_provider_spec.driver import Driver, NativeFailure, NotRun
from sandbox_provider_spec.suite import suite_path

FACT_FIELDS = {
    "home": {"home_matches_user"},
    "no_metadata": {"host_metadata_hidden"},
    "arch": {"arch"},
    "root": {"uid_zero"},
    "libc": {"libc"},
    "package_manager": {"installed"},
    "disk_in_memory": {
        "disk_in_memory",
        "wrote_bytes",
        "memory_source",
        "memory_before_bytes",
        "memory_during_bytes",
        "memory_after_bytes",
        "stdout",
    },
    "size_is_ceiling": {"size_is_ceiling"},
    "allocation": {"cpu", "memory_mib"},
}

MEMORY_SEEN = 0.9
"""The share of a size's memory the guest must see. A program inside always sees a little
less than the allocation the provider sells, because the kernel keeps some for itself."""

# Allocate 64 MiB at a time until the process is killed or it reaches twice memory_mib.
# Each page is written so the allocation is resident rather than only reserved.
_MEMORY_EXHAUSTION_SCRIPT = """\
import sys
step = 64 * 1024 * 1024
page = 4096
limit = int(sys.argv[1]) * 2 * 1024 * 1024
held = []
used = 0
while used < limit:
    block = bytearray(step)
    block[::page] = bytes([1]) * ((step + page - 1) // page)
    held.append(block)
    used += step
"""


def _sandbox_state(driver: Driver, target: object) -> str:
    observed = driver.call("get", target, {}).get("state")
    if not isinstance(observed, str):
        raise NotRun("native_state_unobservable")
    return observed


def _echo_alive(driver: Driver, target: object) -> bool:
    try:
        result = driver.call("run", target, {"bash_script": "echo alive"})
    except Exception:  # pylint: disable=broad-exception-caught
        return False
    stdout = result.get("stdout")
    if isinstance(stdout, bytes):
        text = stdout.decode("utf-8", "replace")
    elif isinstance(stdout, str):
        text = stdout
    else:
        return False
    return result.get("exit_code") == 0 and text.strip() == "alive"


def _on_memory_exhausted(
    driver: Driver, target: object, inputs: Mapping[str, object]
) -> Mapping[str, object]:
    """Background allocation, then `get` and `echo alive` after ten seconds.

    `process_killed` requires the sandbox to still be running and the command to print
    `alive`, and a SIGKILL exit. Only a terminal native state proves `sandbox_ended`.
    """
    memory_mib = inputs.get("memory_mib")
    if not isinstance(memory_mib, int) or isinstance(memory_mib, bool) or memory_mib < 1:
        raise ValueError("invalid on_memory_exhausted memory_mib")
    command = "python3 -c " + shlex.quote(_MEMORY_EXHAUSTION_SCRIPT) + " " + str(memory_mib)
    try:
        process = driver.call(
            "process.start",
            target,
            {"bash_script": command, "timeout_ms": 180000},
        )
    except NotRun:
        raise
    except Exception as started:  # pylint: disable=broad-exception-caught
        # The sandbox can die as the allocator starts, before this call returns.
        try:
            state = _sandbox_state(driver, target)
        except NotRun:
            raise
        except Exception:  # pylint: disable=broad-exception-caught
            raise started from None
        if state in {"stopped", "destroyed"}:
            return {"on_memory_exhausted": "sandbox_ended"}
        raise started
    time.sleep(10)
    state = _sandbox_state(driver, target)
    if state in {"stopped", "destroyed"}:
        return {"on_memory_exhausted": "sandbox_ended"}
    if state != "active" or not _echo_alive(driver, target):
        raise NotRun("memory_sandbox_liveness_unproven")
    try:
        result = driver.call("process.wait", process, {"timeout_ms": 1000})
    except NotRun as pending:
        # An allocator still running after the observation window has not proved a kill.
        if "still_running" in str(pending):
            raise NotRun("memory_allocator_still_running") from pending
        raise
    exit_code = result.get("exit_code")
    if isinstance(exit_code, bool) or not isinstance(exit_code, int) or exit_code not in {-9, 137}:
        raise NativeFailure("memory_allocator_exit_unproven")
    return {"on_memory_exhausted": "process_killed"}


def _require_ceiling_size(inputs: Mapping[str, object]) -> None:
    # pylint: disable=too-many-boolean-expressions
    size = inputs.get("size")
    point = size[0] if isinstance(size, list) and len(size) == 1 else None
    if not isinstance(point, Mapping):
        raise ValueError("size ceiling probe requires the tested size")
    cpu = point.get("cpu")
    memory = point.get("memory_mib")
    if (
        isinstance(cpu, bool)
        or not isinstance(cpu, (int, float))
        or not math.isfinite(cpu)
        or cpu <= 0
        or isinstance(memory, bool)
        or not isinstance(memory, int)
        or memory <= 0
    ):
        raise ValueError("size ceiling probe requires the tested size")


def _ceiling_paths(membership: str) -> set[str]:
    """Only the recorded memberships and their ancestors can constrain this command."""
    root = PurePosixPath("/sys/fs/cgroup")
    allowed: set[str] = set()
    for line in membership.splitlines():
        identifier, controllers, member = line.split(":", 2)
        if not identifier.isdecimal() or not member.startswith("/") or ".." in member.split("/"):
            raise ValueError("invalid membership")
        mounts: list[tuple[PurePosixPath, tuple[str, ...]]] = []
        if not controllers:
            mounts.append((root, ("cpu.max", "memory.max")))
        if "cpu" in controllers.split(","):
            for mount in (root / controllers, root / "cpu"):
                mounts.append((mount, ("cpu.cfs_quota_us", "cpu.cfs_period_us")))
        if "memory" in controllers.split(","):
            mounts.append((root / "memory", ("memory.limit_in_bytes",)))
        for mount, names in mounts:
            directory = mount / member.lstrip("/")
            while True:
                allowed.update(str(directory / name) for name in names)
                if directory == mount:
                    break
                directory = directory.parent
    return allowed


def _ceiling_limits(value: object) -> tuple[list[Fraction], list[int]]:
    """Parse exact kernel bounds; larger bounds cannot establish their attainability."""
    if not isinstance(value, dict) or set(value) != {"membership", "files"}:
        raise ValueError("invalid bound observation")
    if not isinstance(value["membership"], str) or not value["membership"]:
        raise ValueError("missing membership")
    allowed = _ceiling_paths(value["membership"])
    files = value["files"]
    if not isinstance(files, dict):
        raise ValueError("invalid bound files")
    cpu: list[Fraction] = []
    memory: list[int] = []
    for name, raw in files.items():
        if not isinstance(name, str) or not isinstance(raw, str):
            raise ValueError("invalid bound file")
        path = PurePosixPath(name)
        if name not in allowed:
            raise ValueError("invalid bound path")
        if path.name == "cpu.max":
            quota, period = raw.split()
            if not period.isdecimal() or int(period) <= 0:
                raise ValueError("invalid CPU period")
            if quota == "max":
                continue
            if not quota.isdecimal() or int(quota) <= 0:
                raise ValueError("invalid CPU quota")
            cpu.append(Fraction(int(quota), int(period)))
        elif path.name in {"cpu.cfs_quota_us", "cpu.cfs_period_us"}:
            quota = files[str(path.with_name("cpu.cfs_quota_us"))]
            period = files[str(path.with_name("cpu.cfs_period_us"))]
            if not isinstance(quota, str) or not isinstance(period, str):
                raise ValueError("invalid v1 CPU bound")
            if not period.isdecimal() or int(period) <= 0:
                raise ValueError("invalid CPU period")
            if quota == "-1":
                continue
            if not quota.isdecimal() or int(quota) <= 0:
                raise ValueError("invalid CPU quota")
            cpu.append(Fraction(int(quota), int(period)))
        elif path.name in {"memory.max", "memory.limit_in_bytes"}:
            if raw == "max" and path.name == "memory.max":
                continue
            if not raw.isdecimal() or int(raw) <= 0:
                raise ValueError("invalid memory maximum")
            memory.append(int(raw))
        else:
            raise ValueError("invalid bound filename")
    return cpu, memory


def _size_ceiling(
    driver: Driver, target: object, inputs: Mapping[str, object]
) -> Mapping[str, object]:
    """Prove a declared size is a hard ceiling, in the cheapest way that can fail.

    Exact enforced cgroup bounds prove a ceiling without destructive memory
    pressure. A larger or absent observed bound proves neither exceedance nor the
    absence of a tighter, unobserved bound, and guest allocation/affinity alone is
    not a whole-sandbox upper bound, so bounds that do not prove the ceiling fall
    back to a measured use test: an over-subscribed CPU burn that must not exceed
    the request, then a memory hog that must be killed or refused. The measured
    path can prove false on an unbounded container; the hog is destructive by
    design, so it always runs last.
    """
    try:
        return _size_ceiling_bounds(driver, target, inputs)
    except NotRun as unproven:
        if "ceiling_bounds_unproven" not in str(unproven):
            raise
        return _size_ceiling_use(driver, target, inputs)


def _size_ceiling_bounds(
    driver: Driver, target: object, inputs: Mapping[str, object]
) -> Mapping[str, object]:
    """Exact enforced bounds can prove a ceiling without destructive memory pressure.

    A larger or absent observed bound proves neither exceedance nor the absence of a
    tighter, unobserved bound. Guest allocation/affinity is not a whole-VM upper bound.
    """
    result = driver.call(
        "run",
        target,
        {
            "bash_script": "python3 /tmp/sps-environment-facts.py",
            "environment": {"SPS_FACT_ARGUMENTS": json.dumps({"probe": "size_ceiling_bounds"})},
            "timeout_ms": 45000,
        },
    )
    if (
        isinstance(result.get("exit_code"), bool)
        or not isinstance(result.get("exit_code"), int)
        or result["exit_code"] != 0
    ):
        raise NativeFailure("guest_fact_probe_failed")
    payload = result.get("stdout")
    if not isinstance(payload, (str, bytes)) or len(payload) > 8192:
        raise NativeFailure("guest_fact_probe_invalid")
    try:
        value = json.loads(payload)
        cpu, memory = _ceiling_limits(value)
    except (ValueError, KeyError, TypeError):
        raise NativeFailure("guest_fact_probe_invalid") from None
    size = cast(list[Mapping[str, object]], inputs["size"])[0]
    if (
        not cpu
        or not memory
        or min(cpu) > Fraction(str(size["cpu"]))
        or min(memory) > cast(int, size["memory_mib"]) * 1048576
    ):
        raise NotRun("ceiling_bounds_unproven")
    return {
        "size_is_ceiling": True,
        "ceiling_evidence": json.dumps(
            {
                "method": "enforced_cgroup_bounds",
                "observation": value,
                "cpu_bound": str(min(cpu)),
                "memory_bound_bytes": min(memory),
                "requested_cpu": str(size["cpu"]),
                "requested_memory_bytes": cast(int, size["memory_mib"]) * 1048576,
                "limitations": "Visible cgroup bounds only; no VM or exceedance inference.",
            },
            sort_keys=True,
        ),
    }


#: Measured CPU-seconds per wall-second may exceed the request by at most this
#: much; the margin covers scheduler jitter, not another processor's worth.
_CPU_CEILING_TOLERANCE = 0.05

_USE_PROBE_FIELDS = {
    "processors",
    "cpu_quota",
    "burn_threads",
    "burn_wall_seconds",
    "burn_cpu_seconds",
}


def _ceiling_use_observation(payload: object) -> Mapping[str, object]:
    """Parse the guest's `size_ceiling_use` answer, rejecting malformed shapes."""
    if not isinstance(payload, dict) or set(payload) != _USE_PROBE_FIELDS:
        raise NativeFailure("guest_fact_probe_invalid")
    processors, quota = payload["processors"], payload["cpu_quota"]
    threads, wall, used = (
        payload["burn_threads"],
        payload["burn_wall_seconds"],
        payload["burn_cpu_seconds"],
    )
    if (  # pylint: disable=too-many-boolean-expressions
        isinstance(processors, bool)
        or not isinstance(processors, int)
        or processors <= 0
        or (quota is not None and (isinstance(quota, bool) or not isinstance(quota, (int, float))))
        or isinstance(threads, bool)
        or not isinstance(threads, int)
        or threads <= 0
        or isinstance(wall, bool)
        or not isinstance(wall, (int, float))
        or not math.isfinite(wall)
        or wall <= 0
        or isinstance(used, bool)
        or not isinstance(used, (int, float))
        or not math.isfinite(used)
        or used < 0
    ):
        raise NativeFailure("guest_fact_probe_invalid")
    return cast(Mapping[str, object], payload)


def _size_ceiling_use(
    driver: Driver, target: object, inputs: Mapping[str, object]
) -> Mapping[str, object]:
    """Measured use test: a CPU burn that cannot exceed, then a hog that cannot hold.

    Runs only when enforced cgroup bounds are unproven, for example on a dedicated
    VM whose ceiling is the virtual hardware rather than a cgroup. The CPU burn
    oversubscribes at least twofold so an unbounded guest measures more than the
    request; affinity and quota corroborate but do not replace the measurement.
    The memory hog targets twice the allocation and must be killed, refused or
    take the sandbox down with it; a survivor proves there was no ceiling.
    """
    size = cast(list[Mapping[str, object]], inputs["size"])[0]
    requested_cpu = float(Fraction(str(size["cpu"])))
    memory_mib = cast(int, size["memory_mib"])
    result = driver.call(
        "run",
        target,
        {
            "bash_script": "python3 /tmp/sps-environment-facts.py",
            "environment": {
                "SPS_FACT_ARGUMENTS": json.dumps(
                    {"probe": "size_ceiling_use", "cpu": str(size["cpu"])}
                )
            },
            "timeout_ms": 120000,
        },
    )
    if (
        isinstance(result.get("exit_code"), bool)
        or not isinstance(result.get("exit_code"), int)
        or result["exit_code"] != 0
    ):
        raise NativeFailure("guest_fact_probe_failed")
    payload = result.get("stdout")
    if not isinstance(payload, (str, bytes)) or len(payload) > 8192:
        raise NativeFailure("guest_fact_probe_invalid")
    try:
        observation = _ceiling_use_observation(json.loads(payload))
    except (ValueError, KeyError, TypeError):
        raise NativeFailure("guest_fact_probe_invalid") from None
    measured = cast(float, observation["burn_cpu_seconds"]) / cast(
        float, observation["burn_wall_seconds"]
    )
    evidence: dict[str, object] = {
        "method": "measured_use",
        "cpu_observation": dict(observation),
        "measured_cpus": measured,
        "requested_cpu": str(size["cpu"]),
        "requested_memory_bytes": memory_mib * 1048576,
        "cpu_tolerance": _CPU_CEILING_TOLERANCE,
    }
    if measured > requested_cpu + _CPU_CEILING_TOLERANCE:
        evidence["memory_outcome"] = "not_attempted"
        return {
            "size_is_ceiling": False,
            "ceiling_evidence": json.dumps(evidence, sort_keys=True),
        }
    outcome = _memory_hog_outcome(driver, target, memory_mib)
    evidence["memory_outcome"] = outcome
    return {
        "size_is_ceiling": outcome != "completed",
        "ceiling_evidence": json.dumps(evidence, sort_keys=True),
    }


def _memory_hog_outcome(driver: Driver, target: object, memory_mib: int) -> str:
    """Run the allocation hog synchronously; classify how its attempt ended.

    `process_killed`, `refused` and `sandbox_ended` all prove the memory could not
    be held; `completed` means the hog wrote past twice the allocation alive.
    """
    command = "python3 -c " + shlex.quote(_MEMORY_EXHAUSTION_SCRIPT) + " " + str(memory_mib)
    try:
        result = driver.call("run", target, {"bash_script": command, "timeout_ms": 200000})
    except Exception as error:  # pylint: disable=broad-exception-caught
        try:
            state = _sandbox_state(driver, target)
        except Exception:  # pylint: disable=broad-exception-caught
            raise NativeFailure("memory_ceiling_unproven") from error
        if state in {"stopped", "destroyed"}:
            return "sandbox_ended"
        raise NativeFailure("memory_ceiling_unproven") from error
    exit_code = result.get("exit_code")
    if isinstance(exit_code, bool) or not isinstance(exit_code, int):
        raise NativeFailure("guest_fact_probe_invalid")
    if exit_code == 0:
        return "completed"
    if exit_code in {-9, -15, 137, 143}:
        return "process_killed"
    # A nonzero exit that is not a kill (for example Python's MemoryError) is the
    # guest refusing the allocation; either way the memory was not held.
    return "refused"


def _requested_size(inputs: Mapping[str, object]) -> tuple[float, int]:
    """The `cpu_min` and `memory_min_mib` the allocation probe compares the guest with."""
    size = inputs.get("size")
    if not isinstance(size, Mapping):
        raise ValueError("allocation probe requires the requested size")
    cpu = size.get("cpu_min")
    memory = size.get("memory_min_mib")
    # pylint: disable=too-many-boolean-expressions
    if (
        isinstance(cpu, bool)
        or not isinstance(cpu, (int, float))
        or not math.isfinite(cpu)
        or cpu <= 0
        or isinstance(memory, bool)
        or not isinstance(memory, int)
        or memory <= 0
    ):
        raise ValueError("allocation probe requires the requested size")
    return float(cpu), memory


def _delivered(value: Mapping[str, object], cpu: float, memory: int) -> Mapping[str, object]:
    """Compare what the guest sees with what was asked; keep the observed numbers."""
    seen_cpu = value["cpu"]
    seen_memory = value["memory_mib"]
    # pylint: disable=too-many-boolean-expressions
    if (
        isinstance(seen_cpu, bool)
        or not isinstance(seen_cpu, (int, float))
        or not math.isfinite(seen_cpu)
        or seen_cpu <= 0
        or isinstance(seen_memory, bool)
        or not isinstance(seen_memory, int)
        or seen_memory <= 0
    ):
        raise NativeFailure("guest_fact_probe_invalid")
    return {
        "observed_cpu": seen_cpu,
        "observed_memory_mib": seen_memory,
        # A CPU quota and a vCPU count are exact; allow only rounding.
        "cpu_delivered": seen_cpu >= cpu - 0.001,
        "memory_delivered": seen_memory >= memory * MEMORY_SEEN,
    }


def guest(driver: Driver, target: object, inputs: Mapping[str, object]) -> Mapping[str, object]:
    probe = inputs.get("probe")
    if probe == "on_memory_exhausted":
        return _on_memory_exhausted(driver, target, inputs)
    if not isinstance(probe, str) or probe not in FACT_FIELDS:
        raise ValueError("unknown supplementary fact probe")
    if probe == "size_is_ceiling":
        _require_ceiling_size(inputs)
    requested = _requested_size(inputs) if probe == "allocation" else None
    script = (suite_path().parent / "fixtures/environment_facts.py").read_bytes()
    path = "/tmp/sps-environment-facts.py"
    driver.call("files.write", target, {"path": path, "data": base64.b64encode(script).decode()})
    if probe == "size_is_ceiling":
        return _size_ceiling(driver, target, inputs)
    if probe == "no_metadata":
        metadata = (suite_path().parent / "fixtures/cloud_metadata.py").read_bytes()
        driver.call(
            "files.write",
            target,
            {"path": "/tmp/cloud_metadata.py", "data": base64.b64encode(metadata).decode()},
        )
    run_inputs: dict[str, object] = {
        "bash_script": "python3 " + path,
        "environment": {"SPS_FACT_ARGUMENTS": json.dumps(dict(inputs))},
    }
    # The metadata baseline does not require a native per-command execution limit.
    if probe != "no_metadata":
        run_inputs["timeout_ms"] = (
            240000
            if probe == "package_manager"
            else 180000
            if probe == "size_is_ceiling"
            else 45000
        )
    result = driver.call(
        "run.as_root" if inputs.get("way") == "per_command" else "run", target, run_inputs
    )
    if result.get("exit_code") != 0:
        raise NativeFailure("guest_fact_probe_failed")
    payload = result.get("stdout")
    if not isinstance(payload, (bytes, str)) or len(payload) > 1024:
        raise NativeFailure("guest_fact_probe_invalid")
    value = json.loads(payload)
    expected_fields = (
        FACT_FIELDS[probe] - {"stdout"} if probe == "disk_in_memory" else FACT_FIELDS[probe]
    )
    if not isinstance(value, dict) or set(value) != expected_fields:
        raise NativeFailure("guest_fact_probe_invalid")
    if any(item is None for item in value.values()):
        raise NotRun("guest_fact_observation_ambiguous")
    if probe in {"arch", "libc"}:
        choices = {"amd64", "arm64"} if probe == "arch" else {"glibc", "musl"}
        if value[probe] not in choices:
            raise NotRun("guest_fact_value_not_in_catalog")
    elif probe == "disk_in_memory":
        if (
            value["wrote_bytes"] != 256 * 1024**2
            or not isinstance(value["disk_in_memory"], bool)
            or not isinstance(value["memory_source"], str)
            or value["memory_source"]
            not in {
                "cgroup_shmem",
                "meminfo_shmem",
                "memavailable",
            }
            or any(
                isinstance(value[key], bool)
                or not isinstance(value[key], int)
                or value[key] < 0
                or value[key] > 2**63 - 1
                for key in (
                    "memory_before_bytes",
                    "memory_during_bytes",
                    "memory_after_bytes",
                )
            )
        ):
            raise NativeFailure("guest_fact_probe_invalid")
    elif requested is not None:
        return _delivered(value, *requested)
    elif any(not isinstance(item, bool) for item in value.values()):
        raise NativeFailure("guest_fact_probe_invalid")
    if probe == "disk_in_memory":
        value["stdout"] = payload.decode("utf-8") if isinstance(payload, bytes) else payload
    return cast(Mapping[str, object], value)


def server(driver: Driver, target: object, inputs: Mapping[str, object]) -> Mapping[str, object]:
    protocol = inputs.get("protocol")
    ports = inputs.get("ports")
    bind = inputs.get("bind", "0.0.0.0")
    # pylint: disable=too-many-boolean-expressions
    if (
        protocol not in {"tcp", "http", "websocket"}
        or bind not in {"0.0.0.0", "127.0.0.1"}
        or not isinstance(ports, list)
        or not ports
        or len(ports) > 64
        or any(not isinstance(p, int) or isinstance(p, bool) or not 1 <= p <= 65535 for p in ports)
        or len(ports) != len(set(ports))
    ):
        raise ValueError("invalid supplementary server configuration")
    if inputs.get("ensure_running") is True:
        # A files-only resume may need its test server restarted. The original
        # preview link is retained; this supplies no native link persistence.
        code = (
            "import urllib.request; "
            "opener=urllib.request.build_opener(urllib.request.ProxyHandler({})); "
            f"response=opener.open('http://127.0.0.1:{ports[0]}/', timeout=2); "
            "assert response.read() == b'sps-preview-proof'"
        )
        result = driver.call("run", target, {"bash_script": "python3 -c " + shlex.quote(code)})
        if result.get("exit_code") == 0:
            return {"existing_server": True}
        driver.call("files.remove", target, {"path": "/tmp/sps-coverage-server-ready"})
    path = "/tmp/sps-coverage-server.py"
    script = (suite_path().parent / "fixtures/protocol_server.py").read_bytes()
    driver.call("files.write", target, {"path": path, "data": base64.b64encode(script).decode()})
    driver.call(
        "files.write",
        target,
        {
            "path": "/tmp/sps-server-configuration.json",
            "data": base64.b64encode(json.dumps(dict(inputs)).encode()).decode(),
        },
    )
    process = driver.call(
        "process.start",
        target,
        {
            "bash_script": "python3 " + path,
            "timeout_ms": 180000,
        },
    )
    deadline = time.monotonic() + 30
    while not driver.call("files.exists", target, {"path": "/tmp/sps-coverage-server-ready"}).get(
        "exists"
    ):
        if time.monotonic() >= deadline:
            raise NativeFailure("guest_server_not_ready")
        time.sleep(0.2)
    return process
