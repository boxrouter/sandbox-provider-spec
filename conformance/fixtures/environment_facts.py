# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Controlled default-image observations; no provider-specific behaviour."""

import json
import math
import os
import platform
import pwd
import shutil
import subprocess
import threading
import time
from pathlib import Path


def _cgroup_directories(mount, path):
    """This process's cgroup directory under one mount and every ancestor up to the mount.

    Without a cgroup namespace the recorded path can name a host directory the mount does
    not show; the ancestors that do exist, ending at the mount, still hold the limits.
    """
    directory = mount / path.lstrip("/")
    found = []
    while True:
        if directory.is_dir():
            found.append(directory)
        if directory == mount or mount not in directory.parents:
            break
        directory = directory.parent
    return found


def _read(path):
    try:
        return path.read_text().strip()
    except OSError:
        return None


def _memory_value(text, source):
    """Parse one supported shmem counter, or the legacy MemAvailable fallback."""
    if text is None:
        return None
    field = (
        "shmem"
        if source == "cgroup_shmem"
        else "Shmem"
        if source == "meminfo_shmem"
        else "MemAvailable"
    )
    for line in text.splitlines():
        parts = line.split()
        if parts and parts[0].rstrip(":") == field and len(parts) >= 2 and parts[1].isdecimal():
            return int(parts[1]) * (1024 if source != "cgroup_shmem" else 1)
    return None


def _memory_source(cgroup_stat=None, meminfo=None):
    """Prefer this cgroup's shmem, then guest shmem, then the legacy host-sensitive value."""
    if cgroup_stat is None:
        cgroup_stat = _read(Path("/sys/fs/cgroup/memory.stat"))
    if _memory_value(cgroup_stat, "cgroup_shmem") is not None:
        return "cgroup_shmem"
    if meminfo is None:
        meminfo = _read(Path("/proc/meminfo"))
    if _memory_value(meminfo, "meminfo_shmem") is not None:
        return "meminfo_shmem"
    if _memory_value(meminfo, "memavailable") is not None:
        return "memavailable"
    return "unavailable"


def _memory_sample(source):
    """Read the same metric throughout one disk probe; never mix sources mid-run."""
    if source == "unavailable":
        return None
    if source == "cgroup_shmem":
        return _memory_value(_read(Path("/sys/fs/cgroup/memory.stat")), source)
    meminfo = _read(Path("/proc/meminfo"))
    return _memory_value(meminfo, source)


def _disk_memory_value(before, during, after, source):
    """Apply the established thresholds to samples from one memory counter."""
    if any(value is None for value in (before, during, after)):
        return None
    if source == "memavailable":
        held = before - during
        recovered = after - during
    else:
        held = during - before
        recovered = during - after
    return (
        True
        if held >= 192 * 1024**2 and recovered >= 128 * 1024**2
        else False
        if abs(held) <= 64 * 1024**2
        else None
    )


def _sample_memory(source, choose):
    values = [_memory_sample(source) for _ in range(5)]
    if any(value is None for value in values):
        return None
    if source == "memavailable":
        return choose(values)
    return sorted(values)[2]


def observe_ceiling_bounds(root=Path("/sys/fs/cgroup"), membership=Path("/proc/self/cgroup")):
    """Read raw enforced cgroup bounds at this process and every visible ancestor.

    Missing limits are not inferred from CPU affinity, MemTotal, or VM/container markers.
    Keep unlimited values as well as limits so the report retains how it was established.
    """
    text = _read(membership)
    if text is None:
        raise ValueError("cgroup membership unreadable")
    files = {}
    for line in text.splitlines():
        _, controllers, path = line.split(":", 2)
        mounts = []
        if not controllers:
            mounts.append((root, ("cpu.max", "memory.max")))
        if "cpu" in controllers.split(","):
            for mount in (root / controllers, root / "cpu"):
                mounts.append((mount, ("cpu.cfs_quota_us", "cpu.cfs_period_us")))
        if "memory" in controllers.split(","):
            mounts.append((root / "memory", ("memory.limit_in_bytes",)))
        for mount, names in mounts:
            for directory in _cgroup_directories(mount, path):
                for name in names:
                    control = directory / name
                    if not control.exists():
                        continue
                    value = _read(control)
                    if value is None:
                        raise ValueError("cgroup bound unreadable")
                    files[str(control)] = value
    return {"membership": text, "files": files}


def cgroup_limits(root=Path("/sys/fs/cgroup"), membership=Path("/proc/self/cgroup")):
    """The tightest CPU (in CPUs) and memory (in bytes) limits on this process, or None.

    Every cgroup from the process's own up to the mount constrains it, so the smallest
    limit among them is the one in force. Reads cgroup v2 `cpu.max` and `memory.max`, and
    cgroup v1 `cpu.cfs_quota_us`, `cpu.cfs_period_us` and `memory.limit_in_bytes`.
    """
    cpus = []
    memory = []
    membership_text = _read(membership)
    if membership_text is None:
        raise ValueError("cgroup membership unreadable")
    for line in membership_text.splitlines():
        _, controllers, path = line.split(":", 2)
        if not controllers:
            for directory in _cgroup_directories(root, path):
                for filename, kind in (("cpu.max", "cpu"), ("memory.max", "memory")):
                    control = directory / filename
                    if not control.exists():
                        continue
                    value = _read(control)
                    if value is None:
                        raise ValueError(f"cgroup {kind} limit unreadable")
                    if kind == "cpu":
                        quota = value.split()
                        if quota[0] != "max" and len(quota) == 2 and int(quota[1]) > 0:
                            cpus.append(int(quota[0]) / int(quota[1]))
                    elif value != "max":
                        memory.append(int(value))
            continue
        names = controllers.split(",")
        if "cpu" in names:
            for mount in (root / controllers, root / "cpu"):
                for directory in _cgroup_directories(mount, path):
                    quota_path = directory / "cpu.cfs_quota_us"
                    period_path = directory / "cpu.cfs_period_us"
                    if not quota_path.exists() and not period_path.exists():
                        continue
                    quota_text = _read(quota_path)
                    period_text = _read(period_path)
                    if quota_text is None or period_text is None:
                        raise ValueError("cgroup CPU limit unreadable")
                    quota = int(quota_text)
                    period = int(period_text)
                    if quota > 0 and period > 0:
                        cpus.append(quota / period)
        if "memory" in names:
            for directory in _cgroup_directories(root / "memory", path):
                limit_path = directory / "memory.limit_in_bytes"
                if not limit_path.exists():
                    continue
                limit = _read(limit_path)
                if limit is None:
                    raise ValueError("cgroup memory limit unreadable")
                memory.append(int(limit))
    return (min(cpus) if cpus else None, min(memory) if memory else None)


def observe_allocation():
    """The CPUs and memory a process in the sandbox can use, as the guest itself sees them.

    CPUs are the fewer of the processors this process may run on and its cgroup quota.
    Memory is the smaller of the kernel's `MemTotal` and its cgroup limit, in whole MiB.
    """
    cpu_limit, memory_limit = cgroup_limits()
    processors = len(os.sched_getaffinity(0))
    cpu = processors if cpu_limit is None else min(processors, cpu_limit)
    total = None
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemTotal:"):
            total = int(line.split()[1]) * 1024
    if total is None:
        raise ValueError("MemTotal absent")
    memory = total if memory_limit is None else min(total, memory_limit)
    return {"cpu": round(cpu, 3), "memory_mib": memory // (1024 * 1024)}


def observe_ceiling_use(args):
    """Measured CPU ceiling evidence: affinity, any quota, and a timed over-subscribed burn.

    The burn runs at least twice the requested CPUs' worth of threads so an
    unbounded guest measures more than the request. The runner, not this guest,
    compares the measured CPU-seconds per wall-second with the request.
    """
    requested = float(args["cpu"])
    threads = max(2, math.ceil(requested * 2))
    seconds = float(args.get("burn_seconds", 4.0))
    stop = time.monotonic() + seconds

    def spin():
        while time.monotonic() < stop:
            pass

    workers = [threading.Thread(target=spin) for _ in range(threads)]
    started_wall = time.monotonic()
    started_cpu = time.process_time()
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()
    wall = time.monotonic() - started_wall
    used = time.process_time() - started_cpu
    cpu_quota, _ = cgroup_limits()
    return {
        "processors": len(os.sched_getaffinity(0)),
        "cpu_quota": cpu_quota,
        "burn_threads": threads,
        "burn_wall_seconds": round(wall, 3),
        "burn_cpu_seconds": round(used, 3),
    }


def observe(args):
    probe = args["probe"]
    result = {}
    if probe == "home":
        expected = pwd.getpwuid(os.getuid()).pw_dir
        result = {
            "home_matches_user": bool(os.environ.get("HOME")) and os.environ["HOME"] == expected
        }
    elif probe == "no_metadata":
        from cloud_metadata import exposed  # noqa: PLC0415  uploaded only for this probe

        result = {"host_metadata_hidden": not exposed()}
    elif probe == "arch":
        machine = platform.machine()
        result = {"arch": {"x86_64": "amd64", "aarch64": "arm64"}.get(machine, machine)}
    elif probe == "root":
        if args["way"] == "sudo":
            value = (
                subprocess.run(["sudo", "-n", "id", "-u"], capture_output=True, timeout=10)
                if shutil.which("sudo")
                else None
            )
            result = {
                "uid_zero": value is not None
                and value.returncode == 0
                and value.stdout.strip() == b"0"
            }
        else:
            result = {"uid_zero": os.getuid() == 0}
    elif probe == "libc":
        name, version = platform.libc_ver()
        if name == "glibc" and version:
            result = {"libc": "glibc"}
        elif any(Path("/lib").glob("ld-musl-*.so.1")):
            result = {"libc": "musl"}
        else:
            result = {"libc": None}
    elif probe == "package_manager":
        manager = args["manager"]
        commands = {
            "apt": [["apt-get", "update", "-qq"], ["apt-get", "install", "-y", "-qq", "hello"]],
            "apk": [["apk", "add", "--no-cache", "hello"]],
            "dnf": [["dnf", "-y", "install", "hello"]],
            "pacman": [["pacman", "-Sy", "--noconfirm", "hello"]],
        }
        present = [key for key, value in commands.items() if shutil.which(value[0][0])]
        if manager == "none":
            result = {"installed": not present}
        elif manager not in present:
            result = {"installed": False}
        else:
            prefix = [] if os.getuid() == 0 else ["sudo", "-n"]
            ok = not prefix or shutil.which("sudo") is not None
            for command in commands[manager]:
                if not ok:
                    break
                value = subprocess.run(prefix + command, capture_output=True, timeout=180)
                ok = value.returncode == 0
            hello = (
                subprocess.run(["hello"], capture_output=True, timeout=10)
                if ok and shutil.which("hello")
                else None
            )
            result = {
                "installed": hello is not None
                and hello.returncode == 0
                and b"Hello" in hello.stdout
            }
    elif probe == "disk_in_memory":
        candidates = [Path.home(), Path("/tmp"), Path("/var/tmp")]
        directory = next(
            (
                p
                for p in candidates
                if p.is_dir()
                and p.stat().st_dev == Path("/").stat().st_dev
                and os.access(p, os.W_OK)
            ),
            None,
        )
        if directory is None:
            print(
                json.dumps(
                    {
                        "disk_in_memory": None,
                        "wrote_bytes": 0,
                        "memory_source": "unavailable",
                        "memory_before_bytes": None,
                        "memory_during_bytes": None,
                        "memory_after_bytes": None,
                    }
                )
            )
            raise SystemExit(0)
        path = directory / "sps-disk-memory-proof"
        source = _memory_source()
        before = _sample_memory(source, min)
        chunk = bytes(1024 * 1024)
        try:
            with path.open("wb") as output:
                for _ in range(256):
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            time.sleep(2)
            during = _sample_memory(source, min)
            size = path.stat().st_size
        finally:
            path.unlink(missing_ok=True)
        time.sleep(2)
        after = _sample_memory(source, max)
        result = {
            "disk_in_memory": _disk_memory_value(before, during, after, source),
            "wrote_bytes": size,
            "memory_source": source,
            "memory_before_bytes": before,
            "memory_during_bytes": during,
            "memory_after_bytes": after,
        }
    elif probe == "size_ceiling_bounds":
        result = observe_ceiling_bounds()
    elif probe == "size_ceiling_use":
        result = observe_ceiling_use(args)
    elif probe == "allocation":
        result = observe_allocation()
    else:
        raise ValueError("unknown fact probe")
    return result


if __name__ == "__main__":
    arguments = json.loads(os.environ["SPS_FACT_ARGUMENTS"])
    print(json.dumps(observe(arguments)))
