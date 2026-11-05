# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""A controlled workload separating closed guest streams from native process completion."""

from __future__ import annotations

import base64
import shlex
import time
from collections.abc import Mapping
from uuid import uuid4

from sandbox_provider_spec.driver import Driver, NativeFailure, NotRun


def observe(driver: Driver, target: object, inputs: Mapping[str, object]) -> Mapping[str, object]:
    """Check state after guest fd closure, then release the workload and preserve exit 7.

    A readiness file is written only after both output descriptors close. A release file
    keeps execution alive during the state query, independent of transport EOF visibility.
    These are ordinary workload files, not a substitute process API or guest supervisor.
    """
    del inputs
    stem = "/tmp/sps-eof-" + uuid4().hex
    ready, release = stem + "-ready", stem + "-release"
    script = (
        "exec >&- 2>&-; "
        f"printf closed > {shlex.quote(ready)}; "
        "for ((i=0; i<600; i++)); do "
        f"if [ -f {shlex.quote(release)} ]; then exit 7; fi; "
        "sleep 0.1; done; exit 19"
    )
    process = driver.call("process.start", target, {"bash_script": script})
    try:
        deadline = time.monotonic() + 15
        while True:
            observed = driver.call("run", target, {"bash_script": f"test -f {shlex.quote(ready)}"})
            if observed.get("exit_code") == 0:
                break
            if observed.get("exit_code") != 1:
                raise NativeFailure("process_eof_readiness_failed")
            if time.monotonic() >= deadline:
                raise NotRun("process_eof_workload_not_ready")
            time.sleep(0.05)
        state = driver.call("process.status", process, {"timeout_ms": 1000})
        if state.get("state") in {None, "unknown"}:
            raise NotRun("native_process_state_unobservable")
    finally:
        driver.call(
            "files.write",
            target,
            {"path": release, "data": base64.b64encode(b"release").decode("ascii")},
        )
    ended = driver.call("process.wait", process, {"timeout_ms": 10000})
    return {
        "state_after_close": state["state"],
        "exit_code_after_close": state.get("exit_code"),
        "exit_code": ended.get("exit_code"),
    }
