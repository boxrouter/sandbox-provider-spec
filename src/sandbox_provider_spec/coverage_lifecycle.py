# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import time
from collections.abc import Mapping

from sandbox_provider_spec.driver import Driver, NativeFailure, NotRun


def active_lifetime(
    driver: Driver, target: object, inputs: Mapping[str, object]
) -> Mapping[str, object]:
    """Observe a lifetime while baseline commands keep the sandbox active."""
    wait_ms = inputs.get("wait_ms")
    if not isinstance(wait_ms, int) or isinstance(wait_ms, bool) or wait_ms < 1000:
        raise NotRun("proof_fixture_window_invalid")
    deadline = time.monotonic() + wait_ms / 1000
    while True:
        result = driver.call(
            "run", target, {"bash_script": "printf sps-active", "timeout_ms": 10000}
        )
        if result.get("exit_code") != 0:
            raise NativeFailure("active_lifetime_command_failed")
        state = driver.call("get", target, {}).get("state")
        if state is None:
            raise NotRun("native_state_unobservable")
        if state != "active":
            return {"state": state, "window_completed": False}
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return {"state": state, "window_completed": True}
        time.sleep(min(5, remaining))
