# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The cost checks of the 1.0 driver (contract section 10): what each `cost.*` step observes."""

from __future__ import annotations

import time
from collections import Counter
from decimal import Decimal
from typing import TYPE_CHECKING

from sandbox_provider_spec.driver import (
    Inputs,
    NativeFailure,
    NotRun,
    Observation,
    Unsupported,
    number,
)
from sandbox_provider_spec.v1.types import Cost

if TYPE_CHECKING:
    from sandbox_provider_spec.v1.suite_driver import ProviderDriver

MAX_FINAL_WAIT_SECONDS = 7 * 24 * 3600  # the longest that the tester waits for `final`
_FINAL_GRACE_SECONDS = 30  # allowed on top of `cost_final_within_seconds`: destroy returns early
_POLL_SECONDS = 2


def final_wait_seconds(driver: ProviderDriver, inputs: Inputs) -> float:
    """How long to wait for a final cost: the step's `timeout_ms`, else what discovery states.
    A statement beyond `MAX_FINAL_WAIT_SECONDS` is a wait that the tester does not make."""
    if "timeout_ms" in inputs:
        return number(inputs, "timeout_ms", 0) / 1000
    stated = driver.wait(driver.api.discovery()).limits.cost_final_within_seconds
    if stated is None:
        raise Unsupported("the provider does not state cost_final_within_seconds")
    if stated + _FINAL_GRACE_SECONDS > MAX_FINAL_WAIT_SECONDS:
        raise NotRun("cost_final_beyond_tester_limit")
    return stated + _FINAL_GRACE_SECONDS


def poll_seconds(window: float) -> float:
    """Poll about fifty times in a window, no faster than every 2 seconds, no slower than 30."""
    return min(30.0, max(float(_POLL_SECONDS), window / 50))


def _read_final(
    driver: ProviderDriver, sandbox_id: str, inputs: Inputs
) -> tuple[Cost, Cost | None]:
    """Read a destroyed sandbox's cost until it is final, then once more. A provider may stop
    answering once the cost is final (it only has to keep it until then), so a second read that
    finds nothing is no read."""
    window = final_wait_seconds(driver, inputs)
    deadline = time.monotonic() + window
    while (cost := driver.wait(driver.api.cost(sandbox_id))).status != "final":
        if time.monotonic() >= deadline:
            raise NotRun("cost_not_final_in_window")
        time.sleep(poll_seconds(window))
    try:
        again: Cost | None = driver.wait(driver.api.cost(sandbox_id))
    except NativeFailure as error:
        if error.code != "not_found":
            raise
        again = None
    return cost, again


def same_figures(first: Cost, second: Cost) -> bool:
    """Two reads of a final cost agree: the status, the total and the lines, in any order."""
    return (
        second.status == first.status
        and second.total_usd == first.total_usd
        and Counter(second.lines) == Counter(first.lines)
    )


def final(driver: ProviderDriver, sandbox_id: str, inputs: Inputs) -> Observation:
    """A destroyed sandbox's final cost names it, adds up, has no open line and reads the same
    twice."""
    cost, again = _read_final(driver, sandbox_id, inputs)
    lines = sum((line.amount_usd for line in cost.lines), start=Decimal(0))
    return {
        "status": cost.status,
        "sandbox_matches": cost.sandbox_id == sandbox_id,
        "total_matches_lines": cost.total_usd == lines,
        "quantities_present": cost.source != "calculated"
        or all(line.quantity is not None and line.unit is not None for line in cost.lines),
        "no_open_line": all(
            not (line.start is not None and line.end is None) for line in cost.lines
        ),
        "stable": again is None or same_figures(cost, again),
    }
