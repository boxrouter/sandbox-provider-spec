# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The cost checks of the 1.0 driver (contract section 10): what each `cost.*` step observes."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import TYPE_CHECKING

from sandbox_provider_spec.driver import Inputs, NativeFailure, NotRun, Observation, number
from sandbox_provider_spec.v1.types import Cost

if TYPE_CHECKING:
    from sandbox_provider_spec.v1.suite_driver import ProviderDriver

_AS_OF_SECONDS = 60  # `as_of` is at most this long before the response while `accruing`
_FINAL_GRACE_SECONDS = 30  # allowed on top of `cost_final_within_seconds`: destroy returns early
_POLL_SECONDS = 2


def final_wait_seconds(driver: ProviderDriver, inputs: Inputs) -> float:
    """How long to wait for a final cost: the step's `timeout_ms`, else what discovery promises."""
    if "timeout_ms" in inputs:
        return number(inputs, "timeout_ms", 0) / 1000
    promised = driver.wait(driver.api.discovery()).limits.cost_final_within_seconds
    return promised + _FINAL_GRACE_SECONDS


def poll_seconds(window: float) -> float:
    """Poll about fifty times in a window, no faster than every 2 seconds, no slower than 30."""
    return min(30.0, max(float(_POLL_SECONDS), window / 50))


def _valid_revision(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 1


def _read_final(
    driver: ProviderDriver, sandbox_id: str, destroyed: Cost | None, inputs: Inputs
) -> tuple[Cost, Cost | None]:
    """Read a destroyed sandbox's cost until it is final, then once more. A provider that returns
    the final cost in the destroy result may no longer know the sandbox, and then that result is
    the only read and the second is `None`."""
    window = final_wait_seconds(driver, inputs)
    deadline = time.monotonic() + window
    cost = destroyed if destroyed is not None and destroyed.status == "final" else None
    while cost is None:
        read = driver.wait(driver.api.cost(sandbox_id))
        if read.status == "final":
            cost = read
        elif time.monotonic() >= deadline:
            raise NotRun("cost_not_final_in_window")
        else:
            time.sleep(poll_seconds(window))
    try:
        again: Cost | None = driver.wait(driver.api.cost(sandbox_id))
    except NativeFailure as error:
        if error.code != "not_found" or destroyed is None:
            raise
        again = None
    return cost, again


def final(
    driver: ProviderDriver, sandbox_id: str, destroyed: Cost | None, inputs: Inputs
) -> Observation:
    """A destroyed sandbox's final cost names it, adds up and reads the same twice."""
    cost, again = _read_final(driver, sandbox_id, destroyed, inputs)
    lines = sum((line.amount_usd for line in cost.lines), start=Decimal(0))
    return {
        "status": cost.status,
        "sandbox_matches": cost.sandbox_id == sandbox_id,
        "total_matches_lines": cost.source == "reported" or lines == cost.total_usd,
        "stable": again is None or (again.status == "final" and again.total_usd == cost.total_usd),
    }


def revision(driver: ProviderDriver, sandbox_id: str) -> Observation:
    """`revision` is an integer of at least 1 and does not go down between two reads."""
    first = driver.wait(driver.api.cost(sandbox_id))
    second = driver.wait(driver.api.cost(sandbox_id))
    valid = _valid_revision(first.revision) and _valid_revision(second.revision)
    return {"revision_valid": valid, "not_decreasing": valid and second.revision >= first.revision}


def as_of(driver: ProviderDriver, sandbox_id: str) -> Observation:
    """On a running sandbox the status is `accruing` and `as_of` is at most 60 seconds old. The
    check uses the time the request started, so the round trip never fails a provider."""
    started = datetime.now(UTC)
    cost = driver.wait(driver.api.cost(sandbox_id))
    return {
        "status": cost.status,
        "as_of_recent": cost.as_of >= started - timedelta(seconds=_AS_OF_SECONDS),
    }


def closed_lines(
    driver: ProviderDriver, sandbox_id: str, destroyed: Cost | None, inputs: Inputs
) -> Observation:
    """After the sandbox ends no line ends after `as_of`, and a second read gives the same lines
    (unless a correction raised `revision` in between)."""
    cost, again = _read_final(driver, sandbox_id, destroyed, inputs)
    return {
        "status": cost.status,
        "ends_by_as_of": all(line.end is None or line.end <= cost.as_of for line in cost.lines),
        "same_lines": again is None
        or again.revision != cost.revision
        or list(again.lines) == list(cost.lines),
    }
