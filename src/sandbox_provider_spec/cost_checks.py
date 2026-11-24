# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The cost checks of the 1.0 driver (contract section 10): what each `cost.*` step observes."""

from __future__ import annotations

import time
from collections import Counter
from collections.abc import Awaitable, Callable
from decimal import Decimal
from typing import TYPE_CHECKING

from sandbox_provider_spec.driver import (
    RATE_LIMIT_BUDGET_SECONDS,
    Inputs,
    NativeFailure,
    NotRun,
    Observation,
    Unsupported,
    number,
    rate_limit_pause,
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


def read_cost(driver: ProviderDriver, read: Callable[[], Awaitable[Cost]], inputs: Inputs) -> Cost:
    """Read a cost with `read`; `final: true` reads until it is final, up to the step's
    `timeout_ms` (else what discovery states)."""
    until_final = inputs.get("final") is True
    window = final_wait_seconds(driver, inputs) if until_final else 0
    deadline = time.monotonic() + window
    started = time.monotonic()
    while True:
        try:
            cost = driver.wait(read())
        except NativeFailure as error:
            if not _wait_out_rate_limit(error, started):
                raise
            continue
        if not until_final or cost.status == "final":
            return cost
        if time.monotonic() >= deadline:
            raise NotRun("cost_not_final_in_window")
        time.sleep(poll_seconds(window))


def _wait_out_rate_limit(error: NativeFailure, started: float) -> bool:
    """Wait what the provider's `retry_after_seconds` says (bounded) and say True, when `error` is a
    `rate_limited` read still inside the retry budget; False when the failure stands."""
    if error.code != "rate_limited":
        return False
    pause = rate_limit_pause(error)
    if time.monotonic() + pause > started + RATE_LIMIT_BUDGET_SECONDS:
        return False
    time.sleep(pause)
    return True


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
    started = time.monotonic()
    while True:
        try:
            cost = driver.wait(driver.api.cost(sandbox_id))
        except NativeFailure as error:
            if not _wait_out_rate_limit(error, started):
                raise
            continue
        if cost.status == "final":
            break
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


def total_matches_lines(cost: Cost) -> bool:
    """The total is the sum of the line amounts. A `usage` cost states no amount: its total and
    every line amount are null."""
    if cost.source == "usage":
        return cost.total_usd is None and all(line.amount_usd is None for line in cost.lines)
    if any(line.amount_usd is None for line in cost.lines):
        return False
    return cost.total_usd == sum((line.amount_usd or Decimal(0) for line in cost.lines), Decimal(0))


def amounts_match_prices(driver: ProviderDriver, cost: Cost) -> bool:
    """Each `calculated` line that discovery prices has the amount quantity x price, within the
    rounding of the amount: half a unit in the last decimal place that it states. A line whose item
    and unit discovery does not price is not checked, and where discovery states several prices for
    them (by size, region or variant) one of them must fit."""
    if cost.source != "calculated":
        return True
    prices: dict[tuple[str, str], set[Decimal]] = {}
    for item in driver.wait(driver.api.discovery()).classes:
        for price in item.prices:
            prices.setdefault((price.item, price.unit), set()).add(price.price_usd)
    for line in cost.lines:
        stated = prices.get((line.item, line.unit or ""))
        if not stated or line.quantity is None or line.amount_usd is None:
            continue
        exponent = line.amount_usd.as_tuple().exponent
        half_unit = Decimal(1).scaleb(exponent if isinstance(exponent, int) else 0) / 2
        if all(abs(line.amount_usd - line.quantity * price) > half_unit for price in stated):
            return False
    return True


def final(driver: ProviderDriver, sandbox_id: str, inputs: Inputs) -> Observation:
    """A destroyed sandbox's final cost names it, adds up, has no open line and reads the same
    twice."""
    cost, again = _read_final(driver, sandbox_id, inputs)
    return {
        "status": cost.status,
        "sandbox_matches": cost.sandbox_id == sandbox_id,
        "total_matches_lines": total_matches_lines(cost),
        "quantities_present": cost.source == "reported"
        or all(line.quantity is not None and line.unit is not None for line in cost.lines),
        "amounts_match_prices": amounts_match_prices(driver, cost),
        "no_open_line": all(
            not (line.start is not None and line.end is None) for line in cost.lines
        ),
        "stable": again is None or same_figures(cost, again),
    }
