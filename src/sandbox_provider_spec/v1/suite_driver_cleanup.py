# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""A tester run's destroys that must wait for the provider (cloud#9848).

A provider that is busy in a state change of its own (a snapshot capture, or the undo of a deleted
one) answers a destroy `unavailable` with a wait, and the same call works later. The cleanup that
follows a run asks again, under ONE budget shared by every destroy the cleanup still owes, so a
provider that refuses every destroy costs the budget once, not once per sandbox. A destroy a step
makes (`destroy.again`) has a budget of its own.

This lives beside `suite_driver.py`, not in it: cleanup is not what a row checks, and a module
outside every row's dependencies moves no row's check digest when it changes (cloud#9877).
"""

from __future__ import annotations

import sys
import time
from collections.abc import Callable
from typing import TypeVar

from sandbox_provider_spec.driver import NativeFailure, rate_limit_pause
from sandbox_provider_spec.v1.types import DestroyResult

T = TypeVar("T")

#: How long the whole cleanup phase asks again, in all. A busy refusal lasted 6 min 20 s over ten
#: refusals on a live run: the 15 + 180 s this replaces gave up at 195 s.
CLEANUP_BUDGET_SECONDS = 600
#: A destroy that a step makes (not the cleanup) asks again for this long.
STEP_BUDGET_SECONDS = 180


class CleanupBudget:
    """The cleanup phase's one budget: it starts at the first refusal and is spent by all."""

    def __init__(self) -> None:
        self._ends: float | None = None

    def ends(self) -> float:
        if self._ends is None:
            self._ends = time.monotonic() + CLEANUP_BUDGET_SECONDS
        return self._ends


def ask_until_free(
    call: Callable[[], T], budget: CleanupBudget | None = None, *, step_seconds: float | None = None
) -> T:
    """`call()`, asked again while the provider answers `unavailable`.

    It waits what the provider says (`retry_after_seconds`, bounded) until `budget` ends (the
    cleanup phase's, shared) or, with none, until `STEP_BUDGET_SECONDS` have passed; then the
    failure stands and the caller reports it. Any other failure is raised at once."""
    step_ends = time.monotonic() + (STEP_BUDGET_SECONDS if step_seconds is None else step_seconds)
    while True:
        try:
            return call()
        except NativeFailure as error:
            if error.code != "unavailable":
                raise
            pause = rate_limit_pause(error)
            ends = step_ends if budget is None else budget.ends()
            if time.monotonic() + pause > ends:
                raise
            time.sleep(pause)


def destroy_when_free(
    destroy: Callable[[], DestroyResult], budget: CleanupBudget | None = None
) -> DestroyResult:
    """A destroy, asked again while the provider answers `unavailable` (see `ask_until_free`)."""
    return ask_until_free(destroy, budget)


def cleanup_failure(kind: str, error: Exception, resource_id: object) -> dict[str, object]:
    """The report's cleanup entry for a release that failed, and one line on stderr naming the
    resource.

    The entry has the spec code, outcome and retry hint of a provider's refusal, never a provider
    message or an id: reports are committed and mirrored. The id is in the run's own log only,
    where a person reading a run's output looks for it."""
    entry: dict[str, object] = {
        "kind": kind,
        "result": "error",
        "reason": "NativeFailure" if isinstance(error, NativeFailure) else type(error).__name__,
    }
    if isinstance(error, NativeFailure):
        entry["code"] = error.code
        outcome = getattr(error, "outcome", None)
        if isinstance(outcome, str):
            entry["outcome"] = outcome
        if error.retry_after_seconds is not None:
            entry["retry_after_seconds"] = error.retry_after_seconds
    print(
        f"cleanup failed: kind={kind} id={resource_id} reason={entry['reason']}"
        f" code={entry.get('code', '-')} outcome={entry.get('outcome', '-')}",
        file=sys.stderr,
        flush=True,
    )
    return entry
