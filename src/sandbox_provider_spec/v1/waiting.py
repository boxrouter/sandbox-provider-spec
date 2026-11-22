# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The one way a provider package waits for the provider inside a call: `pause(seconds)`.

A package sometimes has to wait within one spec call: for a state the provider has not reached
yet (a sandbox still starting, a snapshot not listed yet, a command whose output is not written
yet) or before it sends a request the provider refused for now again (a rate limit, an upstream
502). It waits with `await pause(seconds)`, never with `asyncio.sleep`. The loop around the pause
checks first and pauses only while the provider says the state is not reached.

A host that measures the provider's time installs one observer with `observe_pauses`: a function
that returns a context manager, entered around each pause. A serving engine installs one that
records the pause as provider time of the call that is open, the way it records the call's
requests, so a polled call reads like a blocking one. With no observer a pause is a plain
`asyncio.sleep`. The observer is process-wide; installing another one replaces it.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from contextlib import AbstractContextManager

__all__ = ["observe_pauses", "pause"]

PauseObserver = Callable[[], AbstractContextManager[object]]

_observer: PauseObserver | None = None


def observe_pauses(observer: PauseObserver | None) -> None:
    """Enter `observer()` around every later `pause`; None removes the observer."""
    global _observer  # pylint: disable=global-statement
    _observer = observer


async def pause(seconds: float) -> None:
    """Wait `seconds` (none when it is zero or less) for the provider's state to change."""
    delay = max(0.0, seconds)
    observer = _observer
    if observer is None:
        await asyncio.sleep(delay)
        return
    with observer():
        await asyncio.sleep(delay)
