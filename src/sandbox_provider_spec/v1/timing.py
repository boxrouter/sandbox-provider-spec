# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""How a provider package tells a host which of its requests only find the sandbox: `lookup()`.

A call on a sandbox sometimes has to resolve the sandbox first: read its record for the access
token, turn a name into an id, open a handle from an id. That read is not the operation the
caller asked for, and how often it happens depends on the host (a process that has seen the
sandbox before skips it), not on the provider's speed at the operation. A package wraps exactly
those requests, and nothing else, in `with lookup():`. A host that measures the provider's time
reads `in_lookup()` when a request starts and reports it apart from the operation's own requests;
it still counts it (a rate limit applies to it). With no host that reads it, `lookup()` does
nothing. A package never wraps work the operation does for its own result: the host reports a
lookup separately, so hiding real work in one would hide it from the operation's time.

It is a `ContextVar`, so it follows the task that entered it and no other, and it nests.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

__all__ = ["in_lookup", "lookup"]

_LOOKUP: ContextVar[bool] = ContextVar("sandbox_provider_spec_lookup", default=False)


@contextmanager
def lookup() -> Iterator[None]:
    """Mark the requests sent inside this block as finding the sandbox's handle or record."""
    token = _LOOKUP.set(True)
    try:
        yield
    finally:
        _LOOKUP.reset(token)


def in_lookup() -> bool:
    """Whether the current task is inside `lookup()`."""
    return _LOOKUP.get()
