# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Two provider objects of one account that answer a run's calls in turn.

A consumer runs several API tasks and workers, so a later call on a sandbox may land on another
`Provider` object than the one that made it. An adapter that keeps per-sandbox state in its object
(a stdin offset, a token it issued at create, a set of what it destroyed) passes every test on one
object and fails in production. `TwoInstances` sends each call to the other object than the call
before, so every stateful sequence of a run (create, then run, then files, then destroy) crosses
objects. A handle a call returns (a file stream, a terminal) stays with the object that made it.
"""

from __future__ import annotations

import inspect
from typing import Any, cast

from sandbox_provider_spec.v1.provider import Provider


class TwoInstances:
    """Stands in for a `Provider`; every coroutine method alternates between the two objects."""

    def __init__(self, first: Provider, second: Provider) -> None:
        self._pair = (first, second)
        self._turn = 0

    @property
    def instance_class(self) -> type[Provider]:
        """The class of both objects, which static facts and a report's subject read."""
        return type(self._pair[0])

    def __getattr__(self, name: str) -> Any:
        member = getattr(self._pair[0], name)
        if not inspect.iscoroutinefunction(member) or name == "aclose":
            return member
        target = getattr(self._pair[self._turn], name)
        self._turn = 1 - self._turn
        return target

    async def aclose(self) -> None:
        """Close both objects, even when the first refuses."""
        try:
            await self._pair[0].aclose()
        finally:
            await self._pair[1].aclose()


def two_instances(first: Provider, second: Provider) -> Provider:
    """`first` and `second` as one `Provider` that alternates its calls between them."""
    return cast("Provider", TwoInstances(first, second))


def provider_class(api: object) -> type[Provider]:
    """The `Provider` class behind `api`, which may be the two-object stand-in."""
    if isinstance(api, TwoInstances):
        return api.instance_class
    return cast("type[Provider]", type(api))
