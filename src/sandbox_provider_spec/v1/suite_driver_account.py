# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The account steps of the shared tests (`account.stored_artifacts`), run through the
`account_capacity`, `image_list` and `snapshot_list` operations of a 1.0 `Provider`."""

from __future__ import annotations

from collections.abc import Awaitable, Sequence
from typing import TYPE_CHECKING, TypeVar

from sandbox_provider_spec.driver import Inputs, Observation, Unsupported
from sandbox_provider_spec.v1.provider import Provider

T = TypeVar("T")


class AccountSteps:
    """The account steps of `ProviderDriver`, which inherits them."""

    if TYPE_CHECKING:
        api: Provider

        def wait(self, call: Awaitable[T]) -> T:
            raise NotImplementedError

    def account_stored_artifacts(self, target: object, inputs: Inputs) -> Observation:
        """Whether `account.capacity`'s `stored_artifacts` holds up against what `image.list` and
        `snapshot.list` return: `used` at least that count, and at most `limit` when both are
        stated. Skipped where the provider reports none."""
        del target, inputs
        stated = self.wait(self.api.account_capacity()).stored_artifacts
        if stated is None or (stated.used is None and stated.limit is None):
            raise Unsupported("the provider reports no stored_artifacts")
        listed = 0
        for page_of in (self._image_pages, self._snapshot_pages):
            cursor: str | None = None
            while True:
                try:
                    items, cursor = self.wait(page_of(cursor))
                except Unsupported:
                    break  # the provider keeps no such artifacts
                listed += len(items)
                if cursor is None:
                    break
        used, limit = stated.used, stated.limit
        return {
            "used_covers_listed": used is None or used >= listed,
            "used_within_limit": used is None or limit is None or used <= limit,
        }

    async def _image_pages(self, cursor: str | None) -> tuple[Sequence[object], str | None]:
        page = await self.api.image_list(cursor=cursor)
        return page.images, page.next_cursor

    async def _snapshot_pages(self, cursor: str | None) -> tuple[Sequence[object], str | None]:
        page = await self.api.snapshot_list(cursor=cursor)
        return page.snapshots, page.next_cursor
