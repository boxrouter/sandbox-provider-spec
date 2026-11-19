# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The single-use tickets of the reference server's terminal links."""

from __future__ import annotations

import secrets
from collections.abc import Callable
from dataclasses import dataclass

from sandbox_provider_spec.v1.errors import SpsError
from sandbox_provider_spec.v1.types import TerminalRequest

TERMINAL_TICKET_SECONDS = 60.0  # how long a terminal link waits to be connected
MAX_TERMINAL_TICKETS = 1024  # links waiting to be connected, over all accounts


@dataclass
class Ticket:
    expires: float
    token: str
    sandbox_id: str
    request: TerminalRequest


class Tickets:
    """The single-use tickets of terminal links: a random name for a request that waits, at most
    `TERMINAL_TICKET_SECONDS`, for its WebSocket to connect."""

    def __init__(self, clock: Callable[[], float]) -> None:
        self._clock = clock
        self._items: dict[str, Ticket] = {}

    def _sweep(self) -> None:
        now = self._clock()
        for name in [name for name, item in self._items.items() if item.expires <= now]:
            del self._items[name]

    def issue(self, token: str, sandbox_id: str, request: TerminalRequest) -> str:
        self._sweep()
        if len(self._items) >= MAX_TERMINAL_TICKETS:
            raise SpsError(
                "rate_limited", "Too many terminal links are waiting", retry_after_seconds=1
            )
        name = secrets.token_urlsafe(24)
        self._items[name] = Ticket(
            self._clock() + TERMINAL_TICKET_SECONDS, token, sandbox_id, request
        )
        return name

    def take(self, name: str) -> Ticket | None:
        """The ticket, removed: a name works once, and not after it expires."""
        self._sweep()
        return self._items.pop(name, None)
