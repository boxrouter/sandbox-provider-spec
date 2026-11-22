# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""How a host tells a provider package that a keyed call is the key's first send: `first_send()`.

`create`, `snapshot.create` and `image.prepare` take an idempotency key, and a provider whose own
API has no idempotency finds an earlier call of the key itself: it lists before the call, lists
after it, or scans for a same-key object. Only a resend needs that work, but the key alone does not
say which a call is. A host that knows says so with two facts, each from the layer that knows it:

- `fresh_key(key)`: the key's owner vouches that no call carrying `key` reached this provider
  account before the block, that it sends `key` one call at a time inside the block, each in
  `attempt(key, n)`, and that every send of `key` carries the same body.
- `attempt(key, n)`: the loop that resends numbers each send of `key`: 1, then 2, 3...

A package reads `first_send(key)` once, at the start of the operation, in the call's own task. It is
true only when both facts are in effect for exactly this key and the attempt is 1. Then the package
may skip every request (and every wait) whose only purpose is to find or deduplicate an earlier call
of the same key. It still writes the key on what it makes, as it always does, so that a later resend
and the host's own lookup by key find it, and it skips nothing that another rule needs. A request
the package itself sends again inside the call is a resend. With no host, another key or a later
attempt, `first_send` is false and the package does what it did before: the safe path.
`resend(key)` says the host numbered this send 2 or more, for work only a known resend needs.

Both are `ContextVar`s, so they follow the task that entered them and no other, nest, and reset on
exit; nothing is remembered, so nothing needs invalidating. They do not cross HTTP: a provider
served over HTTP sees no hint and takes the safe path.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

__all__ = ["attempt", "first_send", "fresh_key", "resend"]

_FRESH: ContextVar[str | None] = ContextVar("sandbox_provider_spec_fresh_key", default=None)
_ATTEMPT: ContextVar[tuple[str, int] | None] = ContextVar(
    "sandbox_provider_spec_send_attempt", default=None
)


def _checked(key: object) -> str:
    if not isinstance(key, str) or not key:
        raise ValueError("an idempotency key is a non-empty string")
    return key


@contextmanager
def fresh_key(key: str) -> Iterator[None]:
    """The key's owner vouches that `key` was never sent before and is sent once at a time."""
    token = _FRESH.set(_checked(key))
    try:
        yield
    finally:
        _FRESH.reset(token)


@contextmanager
def attempt(key: str, number: int) -> Iterator[None]:
    """The calls sent inside this block are send `number` (1 for the first) of `key`."""
    if isinstance(number, bool) or not isinstance(number, int) or number < 1:
        raise ValueError("an attempt is numbered from 1")
    token = _ATTEMPT.set((_checked(key), number))
    try:
        yield
    finally:
        _ATTEMPT.reset(token)


def first_send(key: str) -> bool:
    """Whether the host vouches `key` as fresh and numbers this send 1: no earlier call to find."""
    return _FRESH.get() == key and _ATTEMPT.get() == (key, 1)


def resend(key: str) -> bool:
    """Whether the host numbers this send of `key` 2 or more."""
    sent = _ATTEMPT.get()
    return sent is not None and sent[0] == key and sent[1] >= 2
