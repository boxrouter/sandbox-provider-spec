# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""`v1.idempotency`: a first send needs both facts for one key; anything else is the safe path."""

from __future__ import annotations

import asyncio

import pytest

from sandbox_provider_spec.v1.idempotency import attempt, first_send, fresh_key, resend


def test_no_host_says_nothing() -> None:
    assert not first_send("k-1")
    assert not resend("k-1")


def test_a_first_send_needs_the_vouch_and_attempt_one_for_the_same_key() -> None:
    with fresh_key("k-1"):
        assert not first_send("k-1")  # no attempt numbered: an old resend loop
        with attempt("k-1", 1):
            assert first_send("k-1")
            assert not resend("k-1")
            assert not first_send("k-2")
        with attempt("k-1", 2):
            assert not first_send("k-1")
            assert resend("k-1")
    with attempt("k-1", 1):
        assert not first_send("k-1")  # attempt one of a key nobody vouched for


def test_a_vouch_for_another_key_opens_nothing() -> None:
    with fresh_key("mutation-1"), attempt("runner-name", 1):
        assert not first_send("runner-name")
        assert not first_send("mutation-1")


def test_scopes_nest_and_reset_on_exception() -> None:
    with fresh_key("k-1"), attempt("k-1", 1):
        with attempt("k-1", 2):
            assert resend("k-1")
        assert first_send("k-1")
    with pytest.raises(RuntimeError):
        with fresh_key("k-1"), attempt("k-1", 1):
            raise RuntimeError
    assert not first_send("k-1")


def test_the_facts_follow_the_task_and_no_other() -> None:
    async def main() -> tuple[bool, bool]:
        async def child() -> bool:
            return first_send("k-1")

        with fresh_key("k-1"), attempt("k-1", 1):
            inside = await asyncio.create_task(child())
        outside = await asyncio.create_task(child())
        return inside, outside

    assert asyncio.run(main()) == (True, False)


@pytest.mark.parametrize("key", ["", None, 7])
def test_a_key_is_a_non_empty_string(key: object) -> None:
    with pytest.raises(ValueError):
        with fresh_key(key):  # type: ignore[arg-type]
            pass
    with pytest.raises(ValueError):
        with attempt(key, 1):  # type: ignore[arg-type]
            pass


@pytest.mark.parametrize("number", [0, -1, True, 1.0])
def test_an_attempt_is_numbered_from_one(number: object) -> None:
    with pytest.raises(ValueError):
        with attempt("k-1", number):  # type: ignore[arg-type]
            pass
