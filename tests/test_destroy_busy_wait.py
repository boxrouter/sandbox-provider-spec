# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The tester's destroy asks again while the provider says it is busy (spec `unavailable`)."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import pytest

from sandbox_provider_spec.driver import RATE_LIMIT_BUDGET_SECONDS, NativeFailure
from sandbox_provider_spec.v1 import suite_driver
from sandbox_provider_spec.v1.suite_driver import ProviderDriver


class _Stub:
    """`wait` answers each destroy from a script: a failure is raised, anything else returned."""

    def __init__(self, answers: list[Any]) -> None:
        self.answers = answers
        self.destroys = 0
        self.api = SimpleNamespace(destroy=lambda sandbox_id: sandbox_id)

    def wait(self, call: Any) -> Any:
        del call
        self.destroys += 1
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer


@pytest.fixture(name="slept")
def slept_fixture(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    slept: list[float] = []
    clock = [1000.0]

    def sleep(seconds: float) -> None:
        slept.append(seconds)
        clock[0] += seconds

    monkeypatch.setattr(suite_driver.time, "sleep", sleep)
    monkeypatch.setattr(suite_driver.time, "monotonic", lambda: clock[0])
    return slept


def _destroy(stub: _Stub) -> Any:
    return ProviderDriver._destroy_when_free(cast(Any, stub), "sbx")


def test_a_busy_destroy_waits_what_the_provider_says_and_asks_again(slept: list[float]) -> None:
    done = SimpleNamespace(state="destroying")
    stub = _Stub(
        [
            NativeFailure("unavailable", retry_after_seconds=10),
            NativeFailure("unavailable", retry_after_seconds=10),
            done,
        ]
    )
    assert _destroy(stub) is done
    assert slept == [10, 10] and stub.destroys == 3


def test_any_other_failure_is_not_waited_for(slept: list[float]) -> None:
    stub = _Stub([NativeFailure("conflict"), SimpleNamespace(state="destroying")])
    with pytest.raises(NativeFailure):
        _destroy(stub)
    assert slept == [] and stub.destroys == 1


def test_a_destroy_that_stays_busy_fails_once_the_budget_is_spent(slept: list[float]) -> None:
    stub = _Stub([NativeFailure("unavailable", retry_after_seconds=30)] * 20)
    with pytest.raises(NativeFailure):
        _destroy(stub)
    assert sum(slept) <= RATE_LIMIT_BUDGET_SECONDS
