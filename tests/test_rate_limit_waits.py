# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""A read the provider rate-limits is waited for as long as it says, within a bound, not failed."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import pytest

from sandbox_provider_spec import cost_checks
from sandbox_provider_spec.driver import (
    MAX_RATE_LIMIT_PAUSE_SECONDS,
    NativeFailure,
    rate_limit_pause,
)


class _Driver:
    """`wait` answers each read from a script: a failure is raised, anything else returned."""

    def __init__(self, answers: list[Any]) -> None:
        self.answers = answers
        self.reads = 0

    def wait(self, call: Any) -> Any:
        del call
        self.reads += 1
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer


@pytest.fixture(name="slept")
def slept_fixture(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """A clock that only the sleeps move, and what was slept."""
    slept: list[float] = []
    clock = [1000.0]

    def sleep(seconds: float) -> None:
        slept.append(seconds)
        clock[0] += seconds

    monkeypatch.setattr(cost_checks.time, "sleep", sleep)
    monkeypatch.setattr(cost_checks.time, "monotonic", lambda: clock[0])
    return slept


def _read(driver: _Driver) -> Any:
    return cost_checks.read_cost(cast(Any, driver), lambda: cast(Any, None), {})


def test_the_pause_is_what_the_provider_said_between_one_and_the_cap() -> None:
    assert rate_limit_pause(NativeFailure("rate_limited", retry_after_seconds=9)) == 9
    assert rate_limit_pause(NativeFailure("rate_limited")) == 1
    assert rate_limit_pause(NativeFailure("rate_limited", retry_after_seconds=0)) == 1
    assert rate_limit_pause(NativeFailure("rate_limited", retry_after_seconds=600)) == (
        MAX_RATE_LIMIT_PAUSE_SECONDS
    )


def test_a_rate_limited_cost_read_waits_the_retry_after_and_reads_again(slept: list[float]) -> None:
    final = SimpleNamespace(status="final")
    driver = _Driver([NativeFailure("rate_limited", retry_after_seconds=9), final])
    assert _read(driver) is final
    assert slept == [9] and driver.reads == 2


def test_another_failure_is_not_waited_for(slept: list[float]) -> None:
    driver = _Driver([NativeFailure("provider_error"), SimpleNamespace(status="final")])
    with pytest.raises(NativeFailure):
        _read(driver)
    assert slept == [] and driver.reads == 1


def test_a_read_that_stays_limited_fails_once_the_budget_is_spent(slept: list[float]) -> None:
    limited = NativeFailure("rate_limited", retry_after_seconds=30)
    driver = _Driver([limited] * 20)
    with pytest.raises(NativeFailure):
        _read(driver)
    assert sum(slept) <= cost_checks.RATE_LIMIT_BUDGET_SECONDS
