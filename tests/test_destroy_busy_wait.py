# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The tester's destroys ask again while the provider says it is busy (spec `unavailable`), under
one budget shared by the whole cleanup phase (cloud#9848)."""

from __future__ import annotations

from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

import pytest

from sandbox_provider_spec.driver import NativeFailure
from sandbox_provider_spec.v1 import suite_driver_cleanup as cleanup


@pytest.fixture(name="slept")
def slept_fixture(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """A clock that only the sleeps move, and what was slept. The cleanup module's own clock:
    the tester's event loop keeps real time."""
    slept: list[float] = []
    clock = [1000.0]

    def sleep(seconds: float) -> None:
        slept.append(seconds)
        clock[0] += seconds

    monkeypatch.setattr(cleanup.time, "sleep", sleep)
    monkeypatch.setattr(cleanup.time, "monotonic", lambda: clock[0])
    return slept


def _destroys(answers: list[Any]) -> Callable[[], Any]:
    calls = {"n": 0}

    def destroy() -> Any:
        calls["n"] += 1
        answer = answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer

    destroy.calls = calls  # type: ignore[attr-defined]
    return destroy


def _busy(wait: int = 10) -> NativeFailure:
    return NativeFailure("unavailable", retry_after_seconds=wait)


def test_a_busy_destroy_waits_what_the_provider_says_and_asks_again(slept: list[float]) -> None:
    done = SimpleNamespace(state="destroying")
    destroy = _destroys([_busy(), _busy(), done])
    assert cleanup.destroy_when_free(destroy, cleanup.CleanupBudget()) is done
    assert slept == [10, 10]


def test_any_other_failure_is_not_waited_for(slept: list[float]) -> None:
    destroy = _destroys([NativeFailure("conflict"), SimpleNamespace(state="destroying")])
    with pytest.raises(NativeFailure):
        cleanup.destroy_when_free(destroy, cleanup.CleanupBudget())
    assert slept == []


def test_the_cleanup_phase_has_one_budget_for_all_its_destroys(slept: list[float]) -> None:
    """A provider that refuses every destroy costs the budget once, not once per sandbox."""
    budget = cleanup.CleanupBudget()
    for _ in range(5):
        with pytest.raises(NativeFailure):
            cleanup.destroy_when_free(_destroys([_busy(30)] * 100), budget)
    assert sum(slept) <= cleanup.CLEANUP_BUDGET_SECONDS


def test_a_cleanup_that_outlasts_the_old_per_sandbox_wait_still_succeeds(
    slept: list[float],
) -> None:
    """Ten refusals over minutes (live, cloud#9848: six minutes twenty): the pauses are capped at
    30 s each, so 300 s here, past the 195 s the per-sandbox wait gave up at, inside 600 s."""
    done = SimpleNamespace(state="destroying")
    destroy = _destroys([_busy(38)] * 10 + [done])
    assert cleanup.destroy_when_free(destroy, cleanup.CleanupBudget()) is done
    assert sum(slept) == 300 > 195


def test_a_step_destroy_has_a_budget_of_its_own(slept: list[float]) -> None:
    with pytest.raises(NativeFailure):
        cleanup.destroy_when_free(_destroys([_busy(30)] * 100))
    assert sum(slept) <= cleanup.STEP_BUDGET_SECONDS


def test_the_budget_is_the_knob_a_test_sets(
    monkeypatch: pytest.MonkeyPatch, slept: list[float]
) -> None:
    monkeypatch.setattr(cleanup, "CLEANUP_BUDGET_SECONDS", 0)
    with pytest.raises(NativeFailure):
        cleanup.destroy_when_free(_destroys([_busy()] * 3), cleanup.CleanupBudget())
    assert slept == []
