# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The tester's snapshot delete asks again while the provider answers `unavailable` (cloud#10080).

A provider that is still capturing a snapshot does not delete it (one may undo a delete by
finishing the capture as a new snapshot): it answers `unavailable` with a wait, and the same call
works once the capture ends. No test waits real time, and none of it moves a check digest."""

from __future__ import annotations

import time
from collections.abc import Iterator
from typing import Any, ClassVar, cast

import pytest

from sandbox_provider_spec.driver import NativeFailure
from sandbox_provider_spec.v1 import CredentialField, Provider
from sandbox_provider_spec.v1.errors import SpsError
from sandbox_provider_spec.v1.suite_driver_setup import SetupRetryDriver
from sandbox_provider_spec.v1.types import SnapshotDeleteResult


class Saving(Provider, manifest=False):
    """A provider whose snapshot delete answers the scripted outcomes in order."""

    provider_id = "saving"
    name = "Saving"
    spec_version = "1.0"
    credential_fields: ClassVar[tuple[CredentialField, ...]] = (CredentialField("api_key"),)

    def __init__(self, answers: list[SpsError | None]) -> None:
        super().__init__({"api_key": "k"})
        self.answers = answers
        self.deletes = 0

    async def snapshot_delete(self, snapshot_id: str) -> SnapshotDeleteResult:
        self.deletes += 1
        answer = self.answers.pop(0)
        if answer is not None:
            raise answer
        return SnapshotDeleteResult(snapshot_id=snapshot_id, state="deleted")

    create = destroy = discovery = get = list = run = cast(Any, snapshot_delete)
    files_read = files_write = process_start = process_output = cast(Any, snapshot_delete)


def _saving(wait: int | None = 30) -> SpsError:
    return SpsError("unavailable", "still saving", outcome="failed", retry_after_seconds=wait)


@pytest.fixture(name="slept")
def slept_fixture(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    slept: list[float] = []
    clock = [1000.0]

    def sleep(seconds: float) -> None:
        slept.append(seconds)
        clock[0] += seconds

    monkeypatch.setattr(time, "sleep", sleep)
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    return slept


@pytest.fixture(name="driver_for")
def driver_for_fixture() -> Iterator[Any]:
    made: list[SetupRetryDriver] = []

    def make(provider: Saving) -> SetupRetryDriver:
        driver = SetupRetryDriver(provider, run="run-1")
        made.append(driver)
        return driver

    yield make
    for driver in made:
        driver.close()


def test_a_snapshot_still_saving_is_deleted_when_the_capture_ends(
    driver_for: Any, slept: list[float]
) -> None:
    provider = Saving([_saving(), _saving(), None])
    assert driver_for(provider)._delete_snapshot("snap-1") == {"result": "deleted"}
    assert (provider.deletes, slept) == (3, [30, 30])  # what the provider said, each time


def test_a_snapshot_that_stays_saving_past_the_budget_fails_with_its_code(
    driver_for: Any, slept: list[float]
) -> None:
    provider = Saving([_saving() for _ in range(100)])
    with pytest.raises(NativeFailure) as failed:
        driver_for(provider)._delete_snapshot("snap-1")
    assert failed.value.code == "unavailable"
    assert sum(slept) <= 600  # the cleanup phase's budget, not more


def test_any_other_failure_is_not_asked_again_and_a_gone_snapshot_is_deleted(
    driver_for: Any, slept: list[float]
) -> None:
    conflict = Saving([SpsError("conflict", "no")])
    with pytest.raises(NativeFailure) as failed:
        driver_for(conflict)._delete_snapshot("snap-1")
    assert (failed.value.code, conflict.deletes, slept) == ("conflict", 1, [])
    gone = Saving([_saving(), SpsError("not_found", "gone")])
    assert driver_for(gone)._delete_snapshot("snap-1") == {"result": "deleted"}
    assert gone.deletes == 2
