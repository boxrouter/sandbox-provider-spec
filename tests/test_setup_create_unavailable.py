# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""A row's `create` answered `unavailable` is asked again under the same key, then the row is
`not_run: provider_unavailable`, never `error` (cloud#10041); and none of it moves a check digest.
No test waits real time: the driver's clock, sleep and budget are the test's."""

from __future__ import annotations

import dataclasses
import inspect
import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, ClassVar, cast

import pytest

from sandbox_provider_spec import check_digests, conformance
from sandbox_provider_spec.suite import Suite
from sandbox_provider_spec.suite import Test as Scenario
from sandbox_provider_spec.v1 import (
    CreateRequest,
    CredentialField,
    Provider,
    Sandbox,
    from_json,
    tester,
)
from sandbox_provider_spec.v1.errors import SpsError
from sandbox_provider_spec.v1.suite_driver_setup import SetupRetryDriver

EXAMPLES = Path(__file__).resolve().parent / "spec" / "provider-api-1.0-examples"
if not EXAMPLES.is_dir():
    EXAMPLES = Path(__file__).resolve().parents[1] / "spec" / "provider-api-1.0-examples"


class Flaky(Provider, manifest=False):
    """A provider whose create is `unavailable` for its first `refusals` calls. A refusal with
    `outcome="unknown"` may have made the sandbox, as a real provider can: an idempotent repeat of
    the same key finds it."""

    provider_id = "flaky"
    name = "Flaky"
    spec_version = "1.0"
    credential_fields: ClassVar[tuple[CredentialField, ...]] = (CredentialField("api_key"),)

    def __init__(self, refusals: int, *, outcome: str = "unknown", hint: int | None = 7) -> None:
        super().__init__({"api_key": "k"})
        self.refusals = refusals
        self.outcome = outcome
        self.hint = hint
        self.keys: list[str] = []
        self.made: dict[str, str] = {}
        self.destroyed: list[str] = []

    def _box(self, key: str) -> Sandbox:
        if key not in self.made:
            self.made[key] = f"box-{len(self.made) + 1}"
        box = from_json(Sandbox, json.loads((EXAMPLES / "Sandbox.json").read_text("utf-8")))
        return dataclasses.replace(box, id=self.made[key])

    async def create(self, request: CreateRequest, *, idempotency_key: str) -> Sandbox:
        del request
        self.keys.append(idempotency_key)
        if len(self.keys) <= self.refusals:
            if self.outcome == "unknown":
                self._box(idempotency_key)  # the refused call made one anyway
            raise SpsError(
                "unavailable",
                "provider text that never reaches a report",
                outcome=cast(Any, self.outcome),
                retry_after_seconds=self.hint,
            )
        return self._box(idempotency_key)

    async def destroy(self, sandbox_id: str) -> Any:
        self.destroyed.append(sandbox_id)
        return SimpleResult()

    discovery = get = list = run = files_read = files_write = process_start = process_output = cast(
        Any, create
    )


@dataclasses.dataclass
class SimpleResult:
    state: str = "destroyed"


class FakeTime:
    def __init__(self) -> None:
        self.now = 1000.0
        self.slept: list[float] = []

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds

    def clock(self) -> float:
        return self.now


@pytest.fixture(name="driver_for")
def driver_for_fixture() -> Iterator[Callable[..., SetupRetryDriver]]:
    """Makes a driver on a provider with the test's clock; every driver is closed afterwards."""
    made: list[SetupRetryDriver] = []

    def make(provider: Flaky, fake: FakeTime, budget: float = 180) -> SetupRetryDriver:
        driver = SetupRetryDriver(provider, run="run-1")
        driver.sleep, driver.clock, driver.setup_budget_seconds = fake.sleep, fake.clock, budget
        made.append(driver)
        return driver

    yield make
    for driver in made:
        driver.close()


ROW = Suite("test", (Scenario("row", "a row", ({"op": "create", "as": "box"},), ()),))


def test_a_create_that_is_unavailable_once_is_asked_again_and_the_row_passes(
    driver_for: Callable[..., SetupRetryDriver],
) -> None:
    provider, fake = Flaky(1), FakeTime()
    driver = driver_for(provider, fake)
    row = conformance.run_suite(driver, ROW)[0]
    assert row["result"] == "passed"
    assert fake.slept == [7]  # what the provider said
    assert len(provider.keys) == 2 and len(set(provider.keys)) == 1  # the same key
    # the refused call made a sandbox (outcome unknown): the repeat found it, so it is the only
    # one, and the row's cleanup destroyed it
    assert provider.destroyed == list(provider.made.values()) and len(provider.made) == 1


def test_a_create_refused_for_the_whole_budget_is_not_run_with_the_code_and_outcome(
    driver_for: Callable[..., SetupRetryDriver],
) -> None:
    provider, fake = Flaky(10_000), FakeTime()
    driver = driver_for(provider, fake, budget=60)
    row = conformance.run_suite(driver, ROW)[0]
    assert row["result"] == "not_run" and row["reason"] == "provider_unavailable"
    assert row["steps"] == [
        {
            "operation": "create",
            "result": "not_run",
            "reason": "provider_unavailable",
            "detail": "code=unavailable outcome=unknown retry_after_seconds=7",
        }
    ]
    assert sum(fake.slept) <= 60 and len(set(provider.keys)) == 1
    # nothing is recorded as an error, no provider text or id is in the row, and the sandbox the
    # refused calls made is not one the row owns: the run's label sweep covers it
    assert "provider text" not in json.dumps(row) and "box-" not in json.dumps(row)
    assert row["cleanup"] == []


def test_a_refusal_that_did_nothing_says_failed_and_a_missing_hint_is_left_out(
    driver_for: Callable[..., SetupRetryDriver],
) -> None:
    provider, fake = Flaky(10_000, outcome="failed", hint=None), FakeTime()
    driver = driver_for(provider, fake, budget=5)
    steps = cast(list[dict[str, Any]], conformance.run_suite(driver, ROW)[0]["steps"])
    assert steps[0]["detail"] == "code=unavailable outcome=failed"
    assert fake.slept == [1] * 5  # a missing hint waits one second, within the budget
    assert not provider.made


def test_the_wait_is_bounded_to_thirty_seconds(driver_for: Callable[..., SetupRetryDriver]) -> None:
    provider, fake = Flaky(1, hint=600), FakeTime()
    driver = driver_for(provider, fake)
    assert conformance.run_suite(driver, ROW)[0]["result"] == "passed"
    assert fake.slept == [30]


def test_any_other_failure_of_a_create_is_still_the_rows_error(
    driver_for: Callable[..., SetupRetryDriver],
) -> None:
    class Refused(Flaky, manifest=False):
        async def create(self, request: CreateRequest, *, idempotency_key: str) -> Sandbox:
            del request, idempotency_key
            raise SpsError("quota_exceeded", "no", outcome="failed")

    provider, fake = Refused(0), FakeTime()
    driver = driver_for(provider, fake)
    row = conformance.run_suite(driver, ROW)[0]
    assert row["result"] == "error" and row["reason"] == "quota_exceeded"
    assert not fake.slept


def test_the_tester_uses_this_driver() -> None:
    assert "SetupRetryDriver(provider" in inspect.getsource(tester.run_tests)


def test_no_row_digests_the_new_code_or_the_tester() -> None:
    """The rows' check digests hash `SHARED_MODULES` and each operation's modules: this code is in
    neither, so no row's digest moves with it. Every row of the shared suite is checked."""
    suite = tester.shared_suite()
    assert suite.tests
    moved = [
        test.id
        for test in suite.tests
        if {"v1/suite_driver_setup.py", "v1/tester.py"} & set(check_digests.test_dependencies(test))
    ]
    assert moved == []
    assert not {"v1/suite_driver_setup.py", "v1/tester.py"} & set(check_digests.SHARED_MODULES)
