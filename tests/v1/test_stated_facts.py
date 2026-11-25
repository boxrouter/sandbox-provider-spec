# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""`contract.create_meets_stated_facts`: a create asks every yes-or-no fact the class states."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from test_tester import ContractProvider, LocalProvider, with_gates

from sandbox_provider_spec import check_digests
from sandbox_provider_spec.v1 import CreateRequest, Discovery, Sandbox, SpsError
from sandbox_provider_spec.v1.suite_driver_stated_facts import NO_STATED_FACT, stated_asks
from sandbox_provider_spec.v1.tester import TestOptions, run_tests, shared_suite

ROW = "contract.create_meets_stated_facts"


class Stating(LocalProvider, manifest=False):
    """States `extendable_lifetime` and `long_running`, and keeps the `resources` of every create.
    A create that asks a fact in `refuses` is refused, as an adapter refuses an ask it cannot
    meet."""

    def __init__(self, credentials: Mapping[str, str] | None = None) -> None:
        super().__init__(credentials)
        self.asked: list[dict[str, object]] = []
        self.refuses: set[str] = set()

    async def discovery(self) -> Discovery:
        return with_gates({}, {"extendable_lifetime": True, "long_running": True})

    async def create(self, request: CreateRequest, *, idempotency_key: str) -> Sandbox:
        self.asked.append(dict(request.resources))
        refused = self.refuses & set(request.resources)
        if refused:
            raise SpsError("unsupported", f"cannot meet resources.{min(refused)}")
        return await super().create(request, idempotency_key=idempotency_key)


def rows(provider: LocalProvider, tests: tuple[str, ...]) -> dict[str, Any]:
    report = run_tests(provider, TestOptions(tests=tests))
    return {str(row["id"]): row for row in report["tests"]}


def test_the_asks_are_the_yes_or_no_facts_that_the_class_states_true() -> None:
    stated = {
        "extendable_lifetime": True,
        "long_running": False,
        "size_is_ceiling": True,
        "kernel": "dedicated",
        "regions": ["us-east"],
    }
    assert stated_asks(stated) == {"extendable_lifetime": True, "size_is_ceiling": True}
    assert stated_asks({}) == {}


def test_a_class_that_meets_the_facts_it_states_passes() -> None:
    provider = Stating()
    found = rows(provider, (ROW,))
    assert found[ROW]["result"] == "passed", found[ROW]
    assert provider.asked.count({"extendable_lifetime": True, "long_running": True}) == 1
    assert all(box.state == "destroyed" for box in provider.boxes.values())


def test_a_create_that_refuses_a_stated_fact_fails_the_row_and_only_that_row() -> None:
    """A provider that refuses `extendable_lifetime` though its class states it passes the rows
    that ask only floors, and only this row finds that a router's create fails."""
    provider = Stating()
    provider.refuses = {"extendable_lifetime"}
    found = rows(provider, (ROW, "baseline.create_env"))
    assert found["baseline.create_env"]["result"] == "passed"
    assert (found[ROW]["result"], found[ROW]["reason"]) == ("error", "stated_fact_refused")


def test_a_class_that_states_none_of_the_facts_does_not_count() -> None:
    report = run_tests(ContractProvider(), TestOptions(tests=(ROW,)))
    (row,) = report["tests"]
    assert (row["result"], row["reason"]) == ("not_run", NO_STATED_FACT)
    assert report.all_passed


def test_only_the_new_row_digests_the_step() -> None:
    using = [
        test.id
        for test in shared_suite().tests
        if "v1/suite_driver_stated_facts.py" in check_digests.test_dependencies(test)
    ]
    assert using == [ROW]
