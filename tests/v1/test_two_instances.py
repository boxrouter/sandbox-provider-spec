# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""`--two-instances`: a run's calls alternate between two provider objects of one account.

An adapter whose sandbox records live in its own object passes a one-object run and fails here;
one whose records live at the provider passes both.
"""

from __future__ import annotations

import asyncio
import itertools
from collections.abc import Mapping
from typing import Any, ClassVar

import pytest
from test_tester import COMMAND_TESTS, LocalProvider

from sandbox_provider_spec.v1 import CreateRequest, Provider, RunRequest, RunResult, Sandbox
from sandbox_provider_spec.v1.tester import CannotRun, TestOptions, run_tests
from sandbox_provider_spec.v1.two_instances import TwoInstances, provider_class


class Backend(LocalProvider, manifest=False):
    """Keeps its records in a store that every object of the class shares, as a provider does."""

    store: ClassVar[dict[str, Sandbox]] = {}
    ids: ClassVar[Any] = itertools.count(1)
    procs: ClassVar[dict[str, Any]] = {}
    env: ClassVar[dict[str, str]] = {}

    def __init__(self, credentials: Mapping[str, str] | None = None) -> None:
        super().__init__(credentials)
        self.boxes = Backend.store
        self.processes = Backend.procs
        self.counter = Backend.ids

    async def create(self, request: CreateRequest, *, idempotency_key: str) -> Sandbox:
        box = await super().create(request, idempotency_key=idempotency_key)
        Backend.env = self.environment  # the create's env is the backend's, not this object's
        return box

    async def run(self, sandbox_id: str, request: RunRequest) -> RunResult:
        self.environment = Backend.env
        return await super().run(sandbox_id, request)


@pytest.fixture(autouse=True)
def _fresh_backend() -> None:
    Backend.store, Backend.procs, Backend.env = {}, {}, {}
    Backend.ids = itertools.count(1)


def test_calls_alternate_and_both_objects_are_closed() -> None:
    first, second = LocalProvider(), LocalProvider()
    pair = TwoInstances(first, second)
    assert pair.instance_class is LocalProvider
    assert provider_class(pair) is LocalProvider
    assert provider_class(first) is LocalProvider
    assert pair.provider_id == "local"  # a plain attribute reads the first
    assert pair.get is not pair.get  # each lookup of a coroutine method takes the next turn
    # The two lookups above took turns 0 and 1, so the next call is the first object's again.
    asyncio.run(pair.create(_request(), idempotency_key="a"))  # first
    asyncio.run(pair.create(_request(), idempotency_key="b"))  # second
    assert len(first.boxes) == 1
    assert len(second.boxes) == 1
    asyncio.run(pair.aclose())
    assert first.closed
    assert second.closed


def _request() -> CreateRequest:
    return CreateRequest()


def test_a_provider_that_keeps_records_at_the_backend_passes() -> None:
    report = run_tests(
        Backend(), TestOptions(tests=COMMAND_TESTS, two_instances=True, new_client=Backend)
    )
    assert report.all_passed


def test_a_provider_that_keeps_records_in_its_object_fails() -> None:
    report = run_tests(
        LocalProvider(),
        TestOptions(tests=COMMAND_TESTS, two_instances=True, new_client=LocalProvider),
    )
    assert not report.all_passed


def test_two_instances_need_a_way_to_make_the_second() -> None:
    with pytest.raises(CannotRun):
        run_tests(Backend(), TestOptions(tests=COMMAND_TESTS, two_instances=True))


def test_the_report_names_the_provider_class_not_the_stand_in() -> None:
    report = run_tests(
        Backend(), TestOptions(tests=COMMAND_TESTS[:2], two_instances=True, new_client=Backend)
    )
    assert report["provider"] == "example"
    assert isinstance(Backend(), Provider)
