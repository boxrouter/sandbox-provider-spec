# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""`v1.waiting.pause`: a plain sleep, wrapped by the host's observer when there is one."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Iterator
from contextlib import contextmanager

import pytest

from sandbox_provider_spec.v1 import waiting


@pytest.fixture(autouse=True)
def _no_observer() -> Iterator[None]:
    waiting.observe_pauses(None)
    yield
    waiting.observe_pauses(None)


def test_a_pause_without_an_observer_is_a_plain_sleep() -> None:
    started = time.monotonic()
    asyncio.run(waiting.pause(0.02))
    assert time.monotonic() - started >= 0.02


def test_the_observer_is_entered_around_each_pause() -> None:
    spans: list[tuple[float, float]] = []

    @contextmanager
    def observer() -> Iterator[None]:
        started = time.monotonic()
        yield
        spans.append((started, time.monotonic()))

    waiting.observe_pauses(observer)
    asyncio.run(waiting.pause(0.02))
    asyncio.run(waiting.pause(-1))
    assert len(spans) == 2
    assert spans[0][1] - spans[0][0] >= 0.02 and spans[1][1] - spans[1][0] < 0.02


def test_removing_the_observer_stops_it() -> None:
    seen: list[None] = []

    @contextmanager
    def observer() -> Iterator[None]:
        seen.append(None)
        yield

    waiting.observe_pauses(observer)
    waiting.observe_pauses(None)
    asyncio.run(waiting.pause(0))
    assert not seen
