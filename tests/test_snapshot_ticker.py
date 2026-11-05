# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Snapshot evidence requires an intact clock and post-capture progress."""

from __future__ import annotations

import time

import pytest

from sandbox_provider_spec.driver import (
    Differs,
    Driver,
    Inputs,
    NativeFailure,
    NotRun,
    Observation,
    Unsupported,
)
from sandbox_provider_spec.runner import asserted
from sandbox_provider_spec.snapshot_ticker import classify, observe, parse


def ticks(intervals: list[int]) -> list[tuple[int, int]]:
    timestamp = 1000000000
    result = [(0, timestamp)]
    for index, interval in enumerate(intervals, 1):
        timestamp += interval * 1000000
        result.append((index, timestamp))
    return result


def test_partial_write_does_not_invalidate_complete_records() -> None:
    assert parse(b"0 1000000000\n1 1100000000\n2 12") == ticks([100])


@pytest.mark.parametrize("data", [b"0 100\n2 200\n", b"0 100\n1 100\n"])
def test_discontinuous_clock_or_counter_cannot_prove_snapshot_behavior(data: bytes) -> None:
    with pytest.raises(NotRun, match="snapshot_ticker_clock_or_counter_discontinuity"):
        parse(data)


@pytest.mark.parametrize("interval,expected", [(100, "continues"), (250, "briefly_paused")])
def test_snapshot_gap_requires_post_capture_progress(interval: int, expected: str) -> None:
    values = ticks([100, interval, 100, 100, 100, 100])
    control = {"counter": 1, "timestamp": values[1][1], "baseline_gap_ms": 100}
    result = classify(values, control, 2)
    assert result["original_after"] == expected
    assert result["longest_gap_ms"] == interval and result["advancing"] is True
    with pytest.raises(NotRun, match="snapshot_source_ticker_not_advancing"):
        classify(values[:-1], control, 2)


def test_recovery_gap_is_outside_the_snapshot_measurement() -> None:
    values = ticks([100, 100, 100, 900, 100, 100])
    control = {"counter": 1, "timestamp": values[1][1], "baseline_gap_ms": 100}
    assert classify(values, control, 2)["original_after"] == "continues"


def test_ambiguous_gap_is_not_a_passing_proof() -> None:
    values = ticks([100, 200, 100, 100, 100, 100])
    control = {"counter": 1, "timestamp": values[1][1], "baseline_gap_ms": 100}
    with pytest.raises(NotRun, match="snapshot_ticker_gap_ambiguous"):
        classify(values, control, 2)


def test_replaced_source_log_cannot_prove_the_original_source() -> None:
    values = ticks([100, 100, 100, 100, 100, 100])
    control = {"counter": 1, "timestamp": values[1][1] + 1, "baseline_gap_ms": 100}
    with pytest.raises(NotRun, match="snapshot_ticker_boundary_unobservable"):
        classify(values, control, 2)


def test_gap_pending_at_first_post_snapshot_read_cannot_prove_continues() -> None:
    values = ticks([100, 100, 900, 100, 100, 100])
    control = {"counter": 1, "timestamp": values[1][1], "baseline_gap_ms": 100}
    with pytest.raises(NotRun, match="snapshot_ticker_boundary_gap_ambiguous"):
        classify(values, control, 2)


def test_measured_gap_is_retained_when_the_claim_differs() -> None:
    with pytest.raises(Differs) as failure:
        asserted(
            {"original_after": "briefly_paused", "longest_gap_ms": 900},
            {"record": ["longest_gap_ms"], "equals": {"original_after": "continues"}},
        )
    assert failure.value.observation["longest_gap_ms"] == 900


class SourceDriver(Driver):
    """SDK-free driver whose post-capture file observation fails."""

    def __init__(
        self, read: Exception | None, state: object = "destroyed", lookup: bool | Exception = True
    ) -> None:
        super().__init__()
        self.calls: list[str] = []
        self.read, self.state, self.lookup = read, state, lookup
        self.reads = [b"0 1000000000\n1 1100000000\n"]

    def files_exists(self, target: object, inputs: Inputs) -> Observation:
        self.calls.append("files.exists")
        if self.read:
            raise self.read
        return {"exists": True}

    def files_read_bytes(self, target: object, inputs: Inputs) -> Observation:
        self.calls.append("files.read_bytes")
        return {"data": self.reads.pop(0) if len(self.reads) > 1 else self.reads[0]}

    def get(self, target: object, inputs: Inputs) -> Observation:
        self.calls.append("get")
        if isinstance(self.lookup, Exception):
            raise self.lookup
        if not self.lookup:
            raise NativeFailure("lookup_failed")
        return {"state": self.state}


TICKER = {"path": "/tmp/t.log", "counter": 1, "timestamp": 1100000000, "baseline_gap_ms": 100}


@pytest.mark.parametrize("code", ["invalid_state", "not_found"])
def test_confirmed_terminated_source_differs_and_never_passes(code: str) -> None:
    driver = SourceDriver(NativeFailure(code))
    result = observe(driver, object(), TICKER)
    assert result == {"original_after": "terminated", "advancing": False, "baseline_gap_ms": 100}
    assert driver.calls == ["files.exists", "get"]
    for field, wanted in (("original_after", "continues"), ("advancing", True)):
        with pytest.raises(Differs):
            asserted(result, {"record": [], "equals": {field: wanted}})


@pytest.mark.parametrize(
    "driver,code",
    [
        (SourceDriver(NativeFailure("invalid_state"), state="active"), "invalid_state"),
        (SourceDriver(NativeFailure("not_found"), state="unknown"), "not_found"),
        (SourceDriver(NativeFailure("invalid_state"), lookup=False), "invalid_state"),
        (SourceDriver(NativeFailure("invalid_state"), lookup=NotRun("x")), "invalid_state"),
        (SourceDriver(NativeFailure("not_found"), lookup=Unsupported("x")), "not_found"),
    ],
)
def test_unconfirmed_source_keeps_the_original_failure(driver: SourceDriver, code: str) -> None:
    with pytest.raises(NativeFailure) as failure:
        observe(driver, object(), TICKER)
    assert failure.value.code == code


def test_unrelated_read_error_makes_no_extra_lookup() -> None:
    driver = SourceDriver(NativeFailure("timeout"))
    with pytest.raises(NativeFailure, match="timeout"):
        observe(driver, object(), TICKER)
    assert driver.calls == ["files.exists"]


def test_normal_observation_makes_no_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    now = [0.0]
    monkeypatch.setattr(time, "monotonic", lambda: now[0])
    monkeypatch.setattr(time, "sleep", lambda seconds: now.__setitem__(0, now[0] + seconds))
    values = ticks([100] * 12)
    driver = SourceDriver(None)
    driver.reads = ["".join(f"{c} {t}\n" for c, t in values[:count]).encode() for count in (3, 8)]
    control = {"path": "p", "counter": 1, "timestamp": values[1][1], "baseline_gap_ms": 100}
    assert observe(driver, object(), control)["original_after"] == "continues"
    assert "get" not in driver.calls


def test_unexpected_lookup_error_stays_a_hard_error() -> None:
    driver = SourceDriver(NativeFailure("invalid_state"), lookup=TypeError("bug"))
    with pytest.raises(TypeError, match="bug"):
        observe(driver, object(), TICKER)
