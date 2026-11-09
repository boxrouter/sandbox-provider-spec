# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Measure a controlled guest ticker across one native snapshot operation."""

from __future__ import annotations

import base64
import shlex
import time
from collections.abc import Mapping, Sequence
from typing import Any
from uuid import uuid4

from sandbox_provider_spec.driver import Driver, NativeFailure, NotRun, Unsupported
from sandbox_provider_spec.suite import suite_path

Ticks = list[tuple[int, int]]

# Typed refusals a source that no longer exists can give a file observation.
SOURCE_GONE_CODES = frozenset({"invalid_state", "not_found"})


def parse(data: object) -> Ticks:
    """A partially written final record is ignored; discontinuities are inconclusive."""
    if isinstance(data, (bytes, bytearray, memoryview)):
        data = bytes(data).decode("ascii")
    if not isinstance(data, str) or len(data) > 131072:
        raise NativeFailure("snapshot_ticker_observation_invalid")
    complete = data.rpartition("\n")[0] if "\n" in data else ""
    ticks: Ticks = []
    for line in complete.splitlines():
        fields = line.split()
        if len(fields) != 2 or not all(field.isdecimal() for field in fields):
            raise NotRun("snapshot_ticker_records_invalid")
        counter, timestamp = map(int, fields)
        if counter != len(ticks) or timestamp <= 0 or (ticks and timestamp <= ticks[-1][1]):
            raise NotRun("snapshot_ticker_clock_or_counter_discontinuity")
        ticks.append((counter, timestamp))
    return ticks


def gaps(ticks: Sequence[tuple[int, int]]) -> list[int]:
    return [(right[1] - left[1]) // 1000000 for left, right in zip(ticks, ticks[1:], strict=False)]


def _read(driver: Driver, sandbox: object, path: str) -> Ticks:
    exists = driver.call("files.exists", sandbox, {"path": path})
    if exists.get("exists") is not True:
        return []
    result = driver.call("files.read_bytes", sandbox, {"path": path})
    return parse(result.get("data"))


def start(driver: Driver, sandbox: object) -> Mapping[str, object]:
    prefix = "/tmp/sps-ticker-" + uuid4().hex
    path = prefix + ".log"
    script = prefix + ".py"
    code = (suite_path().parent / "fixtures/snapshot_ticker.py").read_bytes()
    driver.call("files.write", sandbox, {"path": script, "data": base64.b64encode(code).decode()})
    driver.call(
        "process.start",
        sandbox,
        {
            "bash_script": "python3 " + shlex.quote(script) + " " + shlex.quote(path),
            "timeout_ms": 300000,
        },
    )
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        ticks = _read(driver, sandbox, path)
        if len(ticks) >= 21:
            baseline = max(gaps(ticks))
            if baseline > 150:
                raise NotRun("snapshot_ticker_control_unstable")
            return {
                "path": path,
                "counter": ticks[-1][0],
                "timestamp": ticks[-1][1],
                "baseline_gap_ms": baseline,
            }
        time.sleep(0.1)
    raise NotRun("snapshot_ticker_unavailable")


def classify(ticks: Ticks, ticker: Mapping[str, Any], cursor: int) -> Mapping[str, object]:
    boundary = ticker["counter"]
    if boundary >= len(ticks) or ticks[boundary][1] != ticker["timestamp"] or cursor < boundary:
        raise NotRun("snapshot_ticker_boundary_unobservable")
    if len(ticks) - 1 < cursor + 4:
        raise NotRun("snapshot_source_ticker_not_advancing")
    measured = gaps(ticks[boundary : cursor + 1])
    closing_gap = gaps(ticks[cursor : cursor + 2])[0]
    longest = max(measured, default=0)
    if longest < 250 and closing_gap > 150:
        # The last observed tick may precede a pause whose next tick is still
        # pending. Such a gap can straddle native return and observation, so
        # it cannot prove either capture behavior or uninterrupted progress.
        raise NotRun("snapshot_ticker_boundary_gap_ambiguous")
    longest = max(longest, closing_gap) if closing_gap <= 150 else longest
    if 150 < longest < 250:
        raise NotRun("snapshot_ticker_gap_ambiguous")
    return {
        "original_after": "briefly_paused" if longest >= 250 else "continues",
        "advancing": True,
        "longest_gap_ms": longest,
        "baseline_gap_ms": ticker["baseline_gap_ms"],
        "capture": "native_default",
    }


def _terminated(driver: Driver, sandbox: object) -> bool:
    """Only the driver's exact lookup of this same source can confirm it is gone."""
    try:
        return driver.call("get", sandbox, {}).get("state") == "destroyed"
    except (NativeFailure, NotRun, Unsupported):
        return False


def observe(driver: Driver, sandbox: object, ticker: Mapping[str, Any]) -> Mapping[str, object]:
    deadline = time.monotonic() + 10
    cursor: int | None = None
    while time.monotonic() < deadline:
        try:
            ticks = _read(driver, sandbox, ticker["path"])
        except NativeFailure as failure:
            if failure.code not in SOURCE_GONE_CODES or not _terminated(driver, sandbox):
                raise
            # Tick records after capture are unreadable, so no gap was measured.
            return {
                "original_after": "terminated",
                "advancing": False,
                "baseline_gap_ms": ticker["baseline_gap_ms"],
            }
        if ticks and ticks[-1][0] >= ticker["counter"]:
            if cursor is None:
                # Assess the pending gap to the first new tick before claiming
                # continues; three more ticks then establish recovery.
                cursor = ticks[-1][0]
            if ticks[-1][0] >= cursor + 4:
                return classify(ticks, ticker, cursor)
        time.sleep(0.1)
    raise NotRun("snapshot_source_ticker_not_advancing")
