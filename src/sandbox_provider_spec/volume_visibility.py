# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Observe mutual visibility without requiring immediate object-store consistency."""

from __future__ import annotations

import base64
import time
from collections.abc import Mapping
from typing import Any, cast

from sandbox_provider_spec.driver import Driver, NotRun, Unsupported


def _contents_match(observation: Mapping[str, object], marker: Mapping[str, Any]) -> bool:
    if "data" not in observation:
        raise NotRun("observation_unmapped")
    data = observation["data"]
    if isinstance(data, str):
        data = data.encode()
    return data == base64.b64decode(marker["data"], validate=True)


def _visible(driver: Driver, writers: list[Mapping[str, Any]]) -> dict[str, bool]:
    results = {}
    for field, reader, marker in zip(
        ("left_reads_right", "right_reads_left"), writers, reversed(writers), strict=True
    ):
        exists = driver.call("files.exists", reader["sandbox"], {"path": marker["path"]})
        if not isinstance(exists.get("exists"), bool):
            raise NotRun("observation_unmapped")
        results[field] = bool(exists["exists"]) and _contents_match(
            driver.call("files.read_bytes", reader["sandbox"], {"path": marker["path"]}),
            marker,
        )
    return results


def _published(driver: Driver, volume: object, writers: list[Mapping[str, Any]]) -> bool:
    for marker in writers:
        result = driver.call("volume.read_bytes", volume, {"path": marker["volume_path"]})
        if not isinstance(result.get("exists"), bool):
            raise NotRun("observation_unmapped")
        if not result["exists"] or not _contents_match(result, marker):
            return False
    return True


def observe(driver: Driver, inputs: Mapping[str, Any]) -> Mapping[str, object]:
    """Keep both writers alive; refresh once, only after both writes are published."""
    writers = cast(list[Mapping[str, Any]], inputs["writers"])
    timeout = inputs.get("timeout_ms", 60000)
    if (
        len(writers) != 2
        or not isinstance(timeout, int)
        or isinstance(timeout, bool)
        or not 1 <= timeout <= 120000
    ):
        raise ValueError("volume visibility requires two writers and a bounded deadline")
    deadline = time.monotonic() + timeout / 1000
    gap: str | None = None
    refreshed = False
    result: dict[str, bool] = {"left_reads_right": False, "right_reads_left": False}
    while time.monotonic() < deadline:
        result = _visible(driver, writers)
        if all(result.values()) and time.monotonic() < deadline:
            return result
        if not refreshed and gap is None:
            try:
                if _published(driver, inputs["volume"], writers):
                    # Refresh can discard local uncommitted writes. Each writer's
                    # marker was therefore read from durable storage first.
                    refreshed = True
                    for writer in writers:
                        driver.call("volume.reload", writer["sandbox"], {})
            except Unsupported:
                gap = "native_volume_visibility_unobservable"
            except NotRun:
                gap = "volume_visibility_mapping_unavailable"
        time.sleep(min(0.2, max(0, deadline - time.monotonic())))
    if gap is not None:
        raise NotRun(gap)
    return result
