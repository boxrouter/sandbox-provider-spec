# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Publication must precede cache refresh; coherent mounts need neither API."""

from __future__ import annotations

from collections.abc import Mapping

import pytest

from sandbox_provider_spec.driver import Driver, Inputs, NotRun, Observation
from sandbox_provider_spec.volume_visibility import observe


def inputs() -> dict[str, object]:
    return {
        "volume": "volume",
        "writers": [
            {"sandbox": "left", "path": "/mount/a", "volume_path": "/a", "data": "bGVmdA=="},
            {"sandbox": "right", "path": "/mount/b", "volume_path": "/b", "data": "cmlnaHQ="},
        ],
        "timeout_ms": 1000,
    }


class VisibleDriver(Driver):
    def files_exists(self, target: object, arguments: Inputs) -> Observation:
        del target, arguments
        return {"exists": True}

    def files_read_bytes(self, target: object, arguments: Inputs) -> Observation:
        del target
        return {"data": b"left" if arguments["path"] == "/mount/a" else b"right"}


def test_direct_visibility_needs_no_publication_or_refresh_mapping() -> None:
    assert observe(VisibleDriver(), inputs()) == {
        "left_reads_right": True,
        "right_reads_left": True,
    }


class CachedDriver(VisibleDriver):
    def __init__(self) -> None:
        super().__init__()
        self.published: set[str] = set()
        self.refreshed: set[object] = set()
        self.reads = 0

    def files_exists(self, target: object, arguments: Inputs) -> Observation:
        del arguments
        return {"exists": target in self.refreshed}

    def volume_read_bytes(self, target: object, arguments: Inputs) -> Observation:
        del target
        self.reads += 1
        if self.reads == 1:
            return {"exists": False}
        path = str(arguments["path"])
        self.published.add(path)
        return {"exists": True, "data": b"left" if path == "/a" else b"right"}

    def volume_reload(self, target: object, arguments: Inputs) -> Observation:
        del arguments
        assert self.published == {"/a", "/b"}
        assert target not in self.refreshed
        self.refreshed.add(target)
        return {}


def test_refresh_happens_once_per_writer_after_both_exact_markers_are_published(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("sandbox_provider_spec.volume_visibility.time.sleep", lambda _: None)
    driver = CachedDriver()
    result = observe(driver, inputs())
    assert result == {"left_reads_right": True, "right_reads_left": True}
    assert driver.reads == 3 and driver.refreshed == {"left", "right"}


def test_missing_mapping_is_inconclusive_only_if_direct_visibility_never_arrives(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    times = iter((0.0, 0.0, 2.0, 2.0))
    monkeypatch.setattr(
        "sandbox_provider_spec.volume_visibility.time.monotonic", lambda: next(times)
    )
    monkeypatch.setattr("sandbox_provider_spec.volume_visibility.time.sleep", lambda _: None)

    class MissingDriver(VisibleDriver):
        def files_exists(self, target: object, arguments: Inputs) -> Observation:
            del target, arguments
            return {"exists": False}

    with pytest.raises(NotRun, match="volume_visibility_mapping_unavailable"):
        observe(MissingDriver(), inputs())


def test_publication_operational_errors_are_not_suppressed() -> None:
    class BrokenDriver(CachedDriver):
        def volume_read_bytes(self, target: object, arguments: Mapping[str, object]) -> Observation:
            del target, arguments
            raise OSError("native operation failed")

    with pytest.raises(OSError):
        observe(BrokenDriver(), inputs())


def test_delayed_direct_visibility_can_pass_despite_missing_refresh_mappings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("sandbox_provider_spec.volume_visibility.time.sleep", lambda _: None)

    class DelayedDriver(VisibleDriver):
        checks = 0

        def files_exists(self, target: object, arguments: Inputs) -> Observation:
            del target, arguments
            self.checks += 1
            return {"exists": self.checks > 2}

    assert all(observe(DelayedDriver(), inputs()).values())


def test_wrong_published_contents_never_trigger_a_refresh(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    times = iter((0.0, 0.0, 2.0, 2.0))
    monkeypatch.setattr(
        "sandbox_provider_spec.volume_visibility.time.monotonic", lambda: next(times)
    )
    monkeypatch.setattr("sandbox_provider_spec.volume_visibility.time.sleep", lambda _: None)

    class WrongDriver(CachedDriver):
        def volume_read_bytes(self, target: object, arguments: Inputs) -> Observation:
            del target, arguments
            return {"exists": True, "data": b"wrong"}

    driver = WrongDriver()
    assert observe(driver, inputs()) == {"left_reads_right": False, "right_reads_left": False}
    assert driver.refreshed == set()
