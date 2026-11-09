# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""A run that leaves one of its own snapshots behind fails, whatever ended the run."""

from __future__ import annotations

import signal
from types import SimpleNamespace
from typing import cast

import pytest
from daytona.common.snapshot import Snapshot
from test_daytona_cleanup import SnapshotInventory, snapshot_driver

from sandbox_provider_spec import conformance, coverage_file_transfer
from sandbox_provider_spec.driver import Driver, Observation, Resource
from sandbox_provider_spec.report import report
from sandbox_provider_spec.run_id import native_name
from sandbox_provider_spec.runner import Runner
from sandbox_provider_spec.suite import Suite
from sandbox_provider_spec.suite import Test as Scenario


@pytest.fixture
def snapshot_clock(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    clock = [0.0]
    monkeypatch.setattr("sandbox_provider_spec.drivers.daytona.time.monotonic", lambda: clock[0])
    monkeypatch.setattr(
        "sandbox_provider_spec.drivers.daytona.time.sleep",
        lambda seconds: clock.__setitem__(0, clock[0] + seconds),
    )
    return clock


def _own(inventory: SnapshotInventory, snapshot_id: str = "late-id") -> str:
    name = native_name()
    inventory.present[snapshot_id] = Snapshot.model_construct(
        id=snapshot_id, name=name, state="active"
    )
    return name


def test_a_clean_run_has_no_leftover_to_report(
    monkeypatch: pytest.MonkeyPatch, snapshot_clock: list[float]
) -> None:
    del snapshot_clock
    inventory = SnapshotInventory()
    driver = snapshot_driver(monkeypatch, inventory)
    assert driver.finish() == []
    assert inventory.deleted == [] and "foreign-id" in inventory.present


def test_an_own_snapshot_that_cleanup_missed_is_deleted_by_id_and_fails_the_run(
    monkeypatch: pytest.MonkeyPatch, snapshot_clock: list[float]
) -> None:
    del snapshot_clock
    inventory = SnapshotInventory()
    driver = snapshot_driver(monkeypatch, inventory)
    _own(inventory)
    # Another run's snapshot carries another run's token: it is never touched.
    inventory.present["other-run"] = Snapshot.model_construct(
        id="other-run", name="sps-r00000000-00000-" + "0" * 32, state="active"
    )
    observations = driver.finish()
    assert observations == [
        {"kind": "snapshot", "result": "error", "reason": "run_snapshot_left_behind"}
    ]
    assert inventory.deleted == ["late-id"]
    assert set(inventory.present) == {"foreign-id", "other-run"}
    document = report(
        driver,
        Suite("sha256:" + "0" * 64, (Scenario("t", "t", (), ()),)),
        [{"id": "t", "result": "passed", "cleanup": observations}],
        spec_revision="0" * 40,
        started_at="2026-10-29T00:00:00+00:00",
    )
    assert document["clean"] is False


def test_a_leftover_that_cannot_be_deleted_is_reported_as_not_removed(
    monkeypatch: pytest.MonkeyPatch, snapshot_clock: list[float]
) -> None:
    inventory = SnapshotInventory()
    inventory.refuse_delete = True
    driver = snapshot_driver(monkeypatch, inventory)
    _own(inventory)
    observations = driver.finish()
    assert observations == [
        {"kind": "snapshot", "result": "error", "reason": "run_snapshot_not_removed"}
    ]
    assert snapshot_clock[0] <= 180  # bounded, never an open-ended wait
    assert "late-id" in inventory.present


def test_an_unreadable_inventory_is_never_proof_that_nothing_is_left(
    monkeypatch: pytest.MonkeyPatch, snapshot_clock: list[float]
) -> None:
    del snapshot_clock
    inventory = SnapshotInventory()
    driver = snapshot_driver(monkeypatch, inventory)

    def broken(*, page: int, limit: int) -> object:
        raise TimeoutError("listing timed out")

    monkeypatch.setattr(inventory, "list", broken)
    observations = driver.finish()
    assert [item["result"] for item in observations] == ["error"]
    assert observations[0]["reason"] == "run_snapshots_unverified"


class _Ledger(Driver):
    provider = "fake"

    def __init__(self) -> None:
        super().__init__()
        self.freed: list[str] = []
        self.finished = 0

    def finish(self) -> list[Observation]:
        self.finished += 1
        return []

    def hold(self, kind: str) -> Resource:
        def free() -> Observation:
            self.freed.append(kind)
            return {"result": "deleted"}

        return self.own(kind, kind, free)


def test_an_interrupted_run_releases_what_it_owns_and_re_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    driver = _Ledger()
    driver.hold("snapshot")
    driver.hold("sandbox")

    def interrupted(self: object, suite: object) -> list[dict[str, object]]:
        raise KeyboardInterrupt

    monkeypatch.setattr(coverage_file_transfer.FileTransferRunner, "run", interrupted)
    with pytest.raises(KeyboardInterrupt):
        conformance.run_suite(driver, Suite("", ()))
    assert driver.freed == ["sandbox", "snapshot"]  # newest first
    assert driver.finished == 1  # and its own-run leftovers were looked for


def test_an_interrupt_closes_the_cases_still_waiting_so_their_cleanup_runs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed: list[str] = []

    def case(self: object, test: Scenario, capacity: int | None = None):  # type: ignore[no-untyped-def]
        try:
            yield 10**9
        finally:
            closed.append(test.id)

    monkeypatch.setattr(Runner, "_case", case)

    def interrupt(seconds: float) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr("sandbox_provider_spec.runner.time.sleep", interrupt)
    waiting = tuple(
        Scenario(name, name, ({"op": "create"}, {"wait_ms": 1}), ()) for name in ("a", "b")
    )
    with pytest.raises(KeyboardInterrupt):
        Runner(cast(Driver, SimpleNamespace(unsupported={}, resources=[]))).run(Suite("", waiting))
    assert sorted(closed) == ["a", "b"]


def test_a_termination_signal_unwinds_like_an_interrupt() -> None:
    previous = signal.getsignal(signal.SIGTERM)
    with conformance.terminating_as_interrupt():
        handler = signal.getsignal(signal.SIGTERM)
        assert callable(handler)
        with pytest.raises(KeyboardInterrupt):
            handler(signal.SIGTERM, None)
    assert signal.getsignal(signal.SIGTERM) is previous
