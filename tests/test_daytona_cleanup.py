# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""SDK readiness failures can occur after a named allocation exists."""

from __future__ import annotations

from types import SimpleNamespace
from typing import cast

import pytest
from daytona import (
    CreateSandboxFromImageParams,
    CreateSandboxFromSnapshotParams,
    CreateSnapshotParams,
    DaytonaConfig,
    Sandbox,
)
from daytona.common.errors import (
    DaytonaBadRequestError,
    DaytonaConflictError,
    DaytonaNotFoundError,
)
from daytona.common.snapshot import PaginatedSnapshots, Snapshot
from daytona.common.volume import Volume
from daytona_api_client.models.volume_state import VolumeState

from sandbox_provider_spec.driver import NativeFailure, Resource, Unsupported, resource
from sandbox_provider_spec.drivers import daytona as native
from sandbox_provider_spec.report import report
from sandbox_provider_spec.runner import Runner
from sandbox_provider_spec.suite import Suite
from sandbox_provider_spec.suite import Test as Scenario


@pytest.mark.parametrize(
    "snapshot_test,explicit_lifetime,minutes",
    [(True, None, 5), (True, 60, 1), (False, None, 2)],
)
def test_snapshot_budget_preserves_explicit_timer_settings(
    monkeypatch: pytest.MonkeyPatch,
    snapshot_test: bool,
    explicit_lifetime: int | None,
    minutes: int,
) -> None:
    captured: list[int | None] = []

    class Client:
        def __init__(self, config: DaytonaConfig) -> None:
            del config

        def create(self, params: CreateSandboxFromSnapshotParams, *, timeout: float) -> Sandbox:
            assert timeout == 60
            captured.append(params.ttl_minutes)
            return Sandbox.model_construct(id="source", sandbox_class="container")

    monkeypatch.setattr(native, "Daytona", Client)
    inputs: dict[str, object] = {}
    if snapshot_test:
        inputs["requirements"] = {"snapshots": {"original_after": "any"}}
    if explicit_lifetime is not None:
        inputs["lifetime_seconds"] = explicit_lifetime
    native.DaytonaDriver("container", {}).create(None, inputs)
    assert captured == [minutes]


@pytest.mark.parametrize("execution_class", ["container", "gpu"])
def test_memory_pause_requires_vm_before_any_native_mutation(
    monkeypatch: pytest.MonkeyPatch, execution_class: str
) -> None:
    monkeypatch.setattr(native, "Daytona", lambda config: object())
    driver = native.DaytonaDriver(execution_class, {})
    with pytest.raises(Unsupported, match="requires a VM sandbox"):
        driver.pause(None, {"keeps": "files_and_memory"})
    with pytest.raises(Unsupported, match="requires a VM sandbox"):
        driver.create(None, {"requirements": {"idle_shutdown": {"on_idle": "paused"}}})


def test_create_failure_cleans_the_reserved_native_name(monkeypatch: pytest.MonkeyPatch) -> None:
    class Client:
        def __init__(self, config: DaytonaConfig) -> None:
            del config
            self.allocated = False
            self.names: list[str] = []

        def create(
            self,
            params: CreateSandboxFromSnapshotParams | CreateSandboxFromImageParams,
            *,
            timeout: float,
        ) -> Sandbox:
            del timeout
            self.allocated = True
            assert params.name is not None
            self.names.append(params.name)
            raise RuntimeError("native readiness failed after allocation")

        def get(self, identity: str, *, request_timeout: float) -> Sandbox:
            del request_timeout
            assert identity in self.names
            if not self.allocated:
                raise DaytonaNotFoundError("gone")
            return Sandbox.model_construct(id=identity, sandbox_class="container")

        def delete(self, sandbox: Sandbox, *, timeout: float, wait: bool) -> None:
            del sandbox, timeout
            assert wait
            self.allocated = False

    monkeypatch.setattr(native, "Daytona", Client)
    driver = native.DaytonaDriver("container", {})
    result = Runner(driver).run_test(Scenario("candidate", "create", ({"op": "create"},), ()))
    assert result["result"] == "error"
    assert result["cleanup"] == [{"kind": "sandbox", "result": "deleted"}]
    assert driver.resources[0].released


def test_provisioning_volume_is_owned_until_it_can_be_deleted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Volumes:
        deleted = False
        reads = 0

        def create(self, name: str) -> Volume:
            del name
            raise RuntimeError("allocation completed before readiness failed")

        def get(self, name: str) -> Volume:
            if self.deleted:
                raise DaytonaNotFoundError("gone")
            self.reads += 1
            return Volume.model_construct(
                name=name,
                state=VolumeState.PENDING_CREATE if self.reads == 1 else VolumeState.READY,
            )

        def delete(self, volume: Volume) -> None:
            assert volume.state == VolumeState.READY
            self.deleted = True

    class Client:
        def __init__(self, config: DaytonaConfig) -> None:
            del config
            self.volume = Volumes()

    monkeypatch.setattr(native, "Daytona", Client)
    monkeypatch.setattr("sandbox_provider_spec.drivers.daytona.time.sleep", lambda seconds: None)
    driver = native.DaytonaDriver("container", {})
    result = Runner(driver).run_test(
        Scenario("volume", "provisioning", ({"op": "volume.create"},), ())
    )
    assert result["result"] == "error"
    assert result["cleanup"] == [{"kind": "volume", "result": "deleted"}]
    assert driver.resources[0].released


def test_native_transition_conflict_is_retried_with_fresh_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Client:
        deleted = False
        reads = 0
        deletes = 0

        def __init__(self, config: DaytonaConfig) -> None:
            del config

        def get(self, identity: str, *, request_timeout: float) -> Sandbox:
            del request_timeout
            self.reads += 1
            if self.deleted:
                raise DaytonaNotFoundError("gone")
            return Sandbox.model_construct(id=identity)

        def delete(self, sandbox: Sandbox, *, timeout: float, wait: bool) -> None:
            del sandbox, timeout, wait
            self.deletes += 1
            if self.deletes == 1:
                raise DaytonaConflictError("native transition")
            self.deleted = True

    monkeypatch.setattr(native, "Daytona", Client)
    monkeypatch.setattr("sandbox_provider_spec.drivers.daytona.time.sleep", lambda seconds: None)
    driver = native.DaytonaDriver("container", {})
    assert driver._delete("owned-name") == {"result": "deleted"}  # pylint: disable=protected-access
    assert driver.client.reads == 3  # type: ignore[attr-defined]
    assert driver.client.deletes == 2  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "message,expected",
    [
        ("Domain network policy cannot be set on this tier", "not_run"),
        ("bad domain syntax", "error"),
    ],
)
def test_domain_policy_refusal_requires_explicit_provider_plan_reason(
    monkeypatch: pytest.MonkeyPatch, message: str, expected: str
) -> None:
    class Client:
        def __init__(self, config: DaytonaConfig) -> None:
            del config

        def create(self, *args: object, **kwargs: object) -> None:
            del args, kwargs
            raise DaytonaBadRequestError(message)

        def get(self, *args: object, **kwargs: object) -> None:
            del args, kwargs
            raise DaytonaNotFoundError("absent")

    monkeypatch.setattr(native, "Daytona", Client)
    result = Runner(native.DaytonaDriver("container", {})).run_test(
        Scenario(
            "domain",
            "tier condition",
            (
                {
                    "op": "create",
                    "in": {
                        "requirements": {
                            "network_lockdown": {
                                "policy": "allowlist_domains",
                                "allow": ["example.com"],
                            }
                        }
                    },
                },
            ),
            (),
        )
    )
    assert result["result"] == expected
    assert result["cleanup"] == [{"kind": "sandbox", "result": "deleted"}]
    if expected == "not_run":
        assert result["reason"] == "account_network_policy_tier_required"


@pytest.mark.parametrize("exit_code", [None, 0])
def test_reattach_reconstructs_a_fresh_native_observer_without_deleting_session(
    monkeypatch: pytest.MonkeyPatch, exit_code: int | None
) -> None:
    events: list[str] = []

    class Process:
        def get_session(self, session: str, *, request_timeout: int) -> SimpleNamespace:
            del request_timeout
            assert session == "native-session"
            events.append("session-get")
            return SimpleNamespace(session_id=session)

        def get_session_command(
            self, session: str, command: str, *, request_timeout: int
        ) -> SimpleNamespace:
            del request_timeout
            assert (session, command) == ("native-session", "native-command")
            events.append("command-get")
            return SimpleNamespace(id=command, exit_code=exit_code)

        def get_session_command_logs(
            self, session: str, command: str, *, request_timeout: int
        ) -> SimpleNamespace:
            del request_timeout
            assert (session, command) == ("native-session", "native-command")
            events.append("logs-get")
            return SimpleNamespace(stdout="after", stderr="")

    class Client:
        def __init__(self, config: DaytonaConfig) -> None:
            assert config.use_deprecated_polling is None
            events.append("client-created")

        def get(self, identity: str, *, request_timeout: int) -> SimpleNamespace:
            del request_timeout
            assert identity == "native-sandbox"
            events.append("sandbox-get")
            return SimpleNamespace(id=identity, process=Process())

    monkeypatch.setattr(native, "Daytona", Client)
    driver = native.DaytonaDriver("container", {})
    parent = cast(Sandbox, SimpleNamespace(id="native-sandbox"))
    box = {"resource": driver.own("sandbox", parent, lambda: {"result": "deleted"})}

    def cleanup() -> dict[str, str]:
        events.append("session-delete")
        return {"result": "deleted"}

    owned = driver.own(
        "process", native.SessionCommand(parent, "native-session", "native-command"), cleanup
    )
    driver.call("process.disconnect", {"resource": owned}, {})
    assert owned.native is None
    assert "session-delete" not in events
    identity = {"session": "native-session", "command": "native-command"}
    if exit_code is not None:
        with pytest.raises(NativeFailure, match="native_process_already_ended"):
            driver.call("process.reattach", box, {"identity": identity})
    else:
        observer = driver.call("process.reattach", box, {"identity": identity})
        assert driver.call("process.output", observer, {}) == {"stdout": "after", "stderr": ""}
        assert "session-delete" not in events
    assert events[:5] == [
        "client-created",
        "client-created",
        "sandbox-get",
        "session-get",
        "command-get",
    ]
    driver.release(owned)
    assert events[-1] == "session-delete"


@pytest.mark.parametrize("finishes,expected_elapsed", [(True, 240), (False, 600)])
def test_capture_source_never_seen_snapshotting_has_a_bounded_cleanup_window(
    monkeypatch: pytest.MonkeyPatch, finishes: bool, expected_elapsed: int
) -> None:
    clock = [0.0]
    deletes: list[float] = []

    class Source:
        id = "owned-capture-source"
        state = "started"
        name = ""

        def create_snapshot(self, name: str, *, timeout: int) -> None:
            del name
            assert timeout == 180
            raise TimeoutError("original native capture timed out")

    class Client:
        deleted = False

        def __init__(self, config: DaytonaConfig) -> None:
            del config

        def create(self, params: CreateSandboxFromSnapshotParams, *, timeout: int) -> Sandbox:
            assert timeout == 60
            assert params.name and params.name != Source.id
            Source.name = params.name
            return cast(Sandbox, Source())

        def get(self, identity: str, *, request_timeout: int) -> Sandbox:
            assert (identity, request_timeout) == (Source.name, 10)
            if self.deleted:
                raise DaytonaNotFoundError("gone")
            state = "started" if finishes and clock[0] >= 240 else "stopping"
            return Sandbox.model_construct(id=Source.id, name=identity, state=state)

        def delete(self, sandbox: Sandbox, *, timeout: int, wait: bool) -> None:
            assert (timeout, wait) == (30, True)
            if sandbox.state != "started":
                raise DaytonaConflictError("native transition")
            deletes.append(clock[0])
            self.deleted = True

    monkeypatch.setattr(native, "Daytona", Client)
    monkeypatch.setattr("sandbox_provider_spec.drivers.daytona.time.monotonic", lambda: clock[0])
    monkeypatch.setattr(
        "sandbox_provider_spec.drivers.daytona.time.sleep",
        lambda seconds: clock.__setitem__(0, clock[0] + seconds),
    )
    driver = native.DaytonaDriver("container", {})
    created = driver.create(None, {"requirements": {"snapshots": {"keeps": "files_only"}}})
    source = driver.resources[0]
    with pytest.raises(TimeoutError):
        driver.call("snapshot.take", created, {"keeps": "files_only"})
    if finishes:
        assert driver.release(source) == {"kind": "sandbox", "result": "deleted"}
        assert source.released
        assert deletes == [240]
        assert clock[0] < 241
        assert Source.id not in driver.capture_sources
    else:
        with pytest.raises(NativeFailure, match="cleanup_not_confirmed"):
            driver.release(source)
        assert not source.released
        assert not deletes
    assert int(clock[0]) == expected_elapsed


def test_non_capture_source_keeps_the_original_cleanup_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [0.0]

    class Client:
        def __init__(self, config: DaytonaConfig) -> None:
            del config

        def get(self, identity: str, *, request_timeout: int) -> Sandbox:
            del request_timeout
            return Sandbox.model_construct(id=identity, state="snapshotting")

        def delete(self, sandbox: Sandbox, *, timeout: int, wait: bool) -> None:
            del sandbox, timeout, wait
            raise DaytonaConflictError("unrelated native transition")

    monkeypatch.setattr(native, "Daytona", Client)
    monkeypatch.setattr("sandbox_provider_spec.drivers.daytona.time.monotonic", lambda: clock[0])
    monkeypatch.setattr(
        "sandbox_provider_spec.drivers.daytona.time.sleep",
        lambda seconds: clock.__setitem__(0, clock[0] + seconds),
    )
    driver = native.DaytonaDriver("container", {})
    with pytest.raises(NativeFailure, match="cleanup_not_confirmed"):
        driver._delete("ordinary-source")  # pylint: disable=protected-access
    assert clock[0] == 120


@pytest.fixture
def snapshot_clock(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    clock = [0.0]
    monkeypatch.setattr("sandbox_provider_spec.drivers.daytona.time.monotonic", lambda: clock[0])
    monkeypatch.setattr(
        "sandbox_provider_spec.drivers.daytona.time.sleep",
        lambda seconds: clock.__setitem__(0, clock[0] + seconds),
    )
    return clock


class SnapshotInventory:
    """Name lookup is unavailable; native ID inventory is authoritative."""

    def __init__(self) -> None:
        self.present = {"foreign-id": Snapshot.model_construct(id="foreign-id", name="foreign")}
        self.deleted: list[str] = []
        self.pages: list[int] = []
        self.refuse_delete = False
        self.incomplete = False

    def create(self, params: CreateSnapshotParams, *, timeout: int) -> Snapshot:
        del timeout
        name = params.name
        artifact = Snapshot.model_construct(id="owned-id", name=name, state="active")
        self.present[artifact.id] = artifact
        return artifact

    def get(self, identity: str) -> Snapshot:
        del identity
        raise DaytonaNotFoundError("name resolution is unavailable")

    def list(self, *, page: int, limit: int) -> PaginatedSnapshots:
        assert limit == 100
        self.pages.append(page)
        items = list(self.present.values())
        # Put the owned object after the first page: checking page one is unsafe.
        pages = max(1, len(items))
        return PaginatedSnapshots.model_construct(
            items=items[page - 1 : page],
            page=page,
            total=len(items) + int(self.incomplete),
            total_pages=pages,
        )

    def delete(self, snapshot: Snapshot | str) -> None:
        if isinstance(snapshot, str):
            self.deleted.append(snapshot)
            raise DaytonaNotFoundError("name or already-deleted ID")
        assert snapshot.id != "foreign-id"
        self.deleted.append(snapshot.id)
        if not self.refuse_delete:
            del self.present[snapshot.id]


def snapshot_driver(
    monkeypatch: pytest.MonkeyPatch, inventory: SnapshotInventory
) -> native.DaytonaDriver:
    monkeypatch.setattr(native, "Daytona", lambda config: SimpleNamespace(snapshot=inventory))
    return native.DaytonaDriver("container", {})


@pytest.mark.parametrize("kind", ["image", "sized_image"])
def test_returned_image_id_survives_broken_name_lookup(
    monkeypatch: pytest.MonkeyPatch, snapshot_clock: list[float], kind: str
) -> None:
    inventory = SnapshotInventory()
    driver = snapshot_driver(monkeypatch, inventory)
    if kind == "image":
        prepared = driver.image_prepare(None, {"source": "oci", "image": "python:3.12-slim"})
        owned = resource(prepared)
    else:
        # Fail sandbox readiness after the sized image has successfully returned.
        with pytest.raises(AttributeError):
            driver.create(None, {"resources": {"cpu_min": 2}})
        owned = driver.resources[0]
    assert owned.native == "owned-id"
    assert driver.release(owned) == {"kind": "image", "result": "deleted"}
    assert inventory.deleted == ["owned-id"]
    assert list(inventory.present) == ["foreign-id"]
    assert 2 in inventory.pages
    assert snapshot_clock[0] < 1


@pytest.mark.parametrize("incomplete", [True, False])
def test_runner_keeps_artifact_unreleased_when_native_absence_is_not_confirmed(
    monkeypatch: pytest.MonkeyPatch, snapshot_clock: list[float], incomplete: bool
) -> None:
    inventory = SnapshotInventory()
    inventory.incomplete = incomplete
    inventory.refuse_delete = True
    driver = snapshot_driver(monkeypatch, inventory)
    result = Runner(driver).run_test(
        Scenario(
            "image",
            "native survivor",
            (
                {
                    "op": "image.prepare",
                    "in": {
                        "source": "oci",
                        "image": "python:3.12-slim",
                    },
                },
            ),
            (),
        )
    )
    assert cast(list[dict[str, object]], result["cleanup"])[0]["result"] == "error"
    assert not driver.resources[0].released
    assert "owned-id" in inventory.present
    assert bool(inventory.deleted) is not incomplete
    # A persistently inconsistent inventory is re-read until the deadline.
    assert snapshot_clock[0] == 30


@pytest.mark.parametrize("source_seconds,published", [(240, True), (600, True), (240, False)])
def test_failed_capture_releases_producer_then_observes_late_native_id(
    monkeypatch: pytest.MonkeyPatch,
    snapshot_clock: list[float],
    source_seconds: int,
    published: bool,
) -> None:
    inventory = SnapshotInventory()
    driver = snapshot_driver(monkeypatch, inventory)
    original_listing = inventory.list
    source_deleted = [False]
    pending: list[Snapshot] = []

    class Source:
        id = "capture-source-id"

        def create_snapshot(self, name: str, *, timeout: int) -> None:
            assert timeout == 180
            # The late artifact is only visible once cleanup has stopped the producer.
            artifact = Snapshot.model_construct(id="owned-id", name=name, state="active")
            pending.append(artifact)
            raise TimeoutError("capture readiness timed out")

    def release_source() -> dict[str, str]:
        snapshot_clock[0] += source_seconds
        source_deleted[0] = True
        return {"result": "deleted"}

    def listing(*, page: int, limit: int) -> PaginatedSnapshots:
        assert source_deleted[0]
        if published and snapshot_clock[0] >= source_seconds + 5:
            for artifact in pending:
                inventory.present[artifact.id] = artifact
            pending.clear()
        return original_listing(page=page, limit=limit)

    monkeypatch.setattr(inventory, "list", listing)
    parent = driver.own("sandbox", Source(), release_source)
    with pytest.raises(TimeoutError):
        driver.snapshot_take({"resource": parent}, {})
    owned = driver.resources[-1]
    if source_seconds == 240 and published:
        assert driver.release(owned) == {"kind": "snapshot", "result": "deleted"}
        assert inventory.deleted == ["owned-id"]
        assert owned.native == "owned-id"
        assert source_seconds + 5 <= snapshot_clock[0] < source_seconds + 6
    else:
        with pytest.raises(NativeFailure, match="cleanup_not_confirmed"):
            driver.release(owned)
        assert not owned.released
        assert inventory.deleted == []
        assert snapshot_clock[0] == 600
    assert parent.released
    assert "foreign-id" in inventory.present


@pytest.mark.parametrize("allocated", [True, False])
def test_failed_image_create_cannot_release_a_never_observed_reservation(
    monkeypatch: pytest.MonkeyPatch, snapshot_clock: list[float], allocated: bool
) -> None:
    inventory = SnapshotInventory()
    driver = snapshot_driver(monkeypatch, inventory)
    original_create = inventory.create

    def late_create(params: CreateSnapshotParams, *, timeout: int) -> Snapshot:
        if allocated:
            original_create(params, timeout=timeout)
        raise TimeoutError("readiness timed out before returning ID")

    monkeypatch.setattr(inventory, "create", late_create)
    result = Runner(driver).run_test(
        Scenario(
            "image",
            "late readiness failure",
            (
                {
                    "op": "image.prepare",
                    "in": {
                        "source": "oci",
                        "image": "python:3.12-slim",
                    },
                },
            ),
            (),
        )
    )
    assert result["result"] == "error"
    document = report(
        driver,
        Suite("sha256:" + "0" * 64, (Scenario("image", "failure", (), ()),)),
        [result],
        spec_revision="0" * 40,
        started_at="2026-09-30T00:00:00+00:00",
    )
    assert document["clean"] is allocated
    if allocated:
        assert result["cleanup"] == [{"kind": "image", "result": "deleted"}]
        assert driver.resources[0].released
        assert snapshot_clock[0] < 1
    else:
        assert cast(list[dict[str, object]], result["cleanup"])[0]["result"] == "error"
        assert not driver.resources[0].released
        assert snapshot_clock[0] == 30
    assert inventory.deleted == (["owned-id"] if allocated else [])
    assert list(inventory.present) == ["foreign-id"]


def test_repeated_snapshot_delete_still_attempts_native_id_operation(
    monkeypatch: pytest.MonkeyPatch, snapshot_clock: list[float]
) -> None:
    del snapshot_clock
    inventory = SnapshotInventory()
    driver = snapshot_driver(monkeypatch, inventory)
    owned, reservation = driver._reserve_snapshot("snapshot", "reserved-name")  # pylint: disable=protected-access
    reservation.returned = True
    inventory.present["owned-id"] = Snapshot.model_construct(id="owned-id", name="reserved-name")
    driver.release(owned)
    assert driver.snapshot_delete_again({"resource": owned}, {}) == {
        "native_delete_attempted": True
    }
    assert inventory.deleted == ["owned-id", "owned-id"]
    assert list(inventory.present) == ["foreign-id"]


def test_inventory_shifted_by_another_run_is_read_again(
    monkeypatch: pytest.MonkeyPatch, snapshot_clock: list[float]
) -> None:
    """The account is shared: a snapshot created or deleted by another run between two
    pages changes the total once, and must not fail this run's cleanup."""

    class Shifting(SnapshotInventory):
        def list(self, *, page: int, limit: int) -> PaginatedSnapshots:
            self.incomplete = len(self.pages) < 2
            return super().list(page=page, limit=limit)

    inventory = Shifting()
    driver = snapshot_driver(monkeypatch, inventory)
    result = Runner(driver).run_test(
        Scenario(
            "image",
            "shared account",
            ({"op": "image.prepare", "in": {"source": "oci", "image": "python:3.12-slim"}},),
            (),
        )
    )
    assert cast(list[dict[str, object]], result["cleanup"])[0]["result"] == "deleted"
    assert "owned-id" not in inventory.present
    assert "foreign-id" in inventory.present
    assert snapshot_clock[0] < 30


@pytest.mark.parametrize(
    "native_state,expected",
    [
        ("started", "active"),
        ("stopped", "stopped"),
        ("destroying", "destroyed"),
        ("destroyed", "destroyed"),
        ("error", "error"),
    ],
)
def test_get_reports_the_suite_state_of_a_native_state(native_state: str, expected: str) -> None:
    class Client:
        def get(self, identity: str, request_timeout: int) -> SimpleNamespace:
            del identity, request_timeout
            return SimpleNamespace(state=SimpleNamespace(value=native_state))

    driver = native.DaytonaDriver.__new__(native.DaytonaDriver)
    driver.client = cast(object, Client())  # type: ignore[assignment]
    target = {"resource": Resource("sandbox", SimpleNamespace(id="sandbox-1"), lambda: {})}
    assert driver.get(target, {}) == {"state": expected}
