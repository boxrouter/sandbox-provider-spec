# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Deleting a snapshot must resolve a fresh Image lookup, not a lazy handle."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from types import SimpleNamespace
from typing import cast

import modal
import pytest
from modal.exception import ImageBuildError, InvalidError, NotFoundError

from sandbox_provider_spec.driver import Inputs, NativeFailure, NotRun, Observation
from sandbox_provider_spec.drivers import modal as native
from sandbox_provider_spec.runner import Runner
from sandbox_provider_spec.suite import Test as Scenario


def test_preview_block_all_incompatibility_is_rejected_before_app_allocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_app() -> None:
        raise AssertionError("must not allocate an App")

    monkeypatch.setattr(modal, "App", unexpected_app)
    result = Runner(native.ModalDriver()).run_test(
        Scenario(
            "combination",
            "native conflict",
            (
                {
                    "op": "create",
                    "in": {
                        "requirements": {
                            "previews": {"access": "public", "ports": [3000]},
                            "network_lockdown": {"policy": "deny_all"},
                        }
                    },
                },
            ),
            (),
        )
    )
    assert result["result"] == "unsupported" and result["cleanup"] == []


@pytest.mark.parametrize("missing", [True, False])
def test_remote_volume_read_translates_only_native_missing_file(missing: bool) -> None:
    class Volume:
        def read_file(self, path: str) -> Iterator[bytes]:
            assert path == "/marker"
            if missing:
                raise FileNotFoundError("native response")
            yield b"mark"
            yield b"er"

    driver = native.ModalDriver()
    owned = driver.own("volume", Volume(), lambda: {"result": "deleted"})
    result = driver.volume_read_bytes({"resource": owned}, {"path": "/marker"})
    if missing:
        assert result == {"exists": False}
    else:
        assert result == {"exists": True, "data": b"marker"}


def test_snapshot_cleanup_confirms_absence(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def delete(image_id: str) -> None:
        calls.append(f"delete:{image_id}")

    def resolve(image: modal.Image, app: modal.App) -> modal.Image:
        del app
        assert isinstance(image, modal.Image)
        calls.append("resolve")
        raise NotFoundError("gone")

    monkeypatch.setattr(native, "image_delete", delete)
    # Keep the SDK's real lazy from_id handle. Mocking that constructor hid the
    # SDK's refusal to hydrate it without an App build context.
    monkeypatch.setattr(modal.Image, "build", resolve)
    app = cast(modal.App, SimpleNamespace(app_id="ap-test"))
    result = native.ModalDriver._delete_image("example", app)  # pylint: disable=protected-access
    assert result == {"result": "deleted"}
    assert calls == ["delete:example", "resolve"]


def test_snapshot_cleanup_refuses_unconfirmed_deletion(monkeypatch: pytest.MonkeyPatch) -> None:
    def resolve(image: modal.Image, app: modal.App) -> modal.Image:
        del app
        return image

    times = iter([0.0, 31.0])
    monkeypatch.setattr(native, "image_delete", lambda image_id: None)
    monkeypatch.setattr(modal.Image, "build", resolve)
    monkeypatch.setattr("sandbox_provider_spec.drivers.modal.time.monotonic", lambda: next(times))
    app = cast(modal.App, SimpleNamespace(app_id="ap-test"))
    with pytest.raises(NativeFailure, match="^cleanup_not_confirmed$"):
        native.ModalDriver._delete_image("example", app)  # pylint: disable=protected-access


def test_cleanup_lookup_owns_a_context_after_the_original_app_ended(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    lookup_app = cast(modal.App, SimpleNamespace(app_id="ap-lookup"))

    class LookupContext:
        @staticmethod
        @contextmanager
        def run() -> Iterator[modal.App]:
            events.append("start")
            try:
                yield lookup_app
            finally:
                events.append("end")

    def resolve(image: modal.Image, app: modal.App) -> modal.Image:
        del image
        assert app is lookup_app
        assert events == ["start"]
        raise NotFoundError("gone")

    monkeypatch.setattr(native, "image_delete", lambda image_id: None)
    monkeypatch.setattr(modal.Image, "build", resolve)
    monkeypatch.setattr(modal, "App", LookupContext)
    ended = cast(modal.App, SimpleNamespace(app_id=None))
    result = native.ModalDriver._delete_image("example", ended)  # pylint: disable=protected-access
    assert result == {"result": "deleted"}
    assert events == ["start", "end"]


def test_failed_memory_snapshot_is_not_omitted_from_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Parent:
        @staticmethod
        def _experimental_snapshot() -> object:
            raise RuntimeError("readiness failed after native allocation")

    class Driver(native.ModalDriver):
        def create(self, target: object, inputs: Inputs) -> Observation:
            del target, inputs
            return {"resource": self.own("sandbox", object(), lambda: {"result": "deleted"})}

    def parent(target: object) -> modal.Sandbox:
        assert isinstance(target, Mapping)
        return cast(modal.Sandbox, Parent())

    monkeypatch.setattr(native, "box", parent)
    result = Runner(Driver()).run_test(
        Scenario(
            "snapshot",
            "readiness failure",
            (
                {"op": "create", "as": "box"},
                {"op": "snapshot.take", "target": "box", "in": {"keeps": "files_and_memory"}},
            ),
            (),
        )
    )
    assert result["result"] == "error"
    assert result["cleanup"] == [
        {"kind": "memory_snapshot_attempt", "result": "error", "reason": "NativeFailure"},
        {"kind": "sandbox", "result": "deleted"},
    ]


def test_failed_create_reconciles_only_its_own_application(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    present = False

    @contextmanager
    def session() -> Iterator[SimpleNamespace]:
        yield SimpleNamespace(app_id="own-application")

    class Sandbox:
        @staticmethod
        def create(**options: object) -> None:
            nonlocal present
            assert options["app"].app_id == "own-application"  # type: ignore[attr-defined]
            present = True
            raise RuntimeError("readiness failed after allocation")

        @staticmethod
        def list(*, app_id: str) -> Iterator[Sandbox]:
            assert app_id == "own-application"
            if present:
                yield Sandbox()

        @staticmethod
        def terminate(*, wait: bool) -> None:
            nonlocal present
            assert not wait
            present = False

        @staticmethod
        def poll() -> int:
            return 0

    monkeypatch.setattr(modal, "App", lambda *_name: SimpleNamespace(run=session))
    monkeypatch.setattr(modal, "Sandbox", Sandbox)
    result = Runner(native.ModalDriver()).run_test(
        Scenario("create", "failed readiness", ({"op": "create"},), ())
    )
    assert result["result"] == "error"
    assert result["cleanup"] == [
        {"kind": "sandbox", "result": "deleted"},
        {"kind": "application_session", "result": "deleted"},
    ]
    assert not present


def test_native_dockerfile_dependency_is_owned_before_a_child_build_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    deleted: list[str] = []
    built: list[str] = []

    class Image:
        def __init__(self, identity: str, parent: Image | None = None) -> None:
            self.object_id = identity
            self.parent = parent

        def _deps_(self) -> list[Image]:
            return [self.parent] if self.parent is not None else []

        def build(self, app: object) -> None:
            del app
            built.append(self.object_id)
            if self.parent is not None:
                raise ImageBuildError("native child build failed", self.object_id)

    parent = Image("base")
    child = Image("child", parent)
    monkeypatch.setattr(modal, "Image", Image)

    def delete(identity: str, app: object) -> Observation:
        del app
        deleted.append(identity)
        return {"result": "deleted"}

    monkeypatch.setattr(
        native.ModalDriver,
        "_delete_image",
        staticmethod(delete),
    )

    class Driver(native.ModalDriver):
        def create(self, target: object, inputs: Inputs) -> Observation:
            del target, inputs
            self._build_owned_image(cast(modal.Image, child), modal.App())
            return {}

    result = Runner(Driver()).run_test(
        Scenario("build", "failed native child build", ({"op": "create"},), ())
    )
    assert result["result"] == "error"
    assert built == ["base", "child"]
    assert deleted == ["child", "base"]
    assert result["cleanup"] == [
        {"kind": "image", "result": "deleted"},
        {"kind": "image", "result": "deleted"},
    ]


def test_unobservable_allocation_is_not_run_and_sandbox_is_deleted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class AllocatedDriver(native.ModalDriver):
        def create(self, target: object, inputs: Inputs) -> Observation:
            del target, inputs
            return {
                "resource": self.own(
                    "sandbox", SimpleNamespace(object_id="own"), lambda: {"result": "deleted"}
                )
            }

    test = Scenario(
        "allocation",
        "Native allocation metadata",
        (
            {"op": "create", "as": "box"},
            {"op": "allocation.observe", "target": "box"},
        ),
        (),
    )
    result = Runner(AllocatedDriver()).run_test(test)
    assert result["result"] == "not_run"
    assert result["reason"] == "native_allocation_metadata_unobservable"
    assert result["proves"] == []
    assert result["cleanup"] == [{"kind": "sandbox", "result": "deleted"}]


def test_idle_observation_is_not_run_without_sdk_query(monkeypatch: pytest.MonkeyPatch) -> None:
    del monkeypatch
    with pytest.raises(NotRun, match="native_idle_configuration_unobservable"):
        native.ModalDriver().long_running_observe({}, {"idle_disabled": True})


@pytest.mark.parametrize(
    "message,expected",
    [
        ("Sandbox GPU T4 requires a payment method", "not_run"),
        ("invalid GPU configuration", "error"),
    ],
)
def test_only_explicit_gpu_payment_refusal_confirms_no_allocation(
    monkeypatch: pytest.MonkeyPatch, message: str, expected: str
) -> None:
    @contextmanager
    def session() -> Iterator[SimpleNamespace]:
        yield SimpleNamespace(app_id="owned-app")

    def create(**kwargs: object) -> None:
        del kwargs
        raise InvalidError(message)

    monkeypatch.setattr(modal, "App", lambda *_name: SimpleNamespace(run=session))
    monkeypatch.setattr(modal.Sandbox, "create", create)
    monkeypatch.setattr(modal.Sandbox, "list", lambda **kwargs: iter(()))
    result = Runner(native.ModalDriver()).run_test(
        Scenario(
            "gpu",
            "refused",
            ({"op": "create", "in": {"resources": {"gpu_model": ["nvidia:t4"]}}},),
            (),
        )
    )
    assert result["result"] == expected
    cleanup = result["cleanup"]
    assert isinstance(cleanup, list)
    assert cleanup[0]["result"] == ("already_released" if expected == "not_run" else "error")
    if expected == "not_run":
        assert result["reason"] == "account_gpu_payment_method_required"
