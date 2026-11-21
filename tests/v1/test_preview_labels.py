# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Preview access and revocation, and label updates: the tester's driver and its selection."""

from __future__ import annotations

import dataclasses
import json
from collections.abc import AsyncIterable, Mapping
from pathlib import Path
from typing import Any, ClassVar, TypeVar

import pytest

from sandbox_provider_spec.driver import NativeFailure, Unsupported, resource
from sandbox_provider_spec.v1 import (
    CreateRequest,
    CredentialField,
    DestroyResult,
    Discovery,
    FileInfo,
    FileStream,
    OutputPage,
    PreviewAccess,
    PreviewLink,
    Process,
    ProcessStartRequest,
    Provider,
    RunRequest,
    RunResult,
    Sandbox,
    SandboxPage,
    SpsError,
    from_json,
)
from sandbox_provider_spec.v1.suite_driver import RUN_LABEL, ProviderDriver
from sandbox_provider_spec.v1.tester import (
    TestOptions,
    claimed_sections,
    select_tests,
    shared_suite,
    unsupported_operations,
)

EXAMPLES = Path(__file__).resolve().parents[2] / "spec" / "provider-api-1.0-examples"
T = TypeVar("T")


def example(cls: type[T]) -> T:
    return from_json(cls, json.loads((EXAMPLES / f"{cls.__name__}.json").read_text("utf-8")))


class Recording(Provider, manifest=False):
    """Keeps sandboxes, links and labels in memory; every call is recorded."""

    provider_id = "recording"
    name = "Recording"
    spec_version = "1.0"
    credential_fields: ClassVar[tuple[CredentialField, ...]] = (CredentialField("api_key"),)

    def __init__(self) -> None:
        super().__init__({"api_key": "k"})
        self.boxes: dict[str, Sandbox] = {}
        self.links: dict[str, str] = {}
        self.calls: list[tuple[str, tuple[Any, ...]]] = []
        self.revocable = True

    async def discovery(self) -> Discovery:
        return example(Discovery)

    async def create(self, request: CreateRequest, *, idempotency_key: str) -> Sandbox:
        box = dataclasses.replace(
            example(Sandbox), id=f"box-{len(self.boxes) + 1}", labels=dict(request.labels)
        )
        self.boxes[box.id] = box
        return box

    async def get(self, sandbox_id: str) -> Sandbox:
        if sandbox_id not in self.boxes:
            raise SpsError("not_found", "no such sandbox")
        return self.boxes[sandbox_id]

    async def list(
        self,
        *,
        labels: Mapping[str, str] | None = None,
        cursor: str | None = None,
        limit: int = 100,
    ) -> SandboxPage:
        found = [
            box
            for box in self.boxes.values()
            if all(box.labels.get(key) == value for key, value in (labels or {}).items())
        ]
        return SandboxPage(sandboxes=found, next_cursor=None)

    async def destroy(self, sandbox_id: str) -> DestroyResult:
        await self.get(sandbox_id)
        del self.boxes[sandbox_id]
        return DestroyResult(sandbox_id=sandbox_id, state="destroyed")

    async def run(self, sandbox_id: str, request: RunRequest) -> RunResult:
        raise NotImplementedError

    async def files_read(self, sandbox_id: str, path: str) -> FileStream:
        raise NotImplementedError

    async def files_write(
        self,
        sandbox_id: str,
        path: str,
        data: AsyncIterable[bytes],
        *,
        size: int,
        user: str | None = None,
    ) -> FileInfo:
        raise NotImplementedError

    async def process_start(self, sandbox_id: str, request: ProcessStartRequest) -> Process:
        raise NotImplementedError

    async def process_output(
        self, sandbox_id: str, process_id: str, *, cursor: str | None = None, wait_ms: int = 0
    ) -> OutputPage:
        raise NotImplementedError

    async def preview_link(
        self,
        sandbox_id: str,
        port: int,
        *,
        access: PreviewAccess = "public",
        lifetime_seconds: int | None = None,
    ) -> PreviewLink:
        await self.get(sandbox_id)
        self.calls.append(("preview_link", (sandbox_id, port, access, lifetime_seconds)))
        link_id = f"prv-{len(self.links) + 1}" if self.revocable else None
        if link_id is not None:
            self.links[link_id] = sandbox_id
        return dataclasses.replace(
            example(PreviewLink),
            id=link_id,
            access=access,
            credential="header" if access == "private" else None,
        )

    async def preview_revoke(self, sandbox_id: str, preview_id: str) -> None:
        await self.get(sandbox_id)
        self.calls.append(("preview_revoke", (sandbox_id, preview_id)))
        self.links.pop(preview_id, None)  # an id that is already gone succeeds

    async def labels_update(self, sandbox_id: str, labels: Mapping[str, str]) -> Sandbox:
        box = await self.get(sandbox_id)
        merged = {**box.labels, **labels}
        box = dataclasses.replace(box, labels={k: v for k, v in merged.items() if v != ""})
        self.boxes[sandbox_id] = box
        return box


@pytest.fixture(name="driver")
def driver_fixture() -> Any:
    driver = ProviderDriver(Recording(), run="run-1")
    yield driver
    driver.close()


def test_the_driver_sends_access_and_lifetime_only_when_a_test_names_them(
    driver: ProviderDriver,
) -> None:
    box = driver.call("create", None, {})
    plain = driver.call("preview.link", box, {"port": 3000})
    private = driver.call(
        "preview.link",
        box,
        {"port": 3001, "access": "private", "credential": "header", "lifetime_seconds": 60},
    )
    calls = driver.api.calls  # type: ignore[attr-defined]
    assert calls == [
        ("preview_link", ("box-1", 3000, "public", None)),
        ("preview_link", ("box-1", 3001, "private", 60)),
    ]
    assert (plain["access"], plain["credential"]) == ("public", None)
    assert (private["access"], private["credential"]) == ("private", "header")
    with pytest.raises(ValueError, match="access"):
        driver.call("preview.link", box, {"port": 3000, "access": "secret"})


def test_preview_revoke_names_the_link_by_its_id(driver: ProviderDriver) -> None:
    box = driver.call("create", None, {})
    first = driver.call("preview.link", box, {"port": 3000})
    driver.call("preview.link", box, {"port": 3001})
    assert driver.call("preview.revoke", first, {}) == {}
    assert driver.api.links == {"prv-2": "box-1"}  # type: ignore[attr-defined]
    assert driver.call("preview.revoke", first, {}) == {}  # revoking again is success


def test_a_link_without_an_id_cannot_be_revoked_and_needs_no_cleanup(
    driver: ProviderDriver,
) -> None:
    driver.api.revocable = False  # type: ignore[attr-defined]
    box = driver.call("create", None, {})
    link = driver.call("preview.link", box, {"port": 3000})
    with pytest.raises(Unsupported):
        driver.call("preview.revoke", link, {})
    assert driver.release(resource(link)) == {"kind": "preview", "result": "deleted"}


def test_the_run_revokes_the_links_it_made_and_survives_a_destroyed_sandbox(
    driver: ProviderDriver,
) -> None:
    box = driver.call("create", None, {})
    link = driver.call("preview.link", box, {"port": 3000})
    driver.call("destroy", box, {})  # the sandbox goes first; the link's cleanup finds nothing
    assert driver.release(resource(link)) == {"kind": "preview", "result": "deleted"}
    # The fake answers `not_found` before it records a revoke, as a provider with no sandbox does.
    assert [name for name, _ in driver.api.calls] == ["preview_link"]  # type: ignore[attr-defined]


def test_a_failing_revoke_other_than_not_found_is_reported(driver: ProviderDriver) -> None:
    box = driver.call("create", None, {})
    link = driver.call("preview.link", box, {"port": 3000})

    async def refuse(sandbox_id: str, preview_id: str) -> None:
        raise SpsError("forbidden", "no")

    driver.api.preview_revoke = refuse  # type: ignore[method-assign]
    with pytest.raises(NativeFailure) as raised:
        driver.call("preview.revoke", link, {})
    assert raised.value.code == "forbidden"


def test_labels_update_reports_the_labels_without_the_runs_own(driver: ProviderDriver) -> None:
    box = driver.call("create", None, {"labels": {"keep": "1", "change": "a", "drop": "x"}})
    seen = driver.call("labels.update", box, {"labels": {"change": "b", "drop": "", "add": "2"}})
    assert seen == {"labels": {"keep": "1", "change": "b", "add": "2"}}
    assert driver.call("get", box, {})["labels"] == seen["labels"]
    assert RUN_LABEL in driver.api.boxes["box-1"].labels  # type: ignore[attr-defined]
    found = driver.call("list", None, {"labels": {"change": "b"}})
    assert found["count"] == 1


def discovery_with(
    gates: Mapping[str, object] | None = None, operations: tuple[str, ...] = ()
) -> Discovery:
    discovery = example(Discovery)
    first = dataclasses.replace(
        discovery.classes[0], gates=dict(gates or {}), operations=operations
    )
    return dataclasses.replace(discovery, classes=[first, *discovery.classes[1:]])


def test_labels_update_and_preview_revoke_follow_the_claims() -> None:
    nothing = unsupported_operations(discovery_with())
    assert {"labels.update", "preview.revoke", "preview.link"} <= set(nothing)
    revocable = unsupported_operations(
        discovery_with({"previews": [{"access": ["public"], "revocable": True}]})
    )
    assert "preview.link" not in revocable and "preview.revoke" not in revocable
    plain = unsupported_operations(
        discovery_with({"previews": [{"access": ["public"], "revocable": False}]})
    )
    assert "preview.link" not in plain and "preview.revoke" in plain
    labelled = unsupported_operations(discovery_with(operations=("labels.update",)))
    assert "labels.update" not in labelled


def test_the_labels_section_needs_only_labels_update_and_directories_all_four() -> None:
    assert claimed_sections(discovery_with(operations=("labels.update",))) == ["labels"]
    four = ("files.list", "files.mkdir", "files.remove", "files.exists")
    assert claimed_sections(discovery_with(operations=four)) == ["directories"]
    assert claimed_sections(discovery_with(operations=(*four, "labels.update"))) == [
        "directories",
        "labels",
    ]
    assert claimed_sections(discovery_with(operations=("files.list", "labels.update"))) == [
        "labels"
    ]


def test_the_labels_test_runs_only_for_a_class_that_lists_the_operation() -> None:
    suite = shared_suite()
    off = {t.id for t in select_tests(suite, discovery_with(), TestOptions()).tests}
    on = {
        t.id
        for t in select_tests(
            suite, discovery_with(operations=("labels.update",)), TestOptions()
        ).tests
    }
    assert "labels.update" not in off
    assert "labels.update" in on


def test_a_private_link_gets_the_unauthenticated_url_the_suite_probes(
    driver: ProviderDriver,
) -> None:
    box = driver.call("create", None, {})
    public = driver.call("preview.link", box, {"port": 3000})
    header = driver.call("preview.link", box, {"port": 3001, "access": "private"})
    assert "unauthorized_url" not in public
    assert header["unauthorized_url"] == header["url"]  # the credential is in the headers

    async def with_link_credential(sandbox_id: str, port: int, **options: Any) -> PreviewLink:
        return dataclasses.replace(
            example(PreviewLink),
            url="https://p-3000.example.test/app?token=SECRET&x=1#frag",
            access="private",
            credential="link",
        )

    driver.api.preview_link = with_link_credential  # type: ignore[method-assign]
    link = driver.call("preview.link", box, {"port": 3002, "access": "private"})
    assert link["unauthorized_url"] == "https://p-3000.example.test/app"
    assert "SECRET" not in str(link["unauthorized_url"])
