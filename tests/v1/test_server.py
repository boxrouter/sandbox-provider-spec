# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The reference server: routes, strict bodies, error mapping, tokens, streaming and the pool."""

from __future__ import annotations

import asyncio
import json
import socket
import threading
import time
from collections.abc import AsyncIterable, AsyncIterator, Mapping, MutableMapping
from datetime import datetime
from pathlib import Path
from typing import Any, ClassVar, TypeVar

import pytest

from sandbox_provider_spec.cli import main
from sandbox_provider_spec.v1 import (
    AccountCost,
    Cost,
    CreateRequest,
    CredentialField,
    DestroyResult,
    DirectoryEntry,
    DirectoryPage,
    Discovery,
    FileInfo,
    FileLink,
    FileLinkRequest,
    FileStream,
    OutputPage,
    PathInfo,
    PreviewAccess,
    PreviewLink,
    Process,
    ProcessStartRequest,
    Provider,
    RunRequest,
    RunResult,
    Sandbox,
    SandboxPage,
    Snapshot,
    SnapshotDeleteResult,
    SnapshotPage,
    SnapshotRequest,
    SpsError,
    TcpLink,
    from_json,
    to_json,
)
from sandbox_provider_spec.v1.server import create_app
from sandbox_provider_spec.v1.tokens import encode

EXAMPLES = Path(__file__).resolve().parents[2] / "spec" / "provider-api-1.0-examples"
T = TypeVar("T")
MIB = 1024 * 1024
BEARER = "tok-abcdef"
IDEM = "key-12345678"


def example(cls: type[T]) -> T:
    data = json.loads((EXAMPLES / f"{cls.__name__}.json").read_text(encoding="utf-8"))
    return from_json(cls, data)


class Recorder(Provider, manifest=False):
    """Records every call and answers with the OpenAPI examples."""

    provider_id = "recorder"
    name = "Recorder"
    spec_version = "1.0"
    credential_fields: ClassVar[tuple[CredentialField, ...]] = (CredentialField("api_key"),)
    constructed: list[Mapping[str, str]] = []
    closed: list[Mapping[str, str]] = []
    calls: list[tuple[str, tuple[Any, ...]]] = []
    explode: BaseException | None = None
    upload_chunks: list[int] = []

    def __init__(self, credentials: Mapping[str, str]) -> None:
        super().__init__(credentials)
        type(self).constructed.append(dict(self.credentials))

    async def aclose(self) -> None:
        type(self).closed.append(dict(self.credentials))

    def _note(self, name: str, *args: Any) -> None:
        type(self).calls.append((name, args))
        failure = type(self).explode
        if failure is not None:
            raise failure

    async def discovery(self) -> Discovery:
        self._note("discovery")
        return example(Discovery)

    async def create(self, request: CreateRequest, *, idempotency_key: str) -> Sandbox:
        self._note("create", request, idempotency_key)
        return example(Sandbox)

    async def get(self, sandbox_id: str) -> Sandbox:
        self._note("get", sandbox_id)
        return example(Sandbox)

    async def list(
        self,
        *,
        labels: Mapping[str, str] | None = None,
        cursor: str | None = None,
        limit: int = 100,
    ) -> SandboxPage:
        self._note("list", labels, cursor, limit)
        return example(SandboxPage)

    async def destroy(self, sandbox_id: str) -> DestroyResult:
        self._note("destroy", sandbox_id)
        return example(DestroyResult)

    async def run(self, sandbox_id: str, request: RunRequest) -> RunResult:
        self._note("run", sandbox_id, request)
        return example(RunResult)

    async def files_read(self, sandbox_id: str, path: str) -> FileStream:
        self._note("files_read", sandbox_id, path)

        async def chunks() -> AsyncIterator[bytes]:
            yield b"hello "
            yield b"world"

        return FileStream(size=11, chunks=chunks())

    async def files_write(  # type: ignore[override]  # an older provider: no `user`
        self, sandbox_id: str, path: str, data: AsyncIterable[bytes], *, size: int
    ) -> FileInfo:
        self._note("files_write", sandbox_id, path, size)
        sizes = type(self).upload_chunks = []
        async for chunk in data:
            sizes.append(len(chunk))
        return FileInfo(path, sum(sizes))

    async def process_start(self, sandbox_id: str, request: ProcessStartRequest) -> Process:
        self._note("process_start", sandbox_id, request)
        return example(Process)

    async def process_output(
        self, sandbox_id: str, process_id: str, *, cursor: str | None = None, wait_ms: int = 0
    ) -> OutputPage:
        self._note("process_output", sandbox_id, process_id, cursor, wait_ms)
        return example(OutputPage)

    async def cost(self, sandbox_id: str, *, created_at: datetime | None = None) -> Cost:
        self._note("cost", sandbox_id, created_at)
        return example(Cost)

    async def account_cost(self, start: datetime, end: datetime) -> AccountCost:
        self._note("account_cost", start, end)
        return example(AccountCost)

    async def files_link(self, sandbox_id: str, request: FileLinkRequest) -> FileLink:
        self._note("files_link", sandbox_id, request)
        return example(FileLink)

    async def pause(self, sandbox_id: str) -> Sandbox | None:
        self._note("pause", sandbox_id)
        return example(Sandbox)

    async def resume(self, sandbox_id: str) -> Sandbox | None:
        self._note("resume", sandbox_id)
        return example(Sandbox)

    async def lifetime_extend(self, sandbox_id: str, seconds: int) -> Sandbox | None:
        self._note("lifetime_extend", sandbox_id, seconds)
        return example(Sandbox)

    async def process_write_stdin(self, sandbox_id: str, process_id: str, data: bytes) -> None:
        self._note("process_write_stdin", sandbox_id, process_id, data)

    async def process_close_stdin(self, sandbox_id: str, process_id: str) -> None:
        self._note("process_close_stdin", sandbox_id, process_id)

    async def process_cancel(self, sandbox_id: str, process_id: str) -> None:
        self._note("process_cancel", sandbox_id, process_id)

    async def preview_link(
        self,
        sandbox_id: str,
        port: int,
        *,
        access: PreviewAccess = "public",
        lifetime_seconds: int | None = None,
    ) -> PreviewLink:
        self._note("preview_link", sandbox_id, port, access, lifetime_seconds)
        return example(PreviewLink)

    async def preview_revoke(self, sandbox_id: str, preview_id: str) -> None:
        self._note("preview_revoke", sandbox_id, preview_id)

    async def labels_update(self, sandbox_id: str, labels: Mapping[str, str]) -> Sandbox:
        self._note("labels_update", sandbox_id, dict(labels))
        return example(Sandbox)

    async def network_update(
        self, sandbox_id: str, policy: str, *, allow: Any = (), deny: Any = ()
    ) -> None:
        self._note("network_update", sandbox_id, policy, list(allow), list(deny))

    async def terminal_end(self, sandbox_id: str, terminal_id: str) -> None:
        self._note("terminal_end", sandbox_id, terminal_id)

    async def tcp_link(self, sandbox_id: str, port: int) -> TcpLink:
        self._note("tcp_link", sandbox_id, port)
        return example(TcpLink)

    async def files_list(
        self, sandbox_id: str, path: str, *, cursor: str | None = None, limit: int = 100
    ) -> DirectoryPage:
        self._note("files_list", sandbox_id, path, cursor, limit)
        return DirectoryPage((DirectoryEntry("a", "file", 1),), None)

    async def files_mkdir(self, sandbox_id: str, path: str, *, parents: bool = False) -> None:
        self._note("files_mkdir", sandbox_id, path, parents)

    async def files_remove(self, sandbox_id: str, path: str, *, recursive: bool = False) -> None:
        self._note("files_remove", sandbox_id, path, recursive)

    async def files_exists(self, sandbox_id: str, path: str) -> PathInfo:
        self._note("files_exists", sandbox_id, path)
        return example(PathInfo)

    async def snapshot_create(
        self, sandbox_id: str, request: SnapshotRequest, *, idempotency_key: str
    ) -> Snapshot:
        self._note("snapshot_create", sandbox_id, request, idempotency_key)
        return example(Snapshot)

    async def snapshot_get(self, snapshot_id: str) -> Snapshot:
        self._note("snapshot_get", snapshot_id)
        return example(Snapshot)

    async def snapshot_list(
        self,
        *,
        labels: Mapping[str, str] | None = None,
        sandbox_id: str | None = None,
        cursor: str | None = None,
        limit: int = 100,
    ) -> SnapshotPage:
        self._note("snapshot_list", labels, sandbox_id, cursor, limit)
        return example(SnapshotPage)

    async def snapshot_delete(self, snapshot_id: str) -> SnapshotDeleteResult:
        self._note("snapshot_delete", snapshot_id)
        return example(SnapshotDeleteResult)

    async def snapshot_cost(self, snapshot_id: str) -> Cost:
        self._note("snapshot_cost", snapshot_id)
        return example(Cost)


class TwoFields(Recorder, manifest=False):
    provider_id = "two"
    credential_fields = (CredentialField("key_id"), CredentialField("secret"))
    constructed: list[Mapping[str, str]] = []
    closed: list[Mapping[str, str]] = []
    calls: list[tuple[str, tuple[Any, ...]]] = []


@pytest.fixture(autouse=True)
def reset() -> None:
    for cls in (Recorder, TwoFields):
        cls.constructed, cls.closed, cls.calls = [], [], []
        cls.explode = None
        cls.upload_chunks = []


class Reply:
    def __init__(self) -> None:
        self.status = 0
        self.headers: dict[str, str] = {}
        self.body = bytearray()
        self.parts: list[int] = []
        self.finished = False

    def json(self) -> Any:
        return json.loads(bytes(self.body))


async def call(
    app: Any,
    method: str,
    path: str,
    *,
    body: bytes | list[bytes] | AsyncIterator[bytes] = b"",
    token: str | None = BEARER,
    headers: dict[str, str] | None = None,
    query: str = "",
    length: int | None = None,
) -> Reply:
    """Drive the ASGI app directly, so that the chunks of a body are exactly the ones given."""
    parts: AsyncIterator[bytes]
    if isinstance(body, bytes):
        parts = _once([body])
    elif isinstance(body, list):
        parts = _once(body)
    else:
        parts = body
    raw: list[tuple[bytes, bytes]] = []
    if token is not None:
        raw.append((b"authorization", f"Bearer {token}".encode()))
    for name, value in (headers or {}).items():
        raw.append((name.lower().encode(), value.encode()))
    if length is not None:
        raw.append((b"content-length", str(length).encode()))
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "query_string": query.encode(),
        "headers": raw,
    }
    pending: Any = None

    async def receive() -> dict[str, Any]:
        nonlocal pending
        if pending is None:
            pending = await anext(parts, None)
        current = pending
        if current is None:
            return {"type": "http.disconnect"}
        pending = await anext(parts, None)
        return {"type": "http.request", "body": current, "more_body": pending is not None}

    reply = Reply()

    async def send(message: dict[str, Any]) -> None:
        if message["type"] == "http.response.start":
            reply.status = message["status"]
            reply.headers = {k.decode(): v.decode() for k, v in message["headers"]}
        else:
            reply.body += message.get("body", b"")
            reply.parts.append(len(message.get("body", b"")))
            reply.finished = not message.get("more_body", False)

    await app(scope, receive, send)
    return reply


async def _once(items: list[bytes]) -> AsyncIterator[bytes]:
    for item in items:
        yield item


def j(value: Any) -> bytes:
    return json.dumps(value).encode()


def request_json(name: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((EXAMPLES / f"{name}.json").read_text(encoding="utf-8"))
    return data


ROUTES: list[tuple[str, str, str, Any, str]] = [
    # (operation, method, path, body or query marker, Provider method that must be called)
    ("discovery", "GET", "/v1/discovery", None, "discovery"),
    ("create", "POST", "/v1/sandboxes", request_json("CreateRequest"), "create"),
    ("list", "GET", "/v1/sandboxes", None, "list"),
    ("get", "GET", "/v1/sandboxes/sbx-1", None, "get"),
    ("destroy", "DELETE", "/v1/sandboxes/sbx-1", None, "destroy"),
    ("run", "POST", "/v1/sandboxes/sbx-1/run", request_json("RunRequest"), "run"),
    ("files_read", "GET", "/v1/sandboxes/sbx-1/files", None, "files_read"),
    ("files_write", "PUT", "/v1/sandboxes/sbx-1/files", b"abc", "files_write"),
    (
        "process_start",
        "POST",
        "/v1/sandboxes/sbx-1/processes",
        request_json("ProcessStartRequest"),
        "process_start",
    ),
    ("process_output", "GET", "/v1/sandboxes/sbx-1/processes/p-1/output", None, "process_output"),
    ("cost", "GET", "/v1/sandboxes/sbx-1/cost", None, "cost"),
    (
        "files_link",
        "POST",
        "/v1/sandboxes/sbx-1/file-links",
        request_json("FileLinkRequest"),
        "files_link",
    ),
    ("files_list", "GET", "/v1/sandboxes/sbx-1/directories", None, "files_list"),
    (
        "files_mkdir",
        "POST",
        "/v1/sandboxes/sbx-1/directories",
        request_json("MkdirRequest"),
        "files_mkdir",
    ),
    ("files_remove", "DELETE", "/v1/sandboxes/sbx-1/files", None, "files_remove"),
    ("files_exists", "GET", "/v1/sandboxes/sbx-1/files/exists", None, "files_exists"),
    ("pause", "POST", "/v1/sandboxes/sbx-1/pause", {}, "pause"),
    ("resume", "POST", "/v1/sandboxes/sbx-1/resume", {}, "resume"),
    (
        "lifetime_extend",
        "POST",
        "/v1/sandboxes/sbx-1/lifetime",
        request_json("LifetimeExtendRequest"),
        "lifetime_extend",
    ),
    (
        "process_write_stdin",
        "POST",
        "/v1/sandboxes/sbx-1/processes/p-1/stdin",
        b"input",
        "process_write_stdin",
    ),
    (
        "process_close_stdin",
        "DELETE",
        "/v1/sandboxes/sbx-1/processes/p-1/stdin",
        None,
        "process_close_stdin",
    ),
    ("process_cancel", "POST", "/v1/sandboxes/sbx-1/processes/p-1/cancel", {}, "process_cancel"),
    (
        "preview_link",
        "POST",
        "/v1/sandboxes/sbx-1/previews",
        request_json("PreviewRequest"),
        "preview_link",
    ),
    ("preview_revoke", "DELETE", "/v1/sandboxes/sbx-1/previews/prv-1", None, "preview_revoke"),
    (
        "network_update",
        "PUT",
        "/v1/sandboxes/sbx-1/network",
        request_json("NetworkUpdateRequest"),
        "network_update",
    ),
    ("terminal_end", "DELETE", "/v1/sandboxes/sbx-1/terminals/term-0001", None, "terminal_end"),
    (
        "labels_update",
        "PATCH",
        "/v1/sandboxes/sbx-1/labels",
        request_json("LabelsUpdateRequest"),
        "labels_update",
    ),
    (
        "tcp_link",
        "POST",
        "/v1/sandboxes/sbx-1/tcp-links",
        request_json("TcpLinkRequest"),
        "tcp_link",
    ),
    (
        "snapshot_create",
        "POST",
        "/v1/sandboxes/sbx-1/snapshots",
        request_json("SnapshotRequest"),
        "snapshot_create",
    ),
    ("snapshot_list", "GET", "/v1/snapshots", None, "snapshot_list"),
    ("snapshot_get", "GET", "/v1/snapshots/snap-9", None, "snapshot_get"),
    ("snapshot_delete", "DELETE", "/v1/snapshots/snap-9", None, "snapshot_delete"),
    ("snapshot_cost", "GET", "/v1/snapshots/snap-9/cost", None, "snapshot_cost"),
    ("account_cost", "GET", "/v1/cost", None, "account_cost"),
]


async def drive(app: Any, method: str, path: str, body: Any) -> Reply:
    headers: dict[str, str] = {}
    query = ""
    if path == "/v1/cost":
        query = "start=2026-11-13T10:00:00Z&end=2026-11-13T11:00:00Z"
    if path.endswith(("/files", "/files/exists")) or (
        path.endswith("/directories") and method == "GET"
    ):
        query = "path=/work/a.txt"
    if method == "POST" and path in ("/v1/sandboxes", "/v1/sandboxes/sbx-1/snapshots"):
        headers["Idempotency-Key"] = IDEM
    if isinstance(body, bytes):
        return await call(
            app, method, path, body=body, headers=headers, query=query, length=len(body)
        )
    payload = b"" if body is None else j(body)
    return await call(app, method, path, body=payload, headers=headers, query=query)


def test_the_route_table_covers_all_operations() -> None:
    assert len({operation for operation, *_ in ROUTES}) == 34


@pytest.mark.parametrize(("operation", "method", "path", "body", "called"), ROUTES)
def test_each_route_reaches_its_method(
    operation: str, method: str, path: str, body: Any, called: str
) -> None:
    app = create_app(Recorder)
    reply = asyncio.run(drive(app, method, path, body))
    assert reply.status == (201 if operation in ("create", "snapshot_create") else 200), bytes(
        reply.body
    )
    assert [name for name, _ in Recorder.calls] == [called]
    assert operation == called
    assert reply.headers["request-id"]
    if operation == "files_read":
        assert bytes(reply.body) == b"hello world"
        assert reply.headers["content-length"] == "11"
    else:
        assert isinstance(reply.json(), dict)


def test_a_preview_request_passes_access_and_lifetime_only_when_they_are_set() -> None:
    app = create_app(Recorder)
    path = "/v1/sandboxes/sbx-1/previews"
    asyncio.run(call(app, "POST", path, body=j({"port": 3000})))
    asyncio.run(
        call(app, "POST", path, body=j({"port": 3000, "access": "private", "lifetime_seconds": 60}))
    )
    assert Recorder.calls == [
        ("preview_link", ("sbx-1", 3000, "public", None)),
        ("preview_link", ("sbx-1", 3000, "private", 60)),
    ]


def test_a_provider_with_the_short_preview_signature_still_serves_a_plain_request() -> None:
    class Short(Recorder, manifest=False):
        async def preview_link(  # type: ignore[override]  # pylint: disable=arguments-differ
            self, sandbox_id: str, port: int
        ) -> PreviewLink:
            self._note("preview_link", sandbox_id, port)
            return example(PreviewLink)

    app = create_app(Short)
    reply = asyncio.run(call(app, "POST", "/v1/sandboxes/sbx-1/previews", body=j({"port": 3000})))
    assert reply.status == 200
    assert reply.json()["access"] == "public"


@pytest.mark.parametrize(
    ("operation", "path", "body", "args"),
    [
        ("pause", "pause", {}, ("sbx-1",)),
        ("resume", "resume", {}, ("sbx-1",)),
        ("lifetime_extend", "lifetime", {"seconds": 90}, ("sbx-1", 90)),
    ],
)
def test_an_operation_that_returns_nothing_is_answered_with_one_get(
    operation: str, path: str, body: dict[str, Any], args: tuple[Any, ...]
) -> None:
    class Quiet(Recorder, manifest=False):
        async def pause(self, sandbox_id: str) -> Sandbox | None:
            self._note("pause", sandbox_id)
            return None

        async def resume(self, sandbox_id: str) -> Sandbox | None:
            self._note("resume", sandbox_id)
            return None

        async def lifetime_extend(self, sandbox_id: str, seconds: int) -> Sandbox | None:
            self._note("lifetime_extend", sandbox_id, seconds)
            return None

    app = create_app(Quiet)
    reply = asyncio.run(call(app, "POST", f"/v1/sandboxes/sbx-1/{path}", body=j(body)))
    assert reply.status == 200
    assert reply.json() == to_json(example(Sandbox))  # the wire answer is still the sandbox
    assert Recorder.calls == [(operation, args), ("get", ("sbx-1",))]


@pytest.mark.parametrize(
    "body",
    [
        {"port": 3000, "access": "secret"},
        {"port": 3000, "lifetime_seconds": 0},
    ],
)
def test_a_preview_request_with_a_bad_access_or_lifetime_is_refused(body: dict[str, Any]) -> None:
    app = create_app(Recorder)
    reply = asyncio.run(call(app, "POST", "/v1/sandboxes/sbx-1/previews", body=j(body)))
    assert reply.status == 400 and Recorder.calls == []


def test_network_update_passes_the_policy_and_entries_and_refuses_bad_ones() -> None:
    app = create_app(Recorder)
    path = "/v1/sandboxes/sbx-1/network"
    body = {"policy": "allowlist", "allow": ["a.example.com", "10.0.0.0/24"]}
    assert asyncio.run(call(app, "PUT", path, body=j(body))).status == 200
    assert asyncio.run(call(app, "PUT", path, body=j({"policy": "deny_all"}))).status == 200
    assert Recorder.calls == [
        ("network_update", ("sbx-1", "allowlist", ["a.example.com", "10.0.0.0/24"], [])),
        ("network_update", ("sbx-1", "deny_all", [], [])),
    ]
    Recorder.calls.clear()
    for bad in ({}, {"policy": "nope"}, {"policy": "allowlist", "allow": "a"}, {"allow": ["a"]}):
        assert asyncio.run(call(app, "PUT", path, body=j(bad))).status == 400
    assert Recorder.calls == []


def test_a_terminal_end_of_a_bad_id_is_refused() -> None:
    app = create_app(Recorder)
    reply = asyncio.run(call(app, "DELETE", "/v1/sandboxes/sbx-1/terminals/a%20b"))
    assert reply.status == 400 and Recorder.calls == []


def test_labels_update_passes_the_labels_and_refuses_bad_ones() -> None:
    app = create_app(Recorder)
    path = "/v1/sandboxes/sbx-1/labels"
    reply = asyncio.run(call(app, "PATCH", path, body=j({"labels": {"a": "b", "gone": ""}})))
    assert reply.status == 200
    assert Recorder.calls == [("labels_update", ("sbx-1", {"a": "b", "gone": ""}))]
    Recorder.calls.clear()
    for bad in ({}, {"labels": {"bad key": "x"}}, {"labels": {"a": "x" * 256}}, {"labels": 1}):
        refused = asyncio.run(call(app, "PATCH", path, body=j(bad)))
        assert refused.status == 400
    too_many = {f"k{i}": "v" for i in range(33)}
    assert asyncio.run(call(app, "PATCH", path, body=j({"labels": too_many}))).status == 400
    assert Recorder.calls == []


def test_a_preview_revoke_of_a_bad_id_is_refused() -> None:
    app = create_app(Recorder)
    reply = asyncio.run(call(app, "DELETE", "/v1/sandboxes/sbx-1/previews/a%20b"))
    assert reply.status == 400 and Recorder.calls == []


def test_arguments_arrive_as_typed_values() -> None:
    app = create_app(Recorder)
    asyncio.run(
        call(
            app,
            "GET",
            "/v1/sandboxes",
            query="label=team=a=b&label=env=prod&cursor=c1&limit=7",
        )
    )
    asyncio.run(
        call(
            app,
            "GET",
            "/v1/sandboxes/s1/processes/p1/output",
            query="cursor=c2&wait_ms=250",
        )
    )
    created = asyncio.run(
        call(
            app,
            "POST",
            "/v1/sandboxes",
            body=j({"labels": {"a": "b"}, "lifetime_seconds": 60}),
            headers={"Idempotency-Key": IDEM},
        )
    )
    assert created.status == 201
    listed, output, create = Recorder.calls
    assert listed == ("list", ({"team": "a=b", "env": "prod"}, "c1", 7))
    assert output == ("process_output", ("s1", "p1", "c2", 250))
    request = create[1][0]
    assert isinstance(request, CreateRequest)
    assert (request.labels, request.lifetime_seconds, create[1][1]) == ({"a": "b"}, 60, IDEM)


def test_files_list_arguments_and_defaults() -> None:
    app = create_app(Recorder)
    asyncio.run(call(app, "GET", "/v1/sandboxes/s1/directories", query="path=/d"))
    asyncio.run(call(app, "GET", "/v1/sandboxes/s1/directories", query="path=/d&cursor=c9&limit=7"))
    assert Recorder.calls == [
        ("files_list", ("s1", "/d", None, 100)),
        ("files_list", ("s1", "/d", "c9", 7)),
    ]


def test_files_mkdir_and_files_remove_arguments() -> None:
    app = create_app(Recorder)
    made = asyncio.run(call(app, "POST", "/v1/sandboxes/s1/directories", body=j({"path": "/d/e"})))
    assert (made.status, made.json()) == (200, {})
    asyncio.run(
        call(
            app,
            "POST",
            "/v1/sandboxes/s1/directories",
            body=j({"path": "/d/e", "parents": True}),
        )
    )
    removed = asyncio.run(call(app, "DELETE", "/v1/sandboxes/s1/files", query="path=/d"))
    assert (removed.status, removed.json()) == (200, {})
    asyncio.run(call(app, "DELETE", "/v1/sandboxes/s1/files", query="path=/d&recursive=true"))
    assert Recorder.calls == [
        ("files_mkdir", ("s1", "/d/e", False)),
        ("files_mkdir", ("s1", "/d/e", True)),
        ("files_remove", ("s1", "/d", False)),
        ("files_remove", ("s1", "/d", True)),
    ]


@pytest.mark.parametrize(
    ("method", "path", "body", "query"),
    [
        ("GET", "/v1/sandboxes/s1/directories", b"", ""),  # no path
        ("GET", "/v1/sandboxes/s1/directories", b"", "path=/d&limit=0"),
        ("GET", "/v1/sandboxes/s1/directories", b"", "path=/d&cursor="),
        ("GET", "/v1/sandboxes/s1/directories", b"", "path=/d&extra=1"),
        ("POST", "/v1/sandboxes/s1/directories", j({"parents": True}), ""),  # no path
        ("POST", "/v1/sandboxes/s1/directories", j({"path": "/d", "parents": "yes"}), ""),
        ("POST", "/v1/sandboxes/s1/directories", j({"path": "/d", "surprise": 1}), ""),
        ("POST", "/v1/sandboxes/s1/directories", j({"path": "d"}), ""),
        ("DELETE", "/v1/sandboxes/s1/files", b"", "path=/d&recursive=maybe"),
        ("DELETE", "/v1/sandboxes/s1/files", b"", "recursive=true"),
        ("GET", "/v1/sandboxes/s1/files/exists", b"", ""),
        ("GET", "/v1/sandboxes/s1/files/exists", b"", "path=relative"),
    ],
)
def test_a_malformed_directory_request_is_invalid_request(
    method: str, path: str, body: bytes, query: str
) -> None:
    app = create_app(Recorder)
    reply = asyncio.run(call(app, method, path, body=body, query=query))
    assert reply.status == 400, bytes(reply.body)
    assert reply.json()["error"]["code"] == "invalid_request"
    assert Recorder.calls == []


def test_a_path_component_over_255_bytes_is_refused_by_every_directory_operation() -> None:
    app = create_app(Recorder)
    long = "/d/" + "x" * 256
    replies = [
        asyncio.run(call(app, "GET", "/v1/sandboxes/s1/directories", query=f"path={long}")),
        asyncio.run(call(app, "POST", "/v1/sandboxes/s1/directories", body=j({"path": long}))),
        asyncio.run(call(app, "DELETE", "/v1/sandboxes/s1/files", query=f"path={long}")),
        asyncio.run(call(app, "GET", "/v1/sandboxes/s1/files/exists", query=f"path={long}")),
    ]
    assert [reply.status for reply in replies] == [400] * 4
    assert Recorder.calls == []


def test_a_directory_operation_that_the_provider_lacks_is_unsupported() -> None:
    class Bare(Provider, manifest=False):
        provider_id = "bare"
        name = "Bare"
        spec_version = "1.0"
        credential_fields: ClassVar[tuple[CredentialField, ...]] = (CredentialField("api_key"),)

        async def discovery(self) -> Any: ...
        async def create(self, request: Any, *, idempotency_key: str) -> Any: ...
        async def get(self, sandbox_id: str) -> Any: ...
        async def list(
            self, *, labels: Any = None, cursor: Any = None, limit: int = 100
        ) -> Any: ...
        async def destroy(self, sandbox_id: str) -> Any: ...
        async def run(self, sandbox_id: str, request: Any) -> Any: ...
        async def files_read(self, sandbox_id: str, path: str) -> Any: ...
        async def files_write(
            self,
            sandbox_id: str,
            path: str,
            data: AsyncIterable[bytes],
            *,
            size: int,
            user: str | None = None,
        ) -> Any: ...
        async def process_start(self, sandbox_id: str, request: Any) -> Any: ...
        async def process_output(
            self, sandbox_id: str, process_id: str, *, cursor: Any = None, wait_ms: int = 0
        ) -> Any: ...
        async def cost(self, sandbox_id: str, *, created_at: datetime | None = None) -> Any: ...

    app = create_app(Bare)
    reply = asyncio.run(call(app, "GET", "/v1/sandboxes/s1/files/exists", query="path=/d"))
    assert (reply.status, reply.json()["error"]["code"]) == (422, "unsupported")


def test_snapshot_arguments_arrive_as_typed_values() -> None:
    app = create_app(Recorder)
    listed = asyncio.run(
        call(
            app,
            "GET",
            "/v1/snapshots",
            query="label=team=a=b&label=env=prod&sandbox_id=sbx-1&cursor=c1&limit=7",
        )
    )
    created = asyncio.run(
        call(
            app,
            "POST",
            "/v1/sandboxes/sbx-1/snapshots",
            body=j({"keeps": "files_only", "labels": {"a": "b"}}),
            headers={"Idempotency-Key": IDEM},
        )
    )
    restored = asyncio.run(
        call(
            app,
            "POST",
            "/v1/sandboxes",
            body=j({"snapshot": "snap-9"}),
            headers={"Idempotency-Key": IDEM},
        )
    )
    assert (listed.status, created.status, restored.status) == (200, 201, 201)
    list_call, create_call, restore_call = Recorder.calls
    assert list_call == ("snapshot_list", ({"team": "a=b", "env": "prod"}, "sbx-1", "c1", 7))
    assert create_call[1][0] == "sbx-1"
    assert create_call[1][1] == SnapshotRequest(keeps="files_only", labels={"a": "b"})
    assert create_call[1][2] == IDEM
    assert restore_call[1][0].snapshot == "snap-9"


@pytest.mark.parametrize(
    ("method", "path", "body", "headers"),
    [
        ("POST", "/v1/sandboxes/s1/snapshots", {"surprise": 1}, {"Idempotency-Key": IDEM}),
        ("POST", "/v1/sandboxes/s1/snapshots", {"keeps": "everything"}, {"Idempotency-Key": IDEM}),
        ("POST", "/v1/sandboxes/s1/snapshots", {}, {}),
        ("POST", "/v1/sandboxes/s1/snapshots", {}, {"Idempotency-Key": "short"}),
    ],
)
def test_a_malformed_snapshot_create_is_invalid_request(
    method: str, path: str, body: dict[str, Any], headers: dict[str, str]
) -> None:
    reply = asyncio.run(call(create_app(Recorder), method, path, body=j(body), headers=headers))
    assert reply.status == 400
    assert reply.json()["error"]["code"] == "invalid_request"
    assert Recorder.calls == []


def test_a_snapshot_list_refuses_unknown_and_repeated_parameters() -> None:
    app = create_app(Recorder)
    for query in ("surprise=1", "limit=0", "sandbox_id=a&sandbox_id=b", "cursor="):
        reply = asyncio.run(call(app, "GET", "/v1/snapshots", query=query))
        assert reply.status == 400, query
    assert Recorder.calls == []


def test_a_repeated_idempotent_create_still_returns_created() -> None:
    app = create_app(Recorder)
    request = j({"labels": {"team": "test"}, "lifetime_seconds": 60})

    first = asyncio.run(
        call(app, "POST", "/v1/sandboxes", body=request, headers={"Idempotency-Key": IDEM})
    )
    repeated = asyncio.run(
        call(app, "POST", "/v1/sandboxes", body=request, headers={"Idempotency-Key": IDEM})
    )

    assert (first.status, repeated.status) == (201, 201)
    assert first.json() == repeated.json()
    assert [name for name, _ in Recorder.calls] == ["create", "create"]


def test_defaults_for_list_and_process_output() -> None:
    app = create_app(Recorder)
    asyncio.run(call(app, "GET", "/v1/sandboxes"))
    asyncio.run(call(app, "GET", "/v1/sandboxes/s1/processes/p1/output"))
    assert Recorder.calls == [
        ("list", (None, None, 100)),
        ("process_output", ("s1", "p1", None, 0)),
    ]


# --- strict requests -------------------------------------------------------------------------


@pytest.mark.rule("provider-api/unknown-fields-refused")
@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/v1/sandboxes", {"labels": {}, "surprise": 1}),
        ("/v1/sandboxes/s1/run", {"argv": ["true"], "surprise": 1}),
        ("/v1/sandboxes/s1/processes", {"argv": ["true"], "surprise": 1}),
        ("/v1/sandboxes/s1/pause", {"surprise": 1}),
        ("/v1/sandboxes/s1/lifetime", {"seconds": 5, "surprise": 1}),
        ("/v1/sandboxes/s1/previews", {"port": 80, "surprise": 1}),
    ],
)
def test_an_unknown_body_field_is_refused(path: str, body: dict[str, Any]) -> None:
    app = create_app(Recorder)
    reply = asyncio.run(call(app, "POST", path, body=j(body), headers={"Idempotency-Key": IDEM}))
    assert reply.status == 400
    error = reply.json()["error"]
    assert (error["code"], error["outcome"]) == ("invalid_request", "failed")
    assert Recorder.calls == []


@pytest.mark.parametrize(
    ("method", "path", "body", "query", "headers"),
    [
        ("POST", "/v1/sandboxes/s1/run", b"not json", "", {}),
        ("POST", "/v1/sandboxes/s1/run", b"", "", {}),
        ("POST", "/v1/sandboxes", b"{}", "", {}),  # no Idempotency-Key
        ("POST", "/v1/sandboxes", b"{}", "", {"Idempotency-Key": "SHORT"}),
        ("GET", "/v1/sandboxes", b"", "nope=1", {}),
        ("GET", "/v1/sandboxes", b"", "limit=0", {}),
        ("GET", "/v1/sandboxes", b"", "label=novalue", {}),
        ("GET", "/v1/sandboxes/s1/files", b"", "", {}),  # no path
        ("GET", "/v1/sandboxes/s1/files", b"", "path=relative", {}),
        ("GET", "/v1/sandboxes/s%20x", b"", "", {}),
        ("PUT", "/v1/sandboxes/s1/files", b"abc", "path=/a", {}),  # no Content-Length
    ],
)
def test_a_malformed_request_is_invalid_request(
    method: str, path: str, body: bytes, query: str, headers: dict[str, str]
) -> None:
    app = create_app(Recorder)
    reply = asyncio.run(call(app, method, path, body=body, query=query, headers=headers))
    assert reply.status == 400, bytes(reply.body)
    assert reply.json()["error"]["code"] == "invalid_request"
    assert Recorder.calls == []


def test_a_json_body_over_one_mib_is_too_large() -> None:
    app = create_app(Recorder)
    reply = asyncio.run(call(app, "POST", "/v1/sandboxes/s1/run", body=b" " * (MIB + 1)))
    assert reply.status == 413
    assert reply.json()["error"]["code"] == "too_large"


def test_unknown_routes_and_wrong_methods_are_not_found() -> None:
    app = create_app(Recorder)
    for method, path in [("GET", "/v2/discovery"), ("POST", "/v1/discovery"), ("GET", "/")]:
        reply = asyncio.run(call(app, method, path))
        assert (reply.status, reply.json()["error"]["code"]) == (404, "not_found")


# --- errors ----------------------------------------------------------------------------------


@pytest.mark.rule("provider-api/no-credential-echo")
def test_an_unexpected_exception_is_an_opaque_500() -> None:
    Recorder.explode = RuntimeError("secret-xyz")
    app = create_app(Recorder)
    reply = asyncio.run(call(app, "GET", "/v1/sandboxes/sbx-1"))
    assert reply.status == 500
    assert b"secret-xyz" not in bytes(reply.body)
    assert reply.json()["error"] == {
        "code": "provider_error",
        "message": "internal error",
        "outcome": "unknown",
        "retry_after_seconds": None,
    }
    assert "secret-xyz" not in json.dumps(dict(reply.headers))


def test_an_sps_error_keeps_its_code_status_and_retry_hint() -> None:
    Recorder.explode = SpsError("rate_limited", "Slow down", retry_after_seconds=7)
    app = create_app(Recorder)
    reply = asyncio.run(call(app, "GET", "/v1/sandboxes/sbx-1"))
    assert (reply.status, reply.headers["retry-after"]) == (429, "7")
    assert reply.json()["error"]["retry_after_seconds"] == 7
    Recorder.explode = SpsError("timeout", "Too slow", outcome="unknown")
    reply = asyncio.run(call(app, "GET", "/v1/sandboxes/sbx-1"))
    assert (reply.status, reply.json()["error"]["outcome"]) == (504, "unknown")


def test_every_error_code_has_its_status() -> None:
    from sandbox_provider_spec.v1 import ERROR_TABLE  # noqa: PLC0415

    app = create_app(Recorder)
    for code, (status, _) in ERROR_TABLE.items():
        Recorder.explode = SpsError(code, "x")
        reply = asyncio.run(call(app, "GET", "/v1/sandboxes/sbx-1"))
        assert (reply.status, reply.json()["error"]["code"]) == (status, code)


# --- credentials -----------------------------------------------------------------------------


@pytest.mark.rule("provider-api/bearer-only")
def test_a_missing_or_malformed_authorization_is_unauthenticated() -> None:
    app = create_app(Recorder)
    for token, headers in [
        (None, {}),
        (None, {"Authorization": "Basic abc"}),
        (None, {"Authorization": "Bearer"}),
        ("", {}),
    ]:
        reply = asyncio.run(call(app, "GET", "/v1/discovery", token=token, headers=headers))
        assert (reply.status, reply.json()["error"]["code"]) == (401, "unauthenticated")
    assert Recorder.constructed == []


@pytest.mark.rule("provider-api/served-token-encoding")
def test_a_single_field_provider_takes_the_token_as_the_value() -> None:
    app = create_app(Recorder)
    reply = asyncio.run(call(app, "GET", "/v1/discovery", token="whole-token"))
    assert reply.status == 200
    assert Recorder.constructed == [{"api_key": "whole-token"}]


@pytest.mark.rule("provider-api/served-token-encoding")
def test_a_two_field_token_reaches_the_constructor() -> None:
    app = create_app(TwoFields)
    token = encode({"key_id": "kid-1", "secret": "s3cret"})
    reply = asyncio.run(call(app, "GET", "/v1/discovery", token=token))
    assert reply.status == 200
    assert TwoFields.constructed == [{"key_id": "kid-1", "secret": "s3cret"}]


@pytest.mark.rule("provider-api/no-credential-echo")
@pytest.mark.rule("provider-api/served-token-encoding")
@pytest.mark.parametrize(
    "token",
    [
        encode({"key_id": "kid-1"}),  # a missing field
        encode({"key_id": "kid-1", "secret": "x", "extra": "y"}),  # an undeclared field
        "plain-value",  # not an sps1 token
        "sps1.!!!",
    ],
)
def test_a_token_that_is_not_the_declared_fields_is_unauthenticated(token: str) -> None:
    app = create_app(TwoFields)
    reply = asyncio.run(call(app, "GET", "/v1/discovery", token=token))
    assert (reply.status, reply.json()["error"]["code"]) == (401, "unauthenticated")
    assert token not in bytes(reply.body).decode()
    assert TwoFields.constructed == []


# --- the pool of instances -------------------------------------------------------------------


def test_one_instance_per_token_is_reused_and_closed_after_the_idle_time() -> None:
    now = [0.0]
    app = create_app(Recorder, idle_seconds=300, clock=lambda: now[0])

    async def scenario() -> None:
        await call(app, "GET", "/v1/discovery", token="a")
        now[0] = 299
        await call(app, "GET", "/v1/discovery", token="a")
        assert Recorder.constructed == [{"api_key": "a"}]
        now[0] = 598
        await call(app, "GET", "/v1/discovery", token="b")
        assert Recorder.closed == [] and len(Recorder.constructed) == 2
        now[0] = 850
        await call(app, "GET", "/v1/discovery", token="b")
        assert Recorder.closed == [{"api_key": "a"}]

    asyncio.run(scenario())


def test_the_pool_holds_at_most_the_limit_and_closes_what_it_evicts() -> None:
    now = [0.0]
    app = create_app(Recorder, max_instances=2, clock=lambda: now[0])

    async def scenario() -> None:
        for token in ["a", "b", "c"]:
            now[0] += 1
            await call(app, "GET", "/v1/discovery", token=token)
        assert Recorder.closed == [{"api_key": "a"}]  # the least recently used

    asyncio.run(scenario())


def test_the_default_pool_limit_is_sixty_four() -> None:
    app = create_app(Recorder)

    async def scenario() -> None:
        for number in range(65):
            await call(app, "GET", "/v1/discovery", token=f"t{number}")

    asyncio.run(scenario())
    assert len(Recorder.constructed) == 65
    assert len(Recorder.closed) == 1


def test_shutdown_closes_every_instance() -> None:
    app = create_app(Recorder)

    async def scenario() -> None:
        for token in ["a", "b"]:
            await call(app, "GET", "/v1/discovery", token=token)
        messages = [{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}]
        sent: list[str] = []

        async def receive() -> dict[str, Any]:
            return messages.pop(0)

        async def send(message: MutableMapping[str, Any]) -> None:
            sent.append(message["type"])

        await app({"type": "lifespan"}, receive, send)
        assert sent == ["lifespan.startup.complete", "lifespan.shutdown.complete"]

    asyncio.run(scenario())
    assert sorted(item["api_key"] for item in Recorder.closed) == ["a", "b"]


def test_a_failing_close_does_not_fail_the_request() -> None:
    class Bad(Recorder, manifest=False):
        async def aclose(self) -> None:
            raise RuntimeError("close failed")

    now = [0.0]
    app = create_app(Bad, idle_seconds=1, clock=lambda: now[0])

    async def scenario() -> None:
        await call(app, "GET", "/v1/discovery", token="a")
        now[0] = 5
        assert (await call(app, "GET", "/v1/discovery", token="b")).status == 200

    asyncio.run(scenario())


# --- streaming -------------------------------------------------------------------------------


async def zeros(total: int, piece: int) -> AsyncIterator[bytes]:
    block = bytes(piece)
    sent = 0
    while sent < total:
        take = min(piece, total - sent)
        yield block[:take]
        sent += take


def test_a_256_mib_upload_reaches_the_provider_in_chunks() -> None:
    app = create_app(Recorder)
    size = 256 * MIB
    reply = asyncio.run(
        call(
            app,
            "PUT",
            "/v1/sandboxes/sbx-1/files",
            body=zeros(size, 4 * MIB),  # larger than the chunk limit: the server splits it
            query="path=/work/big.bin",
            length=size,
        )
    )
    assert reply.status == 200, bytes(reply.body)
    assert reply.json() == {"path": "/work/big.bin", "size": size}
    sizes = Recorder.upload_chunks
    assert sum(sizes) == size
    assert len(sizes) >= 256
    assert max(sizes) <= MIB
    assert Recorder.calls == [("files_write", ("sbx-1", "/work/big.bin", size))]


@pytest.mark.parametrize(("sent", "declared"), [(10, 20), (30, 20)])
def test_an_upload_with_a_size_mismatch_has_unknown_outcome(sent: int, declared: int) -> None:
    app = create_app(Recorder)
    reply = asyncio.run(
        call(
            app,
            "PUT",
            "/v1/sandboxes/sbx-1/files",
            body=[b"x" * sent],
            query="path=/a",
            length=declared,
        )
    )
    error = reply.json()["error"]
    assert (reply.status, error["code"], error["outcome"]) == (400, "invalid_request", "unknown")


def test_a_disconnect_during_an_upload_is_invalid_request() -> None:
    app = create_app(Recorder)

    async def short() -> AsyncIterator[bytes]:
        yield b"x" * 5
        return

    # The body ends with more_body False after 5 of 20 bytes.
    reply = asyncio.run(
        call(app, "PUT", "/v1/sandboxes/s/files", body=short(), query="path=/a", length=20)
    )
    assert (reply.status, reply.json()["error"]["outcome"]) == (400, "unknown")


def test_a_file_read_streams_with_a_declared_length() -> None:
    class Big(Recorder, manifest=False):
        async def files_read(self, sandbox_id: str, path: str) -> FileStream:
            return FileStream(size=3 * MIB + 5, chunks=zeros(3 * MIB + 5, 2 * MIB))

    app = create_app(Big)
    reply = asyncio.run(call(app, "GET", "/v1/sandboxes/s/files", query="path=/a"))
    assert reply.status == 200 and reply.finished
    assert reply.headers["content-length"] == str(3 * MIB + 5)
    assert max(reply.parts) <= MIB
    assert len(reply.body) == 3 * MIB + 5


def test_a_file_read_error_before_the_first_byte_is_an_error_response() -> None:
    class Missing(Recorder, manifest=False):
        async def files_read(self, sandbox_id: str, path: str) -> FileStream:
            raise SpsError("not_found", "No such file")

    app = create_app(Missing)
    reply = asyncio.run(call(app, "GET", "/v1/sandboxes/s/files", query="path=/a"))
    assert (reply.status, reply.json()["error"]["code"]) == (404, "not_found")


def test_a_file_read_that_fails_midway_aborts_the_response() -> None:
    class Broken(Recorder, manifest=False):
        async def files_read(self, sandbox_id: str, path: str) -> FileStream:
            async def chunks() -> AsyncIterator[bytes]:
                yield b"partial"
                raise RuntimeError("secret-xyz")

            return FileStream(size=100, chunks=chunks())

    app = create_app(Broken)

    async def scenario() -> Reply:
        reply = Reply()
        with pytest.raises(Exception, match="aborted") as info:
            reply = await call(app, "GET", "/v1/sandboxes/s/files", query="path=/a")
        assert "secret-xyz" not in str(info.value)
        return reply

    asyncio.run(scenario())


def test_an_empty_file_is_a_complete_empty_response() -> None:
    class Empty(Recorder, manifest=False):
        async def files_read(self, sandbox_id: str, path: str) -> FileStream:
            async def chunks() -> AsyncIterator[bytes]:
                return
                yield b""  # pragma: no cover

            return FileStream(size=0, chunks=chunks())

    reply = asyncio.run(call(create_app(Empty), "GET", "/v1/sandboxes/s/files", query="path=/a"))
    assert (reply.status, bytes(reply.body), reply.finished) == (200, b"", True)


# --- the command ------------------------------------------------------------------------------


def test_serve_needs_a_port_or_a_socket_and_a_known_provider(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit):
        main(["serve", "recorder"])
    with pytest.raises(SystemExit):
        main(["serve", "recorder", "--port", "1", "--socket", "/tmp/x"])
    capsys.readouterr()
    assert main(["serve", "no-such-provider", "--port", "1"]) == 1
    assert "no installed provider 'no-such-provider'" in capsys.readouterr().err


@pytest.mark.loopback
@pytest.mark.integration
def test_a_real_uvicorn_server_carries_a_large_round_trip_in_chunks() -> None:
    import httpx  # noqa: PLC0415 - the `http` extra
    import uvicorn  # noqa: PLC0415

    class Store(Recorder, manifest=False):
        blob = bytearray()

        async def files_write(
            self,
            sandbox_id: str,
            path: str,
            data: AsyncIterable[bytes],
            *,
            size: int,
            user: str | None = None,
        ) -> FileInfo:
            type(self).blob = bytearray()
            async for chunk in data:
                assert len(chunk) <= MIB
                type(self).blob += chunk
            return FileInfo(path, len(type(self).blob))

        async def files_read(self, sandbox_id: str, path: str) -> FileStream:
            blob = bytes(type(self).blob)

            async def chunks() -> AsyncIterator[bytes]:
                for start in range(0, len(blob), MIB):
                    yield blob[start : start + MIB]

            return FileStream(size=len(blob), chunks=chunks())

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    server = uvicorn.Server(
        uvicorn.Config(create_app(Store), host="127.0.0.1", port=port, log_level="error")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        for _ in range(100):
            if server.started:
                break
            time.sleep(0.05)
        assert server.started
        base = f"http://127.0.0.1:{port}"
        size = 16 * MIB + 3
        payload = bytes(range(256)) * (size // 256 + 1)
        payload = payload[:size]
        auth = {"Authorization": f"Bearer {BEARER}"}
        with httpx.Client(timeout=30) as client:
            put = client.put(
                f"{base}/v1/sandboxes/s/files", params={"path": "/b"}, content=payload, headers=auth
            )
            assert put.status_code == 200 and put.json() == {"path": "/b", "size": size}
            with client.stream(
                "GET", f"{base}/v1/sandboxes/s/files", params={"path": "/b"}, headers=auth
            ) as got:
                assert got.status_code == 200
                assert b"".join(got.iter_bytes()) == payload
            missing = client.get(f"{base}/v1/discovery")
            assert missing.status_code == 401
    finally:
        server.should_exit = True
        thread.join(timeout=10)


class UserRecorder(Recorder, manifest=False):
    async def files_write(
        self,
        sandbox_id: str,
        path: str,
        data: AsyncIterable[bytes],
        *,
        size: int,
        user: str | None = None,
    ) -> FileInfo:
        self._note("files_write_user", sandbox_id, path, size, user)
        async for _ in data:
            pass
        return FileInfo(path, size)


def test_a_named_user_and_the_base64_output_reach_the_provider() -> None:
    app = create_app(UserRecorder)
    body = {"argv": ["id"], "user": "runner", "output": "base64"}
    asyncio.run(call(app, "POST", "/v1/sandboxes/s1/run", body=j(body)))
    asyncio.run(
        call(app, "POST", "/v1/sandboxes/s1/processes", body=j({"argv": ["id"], "user": "runner"}))
    )
    asyncio.run(
        call(
            app,
            "PUT",
            "/v1/sandboxes/s1/files",
            body=b"abc",
            length=3,
            query="path=/f&user=runner",
        )
    )
    asyncio.run(call(app, "PUT", "/v1/sandboxes/s1/files", body=b"abc", length=3, query="path=/f"))
    run, process, named, unnamed = UserRecorder.calls
    run_request, process_request = run[1][1], process[1][1]
    assert (run_request.user, run_request.output) == ("runner", "base64")
    assert process_request.user == "runner"
    assert named == ("files_write_user", ("s1", "/f", 3, "runner"))
    assert unnamed == ("files_write_user", ("s1", "/f", 3, None))


def test_files_write_sends_user_only_when_named_so_an_older_provider_still_works() -> None:
    app = create_app(Recorder)  # its files_write takes no `user`
    plain = asyncio.run(
        call(app, "PUT", "/v1/sandboxes/s1/files", body=b"abc", length=3, query="path=/f")
    )
    assert plain.status == 200
    with_user = asyncio.run(
        call(app, "PUT", "/v1/sandboxes/s1/files", body=b"abc", length=3, query="path=/f&user=x")
    )
    assert (
        with_user.status == 500
    )  # a provider that cannot take `user` is a fault, not a silent run


@pytest.mark.parametrize("user", ["", "a b", "-x", "x" * 65, "a;b"])
def test_a_malformed_user_is_invalid_request(user: str) -> None:
    app = create_app(UserRecorder)
    reply = asyncio.run(
        call(
            app, "PUT", "/v1/sandboxes/s1/files", body=b"a", length=1, query=f"path=/f&user={user}"
        )
    )
    assert (reply.status, reply.json()["error"]["code"]) == (400, "invalid_request")
    run = asyncio.run(
        call(
            app,
            "POST",
            "/v1/sandboxes/s1/run",
            body=j({"argv": ["id"], "user": user}),
        )
    )
    assert (run.status, run.json()["error"]["code"]) == (400, "invalid_request")


def test_an_unknown_output_form_is_invalid_request() -> None:
    app = create_app(UserRecorder)
    reply = asyncio.run(
        call(app, "POST", "/v1/sandboxes/s1/run", body=j({"argv": ["id"], "output": "hex"}))
    )
    assert (reply.status, reply.json()["error"]["code"]) == (400, "invalid_request")
