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
from pathlib import Path
from typing import Any, ClassVar, TypeVar

import pytest

from sandbox_provider_spec.cli import main
from sandbox_provider_spec.v1 import (
    Cost,
    CreateRequest,
    CredentialField,
    DestroyResult,
    Discovery,
    FileInfo,
    FileLink,
    FileLinkRequest,
    FileStream,
    OutputPage,
    PreviewLink,
    Process,
    ProcessStartRequest,
    Provider,
    RunRequest,
    RunResult,
    Sandbox,
    SandboxPage,
    SpsError,
    TcpLink,
    from_json,
)
from sandbox_provider_spec.v1.server import create_app
from sandbox_provider_spec.v1.tokens import encode

EXAMPLES = Path(__file__).resolve().parents[2] / "spec" / "provider-api-1.0-examples"
T = TypeVar("T")
MIB = 1024 * 1024
TOKEN = "tok-abcdef"
KEY = "key-12345678"


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

    async def files_write(
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

    async def cost(self, sandbox_id: str) -> Cost:
        self._note("cost", sandbox_id)
        return example(Cost)

    async def files_link(self, sandbox_id: str, request: FileLinkRequest) -> FileLink:
        self._note("files_link", sandbox_id, request)
        return example(FileLink)

    async def pause(self, sandbox_id: str) -> Sandbox:
        self._note("pause", sandbox_id)
        return example(Sandbox)

    async def resume(self, sandbox_id: str) -> Sandbox:
        self._note("resume", sandbox_id)
        return example(Sandbox)

    async def lifetime_extend(self, sandbox_id: str, seconds: int) -> Sandbox:
        self._note("lifetime_extend", sandbox_id, seconds)
        return example(Sandbox)

    async def process_write_stdin(self, sandbox_id: str, process_id: str, data: bytes) -> None:
        self._note("process_write_stdin", sandbox_id, process_id, data)

    async def process_close_stdin(self, sandbox_id: str, process_id: str) -> None:
        self._note("process_close_stdin", sandbox_id, process_id)

    async def process_cancel(self, sandbox_id: str, process_id: str) -> None:
        self._note("process_cancel", sandbox_id, process_id)

    async def preview_link(self, sandbox_id: str, port: int) -> PreviewLink:
        self._note("preview_link", sandbox_id, port)
        return example(PreviewLink)

    async def tcp_link(self, sandbox_id: str, port: int) -> TcpLink:
        self._note("tcp_link", sandbox_id, port)
        return example(TcpLink)


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
    token: str | None = TOKEN,
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
    (
        "tcp_link",
        "POST",
        "/v1/sandboxes/sbx-1/tcp-links",
        request_json("TcpLinkRequest"),
        "tcp_link",
    ),
]


async def drive(app: Any, method: str, path: str, body: Any) -> Reply:
    headers: dict[str, str] = {}
    query = ""
    if path.endswith("/files"):
        query = "path=/work/a.txt"
    if path == "/v1/sandboxes" and method == "POST":
        headers["Idempotency-Key"] = KEY
    if isinstance(body, bytes):
        return await call(
            app, method, path, body=body, headers=headers, query=query, length=len(body)
        )
    payload = b"" if body is None else j(body)
    return await call(app, method, path, body=payload, headers=headers, query=query)


def test_the_route_table_covers_all_twenty_operations() -> None:
    assert len({operation for operation, *_ in ROUTES}) == 20


@pytest.mark.parametrize(("operation", "method", "path", "body", "called"), ROUTES)
def test_each_route_reaches_its_method(
    operation: str, method: str, path: str, body: Any, called: str
) -> None:
    app = create_app(Recorder)
    reply = asyncio.run(drive(app, method, path, body))
    assert reply.status == (201 if operation == "create" else 200), bytes(reply.body)
    assert [name for name, _ in Recorder.calls] == [called]
    assert operation == called
    assert reply.headers["request-id"]
    if operation == "files_read":
        assert bytes(reply.body) == b"hello world"
        assert reply.headers["content-length"] == "11"
    else:
        assert isinstance(reply.json(), dict)


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
            headers={"Idempotency-Key": KEY},
        )
    )
    assert created.status == 201
    listed, output, create = Recorder.calls
    assert listed == ("list", ({"team": "a=b", "env": "prod"}, "c1", 7))
    assert output == ("process_output", ("s1", "p1", "c2", 250))
    request = create[1][0]
    assert isinstance(request, CreateRequest)
    assert (request.labels, request.lifetime_seconds, create[1][1]) == ({"a": "b"}, 60, KEY)


def test_defaults_for_list_and_process_output() -> None:
    app = create_app(Recorder)
    asyncio.run(call(app, "GET", "/v1/sandboxes"))
    asyncio.run(call(app, "GET", "/v1/sandboxes/s1/processes/p1/output"))
    assert Recorder.calls == [
        ("list", (None, None, 100)),
        ("process_output", ("s1", "p1", None, 0)),
    ]


# --- strict requests -------------------------------------------------------------------------


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
    reply = asyncio.run(call(app, "POST", path, body=j(body), headers={"Idempotency-Key": KEY}))
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


def test_a_single_field_provider_takes_the_token_as_the_value() -> None:
    app = create_app(Recorder)
    reply = asyncio.run(call(app, "GET", "/v1/discovery", token="whole-token"))
    assert reply.status == 200
    assert Recorder.constructed == [{"api_key": "whole-token"}]


def test_a_two_field_token_reaches_the_constructor() -> None:
    app = create_app(TwoFields)
    token = encode({"key_id": "kid-1", "secret": "s3cret"})
    reply = asyncio.run(call(app, "GET", "/v1/discovery", token=token))
    assert reply.status == 200
    assert TwoFields.constructed == [{"key_id": "kid-1", "secret": "s3cret"}]


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
def test_an_upload_that_is_not_content_length_bytes_is_invalid_request(
    sent: int, declared: int
) -> None:
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
    assert (reply.status, reply.json()["error"]["code"]) == (400, "invalid_request")


def test_a_disconnect_during_an_upload_is_invalid_request() -> None:
    app = create_app(Recorder)

    async def short() -> AsyncIterator[bytes]:
        yield b"x" * 5
        return

    # The body ends with more_body False after 5 of 20 bytes.
    reply = asyncio.run(
        call(app, "PUT", "/v1/sandboxes/s/files", body=short(), query="path=/a", length=20)
    )
    assert reply.status == 400


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
            self, sandbox_id: str, path: str, data: AsyncIterable[bytes], *, size: int
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
        auth = {"Authorization": f"Bearer {TOKEN}"}
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
