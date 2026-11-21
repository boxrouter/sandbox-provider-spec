# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""`HttpProvider` sends the method and path of every operation, turns every error body into
`SpsError`, never follows a redirect, never shows its token, and streams files in small chunks."""

from __future__ import annotations

import asyncio
import json
import traceback
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from typing import Any, cast

import httpx
import pytest

from sandbox_provider_spec.v1 import (
    ERROR_TABLE,
    CreateRequest,
    FileLinkRequest,
    Provider,
    RunRequest,
    SnapshotRequest,
    SpsError,
)
from sandbox_provider_spec.v1.http_client import CHUNK_BYTES, HttpProvider
from sandbox_provider_spec.v1.types import ProcessStartRequest

EXAMPLES = Path(__file__).resolve().parents[2] / "spec" / "provider-api-1.0-examples"
BEARER = "tok-SECRET-0123456789"
BASE = "https://api.example.test/sps"
IDEM = "0123abcd-4567-89ef"
Handler = Callable[[httpx.Request], httpx.Response]


def example(name: str) -> Any:
    return json.loads((EXAMPLES / f"{name}.json").read_text(encoding="utf-8"))


def reply(name: str, status: int = 200) -> httpx.Response:
    return httpx.Response(status, json=example(name))


def provider(handler: Handler, **kwargs: Any) -> HttpProvider:
    return HttpProvider(BASE, BEARER, transport=httpx.MockTransport(handler), **kwargs)


def call(run: Callable[[HttpProvider], Awaitable[Any]], handler: Handler, **kwargs: Any) -> Any:
    async def main() -> Any:
        client = provider(handler, **kwargs)
        try:
            return await run(client)
        finally:
            await client.aclose()

    return asyncio.run(main())


async def no_data() -> AsyncIterator[bytes]:
    yield b"hello"


# (operation name, what to call, method, path, example returned, status)
OPERATIONS: list[tuple[str, Callable[[HttpProvider], Awaitable[Any]], str, str, str, int]] = [
    ("discovery", lambda p: p.discovery(), "GET", "/v1/discovery", "Discovery", 200),
    (
        "create",
        lambda p: p.create(CreateRequest(), idempotency_key=IDEM),
        "POST",
        "/v1/sandboxes",
        "Sandbox",
        201,
    ),
    ("get", lambda p: p.get("sbx-17"), "GET", "/v1/sandboxes/sbx-17", "Sandbox", 200),
    ("list", lambda p: p.list(), "GET", "/v1/sandboxes", "SandboxPage", 200),
    (
        "destroy",
        lambda p: p.destroy("sbx-17"),
        "DELETE",
        "/v1/sandboxes/sbx-17",
        "DestroyResult",
        200,
    ),
    (
        "run",
        lambda p: p.run("sbx-17", RunRequest(argv=["true"])),
        "POST",
        "/v1/sandboxes/sbx-17/run",
        "RunResult",
        200,
    ),
    (
        "files_write",
        lambda p: p.files_write("sbx-17", "/tmp/a", no_data(), size=5),
        "PUT",
        "/v1/sandboxes/sbx-17/files",
        "FileInfo",
        200,
    ),
    (
        "process_start",
        lambda p: p.process_start("sbx-17", ProcessStartRequest(argv=["sleep", "1"])),
        "POST",
        "/v1/sandboxes/sbx-17/processes",
        "Process",
        200,
    ),
    (
        "process_output",
        lambda p: p.process_output("sbx-17", "proc-1"),
        "GET",
        "/v1/sandboxes/sbx-17/processes/proc-1/output",
        "OutputPage",
        200,
    ),
    ("cost", lambda p: p.cost("sbx-17"), "GET", "/v1/sandboxes/sbx-17/cost", "Cost", 200),
    (
        "files_link",
        lambda p: p.files_link("sbx-17", FileLinkRequest("/tmp/a", "read", 60)),
        "POST",
        "/v1/sandboxes/sbx-17/file-links",
        "FileLink",
        200,
    ),
    ("pause", lambda p: p.pause("sbx-17"), "POST", "/v1/sandboxes/sbx-17/pause", "Sandbox", 200),
    ("resume", lambda p: p.resume("sbx-17"), "POST", "/v1/sandboxes/sbx-17/resume", "Sandbox", 200),
    (
        "lifetime_extend",
        lambda p: p.lifetime_extend("sbx-17", 60),
        "POST",
        "/v1/sandboxes/sbx-17/lifetime",
        "Sandbox",
        200,
    ),
    (
        "process_write_stdin",
        lambda p: p.process_write_stdin("sbx-17", "proc-1", b"x"),
        "POST",
        "/v1/sandboxes/sbx-17/processes/proc-1/stdin",
        "EmptyObject",
        200,
    ),
    (
        "process_close_stdin",
        lambda p: p.process_close_stdin("sbx-17", "proc-1"),
        "DELETE",
        "/v1/sandboxes/sbx-17/processes/proc-1/stdin",
        "EmptyObject",
        200,
    ),
    (
        "process_cancel",
        lambda p: p.process_cancel("sbx-17", "proc-1"),
        "POST",
        "/v1/sandboxes/sbx-17/processes/proc-1/cancel",
        "EmptyObject",
        200,
    ),
    (
        "preview_link",
        lambda p: p.preview_link("sbx-17", 8080),
        "POST",
        "/v1/sandboxes/sbx-17/previews",
        "PreviewLink",
        200,
    ),
    (
        "tcp_link",
        lambda p: p.tcp_link("sbx-17", 5432),
        "POST",
        "/v1/sandboxes/sbx-17/tcp-links",
        "TcpLink",
        200,
    ),
    (
        "files_list",
        lambda p: p.files_list("sbx-17", "/d"),
        "GET",
        "/v1/sandboxes/sbx-17/directories",
        "DirectoryPage",
        200,
    ),
    (
        "files_mkdir",
        lambda p: p.files_mkdir("sbx-17", "/d/e", parents=True),
        "POST",
        "/v1/sandboxes/sbx-17/directories",
        "EmptyObject",
        200,
    ),
    (
        "files_remove",
        lambda p: p.files_remove("sbx-17", "/d", recursive=True),
        "DELETE",
        "/v1/sandboxes/sbx-17/files",
        "EmptyObject",
        200,
    ),
    (
        "files_exists",
        lambda p: p.files_exists("sbx-17", "/d"),
        "GET",
        "/v1/sandboxes/sbx-17/files/exists",
        "PathInfo",
        200,
    ),
    (
        "snapshot_create",
        lambda p: p.snapshot_create("sbx-17", SnapshotRequest(), idempotency_key=IDEM),
        "POST",
        "/v1/sandboxes/sbx-17/snapshots",
        "Snapshot",
        201,
    ),
    (
        "snapshot_get",
        lambda p: p.snapshot_get("snap-9"),
        "GET",
        "/v1/snapshots/snap-9",
        "Snapshot",
        200,
    ),
    ("snapshot_list", lambda p: p.snapshot_list(), "GET", "/v1/snapshots", "SnapshotPage", 200),
    (
        "snapshot_delete",
        lambda p: p.snapshot_delete("snap-9"),
        "DELETE",
        "/v1/snapshots/snap-9",
        "SnapshotDeleteResult",
        200,
    ),
    (
        "snapshot_cost",
        lambda p: p.snapshot_cost("snap-9"),
        "GET",
        "/v1/snapshots/snap-9/cost",
        "Cost",
        200,
    ),
]


def test_is_a_provider() -> None:
    assert issubclass(HttpProvider, Provider)


def test_files_read_is_the_twenty_ninth_operation() -> None:
    # files_read returns a stream and has its own tests below; the other 28 are in OPERATIONS.
    assert len(OPERATIONS) == 28


@pytest.mark.parametrize(("name", "run", "method", "path", "body", "status"), OPERATIONS)
def test_method_path_and_token_of_each_operation(
    name: str,
    run: Callable[[HttpProvider], Awaitable[Any]],
    method: str,
    path: str,
    body: str,
    status: int,
) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return reply(body, status)

    result = call(run, handler)
    assert len(seen) == 1, name
    request = seen[0]
    assert (request.method, request.url.path) == (method, "/sps" + path), name
    assert request.headers["Authorization"] == f"Bearer {BEARER}"
    assert (result is None) == (body == "EmptyObject"), name


def test_snapshot_list_and_create_send_their_parameters() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return reply("SnapshotPage" if request.method == "GET" else "Snapshot", 200)

    call(
        lambda p: p.snapshot_list(labels={"a": "b=c"}, sandbox_id="sbx-17", cursor="c1", limit=5),
        handler,
    )
    query = seen[0].url.params.multi_items()
    assert query == [
        ("label", "a=b=c"),
        ("sandbox_id", "sbx-17"),
        ("cursor", "c1"),
        ("limit", "5"),
    ]
    call(
        lambda p: p.snapshot_create(
            "sbx-17", SnapshotRequest("files_only", {"k": "v"}), idempotency_key=IDEM
        ),
        handler,
    )
    assert seen[1].headers["Idempotency-Key"] == IDEM
    assert json.loads(seen[1].content) == {"keeps": "files_only", "labels": {"k": "v"}}
    with pytest.raises(SpsError):
        call(lambda p: p.snapshot_get("../x"), handler)


def test_files_read_method_and_path() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, content=b"abc")

    async def run(client: HttpProvider) -> bytes:
        stream = await client.files_read("sbx-17", "/tmp/a b")
        assert stream.size == 3
        return b"".join([chunk async for chunk in stream.chunks])

    assert call(run, handler) == b"abc"
    assert (seen[0].method, seen[0].url.path) == ("GET", "/sps/v1/sandboxes/sbx-17/files")
    assert seen[0].url.params["path"] == "/tmp/a b"
    assert seen[0].headers["Authorization"] == f"Bearer {BEARER}"


def test_query_and_idempotency_key() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.method == "POST":
            return reply("Sandbox", 201)
        return reply("OutputPage" if request.url.path.endswith("/output") else "SandboxPage")

    async def run(client: HttpProvider) -> None:
        await client.list(labels={"a": "1", "b": "2"}, cursor="c1", limit=5)
        await client.create(CreateRequest(), idempotency_key=IDEM)
        await client.process_output("sbx-17", "proc-1", cursor="k", wait_ms=1500)

    call(run, handler)
    listing, create, output = seen
    assert listing.url.params.get_list("label") == ["a=1", "b=2"]
    assert listing.url.params["cursor"] == "c1" and listing.url.params["limit"] == "5"
    assert create.headers["Idempotency-Key"] == IDEM
    assert json.loads(create.content)["sandbox_class"] == "default"
    assert output.url.params["cursor"] == "k" and output.url.params["wait_ms"] == "1500"


@pytest.mark.parametrize("code", sorted(ERROR_TABLE))
def test_every_error_code_becomes_sps_error(code: str) -> None:
    status, fault = ERROR_TABLE[code]  # type: ignore[index]
    outcome = "unknown" if fault == "provider" else "failed"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status,
            json={
                "error": {
                    "code": code,
                    "message": f"it went wrong: {code}",
                    "outcome": outcome,
                    "retry_after_seconds": 7,
                }
            },
        )

    with pytest.raises(SpsError) as raised:
        call(lambda p: p.get("sbx-17"), handler)
    error = raised.value
    assert (error.code, error.outcome, error.retry_after_seconds) == (code, outcome, 7)
    assert str(error) == f"{code}: it went wrong: {code}"


def test_the_code_decides_not_the_status() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            500,
            json={
                "error": {
                    "code": "not_found",
                    "message": "gone",
                    "outcome": "failed",
                    "retry_after_seconds": None,
                }
            },
        )

    with pytest.raises(SpsError) as raised:
        call(lambda p: p.get("sbx-17"), handler)
    assert raised.value.code == "not_found"


def test_retry_after_header_is_used_when_the_body_has_none() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            429,
            headers={"Retry-After": "12"},
            json={
                "error": {
                    "code": "rate_limited",
                    "message": "slow down",
                    "outcome": "failed",
                    "retry_after_seconds": None,
                }
            },
        )

    with pytest.raises(SpsError) as raised:
        call(lambda p: p.get("sbx-17"), handler)
    assert raised.value.retry_after_seconds == 12


def test_html_502_is_provider_error_unknown() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            502, headers={"Content-Type": "text/html"}, content=b"<html>Bad Gateway</html>"
        )

    with pytest.raises(SpsError) as raised:
        call(lambda p: p.destroy("sbx-17"), handler)
    assert (raised.value.code, raised.value.outcome) == ("provider_error", "unknown")


def test_error_body_that_is_not_an_error_response_is_provider_error_unknown() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"detail": "nope"})

    with pytest.raises(SpsError) as raised:
        call(lambda p: p.get("sbx-17"), handler)
    assert (raised.value.code, raised.value.outcome) == ("provider_error", "unknown")


def test_a_success_body_that_breaks_the_schema_is_provider_error_unknown() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": 1})

    with pytest.raises(SpsError) as raised:
        call(lambda p: p.get("sbx-17"), handler)
    assert (raised.value.code, raised.value.outcome) == ("provider_error", "unknown")


def test_a_redirect_is_not_followed_and_is_provider_error() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(302, headers={"Location": "https://elsewhere.example/steal"})

    with pytest.raises(SpsError) as raised:
        call(lambda p: p.get("sbx-17"), handler)
    assert raised.value.code == "provider_error"
    assert len(seen) == 1 and "elsewhere" not in seen[0]


def test_connection_failures() -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom " + BEARER, request=request)

    def stall(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow " + BEARER, request=request)

    def drop(request: httpx.Request) -> httpx.Response:
        raise httpx.RemoteProtocolError("closed " + BEARER, request=request)

    errors = []
    for handler, code, outcome in (
        (refuse, "unavailable", "failed"),
        (stall, "timeout", "unknown"),
        (drop, "provider_error", "unknown"),
    ):
        with pytest.raises(SpsError) as raised:
            call(lambda p: p.get("sbx-17"), handler)
        assert (raised.value.code, raised.value.outcome) == (code, outcome)
        errors.append(raised.value)
    for error in errors:
        assert BEARER not in str(error)
        assert BEARER not in "".join(traceback.format_exception(error))


def test_token_is_absent_from_every_error() -> None:
    """Even a server that echoes the token, or a failure deep in the library, leaks nothing."""
    texts: list[str] = []

    def echo(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401,
            json={
                "error": {
                    "code": "unauthenticated",
                    "message": f"bad token {request.headers['Authorization']}",
                    "outcome": "failed",
                    "retry_after_seconds": None,
                }
            },
        )

    def html(request: httpx.Request) -> httpx.Response:
        return httpx.Response(502, content=f"<html>{BEARER}</html>".encode())

    def redirect(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": f"https://x.example/?t={BEARER}"})

    def invalid(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=BEARER.encode())

    for handler in (echo, html, redirect, invalid):
        with pytest.raises(SpsError) as raised:
            call(lambda p: p.get("sbx-17"), handler)
        error = raised.value
        texts.extend([str(error), repr(error), "".join(traceback.format_exception(error))])
    for text in texts:
        assert BEARER not in text
    assert "[redacted]" in texts[0]

    client = provider(lambda request: reply("Sandbox"))
    assert BEARER not in repr(client) and BEARER not in str(client)
    for bad in ("", "has space", "line\nbreak", "tök"):
        with pytest.raises(SpsError) as raised:
            HttpProvider(BASE, bad)
        assert bad == "" or bad not in str(raised.value)


def test_a_64_mib_read_arrives_in_chunks_of_at_most_1_mib() -> None:
    total = 64 * 1024 * 1024
    block = b"\xab" * (4 * 1024 * 1024)

    async def body() -> AsyncIterator[bytes]:
        for _ in range(total // len(block)):
            yield block

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Content-Length": str(total)}, content=body())

    async def run(client: HttpProvider) -> tuple[int, int, int | None]:
        stream = await client.files_read("sbx-17", "/big")
        count = largest = 0
        async for chunk in stream.chunks:
            count += len(chunk)
            largest = max(largest, len(chunk))
        return count, largest, stream.size

    count, largest, size = call(run, handler)
    assert (count, size) == (total, total)
    assert 0 < largest <= CHUNK_BYTES == 1024 * 1024


def test_a_file_body_shorter_than_content_length_fails() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Content-Length": "10"}, content=b"short")

    async def run(client: HttpProvider) -> None:
        stream = await client.files_read("sbx-17", "/f")
        async for _ in stream.chunks:
            pass

    with pytest.raises(SpsError) as raised:
        call(run, handler)
    assert (raised.value.code, raised.value.outcome) == ("provider_error", "unknown")


def test_files_read_error_and_early_close() -> None:
    def missing(request: httpx.Request) -> httpx.Response:
        return reply("ErrorResponse", 404)

    with pytest.raises(SpsError) as raised:
        call(lambda p: p.files_read("sbx-17", "/nope"), missing)
    assert raised.value.code == "not_found"

    def big(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * (3 * CHUNK_BYTES))

    async def run(client: HttpProvider) -> int:
        stream = await client.files_read("sbx-17", "/f")
        first = await stream.chunks.__anext__()
        await stream.chunks.aclose()  # type: ignore[attr-defined]
        return len(first)

    assert call(run, big) == CHUNK_BYTES


def test_files_write_sends_content_length_and_small_chunks() -> None:
    size = 3 * CHUNK_BYTES + 5
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["length"] = request.headers["Content-Length"]
        seen["path"] = request.url.params["path"]
        seen["body"] = request.read()
        return httpx.Response(200, json={"path": "/tmp/f", "size": size})

    async def source() -> AsyncIterator[bytes]:
        yield b"a" * (2 * CHUNK_BYTES + 1)
        yield b"b" * (CHUNK_BYTES + 4)

    info = call(lambda p: p.files_write("sbx-17", "/tmp/f", source(), size=size), handler)
    assert info.size == size
    assert seen["length"] == str(size) and seen["path"] == "/tmp/f"
    assert seen["body"] == b"a" * (2 * CHUNK_BYTES + 1) + b"b" * (CHUNK_BYTES + 4)


@pytest.mark.parametrize("size", [3, 9])
def test_files_write_refuses_data_that_does_not_match_size(size: int) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        request.read()
        return httpx.Response(200, json={"path": "/tmp/f", "size": size})

    with pytest.raises(SpsError) as raised:
        call(lambda p: p.files_write("sbx-17", "/tmp/f", no_data(), size=size), handler)
    assert raised.value.code == "invalid_request"


def test_plain_http_is_allowed_only_for_loopback() -> None:
    for url in ("http://example.com", "http://10.0.0.5:8080", "http://localhost.evil.test"):
        with pytest.raises(SpsError) as raised:
            HttpProvider(url, "t")
        assert str(raised.value) == "invalid_request: plain HTTP is allowed only for loopback"
    for url in ("http://127.0.0.1:8000", "http://localhost:8000/sps", "http://[::1]:9"):
        HttpProvider(url, "t")
    HttpProvider("http://10.0.0.5:8080", "t", allow_plain_http=True)
    HttpProvider("https://example.com", "t")


def test_bad_base_urls_are_refused() -> None:
    for url in (
        "ftp://example.com",
        "example.com",
        "https://user:pw@example.com",
        "https://x.test/?q=1",
    ):
        with pytest.raises(SpsError) as raised:
            HttpProvider(url, "t")
        assert raised.value.code == "invalid_request"
        assert "pw" not in str(raised.value)


def test_ids_that_could_change_the_path_are_refused() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("no request may be sent")

    for bad in ("..", ".", "a/b", "a?b", "", "x" * 129, "a b"):

        async def get_bad(p: HttpProvider, name: str = bad) -> Any:
            return await p.get(name)

        with pytest.raises(SpsError) as raised:
            call(get_bad, handler)
        assert raised.value.code == "invalid_request"
    with pytest.raises(SpsError):
        call(lambda p: p.process_output("sbx-17", "../x"), handler)
    with pytest.raises(SpsError):
        call(lambda p: p.create(CreateRequest(), idempotency_key="BAD IDEM"), handler)


def test_unexpected_success_status_is_provider_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(204)

    with pytest.raises(SpsError) as raised:
        call(lambda p: p.get("sbx-17"), handler)
    assert (raised.value.code, raised.value.outcome) == ("provider_error", "unknown")


def test_files_list_sends_path_cursor_and_limit() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return reply("DirectoryPage")

    page = call(lambda p: p.files_list("sbx-17", "/d e", cursor="c1", limit=7), handler)
    assert [entry.name for entry in page.entries] == ["build", "latest", "notes.txt"]
    assert page.next_cursor is None
    assert dict(seen[0].url.params) == {"path": "/d e", "cursor": "c1", "limit": "7"}


def test_files_remove_and_files_mkdir_send_their_flags() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={})

    call(lambda p: p.files_remove("sbx-17", "/d"), handler)
    call(lambda p: p.files_remove("sbx-17", "/d", recursive=True), handler)
    call(lambda p: p.files_mkdir("sbx-17", "/d"), handler)
    assert dict(seen[0].url.params) == {"path": "/d", "recursive": "false"}
    assert dict(seen[1].url.params) == {"path": "/d", "recursive": "true"}
    assert json.loads(seen[2].content) == {"path": "/d", "parents": False}


def test_files_exists_result_is_typed() -> None:
    info = call(lambda p: p.files_exists("sbx-17", "/d"), lambda request: reply("PathInfo"))
    assert (info.exists, info.type) == (True, "symlink")


@pytest.mark.parametrize("code", ["not_found", "conflict", "invalid_request", "unsupported"])
def test_a_directory_operation_error_becomes_sps_error(code: str) -> None:
    body = {
        "error": {"code": code, "message": "x", "outcome": "failed", "retry_after_seconds": None}
    }
    status = ERROR_TABLE[cast(Any, code)][0]

    with pytest.raises(SpsError) as raised:
        call(
            lambda p: p.files_remove("sbx-17", "/d"),
            lambda request: httpx.Response(status, json=body),
        )
    assert raised.value.code == code


def test_run_and_process_start_send_user_and_output_only_when_set() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return reply("RunResult") if request.url.path.endswith("/run") else reply("Process")

    call(lambda p: p.run("sbx-17", RunRequest(argv=["id"])), handler)
    call(
        lambda p: p.run("sbx-17", RunRequest(argv=["id"], user="runner", output="base64")), handler
    )
    call(
        lambda p: p.process_start("sbx-17", ProcessStartRequest(argv=["id"], user="runner")),
        handler,
    )
    plain, named, process = (json.loads(request.content) for request in seen)
    assert "user" not in plain and "output" not in plain
    assert (named["user"], named["output"]) == ("runner", "base64")
    assert process["user"] == "runner"


def test_run_returns_the_base64_streams() -> None:
    body = {
        "exit_code": 0,
        "stdout": "",
        "stderr": "",
        "stdout_truncated": False,
        "stderr_truncated": False,
        "timed_out": False,
        "stdout_base64": "/wD+",
        "stderr_base64": "",
    }
    result = call(
        lambda p: p.run("sbx-17", RunRequest(argv=["id"], output="base64")),
        lambda request: httpx.Response(200, json=body),
    )
    assert (result.stdout_base64, result.stderr_base64) == ("/wD+", "")


def test_files_write_sends_the_user_query_only_when_named() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return reply("FileInfo")

    async def data() -> AsyncIterator[bytes]:
        yield b"abc"

    call(lambda p: p.files_write("sbx-17", "/f", data(), size=3), handler)
    call(lambda p: p.files_write("sbx-17", "/f", data(), size=3, user="runner"), handler)
    assert dict(seen[0].url.params) == {"path": "/f"}
    assert dict(seen[1].url.params) == {"path": "/f", "user": "runner"}
