# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""`HttpProvider`: a `Provider` that calls a native 1.0 provider over its HTTP API.

It needs the distribution's `http` extra (`httpx`).
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import secrets
from collections.abc import AsyncIterable, AsyncIterator, Mapping, Sequence
from datetime import datetime
from types import MappingProxyType
from typing import Any, TypeVar
from urllib.parse import urlsplit

import httpx
import websockets.asyncio.client
import websockets.exceptions

from sandbox_provider_spec.v1.errors import ERROR_TABLE, ErrorCode, SpsError
from sandbox_provider_spec.v1.provider import Provider
from sandbox_provider_spec.v1.types import (
    AccountCapacity,
    AccountCost,
    Cost,
    CreateRequest,
    DestroyResult,
    DirectoryPage,
    Discovery,
    FileInfo,
    FileLink,
    FileLinkRequest,
    FileStream,
    ImageDeleteResult,
    ImagePage,
    ImageRequest,
    OutputPage,
    PathInfo,
    PreparedImage,
    PreviewAccess,
    PreviewLink,
    Process,
    ProcessStartRequest,
    RunRequest,
    RunResult,
    Sandbox,
    SandboxPage,
    Snapshot,
    SnapshotDeleteResult,
    SnapshotPage,
    SnapshotRequest,
    TcpLink,
    Terminal,
    TerminalLink,
    TerminalRequest,
)
from sandbox_provider_spec.v1.wire import (
    WireError,
    error_from_json,
    from_json,
    timestamp,
    to_json,
)

T = TypeVar("T")

CHUNK_BYTES = 1024 * 1024  # files travel in pieces of at most 1 MiB
_MAX_JSON_BYTES = 64 * 1024 * 1024  # a run result holds at most two 16 MiB streams, with headroom
_MAX_ERROR_BYTES = 64 * 1024
_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_IDEMPOTENCY_KEY = re.compile(r"^[a-z0-9][a-z0-9-]{7,62}$")
_TOKEN = re.compile(r"^[\x21-\x7e]+$")  # printable ASCII with no space, so it fits a header
_CONNECT_SECONDS = 10.0
_DEFAULT_READ_SECONDS = 60.0
_IMAGE_PREPARE_READ_SECONDS = 600.0  # a prepare may build before it answers
_SLACK_SECONDS = 30.0  # added to a timeout that the operation itself carries


def _form_part(boundary: str, name: str, data: bytes, media: str) -> bytes:
    return (
        (
            f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n'
            f"Content-Type: {media}\r\n\r\n"
        ).encode()
        + data
        + b"\r\n"
    )


def _multipart_body(
    boundary: str, head: bytes, context: AsyncIterable[bytes] | None, size: int | None
) -> tuple[AsyncIterator[bytes], int | None]:
    """The request body of `image_prepare` as a stream, and its length when that is known."""
    tail = f"\r\n--{boundary}--\r\n".encode()
    part = b""
    if context is not None:
        length = "" if size is None else f"Content-Length: {size}\r\n"
        part = (
            f'--{boundary}\r\nContent-Disposition: form-data; name="context"; '
            f'filename="context.tar"\r\nContent-Type: application/x-tar\r\n{length}\r\n'
        ).encode()
    else:
        tail = f"--{boundary}--\r\n".encode()
    framing = len(head) + len(part) + len(tail)
    total = framing if context is None else (None if size is None else framing + size)

    async def stream() -> AsyncIterator[bytes]:
        yield head + part
        if context is not None:
            sent = 0
            async for piece in context:
                for start in range(0, len(piece), CHUNK_BYTES):
                    chunk = piece[start : start + CHUNK_BYTES]
                    sent += len(chunk)
                    if size is not None and sent > size:
                        raise SpsError("invalid_request", "The context is longer than context_size")
                    yield chunk
            if size is not None and sent != size:
                raise SpsError("invalid_request", "The context is shorter than context_size")
        yield tail

    return stream(), total


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _id(value: str, what: str) -> str:
    """An id from the caller goes into a URL path; refuse anything that could change the path."""
    if not _ID.fullmatch(value) or value in (".", ".."):
        raise SpsError("invalid_request", f"{what} is not a valid id")
    return value


class _BodyStream:
    """The chunks of a `files.read` response. Closing it, or reading it to the end, releases the
    connection. A body that ends early is an error, never a short file."""

    def __init__(self, response: httpx.Response, expected: int | None) -> None:
        self._response = response
        self._expected = expected
        self._source: AsyncIterator[bytes] | None = None
        self._seen = 0
        self._done = False

    def __aiter__(self) -> _BodyStream:
        return self

    async def __anext__(self) -> bytes:
        if self._done:
            raise StopAsyncIteration
        if self._source is None:
            self._source = self._response.aiter_bytes(CHUNK_BYTES)
        try:
            chunk = await self._source.__anext__()
        except StopAsyncIteration:
            await self.aclose()
            if self._expected is not None and self._seen != self._expected:
                raise SpsError(
                    "provider_error",
                    "The file body was shorter than Content-Length",
                    outcome="unknown",
                ) from None
            raise
        except httpx.HTTPError as error:
            await self.aclose()
            raise _transport_error(error, sent=True) from None
        self._seen += len(chunk)
        if self._expected is not None and self._seen > self._expected:
            await self.aclose()
            raise SpsError(
                "provider_error", "The file body was longer than Content-Length", outcome="unknown"
            )
        return chunk

    async def aclose(self) -> None:
        self._done = True
        await self._response.aclose()


TERMINAL_FRAME_BYTES = 65536  # the most that one terminal frame carries (provider-api.md 16)
_TERMINAL_CLOSE_SECONDS = 5.0


class _WebSocketTerminal(Terminal):
    """A `Terminal` on one WebSocket: each message of provider-api.md section 16 is one call."""

    def __init__(self, socket: websockets.asyncio.client.ClientConnection) -> None:
        self._socket = socket
        self.exit_code: int | None = None

    async def write(self, data: bytes) -> None:
        try:
            for start in range(0, len(data), TERMINAL_FRAME_BYTES):
                await self._socket.send(data[start : start + TERMINAL_FRAME_BYTES])
        except websockets.exceptions.ConnectionClosed:
            raise SpsError("unavailable", "The terminal connection is closed") from None

    async def resize(self, columns: int, rows: int) -> None:
        message = json.dumps({"type": "resize", "columns": columns, "rows": rows})
        try:
            await self._socket.send(message)
        except websockets.exceptions.ConnectionClosed:
            raise SpsError("unavailable", "The terminal connection is closed") from None

    async def output(self) -> AsyncIterator[bytes]:  # pylint: disable=invalid-overridden-method
        try:
            async for message in self._socket:
                if isinstance(message, bytes):
                    yield message
                    continue
                kind, error = self._control(message)
                if kind == "exit":
                    return
                assert error is not None
                raise error
        except websockets.exceptions.ConnectionClosedOK:
            return
        except websockets.exceptions.ConnectionClosedError:
            raise SpsError(
                "provider_error", "The terminal connection failed", outcome="unknown"
            ) from None

    def _control(self, text: str) -> tuple[str, SpsError | None]:
        """What a control message says: the program exited (`exit_code` is set), or an error."""
        try:
            document = json.loads(text)
            kind = document["type"]
            if kind == "exit":
                code = document["exit_code"]
                if not isinstance(code, int) or isinstance(code, bool):
                    raise ValueError
                self.exit_code = code
                return "exit", None
            if kind == "error":
                return "error", error_from_json({"error": document["error"]})
        except (ValueError, KeyError, TypeError):
            pass
        return "error", SpsError(
            "provider_error",
            "The terminal sent a message that is not in the 1.0 schema",
            outcome="unknown",
        )

    async def close(self) -> None:
        try:
            await asyncio.wait_for(self._socket.close(), _TERMINAL_CLOSE_SECONDS)
        except (TimeoutError, websockets.exceptions.WebSocketException, OSError):
            pass


def _transport_error(error: httpx.HTTPError, *, sent: bool) -> SpsError:
    """Map a failure of the connection to an error. The text names the kind of failure only: it
    never repeats the library's message, which may quote a URL or a header."""
    kind = type(error).__name__
    if isinstance(error, (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout)):
        # Nothing reached the provider.
        return SpsError("unavailable", f"Could not connect to the provider ({kind})")
    if isinstance(error, httpx.TimeoutException):
        return SpsError(
            "timeout", f"The provider did not answer in time ({kind})", outcome="unknown"
        )
    return SpsError(
        "provider_error",
        f"The connection to the provider failed ({kind})",
        outcome="unknown" if sent else "failed",
    )


def _refusal(status: int, body: bytes | bytearray | None) -> SpsError:
    """The error for a WebSocket upgrade that the provider refused with an HTTP response."""
    try:
        document = json.loads(bytes(body or b""))
    except ValueError:
        document = None
    if isinstance(document, dict) and "error" in document:
        return error_from_json(document)
    code: ErrorCode | None = next(
        (name for name, (number, _) in ERROR_TABLE.items() if number == status), None
    )
    return SpsError(
        code or "provider_error",
        f"The terminal link was refused with HTTP {status}",
        outcome="failed" if code is not None and ERROR_TABLE[code][1] == "caller" else "unknown",
    )


class HttpProvider(Provider, manifest=False):  # pylint: disable=too-many-public-methods
    """A native provider, reached at `base_url` with the account's bearer `token`.

    `transport` lets the caller supply its own `httpx` async transport (for example one that
    refuses private addresses). Plain `http://` is accepted only for a loopback host unless
    `allow_plain_http` is true. The token is sent only in the `Authorization` header and never
    appears in an exception's text.
    """

    def __init__(  # pylint: disable=super-init-not-called
        self,
        base_url: str,
        token: str,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        allow_plain_http: bool = False,
    ) -> None:
        parts = urlsplit(base_url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise SpsError("invalid_request", "base_url must be an http:// or https:// URL")
        if (
            parts.username is not None
            or parts.password is not None
            or parts.query
            or parts.fragment
        ):
            raise SpsError(
                "invalid_request", "base_url must have no credentials, query or fragment"
            )
        if parts.scheme == "http" and not allow_plain_http and not _is_loopback(parts.hostname):
            raise SpsError("invalid_request", "plain HTTP is allowed only for loopback")
        if not _TOKEN.fullmatch(token):
            raise SpsError("unauthenticated", "The token is empty or not a valid bearer token")
        self._token = token
        self._plain_http_ok = allow_plain_http
        self.base_url = base_url.rstrip("/")
        self.credentials = MappingProxyType({})
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            transport=transport,
            follow_redirects=False,
            trust_env=False,
            headers={"Authorization": f"Bearer {token}", "Accept-Encoding": "identity"},
            timeout=httpx.Timeout(_DEFAULT_READ_SECONDS, connect=_CONNECT_SECONDS),
        )

    def __repr__(self) -> str:
        return f"<HttpProvider {self.base_url} (token hidden)>"

    # --- plumbing ---------------------------------------------------------------------------

    def _scrub(self, text: str) -> str:
        return text.replace(self._token, "[redacted]")

    async def _send(  # pylint: disable=too-many-arguments
        self,
        method: str,
        path: str,
        *,
        params: Sequence[tuple[str, str | int]] | None = None,
        body: object | None = None,
        content: bytes | AsyncIterable[bytes] | None = None,
        headers: Mapping[str, str] | None = None,
        read_seconds: float = _DEFAULT_READ_SECONDS,
        expect: tuple[int, ...] = (200,),
    ) -> httpx.Response:
        """Send one request and return the response with its body unread. A response that is not
        one of the `expect`ed statuses is turned into an error and closed."""
        extra = dict(headers or {})
        request_content: bytes | AsyncIterable[bytes] | None = content
        if body is not None:
            request_content = json.dumps(body, separators=(",", ":")).encode("utf-8")
            extra["Content-Type"] = "application/json"
        request = self._client.build_request(
            method,
            path,
            params=None if params is None else tuple(params),
            content=request_content,
            headers=extra,
            timeout=httpx.Timeout(read_seconds, connect=_CONNECT_SECONDS),
        )
        try:
            response = await self._client.send(request, stream=True)
        except httpx.HTTPError as error:
            raise _transport_error(error, sent=True) from None
        if response.status_code in expect:
            return response
        try:
            raise await self._error_for(response)
        finally:
            await response.aclose()

    async def _read(self, response: httpx.Response, limit: int) -> bytes:
        """The whole body, at most `limit` bytes; the response is closed afterwards."""
        data = bytearray()
        try:
            async for piece in response.aiter_bytes():
                data += piece
                if len(data) > limit:
                    raise SpsError(
                        "provider_error", "The response body is too large", outcome="unknown"
                    )
        except httpx.HTTPError as error:
            raise _transport_error(error, sent=True) from None
        finally:
            await response.aclose()
        return bytes(data)

    async def _error_for(self, response: httpx.Response) -> SpsError:
        status = response.status_code
        if 300 <= status < 400:
            return SpsError(
                "provider_error", "The provider answered with a redirect", outcome="unknown"
            )
        try:
            raw = await self._read(response, _MAX_ERROR_BYTES)
            document = json.loads(raw)
        except SpsError as error:
            return error
        except ValueError:
            document = None
        if document is None:
            return SpsError(
                "provider_error",
                f"The provider answered with HTTP {status} and no valid error body",
                outcome="unknown",
            )
        parsed = error_from_json(document)
        retry = parsed.retry_after_seconds
        if retry is None:
            header = response.headers.get("Retry-After", "")
            if header.isdigit():
                retry = int(header)
        return SpsError(
            parsed.code,
            self._scrub(parsed.message),
            outcome=parsed.outcome,
            retry_after_seconds=retry,
        )

    async def _json(
        self,
        cls: type[T],
        method: str,
        path: str,
        *,
        read_seconds: float = _DEFAULT_READ_SECONDS,
        expect: tuple[int, ...] = (200,),
        **kwargs: Any,
    ) -> T:
        response = await self._send(
            method, path, read_seconds=read_seconds, expect=expect, **kwargs
        )
        return self._parse(cls, await self._read(response, _MAX_JSON_BYTES))

    def _parse(self, cls: type[T], raw: bytes) -> T:
        try:
            return from_json(cls, json.loads(raw))
        except (ValueError, WireError):
            # WireError is a ValueError; its text is ours, but the document may quote anything.
            raise SpsError(
                "provider_error", "The response did not match the 1.0 schema", outcome="unknown"
            ) from None

    async def _ack(self, method: str, path: str, **kwargs: Any) -> None:
        response = await self._send(method, path, **kwargs)
        raw = await self._read(response, _MAX_JSON_BYTES)
        try:
            ok = json.loads(raw) == {}
        except ValueError:
            ok = False
        if not ok:
            raise SpsError(
                "provider_error", "The response was not the empty object", outcome="unknown"
            )

    @staticmethod
    def _sandbox_path(sandbox_id: str, tail: str = "") -> str:
        return f"/v1/sandboxes/{_id(sandbox_id, 'sandbox_id')}{tail}"

    @staticmethod
    def _snapshot_path(snapshot_id: str, tail: str = "") -> str:
        return f"/v1/snapshots/{_id(snapshot_id, 'snapshot_id')}{tail}"

    def _process_path(self, sandbox_id: str, process_id: str, tail: str) -> str:
        return self._sandbox_path(sandbox_id, f"/processes/{_id(process_id, 'process_id')}{tail}")

    # --- required operations ----------------------------------------------------------------

    async def discovery(self) -> Discovery:
        return await self._json(Discovery, "GET", "/v1/discovery")

    async def create(self, request: CreateRequest, *, idempotency_key: str) -> Sandbox:
        if not _IDEMPOTENCY_KEY.fullmatch(idempotency_key):
            raise SpsError("invalid_request", "idempotency_key is not a valid key")
        return await self._json(
            Sandbox,
            "POST",
            "/v1/sandboxes",
            body=to_json(request),
            headers={"Idempotency-Key": idempotency_key},
            expect=(200, 201),
        )

    async def get(self, sandbox_id: str) -> Sandbox:
        return await self._json(Sandbox, "GET", self._sandbox_path(sandbox_id))

    async def list(
        self,
        *,
        labels: Mapping[str, str] | None = None,
        cursor: str | None = None,
        limit: int = 100,
    ) -> SandboxPage:
        params = [("label", f"{key}={value}") for key, value in (labels or {}).items()]
        if cursor is not None:
            params.append(("cursor", cursor))
        params.append(("limit", str(limit)))
        return await self._json(SandboxPage, "GET", "/v1/sandboxes", params=params)

    async def destroy(self, sandbox_id: str) -> DestroyResult:
        return await self._json(DestroyResult, "DELETE", self._sandbox_path(sandbox_id))

    async def run(self, sandbox_id: str, request: RunRequest) -> RunResult:
        return await self._json(
            RunResult,
            "POST",
            self._sandbox_path(sandbox_id, "/run"),
            body=to_json(request),
            read_seconds=request.timeout_ms / 1000 + _SLACK_SECONDS,
        )

    async def files_read(self, sandbox_id: str, path: str) -> FileStream:
        response = await self._send(
            "GET", self._sandbox_path(sandbox_id, "/files"), params=[("path", path)]
        )
        if response.headers.get("Content-Encoding", "identity").lower() != "identity":
            await response.aclose()
            raise SpsError(
                "provider_error", "The file body has a content encoding", outcome="unknown"
            )
        length = response.headers.get("Content-Length")
        size = int(length) if length is not None and length.isdigit() else None
        return FileStream(size=size, chunks=_BodyStream(response, size))

    async def files_write(
        self,
        sandbox_id: str,
        path: str,
        data: AsyncIterable[bytes],
        *,
        size: int,
        user: str | None = None,
    ) -> FileInfo:
        if size < 0:
            raise SpsError("invalid_request", "size cannot be negative")

        async def body() -> AsyncIterator[bytes]:
            sent = 0
            async for piece in data:
                for start in range(0, len(piece), CHUNK_BYTES):
                    part = piece[start : start + CHUNK_BYTES]
                    sent += len(part)
                    if sent > size:
                        raise SpsError("invalid_request", "The data is longer than size")
                    yield part
            if sent != size:
                raise SpsError("invalid_request", "The data is shorter than size")

        return await self._json(
            FileInfo,
            "PUT",
            self._sandbox_path(sandbox_id, "/files"),
            params=[("path", path), *([("user", user)] if user is not None else [])],
            content=body(),
            headers={"Content-Type": "application/octet-stream", "Content-Length": str(size)},
        )

    async def process_start(self, sandbox_id: str, request: ProcessStartRequest) -> Process:
        return await self._json(
            Process,
            "POST",
            self._sandbox_path(sandbox_id, "/processes"),
            body=to_json(request),
        )

    async def process_output(
        self, sandbox_id: str, process_id: str, *, cursor: str | None = None, wait_ms: int = 0
    ) -> OutputPage:
        params = [("wait_ms", str(wait_ms))]
        if cursor is not None:
            params.append(("cursor", cursor))
        return await self._json(
            OutputPage,
            "GET",
            self._process_path(sandbox_id, process_id, "/output"),
            params=None if params is None else tuple(params),
            read_seconds=wait_ms / 1000 + _SLACK_SECONDS,
        )

    async def cost(self, sandbox_id: str, *, created_at: datetime | None = None) -> Cost:
        params = None if created_at is None else [("created_at", timestamp(created_at))]
        return await self._json(Cost, "GET", self._sandbox_path(sandbox_id, "/cost"), params=params)

    async def account_cost(self, start: datetime, end: datetime) -> AccountCost:
        params = [("start", timestamp(start)), ("end", timestamp(end))]
        return await self._json(AccountCost, "GET", "/v1/cost", params=params)

    # --- optional operations ----------------------------------------------------------------

    async def cost_capture(self, sandbox_id: str, *, idempotency_key: str) -> Cost:
        if not _IDEMPOTENCY_KEY.fullmatch(idempotency_key):
            raise SpsError("invalid_request", "idempotency_key is not a valid key")
        return await self._json(
            Cost,
            "POST",
            self._sandbox_path(sandbox_id, "/cost/capture"),
            headers={"Idempotency-Key": idempotency_key},
        )

    async def account_capacity(self) -> AccountCapacity:
        return await self._json(AccountCapacity, "GET", "/v1/account/capacity")

    async def files_link(self, sandbox_id: str, request: FileLinkRequest) -> FileLink:
        return await self._json(
            FileLink,
            "POST",
            self._sandbox_path(sandbox_id, "/file-links"),
            body=to_json(request),
        )

    async def pause(self, sandbox_id: str) -> Sandbox:
        return await self._json(Sandbox, "POST", self._sandbox_path(sandbox_id, "/pause"), body={})

    async def resume(self, sandbox_id: str) -> Sandbox:
        return await self._json(Sandbox, "POST", self._sandbox_path(sandbox_id, "/resume"), body={})

    async def lifetime_extend(self, sandbox_id: str, seconds: int) -> Sandbox:
        return await self._json(
            Sandbox,
            "POST",
            self._sandbox_path(sandbox_id, "/lifetime"),
            body={"seconds": seconds},
        )

    async def process_write_stdin(self, sandbox_id: str, process_id: str, data: bytes) -> None:
        await self._ack(
            "POST",
            self._process_path(sandbox_id, process_id, "/stdin"),
            content=data,
            headers={"Content-Type": "application/octet-stream"},
        )

    async def process_close_stdin(self, sandbox_id: str, process_id: str) -> None:
        await self._ack("DELETE", self._process_path(sandbox_id, process_id, "/stdin"))

    async def process_cancel(self, sandbox_id: str, process_id: str) -> None:
        await self._ack("POST", self._process_path(sandbox_id, process_id, "/cancel"), body={})

    async def preview_link(
        self,
        sandbox_id: str,
        port: int,
        *,
        access: PreviewAccess = "public",
        lifetime_seconds: int | None = None,
    ) -> PreviewLink:
        body: dict[str, Any] = {"port": port}
        if access != "public":
            body["access"] = access
        if lifetime_seconds is not None:
            body["lifetime_seconds"] = lifetime_seconds
        return await self._json(
            PreviewLink, "POST", self._sandbox_path(sandbox_id, "/previews"), body=body
        )

    async def preview_revoke(self, sandbox_id: str, preview_id: str) -> None:
        path = self._sandbox_path(sandbox_id, f"/previews/{_id(preview_id, 'preview_id')}")
        await self._ack("DELETE", path)

    async def labels_update(self, sandbox_id: str, labels: Mapping[str, str]) -> Sandbox:
        return await self._json(
            Sandbox,
            "PATCH",
            self._sandbox_path(sandbox_id, "/labels"),
            body={"labels": dict(labels)},
        )

    async def tcp_link(self, sandbox_id: str, port: int) -> TcpLink:
        return await self._json(
            TcpLink, "POST", self._sandbox_path(sandbox_id, "/tcp-links"), body={"port": port}
        )

    async def files_list(
        self, sandbox_id: str, path: str, *, cursor: str | None = None, limit: int = 100
    ) -> DirectoryPage:
        params = [("path", path)]
        if cursor is not None:
            params.append(("cursor", cursor))
        params.append(("limit", str(limit)))
        return await self._json(
            DirectoryPage, "GET", self._sandbox_path(sandbox_id, "/directories"), params=params
        )

    async def files_mkdir(self, sandbox_id: str, path: str, *, parents: bool = False) -> None:
        await self._ack(
            "POST",
            self._sandbox_path(sandbox_id, "/directories"),
            body={"path": path, "parents": parents},
        )

    async def files_remove(self, sandbox_id: str, path: str, *, recursive: bool = False) -> None:
        await self._ack(
            "DELETE",
            self._sandbox_path(sandbox_id, "/files"),
            params=[("path", path), ("recursive", "true" if recursive else "false")],
        )

    async def files_exists(self, sandbox_id: str, path: str) -> PathInfo:
        return await self._json(
            PathInfo,
            "GET",
            self._sandbox_path(sandbox_id, "/files/exists"),
            params=[("path", path)],
        )

    async def snapshot_create(
        self, sandbox_id: str, request: SnapshotRequest, *, idempotency_key: str
    ) -> Snapshot:
        if not _IDEMPOTENCY_KEY.fullmatch(idempotency_key):
            raise SpsError("invalid_request", "idempotency_key is not a valid key")
        return await self._json(
            Snapshot,
            "POST",
            self._sandbox_path(sandbox_id, "/snapshots"),
            body=to_json(request),
            headers={"Idempotency-Key": idempotency_key},
            expect=(200, 201),
        )

    async def snapshot_get(self, snapshot_id: str) -> Snapshot:
        return await self._json(Snapshot, "GET", self._snapshot_path(snapshot_id))

    async def snapshot_list(
        self,
        *,
        labels: Mapping[str, str] | None = None,
        sandbox_id: str | None = None,
        cursor: str | None = None,
        limit: int = 100,
    ) -> SnapshotPage:
        params = [("label", f"{key}={value}") for key, value in (labels or {}).items()]
        if sandbox_id is not None:
            params.append(("sandbox_id", _id(sandbox_id, "sandbox_id")))
        if cursor is not None:
            params.append(("cursor", cursor))
        params.append(("limit", str(limit)))
        return await self._json(SnapshotPage, "GET", "/v1/snapshots", params=params)

    async def snapshot_delete(self, snapshot_id: str) -> SnapshotDeleteResult:
        return await self._json(SnapshotDeleteResult, "DELETE", self._snapshot_path(snapshot_id))

    async def image_cost(self, image_id: str, *, created_at: datetime | None = None) -> Cost:
        params = None if created_at is None else (("created_at", timestamp(created_at)),)
        return await self._json(
            Cost, "GET", f"/v1/images/{_id(image_id, 'image_id')}/cost", params=params
        )

    async def snapshot_cost(self, snapshot_id: str) -> Cost:
        return await self._json(Cost, "GET", self._snapshot_path(snapshot_id, "/cost"))

    @staticmethod
    def _image_path(image_id: str) -> str:
        return f"/v1/images/{_id(image_id, 'image_id')}"

    async def image_prepare(
        self,
        request: ImageRequest,
        *,
        context: AsyncIterable[bytes] | None = None,
        context_size: int | None = None,
        idempotency_key: str,
    ) -> PreparedImage:
        if not _IDEMPOTENCY_KEY.fullmatch(idempotency_key):
            raise SpsError("invalid_request", "idempotency_key is not a valid key")
        if context_size is not None and context_size < 0:
            raise SpsError("invalid_request", "context_size cannot be negative")
        boundary = secrets.token_hex(24)
        head = _form_part(
            boundary, "request", json.dumps(to_json(request)).encode(), "application/json"
        )
        content, length = _multipart_body(boundary, head, context, context_size)
        headers = {
            "Idempotency-Key": idempotency_key,
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        }
        if length is not None:
            headers["Content-Length"] = str(length)
        return await self._json(
            PreparedImage,
            "POST",
            "/v1/images",
            content=content,
            headers=headers,
            expect=(200, 201),
            read_seconds=_IMAGE_PREPARE_READ_SECONDS,
        )

    async def image_get(self, image_id: str) -> PreparedImage:
        return await self._json(PreparedImage, "GET", self._image_path(image_id))

    async def image_list(
        self,
        *,
        labels: Mapping[str, str] | None = None,
        cursor: str | None = None,
        limit: int = 100,
    ) -> ImagePage:
        params = [("label", f"{key}={value}") for key, value in (labels or {}).items()]
        if cursor is not None:
            params.append(("cursor", cursor))
        params.append(("limit", str(limit)))
        return await self._json(ImagePage, "GET", "/v1/images", params=params)

    async def image_delete(self, image_id: str) -> ImageDeleteResult:
        return await self._json(ImageDeleteResult, "DELETE", self._image_path(image_id))

    async def terminal_link(self, sandbox_id: str, request: TerminalRequest) -> TerminalLink:
        """Call `terminal.open` and return the link, without connecting to it."""
        return await self._json(
            TerminalLink,
            "POST",
            self._sandbox_path(sandbox_id, "/terminals"),
            body=to_json(request),
        )

    async def terminal_connect(self, link: TerminalLink) -> Terminal:
        """Connect to a terminal link, sending only its URL and `headers`: never this provider's
        `Authorization` header, so that a link works for a client with no account token.

        A refusal before the upgrade (a used or expired link) is an `SpsError` whose code is the
        one in the refusal's error body, or the one that its HTTP status names."""
        parts = urlsplit(link.url)
        if parts.scheme not in ("ws", "wss") or not parts.hostname:
            raise SpsError(
                "provider_error", "The terminal link is not a WebSocket URL", outcome="unknown"
            )
        if parts.scheme == "ws" and not (self._plain_http_ok or _is_loopback(parts.hostname)):
            raise SpsError(
                "provider_error", "The terminal link is plain WebSocket", outcome="unknown"
            )
        try:
            socket = await websockets.asyncio.client.connect(
                link.url,
                additional_headers=dict(link.headers),
                proxy=None,
                compression=None,
                max_size=TERMINAL_FRAME_BYTES * 4,
                open_timeout=_CONNECT_SECONDS,
            )
        except websockets.exceptions.InvalidStatus as error:
            raise _refusal(error.response.status_code, error.response.body) from None
        except TimeoutError:
            raise SpsError("timeout", "The terminal link did not answer in time") from None
        except (websockets.exceptions.WebSocketException, OSError):
            raise SpsError("unavailable", "Could not connect to the terminal link") from None
        return _WebSocketTerminal(socket)

    async def terminal_open(self, sandbox_id: str, request: TerminalRequest) -> Terminal:
        return await self.terminal_connect(await self.terminal_link(sandbox_id, request))

    async def aclose(self) -> None:
        await self._client.aclose()
