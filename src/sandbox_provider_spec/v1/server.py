# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The reference server: any `Provider` class served over the 1.0 HTTP API.

`create_app(provider_class)` returns a hand-written ASGI application. It builds the adapter's
credentials from each request's bearer token (section 13 of the standard), keeps a bounded
number of adapter instances, and turns every operation of the OpenAPI file into a call of the
matching `Provider` method. It adds no behavior of its own beyond the wire rules: it checks
request bodies against the OpenAPI schemas, streams files in both directions and maps errors to
the error body.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, MutableMapping
from dataclasses import dataclass
from functools import cache
from typing import Any
from urllib.parse import parse_qsl

from jsonschema import Draft202012Validator, FormatChecker

from sandbox_provider_spec.v1 import tokens
from sandbox_provider_spec.v1._spec_files import registry, schema_ref
from sandbox_provider_spec.v1.errors import SpsError
from sandbox_provider_spec.v1.provider import Provider
from sandbox_provider_spec.v1.types import (
    CreateRequest,
    FileLinkRequest,
    ProcessStartRequest,
    RunRequest,
)
from sandbox_provider_spec.v1.wire import WireError, error_to_json, from_json, to_json

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
App = Callable[[Scope, Receive, Send], Awaitable[None]]

MAX_INSTANCES = 64
IDLE_SECONDS = 300.0
MAX_JSON_BYTES = 1024 * 1024
CHUNK_BYTES = 1024 * 1024

_ID = r"([^/]+)"
_IDEMPOTENCY_KEY = re.compile(r"^[a-z0-9][a-z0-9-]{7,62}$")
_ENTITY_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_LABEL = re.compile(r"^[^=]+=.*$", re.DOTALL)


class _StreamAborted(Exception):
    """A response stream failed after its status line was sent; the connection is dropped."""

    def __init__(self) -> None:
        super().__init__("response stream aborted")


# --- the pool of adapter instances ----------------------------------------------------------


@dataclass
class _Entry:
    provider: Provider
    last_used: float
    in_flight: int = 0


class _Pool:
    """At most `limit` adapter instances, one for each distinct token, closed when idle too long."""

    def __init__(
        self,
        provider_class: type[Provider],
        *,
        limit: int,
        idle_seconds: float,
        clock: Callable[[], float],
    ) -> None:
        self._class = provider_class
        self._limit = limit
        self._idle = idle_seconds
        self._clock = clock
        self._entries: dict[str, _Entry] = {}

    def _credentials(self, token: str) -> dict[str, str]:
        names = [item.name for item in self._class.credential_fields]
        if not names:
            return {}
        if len(names) == 1:
            return {names[0]: token}
        return tokens.decode(token, names)

    def _expired(self) -> list[_Entry]:
        now = self._clock()
        dead = [
            key
            for key, entry in self._entries.items()
            if entry.in_flight == 0 and now - entry.last_used >= self._idle
        ]
        return [self._entries.pop(key) for key in dead]

    async def sweep(self) -> None:
        await _close_all(self._expired())

    async def acquire(self, token: str) -> tuple[str, Provider]:
        await self.sweep()
        key = hashlib.sha256(token.encode("utf-8")).hexdigest()
        entry = self._entries.get(key)
        if entry is None:
            credentials = self._credentials(token)
            victims: list[_Entry] = []
            if len(self._entries) >= self._limit:
                idle = sorted(
                    (k for k, e in self._entries.items() if e.in_flight == 0),
                    key=lambda k: self._entries[k].last_used,
                )
                if not idle:
                    raise SpsError(
                        "unavailable",
                        "Too many accounts are in use at once",
                        retry_after_seconds=1,
                    )
                victims.append(self._entries.pop(idle[0]))
            await _close_all(victims)
            entry = _Entry(self._class(credentials), self._clock())
            self._entries[key] = entry
        entry.in_flight += 1
        entry.last_used = self._clock()
        return key, entry.provider

    def release(self, key: str) -> None:
        entry = self._entries.get(key)
        if entry is not None:
            entry.in_flight -= 1
            entry.last_used = self._clock()

    async def close(self) -> None:
        entries, self._entries = list(self._entries.values()), {}
        await _close_all(entries)


async def _close_all(entries: list[_Entry]) -> None:
    for entry in entries:
        try:
            await entry.provider.aclose()
        except Exception:  # pylint: disable=broad-exception-caught
            pass  # a failing close must not fail the request that triggered it


# --- request validation ---------------------------------------------------------------------


@cache
def _validator(schema: str) -> Draft202012Validator:
    return Draft202012Validator(
        schema_ref(schema), registry=registry(), format_checker=FormatChecker()
    )


def _check(schema: str, data: Any, what: str) -> None:
    errors = sorted(_validator(schema).iter_errors(data), key=lambda e: list(e.path))
    if errors:
        first = errors[0]
        where = "/".join(map(str, first.path)) or "(root)"
        raise SpsError("invalid_request", f"{what} is not valid at {where}: {first.message[:200]}")


def _entity(value: str, what: str) -> str:
    if not _ENTITY_ID.fullmatch(value):
        raise SpsError("invalid_request", f"{what} is not a valid id")
    return value


class _Request:
    """One HTTP request: its parts, and readers for its body."""

    def __init__(self, scope: Scope, receive: Receive) -> None:
        self.method: str = scope["method"]
        self.path_params: tuple[str, ...] = ()
        self._receive = receive
        self.headers: dict[str, str] = {}
        for name, value in scope.get("headers", []):
            self.headers.setdefault(name.decode("latin-1").lower(), value.decode("latin-1"))
        self._query = parse_qsl(
            scope.get("query_string", b"").decode("utf-8", "replace"), keep_blank_values=True
        )
        self._used: set[str] = set()
        self.stream_error: SpsError | None = None

    # query string

    def query_all(self, name: str) -> list[str]:
        self._used.add(name)
        return [value for key, value in self._query if key == name]

    def query_one(self, name: str, *, required: bool = False) -> str | None:
        values = self.query_all(name)
        if len(values) > 1:
            raise SpsError("invalid_request", f"Query parameter {name!r} is repeated")
        if not values:
            if required:
                raise SpsError("invalid_request", f"Query parameter {name!r} is required")
            return None
        return values[0]

    def query_int(self, name: str, default: int, minimum: int) -> int:
        text = self.query_one(name)
        if text is None:
            return default
        if not re.fullmatch(r"[0-9]{1,18}", text) or int(text) < minimum:
            raise SpsError(
                "invalid_request", f"Query parameter {name!r} must be at least {minimum}"
            )
        return int(text)

    def check_query_used(self) -> None:
        for key, _ in self._query:
            if key not in self._used:
                raise SpsError("invalid_request", f"Unknown query parameter {key!r}")

    # body

    def content_length(self) -> int | None:
        text = self.headers.get("content-length")
        if text is None:
            return None
        if not re.fullmatch(r"[0-9]{1,18}", text):
            raise SpsError("invalid_request", "Content-Length is not a number")
        return int(text)

    async def read_all(self, limit: int) -> bytes:
        declared = self.content_length()
        if declared is not None and declared > limit:
            raise SpsError("too_large", f"The body is over {limit} bytes")
        body = bytearray()
        while True:
            message = await self._receive()
            if message["type"] == "http.disconnect":
                raise SpsError("invalid_request", "The connection ended before the body")
            body += message.get("body", b"")
            if len(body) > limit:
                raise SpsError("too_large", f"The body is over {limit} bytes")
            if not message.get("more_body", False):
                return bytes(body)

    async def json_body(self, schema: str, *, empty_ok: bool = False) -> Any:
        raw = await self.read_all(MAX_JSON_BYTES)
        if not raw.strip():
            if not empty_ok:
                raise SpsError("invalid_request", "The request needs a JSON body")
            data: Any = {}
        else:
            try:
                data = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                raise SpsError("invalid_request", "The body is not valid JSON") from None
        _check(schema, data, "The body")
        return data

    async def typed_body(self, cls: type[Any]) -> Any:
        """A JSON body as a 1.0 value; an unknown field or a bad value is `invalid_request`."""
        raw = await self.read_all(MAX_JSON_BYTES)
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise SpsError("invalid_request", "The body is not valid JSON") from None
        try:
            return from_json(cls, data)
        except WireError as error:
            raise SpsError("invalid_request", str(error)[:1000]) from None
        except (ValueError, TypeError, KeyError):
            raise SpsError("invalid_request", "The body does not fit its schema") from None

    async def upload(self, size: int) -> AsyncIterator[bytes]:
        """The body as chunks of at most 1 MiB. A body that is not exactly `size` bytes sets
        `stream_error` and ends the stream with that error."""
        seen = 0
        while True:
            message = await self._receive()
            if message["type"] == "http.disconnect":
                self._fail("The connection ended before the whole body arrived")
            chunk: bytes = message.get("body", b"")
            seen += len(chunk)
            if seen > size:
                self._fail("The body is longer than Content-Length")
            for start in range(0, len(chunk), CHUNK_BYTES):
                yield chunk[start : start + CHUNK_BYTES]
            if not message.get("more_body", False):
                if seen != size:
                    self._fail("The body is shorter than Content-Length")
                return

    def _fail(self, message: str) -> None:
        self.stream_error = SpsError("invalid_request", message)
        raise self.stream_error


# --- responses ------------------------------------------------------------------------------


def _head(status: int, headers: list[tuple[str, str]]) -> Message:
    return {
        "type": "http.response.start",
        "status": status,
        "headers": [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in headers],
    }


async def _send_json(send: Send, status: int, body: Any, request_id: str, extra: Any = ()) -> None:
    payload = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    headers = [
        ("content-type", "application/json"),
        ("content-length", str(len(payload))),
        ("request-id", request_id),
        *extra,
    ]
    await send(_head(status, headers))
    await send({"type": "http.response.body", "body": payload})


async def _send_error(send: Send, error: SpsError, request_id: str) -> None:
    extra = []
    if error.retry_after_seconds is not None:
        extra.append(("retry-after", str(error.retry_after_seconds)))
    await _send_json(send, error.http_status, error_to_json(error), request_id, extra)


# --- operations -----------------------------------------------------------------------------

Reply = tuple[int, Any]  # a JSON status and body; a file read sends its own response


async def _discovery(p: Provider, r: _Request) -> Reply:
    r.check_query_used()
    return 200, to_json(await p.discovery())


async def _create(p: Provider, r: _Request) -> Reply:
    key = r.headers.get("idempotency-key", "")
    if not _IDEMPOTENCY_KEY.fullmatch(key):
        raise SpsError("invalid_request", "Idempotency-Key must be 8 to 63 of a-z 0-9 -")
    request: CreateRequest = await r.typed_body(CreateRequest)
    # The provider interface does not say whether a create was a repeat, so every success is 201.
    return 201, to_json(await p.create(request, idempotency_key=key))


async def _list(p: Provider, r: _Request) -> Reply:
    labels: dict[str, str] = {}
    for item in r.query_all("label"):
        if not _LABEL.fullmatch(item):
            raise SpsError("invalid_request", "A label filter must be <key>=<value>")
        key, _, value = item.partition("=")
        if labels.setdefault(key, value) != value:
            raise SpsError("invalid_request", f"Label {key!r} is filtered twice")
    cursor = r.query_one("cursor")
    if cursor == "":
        raise SpsError("invalid_request", "Query parameter 'cursor' cannot be empty")
    limit = r.query_int("limit", 100, 1)
    r.check_query_used()
    page = await p.list(labels=labels or None, cursor=cursor, limit=limit)
    return 200, to_json(page)


async def _get(p: Provider, r: _Request) -> Reply:
    r.check_query_used()
    return 200, to_json(await p.get(_entity(r.path_params[0], "sandbox_id")))


async def _destroy(p: Provider, r: _Request) -> Reply:
    r.check_query_used()
    return 200, to_json(await p.destroy(_entity(r.path_params[0], "sandbox_id")))


async def _run(p: Provider, r: _Request) -> Reply:
    sandbox_id = _entity(r.path_params[0], "sandbox_id")
    request: RunRequest = await r.typed_body(RunRequest)
    return 200, to_json(await p.run(sandbox_id, request))


async def _process_start(p: Provider, r: _Request) -> Reply:
    sandbox_id = _entity(r.path_params[0], "sandbox_id")
    request: ProcessStartRequest = await r.typed_body(ProcessStartRequest)
    return 200, to_json(await p.process_start(sandbox_id, request))


async def _process_output(p: Provider, r: _Request) -> Reply:
    sandbox_id = _entity(r.path_params[0], "sandbox_id")
    process_id = _entity(r.path_params[1], "process_id")
    cursor = r.query_one("cursor")
    if cursor == "":
        raise SpsError("invalid_request", "Query parameter 'cursor' cannot be empty")
    wait_ms = r.query_int("wait_ms", 0, 0)
    r.check_query_used()
    page = await p.process_output(sandbox_id, process_id, cursor=cursor, wait_ms=wait_ms)
    return 200, to_json(page)


async def _cost(p: Provider, r: _Request) -> Reply:
    r.check_query_used()
    return 200, to_json(await p.cost(_entity(r.path_params[0], "sandbox_id")))


async def _files_write(p: Provider, r: _Request) -> Reply:
    sandbox_id = _entity(r.path_params[0], "sandbox_id")
    path = _file_path(r)
    r.check_query_used()
    size = r.content_length()
    if size is None:
        raise SpsError("invalid_request", "files.write needs a Content-Length header")
    try:
        info = await p.files_write(sandbox_id, path, r.upload(size), size=size)
    except Exception:
        if r.stream_error is not None:
            raise r.stream_error from None
        raise
    if r.stream_error is not None:
        raise r.stream_error
    return 200, to_json(info)


def _file_path(r: _Request) -> str:
    path = r.query_one("path", required=True)
    assert path is not None
    _check("FilePath", path, "The path")
    if any(len(part.encode("utf-8")) > 255 for part in path.split("/")):
        raise SpsError("invalid_request", "A path component is over 255 bytes")
    return path


async def _files_link(p: Provider, r: _Request) -> Reply:
    sandbox_id = _entity(r.path_params[0], "sandbox_id")
    request: FileLinkRequest = await r.typed_body(FileLinkRequest)
    return 200, to_json(await p.files_link(sandbox_id, request))


async def _pause(p: Provider, r: _Request) -> Reply:
    sandbox_id = _entity(r.path_params[0], "sandbox_id")
    await r.json_body("EmptyObject", empty_ok=True)
    return 200, to_json(await p.pause(sandbox_id))


async def _resume(p: Provider, r: _Request) -> Reply:
    sandbox_id = _entity(r.path_params[0], "sandbox_id")
    await r.json_body("EmptyObject", empty_ok=True)
    return 200, to_json(await p.resume(sandbox_id))


async def _lifetime_extend(p: Provider, r: _Request) -> Reply:
    sandbox_id = _entity(r.path_params[0], "sandbox_id")
    body = await r.json_body("LifetimeExtendRequest")
    return 200, to_json(await p.lifetime_extend(sandbox_id, body["seconds"]))


async def _write_stdin(p: Provider, r: _Request) -> Reply:
    sandbox_id = _entity(r.path_params[0], "sandbox_id")
    process_id = _entity(r.path_params[1], "process_id")
    data = await r.read_all(MAX_JSON_BYTES)
    await p.process_write_stdin(sandbox_id, process_id, data)
    return 200, {}


async def _close_stdin(p: Provider, r: _Request) -> Reply:
    await p.process_close_stdin(
        _entity(r.path_params[0], "sandbox_id"), _entity(r.path_params[1], "process_id")
    )
    return 200, {}


async def _cancel(p: Provider, r: _Request) -> Reply:
    sandbox_id = _entity(r.path_params[0], "sandbox_id")
    process_id = _entity(r.path_params[1], "process_id")
    await r.json_body("EmptyObject", empty_ok=True)
    await p.process_cancel(sandbox_id, process_id)
    return 200, {}


async def _preview(p: Provider, r: _Request) -> Reply:
    sandbox_id = _entity(r.path_params[0], "sandbox_id")
    body = await r.json_body("PreviewRequest")
    return 200, to_json(await p.preview_link(sandbox_id, body["port"]))


async def _tcp(p: Provider, r: _Request) -> Reply:
    sandbox_id = _entity(r.path_params[0], "sandbox_id")
    body = await r.json_body("TcpLinkRequest")
    return 200, to_json(await p.tcp_link(sandbox_id, body["port"]))


_Handler = Callable[[Provider, _Request], Awaitable[Reply]]

_S = rf"/v1/sandboxes/{_ID}"
_P = rf"{_S}/processes/{_ID}"
# (method, path pattern, handler); `files.read` is the one route that does not reply with JSON.
_ROUTES: list[tuple[str, re.Pattern[str], _Handler | None]] = [
    (m, re.compile(f"^{pattern}$"), handler)
    for m, pattern, handler in [
        ("GET", "/v1/discovery", _discovery),
        ("POST", "/v1/sandboxes", _create),
        ("GET", "/v1/sandboxes", _list),
        ("GET", _S, _get),
        ("DELETE", _S, _destroy),
        ("POST", f"{_S}/run", _run),
        ("GET", f"{_S}/files", None),
        ("PUT", f"{_S}/files", _files_write),
        ("POST", f"{_S}/processes", _process_start),
        ("GET", f"{_P}/output", _process_output),
        ("GET", f"{_S}/cost", _cost),
        ("POST", f"{_S}/file-links", _files_link),
        ("POST", f"{_S}/pause", _pause),
        ("POST", f"{_S}/resume", _resume),
        ("POST", f"{_S}/lifetime", _lifetime_extend),
        ("POST", f"{_P}/stdin", _write_stdin),
        ("DELETE", f"{_P}/stdin", _close_stdin),
        ("POST", f"{_P}/cancel", _cancel),
        ("POST", f"{_S}/previews", _preview),
        ("POST", f"{_S}/tcp-links", _tcp),
    ]
]


def _bearer(request: _Request) -> str:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token or not token.isascii() or not token.isprintable():
        raise SpsError("unauthenticated", "A bearer token is required")
    return token


async def _send_file(send: Send, stream: Any, request_id: str) -> None:
    size = stream.size
    headers = [("content-type", "application/octet-stream"), ("request-id", request_id)]
    if size is not None:
        headers.append(("content-length", str(size)))
    chunks = stream.chunks
    sent = 0
    started = False
    try:
        async for chunk in chunks:
            for start in range(0, len(chunk), CHUNK_BYTES):
                part = chunk[start : start + CHUNK_BYTES]
                sent += len(part)
                if size is not None and sent > size:
                    raise _StreamAborted
                if not started:
                    await send(_head(200, headers))
                    started = True
                await send({"type": "http.response.body", "body": part, "more_body": True})
        if size is not None and sent != size:
            raise _StreamAborted
    except SpsError:
        if not started:
            raise
        raise _StreamAborted from None
    except _StreamAborted:
        raise
    except Exception:
        if not started:
            raise
        raise _StreamAborted from None
    finally:
        close = getattr(chunks, "aclose", None)
        if close is not None:
            await close()
    if not started:
        await send(_head(200, headers))
    await send({"type": "http.response.body", "body": b"", "more_body": False})


# --- the application ------------------------------------------------------------------------


def create_app(
    provider_class: type[Provider],
    *,
    max_instances: int = MAX_INSTANCES,
    idle_seconds: float = IDLE_SECONDS,
    clock: Callable[[], float] = time.monotonic,
) -> App:
    """An ASGI application that serves `provider_class` over the 1.0 HTTP API."""
    pool = _Pool(provider_class, limit=max_instances, idle_seconds=idle_seconds, clock=clock)

    async def lifespan(receive: Receive, send: Send) -> None:
        sweeper: asyncio.Task[None] | None = None

        async def sweep_forever() -> None:
            while True:
                await asyncio.sleep(max(1.0, min(30.0, idle_seconds / 2)))
                await pool.sweep()

        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                sweeper = asyncio.create_task(sweep_forever())
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                if sweeper is not None:
                    sweeper.cancel()
                await pool.close()
                await send({"type": "lifespan.shutdown.complete"})
                return

    async def http(scope: Scope, receive: Receive, send: Send) -> None:
        request_id = uuid.uuid4().hex
        request = _Request(scope, receive)
        key: str | None = None
        try:
            handler: _Handler | None = None
            found = False
            for method, pattern, candidate in _ROUTES:
                match = pattern.match(scope["path"])
                if match and method == request.method:
                    request.path_params = match.groups()
                    handler, found = candidate, True
                    break
            if not found:
                raise SpsError("not_found", "No such operation")
            key, provider = await pool.acquire(_bearer(request))
            if handler is None:
                sandbox_id = _entity(request.path_params[0], "sandbox_id")
                path = _file_path(request)
                request.check_query_used()
                stream = await provider.files_read(sandbox_id, path)
                await _send_file(send, stream, request_id)
            else:
                status, body = await handler(provider, request)
                await _send_json(send, status, body, request_id)
        except SpsError as error:
            await _send_error(send, error, request_id)
        except _StreamAborted:
            raise
        except Exception:  # pylint: disable=broad-exception-caught
            # Nothing of the exception reaches the response: it may hold a credential.
            internal = SpsError("provider_error", "internal error", outcome="unknown")
            await _send_error(send, internal, request_id)
        finally:
            if key is not None:
                pool.release(key)

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await lifespan(receive, send)
        elif scope["type"] == "http":
            await http(scope, receive, send)

    return app


def run_server(
    provider_class: type[Provider], *, host: str, port: int | None, socket: str | None
) -> None:
    """Serve `provider_class` with uvicorn until interrupted."""
    # pylint: disable-next=import-outside-toplevel
    import uvicorn  # noqa: PLC0415 - the `http` extra; the rest of this module needs only the base install

    app = create_app(provider_class)
    if socket is not None:
        uvicorn.run(app, uds=socket, access_log=False, server_header=False, log_level="warning")
    else:
        assert port is not None
        uvicorn.run(
            app, host=host, port=port, access_log=False, server_header=False, log_level="warning"
        )
