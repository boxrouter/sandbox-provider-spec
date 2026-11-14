# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Example Cloud: a small fake machine provider over HTTP.

Runs each machine as a local Docker container so tools can exercise a
provider-shaped API without a real account. Run it with:

    python template/fake_cloud/server.py --port 18080 --state-dir /tmp/example-cloud

Every request needs a non-empty ``X-Api-Key`` header. The API is documented
in README.md next to this file.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import queue
import re
import sys
import threading
import urllib.parse
from pathlib import Path
from typing import Any

import uvicorn
from backend import _CANCEL, _END, IMAGE, ApiError, ExampleCloud, _drain

_BODY_LIMIT = 1 << 20
_TAG_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_MACHINE_ID = re.compile(r"m-[a-z0-9]{1,32}\Z")
_JOB_ID = re.compile(r"j-[a-z0-9]{1,32}\Z")


async def _read_body(receive: Any, limit: int = _BODY_LIMIT) -> bytes:
    data = bytearray()
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            raise ApiError(400, "invalid_request", "request body was cut off")
        if message["type"] != "http.request":
            continue
        data += message.get("body", b"")
        if len(data) > limit:
            raise ApiError(413, "too_large", "request body is over 1 MiB")
        if not message.get("more_body"):
            return bytes(data)


async def _json_body(receive: Any) -> dict[str, Any]:
    raw = await _read_body(receive)
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except ValueError:
        raise ApiError(400, "invalid_request", "request body is not JSON") from None
    if not isinstance(parsed, dict):
        raise ApiError(400, "invalid_request", "request body must be a JSON object")
    return parsed


async def _send_json(send: Any, status: int, payload: dict[str, Any]) -> None:
    body = json.dumps(payload).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


def _require_string_list(body: dict[str, Any], field: str) -> list[str]:
    value = body.get(field)
    if not isinstance(value, list) or not 1 <= len(value) <= 1024:
        raise ApiError(400, "invalid_request", f"{field} must be a list of 1 to 1024 strings")
    if not all(isinstance(item, str) for item in value):
        raise ApiError(400, "invalid_request", f"{field} must be a list of strings")
    return value


def _require_env(body: dict[str, Any]) -> dict[str, str]:
    value = body.get("env")
    if value is None:
        return {}
    if not isinstance(value, dict) or not all(
        isinstance(key, str) and isinstance(item, str) for key, item in value.items()
    ):
        raise ApiError(400, "invalid_request", "env must be an object of strings")
    return value


def _optional_dir(body: dict[str, Any]) -> str | None:
    value = body.get("dir")
    if value is None:
        return None
    if not isinstance(value, str) or not value.startswith("/"):
        raise ApiError(400, "invalid_request", "dir must be an absolute path")
    return value


def _machine_id(segment: str) -> str:
    if _MACHINE_ID.fullmatch(segment) is None:
        raise ApiError(404, "not_found", f"unknown machine {segment}")
    return segment


def _offset(value: str | None) -> tuple[int, int]:
    if not value:
        return 0, 0
    parts = value.split(".")
    if len(parts) != 2 or not all(part.isdigit() for part in parts):
        raise ApiError(400, "invalid_request", "offset must look like '<out>.<err>'")
    return int(parts[0]), int(parts[1])


def _tags(raw: list[str]) -> list[tuple[str, str]]:
    tags = []
    for item in raw:
        key, sep, value = item.partition(":")
        if not sep or _TAG_KEY.fullmatch(key) is None:
            raise ApiError(400, "invalid_request", f"bad tag filter {item!r}")
        tags.append((key, value))
    return tags


def _int_param(raw: list[str], name: str, default: int, low: int, high: int) -> int:
    if not raw or not raw[0]:
        return default
    try:
        value = int(raw[0])
    except ValueError:
        raise ApiError(400, "invalid_request", f"{name} must be an integer") from None
    if not low <= value <= high:
        raise ApiError(400, "invalid_request", f"{name} must be between {low} and {high}")
    return value


def _offer(incoming: queue.Queue[object], item: object, dead: threading.Event) -> bool:
    while True:
        if dead.is_set():
            return False
        try:
            incoming.put(item, timeout=0.2)
            return True
        except queue.Full:
            continue


async def _fs_put(
    cloud: ExampleCloud,
    machine_id: str,
    query: dict[str, list[str]],
    scope: dict[str, Any],
    receive: Any,
    send: Any,
) -> None:
    path = (query.get("path") or [""])[0]
    if not path:
        raise ApiError(400, "invalid_request", "path is required")
    headers = {key.lower(): value for key, value in scope["headers"]}
    raw_length = headers.get(b"content-length")
    if raw_length is None:
        raise ApiError(400, "invalid_request", "Content-Length is required")
    try:
        size = int(raw_length)
    except ValueError:
        raise ApiError(400, "invalid_request", "bad Content-Length") from None

    incoming: queue.Queue[object] = queue.Queue(maxsize=32)
    results: queue.Queue[object] = queue.Queue(maxsize=1)
    dead = threading.Event()

    def work() -> None:
        try:
            results.put(cloud.write_file(machine_id, path, size, _drain(incoming)))
        except BaseException as exc:
            results.put(exc)
        finally:
            dead.set()

    threading.Thread(target=work, daemon=True).start()
    fed = True
    try:
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                fed = False
                break
            if message["type"] != "http.request":
                continue
            chunk = message.get("body", b"")
            if chunk and not _offer(incoming, chunk, dead):
                fed = False
                break
            if not message.get("more_body"):
                break
    except ApiError:
        fed = False
    if fed:
        _offer(incoming, _END, dead)
    else:
        _offer(incoming, _CANCEL, dead)
    outcome = await asyncio.to_thread(results.get)
    if isinstance(outcome, ApiError):
        raise outcome
    if isinstance(outcome, BaseException):
        raise ApiError(502, "provider_error", f"write failed: {outcome}")
    await _send_json(send, 200, outcome)


async def _fs_get(
    cloud: ExampleCloud,
    machine_id: str,
    query: dict[str, list[str]],
    send: Any,
) -> None:
    path = (query.get("path") or [""])[0]
    if not path:
        raise ApiError(400, "invalid_request", "path is required")
    size, chunks = await asyncio.to_thread(cloud.read_file, machine_id, path)
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [
                (b"content-type", b"application/octet-stream"),
                (b"content-length", str(size).encode()),
            ],
        }
    )
    iterator = iter(chunks)
    end = object()
    try:
        while True:
            block = await asyncio.to_thread(next, iterator, end)
            if block is end:
                break
            await send({"type": "http.response.body", "body": block, "more_body": True})
    finally:
        close = getattr(iterator, "close", None)
        if close is not None:
            await asyncio.to_thread(close)
    await send({"type": "http.response.body", "body": b"", "more_body": False})


async def _handle(cloud: ExampleCloud, scope: dict[str, Any], receive: Any, send: Any) -> None:
    method = scope["method"]
    segments = [seg for seg in scope["path"].split("/") if seg]
    query = urllib.parse.parse_qs(scope["query_string"].decode("utf-8"), keep_blank_values=True)

    if method == "GET" and segments == ["healthz"]:
        await _send_json(send, 200, {"status": "ok"})
        return

    headers = {key.lower(): value for key, value in scope["headers"]}
    if not headers.get(b"x-api-key"):
        raise ApiError(401, "unauthenticated", "an X-Api-Key header is required")

    if not segments or segments[0] != "machines":
        raise ApiError(404, "not_found", "no such route")

    if len(segments) == 1:
        if method == "POST":
            body = await _json_body(receive)
            for field in ("env", "tags"):
                if field in body and not isinstance(body[field], dict):
                    raise ApiError(400, "invalid_request", f"{field} must be an object")
            for key in body.get("tags") or {}:
                if _TAG_KEY.fullmatch(key) is None:
                    raise ApiError(400, "invalid_request", f"bad tag key {key!r}")
            result = await asyncio.to_thread(cloud.create_machine, body)
            await _send_json(send, 201, result)
            return
        if method == "GET":
            tags = _tags(query.get("tag", []))
            token = (query.get("page_token") or [""])[0]
            if token and not token.isdigit():
                raise ApiError(400, "invalid_request", "bad page_token")
            offset = int(token) if token else 0
            limit = _int_param(query.get("limit", []), "limit", 100, 1, 1000)
            result = await asyncio.to_thread(cloud.list_machines, tags, offset, limit)
            await _send_json(send, 200, result)
            return
        raise ApiError(405, "invalid_request", "method not allowed")

    machine_id = _machine_id(segments[1])
    rest = segments[2:]

    if not rest:
        if method == "GET":
            result = await asyncio.to_thread(cloud.describe_machine, machine_id)
            await _send_json(send, 200, result)
            return
        if method == "DELETE":
            result = await asyncio.to_thread(cloud.delete_machine, machine_id)
            await _send_json(send, 200, result)
            return
        raise ApiError(405, "invalid_request", "method not allowed")

    if rest == ["exec"] and method == "POST":
        body = await _json_body(receive)
        cmd = _require_string_list(body, "cmd")
        cwd = _optional_dir(body)
        env = _require_env(body)
        timeout_s = body.get("timeout_s")
        if timeout_s is not None:
            if not isinstance(timeout_s, int | float) or not 0 < timeout_s <= 3600:
                raise ApiError(400, "invalid_request", "timeout_s must be in (0, 3600]")
            timeout_s = float(timeout_s)
        result = await asyncio.to_thread(cloud.exec_command, machine_id, cmd, cwd, env, timeout_s)
        await _send_json(send, 200, result)
        return

    if rest == ["fs"]:
        if method == "PUT":
            await _fs_put(cloud, machine_id, query, scope, receive, send)
            return
        if method == "GET":
            await _fs_get(cloud, machine_id, query, send)
            return
        raise ApiError(405, "invalid_request", "method not allowed")

    if rest == ["jobs"] and method == "POST":
        body = await _json_body(receive)
        cmd = _require_string_list(body, "cmd")
        cwd = _optional_dir(body)
        env = _require_env(body)
        result = await asyncio.to_thread(cloud.start_job, machine_id, cmd, cwd, env)
        await _send_json(send, 200, result)
        return

    if len(rest) == 3 and rest[0] == "jobs" and rest[2] == "log" and method == "GET":
        if _JOB_ID.fullmatch(rest[1]) is None:
            raise ApiError(404, "not_found", f"unknown job {rest[1]}")
        out_pos, err_pos = _offset((query.get("offset") or [None])[0])
        wait_raw = (query.get("wait") or ["0"])[0]
        try:
            wait_s = min(max(float(wait_raw), 0.0), 60.0)
        except ValueError:
            raise ApiError(400, "invalid_request", "wait must be a number") from None
        result = await asyncio.to_thread(
            cloud.job_log, machine_id, rest[1], out_pos, err_pos, wait_s
        )
        await _send_json(send, 200, result)
        return

    if rest == ["usage"] and method == "GET":
        result = await asyncio.to_thread(cloud.get_usage, machine_id)
        await _send_json(send, 200, result)
        return

    raise ApiError(404, "not_found", "no such route")


def make_app(cloud: ExampleCloud) -> Any:
    async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            return
        try:
            await _handle(cloud, scope, receive, send)
        except ApiError as exc:
            await _send_json(
                send,
                exc.status,
                {"error": {"code": exc.code, "message": exc.message}},
            )
        except Exception:
            await _send_json(
                send, 500, {"error": {"code": "provider_error", "message": "internal error"}}
            )

    return app


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="example-cloud", description="Example Cloud, the fake machine provider"
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--owner", default=f"example-{os.getpid()}")
    parser.add_argument("--image", default=IMAGE)
    args = parser.parse_args()
    cloud = ExampleCloud(args.state_dir, args.owner, args.image)
    config = uvicorn.Config(make_app(cloud), host=args.host, port=args.port, log_level="warning")
    try:
        uvicorn.Server(config).run()
    finally:
        cloud.close()


if __name__ == "__main__":
    sys.exit(main())
