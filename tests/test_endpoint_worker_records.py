# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Test a normalized live capture of the HTTP Worker recorder response."""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
import urllib.request
from io import BytesIO
from pathlib import Path
from typing import Any, cast
from urllib.request import BaseHandler, OpenerDirector, Request

from jsonschema import Draft202012Validator
from pytest import MonkeyPatch, skip

from sandbox_provider_spec import coverage_network_probe

ROOT = Path(__file__).parents[1]
RESPONSE_PATH = Path(__file__).parent / "fixtures/endpoints-worker/records-response.json"
SCHEMA_PATH = ROOT / "conformance/fixtures/endpoints-worker/records-response.schema.json"
WORKER_PATH = ROOT / "conformance/fixtures/endpoints-worker/index.ts"


class _Response(BytesIO):
    status = 200


class _StaticOpener:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def open(self, request: Request, timeout: float = 8) -> _Response:
        assert timeout == 8
        assert request.full_url == "https://receiver.example/records/v66-regression-test"
        return _Response(self.payload)


def _response_payload() -> Any:
    return json.loads(RESPONSE_PATH.read_text(encoding="utf-8"))


def test_worker_recorder_response_matches_schema() -> None:
    payload = _response_payload()
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(payload)
    assert "requests" not in payload


def test_network_probe_parser_accepts_worker_recorder_response(
    monkeypatch: MonkeyPatch,
) -> None:
    response = _response_payload()
    payload = json.dumps(response).encode("utf-8")

    def build_opener(*_handlers: BaseHandler) -> OpenerDirector:
        return cast(OpenerDirector, _StaticOpener(payload))

    monkeypatch.setattr(urllib.request, "build_opener", build_opener)

    assert coverage_network_probe.records("https://receiver.example/health", response["token"]) == [
        ("GET", "/health")
    ]


def test_worker_records_requests_and_protects_stream_with_observer_token(
    tmp_path: Path,
) -> None:
    node = shutil.which("node")
    if node is None:
        skip("Node.js is required to execute the TypeScript worker fixture")
    flag_check = subprocess.run(
        [node, "--experimental-strip-types", "--input-type=module", "-e", ""],
        capture_output=True,
        text=True,
    )
    if flag_check.returncode != 0:
        skip("Node.js must support --experimental-strip-types for the worker fixture")

    harness = r"""const fs = await import("node:fs/promises");
const path = await import("node:path");
const { pathToFileURL } = await import("node:url");
const source = await fs.readFile(process.argv[1], "utf8");
const worker = source.replace(/^import \{ DurableObject \} from "cloudflare:workers";\s*/m, "");
const workerModule = worker.slice(0, worker.indexOf("export class Recorder"));
const workerPath = path.join(process.cwd(), "worker.ts");
await fs.writeFile(workerPath, workerModule);
const { default: app } = await import(pathToFileURL(workerPath));
const saved = [];
const env = {
  OBSERVER_TOKENS: JSON.stringify(["observer-secret"]),
  RECORDER: {
    idFromName: (name) => name,
    get: () => ({
      fetch: async (request) => {
        const url = new URL(request.url);
        if (url.pathname === "/record") {
          saved.push(await request.json());
          return new Response("ok");
        }
        const token = url.pathname.split("/").at(-1);
        const records = saved.filter((row) => row.token === token).map((row) => row.request);
        return new Response(JSON.stringify({ records }), {
          headers: { "content-type": "application/json" },
        });
      },
    }),
  },
};
const denied = await app.fetch(new Request("https://worker.example/stream"), env);
if (denied.status !== 401) throw new Error(`unauthorized /stream status: ${denied.status}`);
const wrongToken = await app.fetch(new Request("https://worker.example/stream", {
  headers: { "x-token": "record-token" },
}), env);
if (wrongToken.status !== 401) throw new Error(`wrong-token /stream status: ${wrongToken.status}`);
const request = new Request("https://worker.example/health", {
  headers: { "x-token": "record-token" },
});
const response = await app.fetch(request, env);
if (response.status !== 200) throw new Error(`health status: ${response.status}`);
const recordsRequest = new Request("https://worker.example/records/record-token");
const recordsResponse = await app.fetch(recordsRequest, env);
const document = await recordsResponse.json();
if (document.records.length !== 1 || document.records[0].path !== "/health") {
  throw new Error("worker did not return the recorded request");
}
const authorizedRequest = new Request("https://worker.example/stream", {
  headers: { "x-token": "observer-secret" },
});
const authorized = await app.fetch(authorizedRequest, env);
if (authorized.status !== 200) throw new Error(`authorized /stream status: ${authorized.status}`);
"""
    result = subprocess.run(
        [
            node,
            "--experimental-strip-types",
            "--input-type=module",
            "-e",
            harness,
            str(WORKER_PATH),
        ],
        capture_output=True,
        text=True,
        cwd=tmp_path,
    )
    assert result.returncode == 0, result.stderr


def test_network_probe_accepts_large_rows_without_duplicate_alias(
    monkeypatch: MonkeyPatch,
) -> None:
    row = {
        "method": "POST",
        "path": "/large",
        "headers": {"content-type": "text/plain"},
        "body": "x" * 9000,
        "body_base64": base64.b64encode(b"x" * 9000).decode("ascii"),
    }
    token = "v66-regression-test"
    payload = {
        "token": token,
        "records": [row],
        "connections": [],
    }
    response_bytes = json.dumps(payload).encode("utf-8")
    assert len(response_bytes) < 32 * 1024

    def build_opener(*_handlers: BaseHandler) -> OpenerDirector:
        return cast(OpenerDirector, _StaticOpener(response_bytes))

    monkeypatch.setattr(urllib.request, "build_opener", build_opener)

    assert coverage_network_probe.records("https://receiver.example/health", token) == [
        ("POST", "/large")
    ]
