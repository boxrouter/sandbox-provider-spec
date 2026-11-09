# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The shared guest probe sends a fresh token and accepts only 2xx responses."""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import threading
from collections import defaultdict
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import cast
from urllib.parse import unquote, urlsplit

import pytest

from sandbox_provider_spec.coverage_network_probe import guest_http, runner_controls
from sandbox_provider_spec.driver import Driver, Inputs, NotRun, Observation

pytestmark = [pytest.mark.integration, pytest.mark.loopback]


class Receiver(ThreadingHTTPServer):
    records: dict[str, list[dict[str, str]]]


class Handler(BaseHTTPRequestHandler):
    server: Receiver

    def do_GET(self) -> None:  # noqa: N802
        request_path = urlsplit(self.path).path
        if request_path.startswith("/records/"):
            record_token = unquote(request_path.removeprefix("/records/"))
            payload = json.dumps({"records": self.server.records[record_token]}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        request_token = self.headers.get("X-SPS-Probe")
        if request_token:
            self.server.records[request_token].append({"method": "GET", "path": request_path})
        status = {"/denied": 403, "/missing": 404, "/redirect": 302}.get(request_path, 200)
        self.send_response(status)
        if status == 302:
            self.send_header("Location", "/allowed")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *_: object) -> None:
        pass


@pytest.fixture
def receiver() -> Iterator[tuple[Receiver, str]]:
    server = Receiver(("127.0.0.1", 0), Handler)
    server.records = defaultdict(list)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield server, f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        worker.join()


class GuestDriver(Driver):
    def __init__(self) -> None:
        super().__init__()
        self.files: dict[str, bytes] = {}

    def call(self, operation: str, target: object, inputs: Inputs) -> Observation:
        del target
        if operation == "files.write":
            self.files[str(inputs["path"])] = base64.b64decode(str(inputs["data"]))
            return {}
        assert operation == "run"
        path = str(inputs["bash_script"]).removeprefix("python3 ")
        result = subprocess.run(
            [sys.executable, "-c", self.files[path].decode()],
            capture_output=True,
            check=False,
            env={**os.environ, **cast(dict[str, str], inputs["environment"])},
            timeout=30,
        )
        return {"exit_code": result.returncode, "stdout": result.stdout}


def test_guest_probe_sends_distinct_tokens_and_requires_2xx(
    receiver: tuple[Receiver, str],
) -> None:
    server, base = receiver
    targets = [base + path for path in ("/allowed", "/denied", "/missing", "/redirect")]

    reached, tokens = guest_http(GuestDriver(), object(), [(url, "GET") for url in targets])

    assert reached == [True, False, False, False]
    assert len(set(tokens)) == len(targets)
    assert [server.records[token] for token in tokens] == [
        [{"method": "GET", "path": "/allowed"}],
        [{"method": "GET", "path": "/denied"}],
        [{"method": "GET", "path": "/missing"}],
        [{"method": "GET", "path": "/redirect"}],
    ]


def test_runner_control_requires_2xx_and_recorder_proof(
    receiver: tuple[Receiver, str],
) -> None:
    _, base = receiver
    runner_controls([base + "/control"], ["GET"])
    with pytest.raises(NotRun, match="^network_control_unavailable$"):
        runner_controls([base + "/denied"], ["GET"])
