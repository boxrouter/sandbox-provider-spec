# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Open-connection fixtures use local HTTPS streams and an offline driver."""

from __future__ import annotations

import base64
import json
import ssl
import subprocess
import sys
import threading
import time
from collections.abc import Generator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from urllib.parse import unquote, urlsplit

import pytest

from sandbox_provider_spec import coverage_v3
from sandbox_provider_spec.driver import Driver, Inputs, NotRun, Observation
from sandbox_provider_spec.runner import Runner

TOKEN = "sps-v3-test-token"
POLICY = {"policy": "allowlist", "allow": []}


class StreamingHarness:
    def __init__(self, tmp_path: Path, *, close_connection: bool = False) -> None:
        certificate = tmp_path / "sps-v3-cert.pem"
        key = tmp_path / "sps-v3-key.pem"
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost,IP:127.0.0.1",
                "-keyout",
                str(key),
                "-out",
                str(certificate),
            ],
            check=True,
            capture_output=True,
        )
        self.close_stream = threading.Event()
        self.stop_stream = threading.Event()
        self.allow_bytes = threading.Event()
        self.allow_bytes.set()
        self.authenticated = 0
        self.close_connection = close_connection
        self.records: dict[str, list[dict[str, str]]] = {}
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0" if owner.close_connection else "HTTP/1.1"

            def log_message(self, *_: object) -> None:
                pass

            def do_GET(self) -> None:  # noqa: N802
                if self.path.startswith("/records/"):
                    token = unquote(urlsplit(self.path).path.removeprefix("/records/"))
                    payload = json.dumps({"records": owner.records.get(token, [])}).encode()
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                    return
                if self.path != "/stream" or self.headers.get("X-Token") != TOKEN:
                    self.send_error(401)
                    return
                probe_token = self.headers.get("X-SPS-Probe")
                if probe_token:
                    owner.records.setdefault(probe_token, []).append(
                        {"method": "GET", "path": "/stream"}
                    )
                owner.authenticated += 1
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                if owner.close_connection:
                    self.send_header("Connection", "close")
                else:
                    self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                while not owner.stop_stream.is_set():
                    if owner.allow_bytes.is_set():
                        try:
                            self.wfile.write(b"x" if owner.close_connection else b"1\r\nx\r\n")
                            self.wfile.flush()
                        except (BrokenPipeError, ConnectionResetError):
                            return
                    if owner.close_stream.wait(0.02):
                        if not owner.close_connection:
                            try:
                                self.wfile.write(b"0\r\n\r\n")
                                self.wfile.flush()
                            except (BrokenPipeError, ConnectionResetError):
                                pass
                        return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.worker = threading.Thread(
            target=self.server.serve_forever, name="sps-v3-test-https", daemon=True
        )
        self.worker.start()
        self.ca_pem = certificate.read_text()
        self.url = f"https://127.0.0.1:{self.server.server_port}/stream"

    def fixture(self) -> dict[str, str]:
        return {"stream_url": self.url, "token": TOKEN, "ca_pem": self.ca_pem}

    def close(self) -> None:
        self.stop_stream.set()
        self.close_stream.set()
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(timeout=2)


class LocalDriver(Driver):
    def __init__(
        self, tmp_path: Path, harness: StreamingHarness, close_on_update: bool = False
    ) -> None:
        super().__init__()
        self.tmp_path = tmp_path
        self.harness = harness
        self.close_on_update = close_on_update
        self.policies: list[dict[str, object]] = []

    def local_path(self, path: str) -> Path:
        return self.tmp_path / Path(path).name

    def files_write(self, target: object, inputs: Inputs) -> Observation:
        del target
        path = self.local_path(cast(str, inputs["path"]))
        path.write_bytes(base64.b64decode(cast(str, inputs["data"]), validate=True))
        return {}

    def files_read_bytes(self, target: object, inputs: Inputs) -> Observation:
        del target
        return {"data": self.local_path(cast(str, inputs["path"])).read_bytes()}

    def process_start(self, target: object, inputs: Inputs) -> Observation:
        del target
        parts = cast(str, inputs["bash_script"]).split()
        assert parts[0] == "python3"
        script, config, state = (self.local_path(path) for path in parts[1:])
        process = subprocess.Popen(
            [sys.executable, str(script), str(config), str(state)],
            cwd=self.tmp_path,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        owned = self.own("process", process, lambda: self._kill(process))
        return {"resource": owned, "identity": process.pid}

    @staticmethod
    def _kill(process: subprocess.Popen[bytes]) -> Observation:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=3)
        return {"result": "deleted"}

    def network_update(self, target: object, inputs: Inputs) -> Observation:
        del target
        self.policies.append(dict(inputs))
        if self.close_on_update:
            self.harness.close_stream.set()
        return {}

    def cleanup(self) -> None:
        for owned in reversed(self.resources):
            self.release(owned)


@pytest.fixture
def harness(tmp_path: Path) -> Generator[StreamingHarness, None, None]:
    value = StreamingHarness(tmp_path)
    yield value
    value.close()


@pytest.fixture(params=[False, True], ids=["chunked", "close-delimited"])
def stream_harness(
    tmp_path: Path, request: pytest.FixtureRequest
) -> Generator[StreamingHarness, None, None]:
    value = StreamingHarness(tmp_path, close_connection=bool(request.param))
    yield value
    value.close()


def open_stream(
    driver: LocalDriver, target: object, harness: StreamingHarness
) -> dict[str, object]:
    return dict(
        Runner(driver)._test_operation(
            "fixture.coverage_open_connection", target, {"harness": harness.fixture()}
        )
    )


@pytest.mark.loopback
@pytest.mark.integration
def test_open_connection_starts_an_authenticated_https_stream(
    tmp_path: Path, harness: StreamingHarness
) -> None:
    driver = LocalDriver(tmp_path, harness)
    target = object()
    try:
        opened = open_stream(driver, target, harness)
        connection = cast(coverage_v3._Connection, opened["handle"])
        state = coverage_v3._read_state(driver, target, connection.state_path)
        assert state["connected"] is True
        assert cast(int, state["received"]) > 0
        assert harness.authenticated == 1
        assert set(opened) == {"handle"}
    finally:
        driver.cleanup()


@pytest.mark.loopback
@pytest.mark.integration
def test_connection_update_starts_one_native_update_with_a_ten_second_deadline(
    tmp_path: Path, harness: StreamingHarness
) -> None:
    driver = LocalDriver(tmp_path, harness)
    target = object()
    try:
        opened = open_stream(driver, target, harness)
        started = time.monotonic()
        updated = Runner(driver)._test_operation(
            "fixture.coverage_connection_update",
            target,
            {"connection": opened, "new_policy": POLICY},
        )
        observer = cast(coverage_v3._WindowObserver, updated["observer"])
        assert updated["window_seconds"] == 10
        assert started < cast(float, updated["deadline"]) <= time.monotonic() + 10
        assert driver.policies == [POLICY]
        observer.stop()
        observer.join(1)
    finally:
        driver.cleanup()


@pytest.mark.loopback
@pytest.mark.integration
def test_connection_closed_reports_a_stream_cut_inside_the_window(
    tmp_path: Path, harness: StreamingHarness
) -> None:
    driver = LocalDriver(tmp_path, harness, close_on_update=True)
    target = object()
    try:
        opened = open_stream(driver, target, harness)
        updated = Runner(driver)._test_operation(
            "fixture.coverage_connection_update",
            target,
            {"connection": opened, "new_policy": POLICY},
        )
        closed = Runner(driver)._test_operation(
            "fixture.coverage_connection_closed",
            target,
            {"connection": updated, "window_seconds": 10},
        )
        assert closed == {"closed_within_window": True}
    finally:
        driver.cleanup()


def test_late_state_read_cannot_date_a_closure_before_the_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(coverage_v3, "OBSERVATION_WINDOW_SECONDS", 0.05)
    connection = coverage_v3._Connection(target=object(), process={}, state_path="unused")
    now = 0.0
    # Advance only the observer clock, independently of worker scheduling.
    monkeypatch.setattr(coverage_v3, "time", SimpleNamespace(monotonic=lambda: now))

    def delayed_closed_state(*_args: object) -> dict[str, object]:
        nonlocal now
        now += 0.08
        return {"connected": True, "received": 1, "closed": True, "failed": False}

    monkeypatch.setattr(coverage_v3, "_read_state", delayed_closed_state)
    observer = coverage_v3._WindowObserver(Driver(), connection.target, connection)
    started = now
    observer.start()
    observer.arm(started)
    observer.join(1)

    assert not observer.thread.is_alive()
    assert observer.outcome == "unobservable"
    assert started < observer.deadline < now


@pytest.mark.loopback
@pytest.mark.integration
def test_connection_closed_requires_data_after_the_window_for_false(
    tmp_path: Path, harness: StreamingHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(coverage_v3, "OBSERVATION_WINDOW_SECONDS", 0.2)
    monkeypatch.setattr(coverage_v3, "POLL_SECONDS", 0.02)
    monkeypatch.setattr(coverage_v3, "AFTER_WINDOW_SECONDS", 1.0)
    driver = LocalDriver(tmp_path, harness)
    target = object()
    try:
        opened = open_stream(driver, target, harness)
        updated = Runner(driver)._test_operation(
            "fixture.coverage_connection_update",
            target,
            {"connection": opened, "new_policy": POLICY},
        )
        closed = Runner(driver)._test_operation(
            "fixture.coverage_connection_closed",
            target,
            {"connection": updated, "window_seconds": 10},
        )
        assert closed == {"closed_within_window": False}
        observer = cast(coverage_v3._WindowObserver, updated["observer"])
        assert observer.outcome == "continued"
    finally:
        driver.cleanup()


@pytest.mark.loopback
@pytest.mark.integration
def test_quiet_stream_can_continue_after_the_window(
    tmp_path: Path, stream_harness: StreamingHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert coverage_v3.STREAM_READ_TIMEOUT_SECONDS is None
    monkeypatch.setattr(coverage_v3, "OBSERVATION_WINDOW_SECONDS", 0.25)
    monkeypatch.setattr(coverage_v3, "POLL_SECONDS", 0.02)
    monkeypatch.setattr(coverage_v3, "AFTER_WINDOW_SECONDS", 1.0)
    driver = LocalDriver(tmp_path, stream_harness)
    target = object()
    try:
        opened = open_stream(driver, target, stream_harness)
        updated = Runner(driver)._test_operation(
            "fixture.coverage_connection_update",
            target,
            {"connection": opened, "new_policy": POLICY},
        )
        observer = cast(coverage_v3._WindowObserver, updated["observer"])
        stream_harness.allow_bytes.clear()

        def resume() -> None:
            time.sleep(max(0.0, observer.deadline - time.monotonic()) + 0.1)
            stream_harness.allow_bytes.set()

        threading.Thread(target=resume, name="sps-v3-resume-bytes", daemon=True).start()
        closed = Runner(driver)._test_operation(
            "fixture.coverage_connection_closed",
            target,
            {"connection": updated, "window_seconds": 10},
        )
        assert closed == {"closed_within_window": False}
        assert observer.outcome == "continued"
    finally:
        stream_harness.allow_bytes.set()
        driver.cleanup()


@pytest.mark.loopback
@pytest.mark.integration
def test_short_read_timeout_fails_a_stream_quiet_across_the_window(
    tmp_path: Path, stream_harness: StreamingHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(coverage_v3, "STREAM_READ_TIMEOUT_SECONDS", 5.0)
    monkeypatch.setattr(coverage_v3, "OBSERVATION_WINDOW_SECONDS", 8.0)
    monkeypatch.setattr(coverage_v3, "POLL_SECONDS", 0.1)
    monkeypatch.setattr(coverage_v3, "AFTER_WINDOW_SECONDS", 10.0)
    driver = LocalDriver(tmp_path, stream_harness)
    target = object()
    try:
        opened = open_stream(driver, target, stream_harness)
        updated = Runner(driver)._test_operation(
            "fixture.coverage_connection_update",
            target,
            {"connection": opened, "new_policy": POLICY},
        )
        observer = cast(coverage_v3._WindowObserver, updated["observer"])
        stream_harness.allow_bytes.clear()

        def resume() -> None:
            time.sleep(max(0.0, observer.deadline - time.monotonic()) + 0.5)
            stream_harness.allow_bytes.set()

        threading.Thread(target=resume, name="sps-v3-resume-bytes", daemon=True).start()
        with pytest.raises(NotRun, match="connection_window_observation_unavailable"):
            Runner(driver)._test_operation(
                "fixture.coverage_connection_closed",
                target,
                {"connection": updated, "window_seconds": 10},
            )
    finally:
        stream_harness.allow_bytes.set()
        driver.cleanup()
