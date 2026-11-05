# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Secret observations require external receipts and never return secret material."""

from __future__ import annotations

import base64
import gzip
import io
import json
import runpy
import shlex
import ssl
import subprocess
import sys
import threading
import urllib.error
import urllib.request
import zlib
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import cast

import pytest

from sandbox_provider_spec import coverage_secrets as probe
from sandbox_provider_spec.driver import Driver, Inputs, NativeFailure, NotRun, Observation
from sandbox_provider_spec.suite import suite_path

pytestmark = [pytest.mark.integration, pytest.mark.loopback]


@pytest.mark.parametrize("ignore_proxy", [False, True])
def test_guest_child_timeout_is_no_connection_only_for_proxy_ignoring_request(
    monkeypatch: pytest.MonkeyPatch, ignore_proxy: bool
) -> None:
    def child_timeout(command: list[str], **kwargs: object) -> None:
        assert command == ["python3", "/tmp/sps-secret-request.py"]
        assert kwargs == {"capture_output": True, "timeout": 10}
        raise subprocess.TimeoutExpired(command, 10)

    class GuestDriver(Driver):
        def call(self, operation: str, target: object, inputs: Inputs) -> Observation:
            del target
            if operation == "files.write":
                return {}
            assert operation == "run" and inputs["timeout_ms"] == 15000
            command = shlex.split(str(inputs["bash_script"]))
            assert command[:2] == ["python3", "-c"]
            output = io.StringIO()
            exit_code = 0
            with monkeypatch.context() as guest:
                guest.setattr(subprocess, "run", child_timeout)
                guest.setattr(sys, "stdout", output)
                try:
                    exec(command[2], {})  # pylint: disable=exec-used
                except SystemExit as stopped:
                    assert stopped.code == 0
                    exit_code = 0
                except subprocess.TimeoutExpired:
                    exit_code = 1
            return {"exit_code": exit_code, "stdout": output.getvalue()}

    driver = GuestDriver()
    if ignore_proxy:
        assert probe.response(
            driver, object(), url="https://fixture/request", placeholder=False, ignore_proxy=True
        ) == {"status": 0, "headers": {}, "body": ""}
    else:
        with pytest.raises(NativeFailure, match="secret_fixture_request_failed"):
            probe.response(driver, object(), url="https://fixture/request", placeholder=False)


def test_receiver_observes_both_generations_and_echoes_uncompressed_verbatim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = runpy.run_path(str(suite_path().parent / "fixtures/secret_receiver.py"))
    handler = cast(Callable[[dict[str, object]], type[BaseHTTPRequestHandler]], module["handler"])
    config: dict[str, object] = {
        "nonce": "fixture-nonce",
        "observer": "fixture-observer",
        "value": "fixture-first",
        "values": ["fixture-first", "fixture-second"],
    }
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler(config))
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    url = f"http://127.0.0.1:{server.server_port}"
    receiver = {
        "observations_url": url + "/observations/fixture-nonce",
        "observer_headers": {"X-SPS-Observer": "fixture-observer"},
    }
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        assert probe.counts(receiver) == [0, 0]
        for value in ("fixture-first", "fixture-second"):
            request = urllib.request.Request(
                url + "/echo/fixture-nonce?sps_run=fixture-nonce", headers={"X-SPS-Secret": value}
            )
            with opener.open(request, timeout=2) as response:
                assert response.headers["X-SPS-Echo"] == value
                assert response.headers.get("Content-Encoding") is None
                assert response.read() == value.encode()
        assert probe.counts(receiver) == [1, 1]
    finally:
        server.shutdown()
        server.server_close()
        worker.join()


@pytest.mark.parametrize("header", ["Authorization", "X-SPS-Secret"])
def test_receiver_checks_selected_header_template_without_echoing_secret(header: str) -> None:
    module = runpy.run_path(str(suite_path().parent / "fixtures/secret_receiver.py"))
    handler = cast(Callable[[dict[str, object]], type[BaseHTTPRequestHandler]], module["handler"])
    config: dict[str, object] = {
        "nonce": "fixture-nonce",
        "observer": "fixture-observer",
        "value": "fixture-secret",
        "header": header,
        "expected_value": "Bearer fixture-secret-sps",
    }
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler(config))
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    url = f"http://127.0.0.1:{server.server_port}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        request = urllib.request.Request(
            url + "/inject/fixture-nonce?sps_run=fixture-nonce",
            headers={header: "Bearer fixture-secret-sps"},
        )
        with opener.open(request, timeout=2) as response:
            assert response.read() == b"received"
        raw_value = urllib.request.Request(
            url + "/inject/fixture-nonce?sps_run=fixture-nonce",
            headers={header: "fixture-secret"},
        )
        with pytest.raises(urllib.error.HTTPError) as rejected:
            opener.open(raw_value, timeout=2)
        assert rejected.value.code == 403
        receipt = urllib.request.Request(
            url + "/receipt/fixture-nonce?sps_run=fixture-nonce",
            headers={"X-SPS-Observer": "fixture-observer"},
        )
        with opener.open(receipt, timeout=2) as response:
            assert response.read() == b"injected-and-not-echoed"
    finally:
        server.shutdown()
        server.server_close()
        worker.join()


class EchoDriver(Driver):
    def __init__(self, *, body: str, header: bool) -> None:
        super().__init__()
        self.value = ""
        self.body = body
        self.header = header

    def call(self, operation: str, target: object, inputs: Inputs) -> Observation:
        del target
        if operation == "secret.create":
            self.value = str(inputs["value"])
            return {}
        if operation in {"create", "files.write"}:
            return {}
        assert operation == "run"
        if inputs["bash_script"] == "printf '%s' \"$SPS_SECRET_PLACEHOLDER\"":
            return {"stdout": ""}
        content = self.value.encode() if self.body in {"verbatim", "gzip_echo"} else b"filtered"
        headers = {"X-SPS-Echo": self.value} if self.header else {}
        if self.body in {"gzip", "gzip_echo"}:
            content = gzip.compress(content)
            headers["Content-Encoding"] = "gzip"
        if self.body == "deflate":
            content = zlib.compress(content)
            headers["Content-Encoding"] = "deflate"
        return {
            "exit_code": 0,
            "stdout": json.dumps(
                {"status": 200, "headers": headers, "body": base64.b64encode(content).decode()}
            ),
        }


@pytest.mark.parametrize(
    ("body", "header", "scrubbed"),
    [
        ("filtered", False, True),
        ("verbatim", False, False),
        ("filtered", True, False),
        ("gzip", False, True),
        ("deflate", False, True),
        ("gzip_echo", False, False),
    ],
)
def test_verbatim_header_and_decompressed_body_are_both_checked_without_leaks(
    monkeypatch: pytest.MonkeyPatch,
    body: str,
    header: bool,
    scrubbed: bool,
) -> None:
    driver = EchoDriver(body=body, header=header)
    sequence = iter([[0], [1]])
    monkeypatch.setattr(probe, "counts", lambda receiver: next(sequence))
    result = probe.observe(
        driver,
        {"probe": "scrubs_responses", "value": True},
        lambda value, replacement: {"hosts": ["fixture"], "echo_url": "https://fixture/echo"},
    )
    assert result == {"scrubs_responses": scrubbed}
    assert driver.value not in json.dumps(result)


def test_a_successful_guest_response_without_an_external_receipt_proves_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(probe, "counts", lambda receiver: [0])
    with pytest.raises(NativeFailure, match="secret_echo_not_received"):
        probe.observe(
            EchoDriver(body="filtered", header=False),
            {"probe": "scrubs_responses", "value": True},
            lambda value, replacement: {"hosts": ["fixture"], "echo_url": "https://fixture/echo"},
        )


def test_cdn_certificate_variation_is_not_tls_interception_proof() -> None:
    with pytest.raises(NotRun, match="native_tls_interception_unobservable"):
        probe.intercepted(
            {"digest": "a", "issuer": "public-ca"}, {"digest": "b", "issuer": "public-ca"}
        )
    assert (
        probe.intercepted(
            {"digest": "a", "issuer": "public-ca"}, {"digest": "a", "issuer": "public-ca"}
        )
        is False
    )
    assert (
        probe.intercepted(
            {"digest": "a", "issuer": "public-ca"}, {"digest": "b", "issuer": "proxy-ca"}
        )
        is True
    )


@pytest.mark.parametrize("changed_late", [False, True])
def test_rotation_checks_the_original_process_after_new_generation_arrives(
    monkeypatch: pytest.MonkeyPatch,
    changed_late: bool,
) -> None:
    calls: list[tuple[str, object]] = []

    class RunningDriver(Driver):
        def call(self, operation: str, target: object, inputs: Inputs) -> Observation:
            del inputs
            calls.append((operation, target))
            return {}

    states = iter(
        [
            {"pid": 44, "instance": "original", "status": 200},
            {"pid": 44, "instance": "original", "status": 200},
            {"pid": 44, "instance": "replacement" if changed_late else "original", "status": 200},
        ]
    )
    monkeypatch.setattr(probe, "wait_file", lambda *args: next(states))
    monkeypatch.setattr(probe, "counts", lambda receiver: [1, 1])
    driver, source, secret = RunningDriver(), object(), object()

    def run() -> Observation:
        return probe.rotation(
            driver, source, secret, {"hosts": ["fixture"]}, "generated-replacement"
        )

    if changed_late:
        with pytest.raises(NativeFailure, match="secret_running_client_changed_or_failed"):
            run()
    else:
        assert run() == {"rotates": True}
    assert calls.count(("process.start", source)) == 1
    assert ("secret.rotate", secret) in calls
    assert all(operation != "create" for operation, target in calls)


@pytest.mark.parametrize("ignore_proxy", [False, True])
def test_real_secret_request_honours_proxy_except_transparent_probe(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], ignore_proxy: bool
) -> None:
    paths: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:
            pass

        def do_GET(self) -> None:  # noqa: N802
            paths.append(self.path)
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

    direct = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    proxy = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    workers = [
        threading.Thread(target=server.serve_forever, daemon=True) for server in (direct, proxy)
    ]
    for worker in workers:
        worker.start()
    url = f"http://127.0.0.1:{direct.server_port}/request"
    config = {"url": url, "use_placeholder": False, "ignore_proxy": ignore_proxy}
    script = (suite_path().parent / "fixtures/secret_request.py").read_text()
    original = Path.read_text
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda path, **kwargs: (
            json.dumps(config)
            if str(path) == "/tmp/sps-secret-request.json"
            else original(path, **kwargs)
        ),
    )
    monkeypatch.setenv("http_proxy", f"http://127.0.0.1:{proxy.server_port}")
    monkeypatch.setenv("no_proxy", "")
    monkeypatch.delenv("NO_PROXY", raising=False)
    try:
        exec(compile(script, "secret_request.py", "exec"), {"__name__": "__main__"})
        reply = json.loads(capsys.readouterr().out)
        assert reply["status"] == 200
        assert paths == ["/request" if ignore_proxy else url]
    finally:
        for server in (direct, proxy):
            server.shutdown()
            server.server_close()
        for worker in workers:
            worker.join()


@pytest.mark.parametrize("direct_receipt,status", [(True, 200), (False, 403), (False, 0)])
def test_transparency_uses_a_positive_ordinary_control_and_direct_receiver_receipt(
    monkeypatch: pytest.MonkeyPatch, direct_receipt: bool, status: int
) -> None:
    driver = EchoDriver(body="filtered", header=False)
    sequence = iter([[0], [1], [1], [2 if direct_receipt else 1]])
    monkeypatch.setattr(probe, "counts", lambda receiver: next(sequence))
    calls: list[bool] = []

    def response(*args: object, **kwargs: object) -> dict[str, object]:
        del args
        ignore = bool(kwargs.get("ignore_proxy", False))
        calls.append(ignore)
        return {"status": status if ignore else 200, "headers": {}, "body": ""}

    monkeypatch.setattr(probe, "response", response)
    assert probe.observe(
        driver,
        {"probe": "transparent", "value": direct_receipt},
        lambda value, replacement: {
            "hosts": ["fixture"],
            "coverage_url": "https://fixture/request",
        },
    ) == {"transparent": direct_receipt}
    assert calls == [False, True]


def test_transparency_cannot_claim_false_without_ordinary_injection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(probe, "received", lambda *args, **kwargs: False)
    with pytest.raises(NativeFailure, match="secret_initial_generation_not_received"):
        probe.observe(
            EchoDriver(body="filtered", header=False),
            {"probe": "transparent", "value": False},
            lambda value, replacement: {
                "hosts": ["fixture"],
                "coverage_url": "https://fixture/request",
            },
        )


def test_secret_tls_fixture_records_peer_before_http10_closes_connection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    certificate, key = tmp_path / "cert.pem", tmp_path / "key.pem"
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

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:
            pass

        def do_GET(self) -> None:  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    script = (suite_path().parent / "fixtures/secret_certificate.py").read_text()
    config = {"url": f"https://127.0.0.1:{server.server_port}/health"}
    original = Path.read_text
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda path, **kwargs: (
            json.dumps(config)
            if str(path) == "/tmp/sps-secret-certificate.json"
            else original(path, **kwargs)
        ),
    )
    default_context = ssl.create_default_context
    monkeypatch.setattr(ssl, "create_default_context", lambda: default_context(cafile=certificate))
    monkeypatch.setenv("no_proxy", "localhost")
    try:
        exec(compile(script, "secret_certificate.py", "exec"), {"__name__": "__main__"})
        peer = json.loads(capsys.readouterr().out)
        assert len(peer["digest"]) == 64
        assert "localhost" in peer["issuer"]
    finally:
        server.shutdown()
        server.server_close()
        worker.join()
