# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Offline V4 checks with a local fake HTTPS receiver."""

from __future__ import annotations

import base64
import json
import socket
import ssl
import subprocess
import threading
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator, Mapping
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from sandbox_provider_spec import coverage_network_probe as network_probe
from sandbox_provider_spec import coverage_v4 as probe
from sandbox_provider_spec.driver import Driver, Inputs, NotRun, Observation

ENDPOINT_SECRET = "sps-generated-test-secret"
HOSTS = ("first.example.test", "second.example.test", "worker.example.test")


class State:
    def __init__(self) -> None:
        self.config: Mapping[str, Any] = {}
        self.header_results: list[Mapping[str, object]] = []
        self.body_results: dict[str, dict[str, bool]] = {}
        self.statuses: list[int] = []
        self.records: dict[str, list[dict[str, object]]] = {}
        self.records_available = True
        self.lock = threading.Lock()


class RecordingDriver(Driver):
    def __init__(self, preview_url: str | None = None) -> None:
        super().__init__()
        self.preview_url = preview_url
        self.secret: Mapping[str, object] = {"secret_id": object()}
        self.calls: list[tuple[str, object, Inputs]] = []
        self.file_writes: list[tuple[object, str, bytes]] = []

    def call(self, operation: str, target: object, inputs: Inputs) -> Observation:
        self.calls.append((operation, target, inputs))
        if operation == "secret.create":
            return self.secret
        if operation == "create":
            return {"sandbox": len(self.calls)}
        if operation == "files.write":
            self.file_writes.append(
                (
                    target,
                    str(inputs["path"]),
                    base64.b64decode(str(inputs["data"])),
                )
            )
            return {}
        if operation == "files.exists":
            return {"exists": True}
        if operation == "preview.link":
            assert self.preview_url is not None
            return {"url": self.preview_url}
        return {}


@pytest.fixture
def fake_receiver(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[State, str]]:
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
            "/CN=127.0.0.1",
            "-addext",
            "subjectAltName=IP:127.0.0.1,DNS:first.example.test,DNS:second.example.test,DNS:worker.example.test,DNS:deep.worker.example.test",
            "-keyout",
            str(key),
            "-out",
            str(certificate),
        ],
        check=True,
        capture_output=True,
    )
    monkeypatch.setenv("SSL_CERT_FILE", str(certificate))
    original_getaddrinfo = socket.getaddrinfo

    def local_dns(host: str, *args: Any, **kwargs: Any) -> Any:
        resolved = "127.0.0.1" if host in HOSTS or host == "deep.worker.example.test" else host
        return original_getaddrinfo(resolved, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", local_dns)
    original_build_opener = urllib.request.build_opener

    class LocalRoutingOpener:
        def __init__(self, opener: urllib.request.OpenerDirector) -> None:
            self.opener = opener

        def open(self, request: urllib.request.Request, *args: Any, **kwargs: Any) -> Any:
            parsed = urllib.parse.urlsplit(request.full_url)
            host = parsed.hostname
            if host in HOSTS or host == "deep.worker.example.test":
                netloc = parsed.netloc.replace(host, "127.0.0.1", 1)
                routed_url = urllib.parse.urlunsplit(parsed._replace(netloc=netloc))
                headers = dict(request.header_items())
                headers["Host"] = parsed.netloc
                request = urllib.request.Request(
                    routed_url,
                    data=request.data,
                    headers=headers,
                    method=request.get_method(),
                )
            return self.opener.open(request, *args, **kwargs)

    def local_routed_opener(*handlers: Any) -> LocalRoutingOpener:
        return LocalRoutingOpener(original_build_opener(*handlers))

    monkeypatch.setattr(urllib.request, "build_opener", local_routed_opener)
    state = State()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:
            pass

        def reply(self, status: int, payload: bytes = b"") -> None:
            with state.lock:
                state.statuses.append(status)
            self.send_response(status)
            self.send_header("Content-Length", str(len(payload)))
            if payload:
                self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:
            config = state.config
            nonce = str(config.get("nonce", "run"))
            path = urllib.parse.urlsplit(self.path).path
            if path.startswith("/records/"):
                if not state.records_available:
                    self.reply(403)
                    return
                requested = urllib.parse.unquote(path.removeprefix("/records/"))
                with state.lock:
                    recorded = list(state.records.get(requested, []))
                self.reply(200, json.dumps({"requests": recorded, "records": recorded}).encode())
                return
            token = self.headers.get("X-SPS-Probe")
            if token:
                with state.lock:
                    state.records.setdefault(token, []).append(
                        {
                            "method": self.command,
                            "path": self.path,
                            "headers": dict(self.headers.items()),
                        }
                    )
            if path == "/check":
                self.reply(200)
                return
            if self.path == f"/health/{nonce}":
                self.reply(200, b"ready")
            elif config.get("mode") == "header" and self.path == f"/header/{nonce}":
                values = self.headers.get_all(str(config["header"]), [])
                result: Mapping[str, object] = {
                    "header_count": len(values),
                    "carries_secret": len(values) == 1 and values[0] == config["value"],
                }
                with state.lock:
                    state.header_results.append(result)
                self.reply(200, b'{"accepted":true}')
            elif self.path == f"/result/{nonce}" and self.headers.get(
                "X-SPS-Observer"
            ) == config.get("observer"):
                if config.get("mode") == "header":
                    result = (
                        state.header_results[-1]
                        if state.header_results
                        else {
                            "header_count": 0,
                            "carries_secret": False,
                        }
                    )
                else:
                    methods = config.get("methods", [])
                    rows = state.body_results
                    result = {
                        "all_methods_injected": len(rows) == len(methods)
                        and all(rows.get(method, {}).get("injected") is True for method in methods),
                        "other_fields_unchanged": len(rows) == len(methods)
                        and all(
                            rows.get(method, {}).get("unchanged") is True for method in methods
                        ),
                    }
                self.reply(200, json.dumps(result).encode())
            else:
                self.reply(404)

        def do_POST(self) -> None:
            self.observe_body()

        def do_PUT(self) -> None:
            self.observe_body()

        def do_PATCH(self) -> None:
            self.observe_body()

        def observe_body(self) -> None:
            config = state.config
            nonce = str(config.get("nonce", "run"))
            if config.get("mode") != "body" or self.path != f"/body/{nonce}":
                self.reply(404)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(length))
            except (ValueError, json.JSONDecodeError):
                body = {}
            if not isinstance(body, dict):
                body = {}
            field = str(config["field"])
            other_fields = {key: value for key, value in body.items() if key != field}
            with state.lock:
                state.body_results[self.command] = {
                    "injected": body.get(field) == config["value"],
                    "unchanged": other_fields == config["other_fields"],
                }
            self.reply(200)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    base = f"https://127.0.0.1:{server.server_port}"
    try:
        yield state, base
    finally:
        server.shutdown()
        server.server_close()
        worker.join()


def native_request(
    url: str,
    headers: Mapping[str, str],
    data: bytes | None = None,
    method: str | None = None,
) -> int:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(url, data=data, headers=dict(headers), method=method)
    try:
        response = opener.open(request, timeout=3)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        response.read(4096)
        status = response.status
        if not isinstance(status, int):
            raise AssertionError("HTTP response status must be an integer")
        return status


def configure_sender(monkeypatch: pytest.MonkeyPatch, state: State) -> None:
    def send(
        driver: RecordingDriver, box: object, script: str, client: Mapping[str, object]
    ) -> None:
        del box, script
        config_data = next(
            data
            for _, path, data in reversed(driver.file_writes)
            if path == "/tmp/sps-v4-receiver.json"
        )
        state.config = json.loads(config_data)
        if state.config["mode"] == "header":
            native_request(
                str(client["url"]),
                {str(client["header"]): str(state.config["value"])},
            )
            return
        field = str(state.config["field"])
        other_fields = client["other_fields"]
        methods = client["methods"]
        if not isinstance(other_fields, Mapping) or not isinstance(methods, list):
            raise AssertionError("body client config is invalid")
        value = {**other_fields, field: state.config["value"]}
        for method in methods:
            native_request(
                str(client["url"]),
                {"Content-Type": "application/json"},
                json.dumps(value).encode(),
                str(method),
            )

    monkeypatch.setattr(probe, "_send", send)


def deliver(items: list[tuple[str, str]], headers: Mapping[str, str]) -> None:
    for url, token in items:
        status = native_request(url, {"X-SPS-Probe": token, **headers})
        if status != 200:
            raise AssertionError("receiver rejected the probe")


@pytest.mark.loopback
@pytest.mark.integration
def test_secret_header_replaces_dummy_and_reports_no_secret_value(
    fake_receiver: tuple[State, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    state, base = fake_receiver
    state.records_available = False
    configure_sender(monkeypatch, state)
    driver = RecordingDriver(base)

    result = probe.secret_header(driver, {"header": "Authorization"}, "run")

    assert result == {"header_count": 1, "carries_secret": True}
    assert set(result) == {"header_count", "carries_secret"}
    secret = next(inputs["value"] for op, _, inputs in driver.calls if op == "secret.create")
    assert len(str(secret)) == 64
    assert str(secret) not in json.dumps(result)
    created = next(inputs for op, _, inputs in reversed(driver.calls) if op == "create")
    assert created["secret"] is driver.secret
    assert created["requirements"] == {
        "hidden_secrets": {"inject_into": ["127.0.0.1"], "injection": "sets_header"}
    }
    assert state.statuses == [200, 200, 200, 200]


@pytest.mark.loopback
@pytest.mark.integration
def test_secret_body_injects_field_for_all_methods_and_preserves_other_fields(
    fake_receiver: tuple[State, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    state, base = fake_receiver
    state.records_available = False
    configure_sender(monkeypatch, state)
    driver = RecordingDriver(base)

    result = probe.secret_body(driver, {"field": "access_token"}, "run")

    assert result == {"all_methods_injected": True, "other_fields_unchanged": True}
    assert set(state.body_results) == {"POST", "PUT", "PATCH"}
    assert all(row == {"injected": True, "unchanged": True} for row in state.body_results.values())
    assert set(result) == {"all_methods_injected", "other_fields_unchanged"}
    created = next(inputs for op, _, inputs in reversed(driver.calls) if op == "create")
    assert created["requirements"] == {
        "hidden_secrets": {"inject_into": ["127.0.0.1"], "injection": "adds_body_field"}
    }
    secret = next(inputs["value"] for op, _, inputs in driver.calls if op == "secret.create")
    assert len(str(secret)) == 64
    assert str(secret) not in json.dumps(result)
    assert state.statuses == [200, 200, 200, 200, 200, 200]


@pytest.mark.loopback
@pytest.mark.integration
def test_secret_hosts_passes_only_when_each_receiver_records_the_secret(
    fake_receiver: tuple[State, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    _state, base = fake_receiver
    value = "sps-v4-run"
    hosts = ["first.example.test", "second.example.test"]
    urls = [f"{base.replace('127.0.0.1', host)}/check" for host in hosts]
    inputs = {"value": value, "hosts": hosts, "urls": urls}

    def send_with_secret(driver: Driver, target: object, items: list[tuple[str, str]]) -> None:
        del driver, target
        deliver(items, {"X-SPS-Secret": value})

    monkeypatch.setattr(probe, "_send_host_requests", send_with_secret)
    driver = RecordingDriver()
    result = probe.secret_hosts(driver, object(), inputs, "run")

    assert result == {"every_host_received": True}
    assert value not in json.dumps(result)

    def send_without_secret(driver: Driver, target: object, items: list[tuple[str, str]]) -> None:
        del driver, target
        deliver(items, {"X-Unrelated": value})

    monkeypatch.setattr(probe, "_send_host_requests", send_without_secret)
    missed = probe.secret_hosts(RecordingDriver(), object(), inputs, "run")

    assert missed == {"every_host_received": False}
    assert value not in json.dumps(missed)


def test_secret_hosts_uses_the_run_nonce_as_a_unique_secret(
    fake_receiver: tuple[State, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    del fake_receiver
    hosts = ["first.example.test", "second.example.test"]
    urls = [f"https://{host}/check" for host in hosts]
    sent: list[str] = []

    def record_statuses(
        _driver: Driver, _target: object, _urls: list[str], secret: str
    ) -> list[bool]:
        sent.append(secret)
        return [True, True]

    monkeypatch.setattr(
        probe,
        "_guest_statuses",
        record_statuses,
    )
    result = probe.secret_hosts(
        RecordingDriver(), object(), {"hosts": hosts, "urls": urls}, "run-unique"
    )

    assert result == {"every_host_received": True}
    assert sent == ["sps-v4-run-unique"]


@pytest.mark.loopback
@pytest.mark.integration
def test_secret_hosts_is_not_run_without_a_recorded_request(
    fake_receiver: tuple[State, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    _state, base = fake_receiver
    hosts = ["first.example.test", "second.example.test"]
    urls = [f"{base.replace('127.0.0.1', host)}/check" for host in hosts]

    def send_nothing(driver: Driver, target: object, items: list[tuple[str, str]]) -> None:
        del driver, target, items

    monkeypatch.setattr(probe, "_send_host_requests", send_nothing)
    with pytest.raises(NotRun, match="secret_receiver_observation_mismatch"):
        probe.secret_hosts(
            RecordingDriver(),
            object(),
            {"value": ENDPOINT_SECRET, "hosts": hosts, "urls": urls},
            "run",
        )


@pytest.mark.loopback
@pytest.mark.integration
def test_secret_wildcard_checks_direct_and_deeper_local_subdomains(
    fake_receiver: tuple[State, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    _state, base = fake_receiver
    monkeypatch.setattr(network_probe, "runner_controls", lambda *_: None)
    value = ENDPOINT_SECRET
    urls = [
        f"{base.replace('127.0.0.1', 'worker.example.test')}/check",
        f"{base.replace('127.0.0.1', 'deep.worker.example.test')}/check",
    ]

    def send_with_secret(driver: Driver, target: object, items: list[tuple[str, str]]) -> None:
        del driver, target
        deliver(items, {"X-SPS-Secret": value})

    monkeypatch.setattr(probe, "_send_host_requests", send_with_secret)
    result = probe.secret_wildcard(
        RecordingDriver(),
        object(),
        {"value": value, "host": "*.example.test", "urls": urls},
        "run",
    )

    assert result == {"every_wildcard_host_received": True}
    assert value not in json.dumps(result)
    with pytest.raises(ValueError, match="wildcard URLs must be subdomains of their host"):
        probe.secret_wildcard(
            RecordingDriver(),
            object(),
            {"value": value, "host": "*.example.test", "urls": [f"{base}/check", urls[1]]},
            "run",
        )
    with pytest.raises(ValueError, match="direct and deeper subdomain"):
        probe.secret_wildcard(
            RecordingDriver(),
            object(),
            {"value": value, "host": "*.example.test", "urls": [urls[0], urls[0]]},
            "run",
        )


def test_host_client_honours_the_sandbox_proxy_and_omits_the_secret() -> None:
    assert "ProxyHandler()" in probe._HOST_CLIENT
    assert "ProxyHandler({})" not in probe._HOST_CLIENT
    assert "X-SPS-Secret" not in probe._HOST_CLIENT


@pytest.mark.loopback
@pytest.mark.integration
def test_host_client_sends_request_through_proxy_and_proxy_injects_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret = "proxy-injected-secret"
    observed: list[tuple[str, str | None]] = []

    class ProxyHandler(BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:
            pass

        def do_GET(self) -> None:
            observed.append((self.path, self.headers.get("X-SPS-Secret")))
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

    proxy = ThreadingHTTPServer(("127.0.0.1", 0), ProxyHandler)
    proxy_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
    proxy_thread.start()
    config = tmp_path / "hosts.json"
    config.write_text(
        json.dumps(
            {"requests": [{"url": "http://destination.example.test/check", "token": "run-token"}]}
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("http_proxy", f"http://127.0.0.1:{proxy.server_port}")
    monkeypatch.setenv("HTTP_PROXY", f"http://127.0.0.1:{proxy.server_port}")
    monkeypatch.setenv("no_proxy", "")
    monkeypatch.setenv("NO_PROXY", "")
    try:
        completed = subprocess.run(
            [
                "python3",
                "-c",
                probe._HOST_CLIENT.replace(
                    'Path("/tmp/sps-v4-hosts.json")', f"Path({str(config)!r})"
                ),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    finally:
        proxy.shutdown()
        proxy.server_close()
        proxy_thread.join()

    assert completed.returncode == 0, completed.stderr
    assert observed == [("http://destination.example.test/check", None)]
    # The sandbox proxy, rather than the guest client, adds the hidden secret.
    assert secret not in probe._HOST_CLIENT


@pytest.mark.loopback
@pytest.mark.integration
def test_guest_clients_send_their_requests_to_the_local_receiver(
    fake_receiver: tuple[State, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state, base = fake_receiver
    state.config = {
        "mode": "header",
        "nonce": "run",
        "header": "Authorization",
        "value": "injected-secret",
        "observer": "observer",
        "field": "access_token",
        "other_fields": {"marker": "kept", "number": 17},
        "methods": ["POST", "PUT", "PATCH"],
    }
    monkeypatch.setenv("NO_PROXY", "*")
    monkeypatch.setenv("no_proxy", "*")

    def run_client(name: str, script: str, config: Mapping[str, object]) -> None:
        config_path = tmp_path / f"{name}.json"
        script_path = tmp_path / f"{name}.py"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        script_path.write_text(
            script.replace("/tmp/sps-v4-client.json", str(config_path)).replace(
                "/tmp/sps-v4-hosts.json", str(config_path)
            ),
            encoding="utf-8",
        )
        result = subprocess.run(
            ["python3", str(script_path)], check=False, capture_output=True, text=True
        )
        assert result.returncode == 0, result.stderr

    run_client(
        "header-client",
        probe._HEADER_CLIENT,
        {"url": f"{base}/header/run", "header": "Authorization"},
    )
    assert state.header_results == [{"header_count": 1, "carries_secret": False}]

    state.config = {**state.config, "mode": "body"}
    run_client(
        "body-client",
        probe._BODY_CLIENT,
        {
            "url": f"{base}/body/run",
            "methods": ["POST", "PUT", "PATCH"],
            "other_fields": {"marker": "kept", "number": 17},
        },
    )
    assert state.body_results == {
        method: {"injected": False, "unchanged": True} for method in ("POST", "PUT", "PATCH")
    }

    state.config = {**state.config, "mode": "hosts"}
    run_client(
        "hosts-client",
        probe._HOST_CLIENT,
        {"requests": [{"url": f"{base}/check", "token": "host-token"}]},
    )
    assert state.records["host-token"][0]["method"] == "GET"
    assert state.records["host-token"][0]["path"] == "/check"
    assert state.statuses == [200, 200, 200, 200, 200]
