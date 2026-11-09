# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Network observations require healthy controls and preserve native source state."""

from __future__ import annotations

import base64
import json
import os
import runpy
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, cast

import pytest
from jsonschema import Draft202012Validator

from sandbox_provider_spec import coverage_network as probe
from sandbox_provider_spec import coverage_network_probe as network_probe
from sandbox_provider_spec.check import spec_dir
from sandbox_provider_spec.driver import Driver, Inputs, NotRun, Observation, Unsupported
from sandbox_provider_spec.runner import Runner
from sandbox_provider_spec.suite import Test as Scenario
from sandbox_provider_spec.suite import suite_path

pytestmark = [pytest.mark.integration, pytest.mark.loopback]


def test_guest_http_ignores_proxy_and_distinguishes_server_denial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = runpy.run_path(str(suite_path().parent / "fixtures/coverage_http.py"))
    request = cast(Callable[[str], dict[str, bool]], module["request"])

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response({"/": 200, "/denied": 403}.get(self.path, 404))
            self.end_headers()

        def log_message(self, *_: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    try:
        url = f"http://127.0.0.1:{server.server_port}"
        assert request(url) == {"reached": True, "ambiguous": False}
        assert request(url + "/denied") == {"reached": False, "ambiguous": False}
        assert request(url + "/missing") == {"reached": False, "ambiguous": False}
    finally:
        server.shutdown()
        server.server_close()
        worker.join()


def test_tls_failure_is_not_policy_proof() -> None:
    with pytest.raises(NotRun, match="network_tls_observation_ambiguous"):
        probe.parse('{"results":[{"reached":false,"ambiguous":true}]}', 1)


def test_http_script_marks_certificate_verification_failure_ambiguous(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class FailingOpener:
        def open(self, *_args: object, **_kwargs: object) -> None:
            raise urllib.error.URLError(ssl.SSLCertVerificationError("certificate verify failed"))

    request = {"url": "https://receiver.example/probe", "method": "GET", "token": "local-test"}
    monkeypatch.setenv(
        network_probe.HTTP_WORKER_REQUEST_ENV,
        base64.b64encode(json.dumps(request).encode()).decode(),
    )
    monkeypatch.setattr(urllib.request, "build_opener", lambda *_args: FailingOpener())

    exec(compile(network_probe.HTTP_WORKER_SCRIPT, "<sps-http-probe-worker>", "exec"), {})

    assert json.loads(capsys.readouterr().out) == {"succeeded": False, "ambiguous": True}


@pytest.mark.parametrize("field", ["requests", "records"])
def test_receiver_records_accepts_deployed_and_legacy_payload_shapes(field: str) -> None:
    payload = json.dumps(
        {
            "token": "per-test-token",
            field: [{"method": "GET", "path": "/health?sps_run=one"}],
            "connections": [],
        }
    ).encode()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/probe"
        assert network_probe.records(url, "per-test-token") == [("GET", "/health")]
    finally:
        server.shutdown()
        server.server_close()
        worker.join()


@pytest.mark.parametrize(
    ("failure", "expected_detail"),
    [
        ("http", "HTTP status 404"),
        ("url", "URLError: collector unavailable"),
        ("url_exception", "OSError: collector unavailable"),
        ("timeout", "TimeoutError: timeout for <url>"),
        ("os", "OSError: socket unavailable at /records/<namespace>"),
    ],
)
def test_records_observer_failure_detail_is_specific_and_redacted(
    monkeypatch: pytest.MonkeyPatch, failure: str, expected_detail: str
) -> None:
    token = "private-namespace-token"

    class FailingOpener:
        def open(self, request: object, timeout: float = 8) -> None:
            assert timeout == 8
            url = request.full_url  # type: ignore[attr-defined]
            if failure == "http":
                raise urllib.error.HTTPError(url, 404, "not found", Message(), None)
            if failure == "url":
                raise urllib.error.URLError("collector unavailable")
            if failure == "url_exception":
                raise urllib.error.URLError(OSError("collector unavailable"))
            if failure == "timeout":
                raise TimeoutError(f"timeout for {url}")
            raise OSError(f"socket unavailable at /records/{token}")

    monkeypatch.setattr(urllib.request, "build_opener", lambda *_args: FailingOpener())
    with pytest.raises(NotRun, match="network_receiver_observer_unavailable") as captured:
        network_probe.records("https://receiver.example/health", token)

    detail = captured.value.detail
    assert detail == expected_detail
    assert detail is not None
    assert token not in detail


def test_runner_keeps_not_run_detail_on_the_step(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable(self: Runner, step: object, bindings: object) -> dict[str, object]:
        del self, step, bindings
        raise NotRun("network_receiver_observer_unavailable", detail="HTTP status 404")

    monkeypatch.setattr(Runner, "_step", unavailable)
    scenario = Scenario("network_lockdown.observer", "observer", ({"op": "probe"},), ())
    result = Runner(Driver()).run_test(scenario)

    assert result["result"] == "not_run"
    assert result["reason"] == "network_receiver_observer_unavailable"
    assert "detail" not in result
    steps = cast(list[dict[str, object]], result["steps"])
    assert steps[0]["detail"] == "HTTP status 404"
    test_schema: dict[str, Any] = {
        "$ref": "#/$defs/test",
        "$defs": json.loads((spec_dir() / "report-schema.json").read_text(encoding="utf-8"))[
            "$defs"
        ],
    }
    assert not list(Draft202012Validator(test_schema).iter_errors(cast(Any, result)))


@pytest.mark.parametrize(("status", "expected"), [(200, True), (403, False)])
def test_guest_http_preserves_success_and_http_error_results(status: int, expected: bool) -> None:
    seen_tokens: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            seen_tokens.append(self.headers.get("X-SPS-Probe", ""))
            self.send_response(status)
            self.end_headers()

        def log_message(self, *_: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    token = "per-test-token"
    requests = [
        {"url": f"http://127.0.0.1:{server.server_port}/blocked", "method": "GET", "token": token}
    ]
    env = os.environ.copy()
    env[network_probe.HTTP_ENV] = base64.b64encode(json.dumps(requests).encode()).decode()
    env[network_probe.HTTP_DEADLINE_ENV] = str(network_probe.HTTP_REQUEST_DEADLINE_SECONDS)
    env[network_probe.HTTP_WORKER_ENV] = base64.b64encode(
        network_probe.HTTP_WORKER_SCRIPT.encode()
    ).decode()
    try:
        result = subprocess.run(
            [sys.executable, "-c", network_probe.HTTP_SCRIPT],
            capture_output=True,
            check=True,
            env=env,
            timeout=10,
        )
        assert json.loads(result.stdout) == [
            {"succeeded": expected, "ambiguous": False, "error": False}
        ]
        assert seen_tokens == [token]
    finally:
        server.shutdown()
        server.server_close()
        worker.join()


def test_guest_http_blocked_dns_completes_as_one_failed_probe_within_deadline() -> None:
    token = "per-test-token"
    requests = [{"url": "http://dns-blocked.invalid/probe", "method": "GET", "token": token}]
    env = os.environ.copy()
    env[network_probe.HTTP_ENV] = base64.b64encode(json.dumps(requests).encode()).decode()
    env[network_probe.HTTP_DEADLINE_ENV] = "10.0"
    worker_script = (
        "import socket, time\n"
        "def blocked_dns(*args, **kwargs):\n"
        "    time.sleep(0.05)\n"
        "    raise socket.gaierror('blocked by policy')\n"
        "socket.getaddrinfo = blocked_dns\n" + network_probe.HTTP_WORKER_SCRIPT
    )
    env[network_probe.HTTP_WORKER_ENV] = base64.b64encode(worker_script.encode()).decode()

    started = time.monotonic()
    result = subprocess.run(
        [sys.executable, "-c", network_probe.HTTP_SCRIPT],
        capture_output=True,
        check=True,
        env=env,
        timeout=30,
    )
    elapsed = time.monotonic() - started

    assert json.loads(result.stdout) == [{"succeeded": False, "ambiguous": False, "error": False}]
    assert elapsed < float(env[network_probe.HTTP_DEADLINE_ENV])


def test_http_script_marks_worker_deadline_expiry_as_error() -> None:
    requests = [{"url": "http://dns-blocked.invalid/probe", "method": "GET", "token": "local"}]
    env = os.environ.copy()
    env[network_probe.HTTP_ENV] = base64.b64encode(json.dumps(requests).encode()).decode()
    env[network_probe.HTTP_DEADLINE_ENV] = "0.25"
    worker_script = "import time\ntime.sleep(5)\n" + network_probe.HTTP_WORKER_SCRIPT
    env[network_probe.HTTP_WORKER_ENV] = base64.b64encode(worker_script.encode()).decode()

    started = time.monotonic()
    result = subprocess.run(
        [sys.executable, "-c", network_probe.HTTP_SCRIPT],
        capture_output=True,
        check=True,
        env=env,
        timeout=3,
    )
    elapsed = time.monotonic() - started

    assert json.loads(result.stdout) == [{"succeeded": False, "ambiguous": False, "error": True}]
    assert elapsed < 1.25


def test_guest_http_worker_deadline_is_inconclusive() -> None:
    class TimedOutDriver(Driver):
        def call(self, operation: str, target: object, inputs: Inputs) -> Observation:
            del target, inputs
            if operation == "files.write":
                return {}
            assert operation == "run"
            return {
                "exit_code": 0,
                "stdout": '[{"succeeded":false,"ambiguous":false,"error":true}]',
            }

    with pytest.raises(NotRun, match="network_guest_probe_inconclusive"):
        network_probe.guest_http(TimedOutDriver(), {}, [("https://example.test/", "GET")])


def test_guest_http_runner_deadline_is_inconclusive() -> None:
    class TimedOutDriver(Driver):
        def call(self, operation: str, target: object, inputs: Inputs) -> Observation:
            del target, inputs
            if operation == "files.write":
                return {}
            assert operation == "run"
            return {"exit_code": 124, "stdout": ""}

    with pytest.raises(NotRun, match="network_guest_probe_inconclusive"):
        network_probe.guest_http(TimedOutDriver(), {}, [("https://example.test/", "GET")])


def test_guest_http_runner_timeout_covers_worker_deadline() -> None:
    class RecordingDriver(Driver):
        def __init__(self) -> None:
            super().__init__()
            self.run_inputs: dict[str, object] = {}

        def call(self, operation: str, target: object, inputs: Inputs) -> Observation:
            del target
            if operation == "files.write":
                return {}
            assert operation == "run"
            self.run_inputs = dict(inputs)
            return {
                "exit_code": 0,
                "stdout": '[{"succeeded":true,"ambiguous":false,"error":false}]',
            }

    driver = RecordingDriver()
    successes, tokens = network_probe.guest_http(
        driver, {}, [("https://receiver.example/probe", "GET")]
    )
    assert successes == [True]
    assert len(tokens) == 1
    env = driver.run_inputs["environment"]
    assert isinstance(env, dict)
    assert env[network_probe.HTTP_DEADLINE_ENV] == str(network_probe.HTTP_REQUEST_DEADLINE_SECONDS)
    assert driver.run_inputs["timeout_ms"] == (
        network_probe.HTTP_REQUEST_DEADLINE_SECONDS * 1000
        + network_probe.HTTP_RUN_TIMEOUT_MARGIN_MS
    )


def test_guest_http_tls_failure_is_ambiguous() -> None:
    class DriverWithAmbiguousTLS(Driver):
        def call(self, operation: str, target: object, inputs: Inputs) -> Observation:
            del target, inputs
            if operation == "files.write":
                return {}
            assert operation == "run"
            return {
                "exit_code": 0,
                "stdout": json.dumps([{"succeeded": False, "ambiguous": True, "error": False}]),
            }

    driver = DriverWithAmbiguousTLS()
    request = [("https://example.test/", "GET")]
    observations, tokens = network_probe.guest_http_observations(driver, {}, request)
    assert observations == [{"succeeded": False, "ambiguous": True, "error": False}]
    assert len(tokens) == 1
    with pytest.raises(NotRun, match="network_tls_observation_ambiguous"):
        network_probe.guest_http(driver, {}, request)


@pytest.mark.parametrize(
    ("recorded_requests", "recorder_unavailable", "expected"),
    [
        ([], False, {"reached": False, "recorded": False}),
        ([("GET", "/blocked")], False, {"reached": True, "recorded": True}),
        ([], True, None),
    ],
)
def test_checked_probe_resolves_tls_failure_from_recorder(
    monkeypatch: pytest.MonkeyPatch,
    recorded_requests: list[tuple[str, str]],
    recorder_unavailable: bool,
    expected: dict[str, bool] | None,
) -> None:
    token = "per-test-token"
    observed_tokens: list[str] = []

    def ambiguous_guest_http(
        driver: Driver, target: object, requests: list[tuple[str, str]]
    ) -> tuple[list[dict[str, bool]], list[str]]:
        del driver, target, requests
        return ([{"succeeded": False, "ambiguous": True, "error": False}], [token])

    def read_records(url: str, observed_token: str) -> list[tuple[str, str]]:
        assert url == "https://receiver.example/blocked"
        observed_tokens.append(observed_token)
        if recorder_unavailable:
            raise NotRun("network_receiver_observer_unavailable", detail="HTTP status 404")
        return recorded_requests

    monkeypatch.setattr(network_probe, "runner_controls", lambda *_args: None)
    monkeypatch.setattr(probe, "outside", lambda _targets: [True])
    monkeypatch.setattr(network_probe, "guest_http_observations", ambiguous_guest_http)
    monkeypatch.setattr(network_probe, "records", read_records)

    request: list[Mapping[str, object]] = [
        {"url": "https://receiver.example/blocked", "recorder": "absent"}
    ]
    if recorder_unavailable:
        with pytest.raises(NotRun, match="network_tls_observation_ambiguous") as captured:
            probe.checked_probe(Driver(), {}, request)
        assert captured.value.detail == "HTTP status 404"
    else:
        assert probe.checked_probe(Driver(), {}, request) == [expected]
    assert observed_tokens == [token]


def test_checked_probe_keeps_recorder_free_tls_failure_ambiguous(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def ambiguous_guest_http(
        driver: Driver, target: object, requests: list[tuple[str, str]]
    ) -> tuple[list[dict[str, bool]], list[str]]:
        del driver, target, requests
        return ([{"succeeded": False, "ambiguous": True, "error": False}], ["token"])

    monkeypatch.setattr(network_probe, "guest_http_observations", ambiguous_guest_http)
    monkeypatch.setattr(probe, "outside", lambda _targets: [True])
    monkeypatch.setattr(
        network_probe,
        "records",
        lambda *_args: pytest.fail("recorder-free probe must not query records"),
    )

    with pytest.raises(NotRun, match="network_tls_observation_ambiguous"):
        probe.checked_probe(
            Driver(), {}, [{"url": "https://receiver.example/blocked", "recorder": "none"}]
        )


class NetworkDriver(Driver):
    def __init__(self, *, update: bool = True, replace_process: bool = False) -> None:
        super().__init__()
        self.update = update
        self.changed = False
        self.replace_process = replace_process
        self.files: dict[str, bytes] = {}
        self.count = 0

    def call(self, operation: str, target: object, inputs: Inputs) -> Observation:
        del target
        if operation == "files.write":
            self.files[str(inputs["path"])] = base64.b64decode(str(inputs["data"]))
            return {}
        if operation == "files.read_bytes":
            path = inputs["path"]
            if path == "/tmp/sps-idle-activity.json":
                self.count += 10
                pid = 2 if self.replace_process and self.changed else 1
                return {"data": json.dumps({"pid": pid, "count": self.count})}
            return {"data": self.files[str(path)]}
        if operation == "network.update":
            if not self.update:
                raise Unsupported("native_update_absent")
            self.changed = True
            return {}
        assert operation == "run"
        script = str(inputs["bash_script"])
        if script.startswith("nohup"):
            return {"exit_code": 0}
        return {
            "exit_code": 0,
            "stdout": json.dumps({"results": [{"reached": not self.changed, "ambiguous": False}]}),
        }


def test_recorded_http_error_does_not_prove_open_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(network_probe, "runner_controls", lambda *_: None)
    monkeypatch.setattr(
        network_probe,
        "guest_http_observations",
        lambda *_: ([{"succeeded": False, "ambiguous": False, "error": False}], ["one-test-token"]),
    )
    monkeypatch.setattr(network_probe, "records", lambda *_args, **_kwargs: [("GET", "/health")])
    with pytest.raises(NotRun, match="network_receiver_observation_mismatch"):
        probe.checked_probe(
            NetworkDriver(),
            {},
            [{"url": "https://fixture.example/health", "reachable": True}],
        )


def test_policy_change_checks_the_same_process_and_retained_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        probe,
        "checked_probe",
        lambda driver, _target, _requests: [
            {
                "reached": not cast(NetworkDriver, driver).changed,
                "recorded": not cast(NetworkDriver, driver).changed,
            }
        ],
    )
    monkeypatch.setattr(time, "sleep", lambda _: None)
    inputs = {"allowed_url": "https://fixture.invalid/", "new_policy": {"policy": "deny_all"}}
    assert probe.policy_change(NetworkDriver(), {}, inputs) == {
        "policy_changed": True,
        "source_preserved": True,
    }
    assert probe.policy_change(NetworkDriver(replace_process=True), {}, inputs) == {
        "policy_changed": True,
        "source_preserved": False,
    }


def test_audited_native_update_absence_proves_false_only_with_unchanged_control(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        probe,
        "checked_probe",
        lambda driver, _target, _requests: [
            {
                "reached": not cast(NetworkDriver, driver).changed,
                "recorded": not cast(NetworkDriver, driver).changed,
            }
        ],
    )
    monkeypatch.setattr(time, "sleep", lambda _: None)
    inputs = {"allowed_url": "https://fixture.invalid/", "new_policy": {"policy": "deny_all"}}
    assert probe.policy_change(NetworkDriver(update=False), {}, inputs) == {
        "policy_changed": False,
        "source_preserved": True,
    }


def test_denylist_does_not_pass_when_the_unlisted_control_is_unreachable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(probe, "http", lambda *_: [False])
    with pytest.raises(NotRun, match="network_unlisted_control_unavailable"):
        probe.denylist(
            NetworkDriver(),
            {},
            {"blocked_urls": ["https://blocked.invalid/"], "allowed_urls": ["https://ok.invalid/"]},
        )


def test_denylist_validates_every_listed_destination_and_both_outside_controls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(probe, "http", lambda _, __, targets: ["ok.invalid" in x for x in targets])
    blocked = [["http://blocked.invalid/", "https://blocked.invalid/"]]
    allowed = ["https://ok.invalid/"]
    assert probe.denylist(
        NetworkDriver(), {}, {"blocked_urls": blocked, "allowed_urls": allowed}
    ) == {
        "listed_blocked": True,
        "unlisted_allowed": True,
    }


def test_http_redirect_cannot_change_the_destination_under_test() -> None:
    module = runpy.run_path(str(suite_path().parent / "fixtures/coverage_http.py"))
    request = cast(Callable[[str], dict[str, bool]], module["request"])
    calls: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            calls.append(self.path)
            self.send_response(302 if self.path == "/redirect" else 403)
            self.send_header("Location", "/denied")
            self.end_headers()

        def log_message(self, *_: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        assert request(f"http://127.0.0.1:{server.server_port}/redirect") == {
            "reached": False,
            "ambiguous": False,
        }
        assert calls == ["/redirect"]
    finally:
        server.shutdown()
        server.server_close()
        worker.join()
