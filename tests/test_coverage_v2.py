# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Offline tests for V2's controlled egress fixtures."""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import threading
from collections import defaultdict
from collections.abc import Iterator, Mapping
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import cast
from urllib.parse import unquote, urlsplit

import pytest

from sandbox_provider_spec import coverage_network, coverage_v2
from sandbox_provider_spec.driver import Driver, Inputs, NotRun, Observation

pytestmark = [pytest.mark.integration, pytest.mark.loopback]


class Receiver(ThreadingHTTPServer):
    """Local receiver that can refuse selected guest requests before recording them."""

    mode = ""
    in_guest = False
    records: dict[str, list[dict[str, str]]] = defaultdict(list)


class ReceiverHandler(BaseHTTPRequestHandler):
    server: Receiver

    def _serve(self, method: str) -> None:
        path = urlsplit(self.path).path
        if path.startswith("/records/"):
            token = unquote(path.removeprefix("/records/"))
            payload = json.dumps({"records": self.server.records[token]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        denied = self.server.in_guest and (
            (self.server.mode == "deny_wins" and path == "/denied")
            or (self.server.mode == "http_rules" and (method != "GET" or path != "/allowed/x"))
            or (self.server.mode == "http_rule_deny" and method == "POST")
        )
        if denied:
            self.send_response(403)
            self.end_headers()
            return

        request_token = self.headers.get("X-SPS-Probe")
        if request_token:
            self.server.records[request_token].append({"method": method, "path": path})
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def do_GET(self) -> None:
        self._serve("GET")

    def do_POST(self) -> None:
        self._serve("POST")

    def log_message(self, *_: object) -> None:
        pass


@pytest.fixture
def receiver() -> Iterator[tuple[Receiver, str]]:
    server = Receiver(("127.0.0.1", 0), ReceiverHandler)
    server.records = defaultdict(list)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield server, f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        worker.join()


class LocalDriver(Driver):
    def __init__(self, server: Receiver) -> None:
        super().__init__()
        self.server = server
        self.files: dict[str, bytes] = {}

    def call(self, operation: str, target: object, inputs: Inputs) -> Observation:
        del target
        if operation == "files.write":
            self.files[str(inputs["path"])] = base64.b64decode(cast(str, inputs["data"]))
            return {}
        assert operation == "run"
        script_path = cast(str, inputs["bash_script"]).removeprefix("python3 ")
        script = self.files[script_path].decode()
        environment = os.environ.copy()
        environment.update(cast(dict[str, str], inputs["environment"]))
        self.server.in_guest = True
        try:
            result = subprocess.run(
                [sys.executable, "-c", script],
                capture_output=True,
                check=False,
                env=environment,
                timeout=60,
            )
        finally:
            self.server.in_guest = False
        return {"exit_code": result.returncode, "stdout": result.stdout}


class StaticDriver(Driver):
    def __init__(self, output: Mapping[str, object] | list[Mapping[str, object]]) -> None:
        super().__init__()
        self.output = output
        self.calls: list[tuple[str, Inputs]] = []

    def call(self, operation: str, target: object, inputs: Inputs) -> Observation:
        del target
        self.calls.append((operation, inputs))
        if operation == "files.write":
            return {}
        assert operation == "run"
        return {"exit_code": 0, "stdout": json.dumps(self.output)}


def test_allowlist_checks_controls_and_reports_success_not_just_reachability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    controls: list[tuple[list[str], list[str]]] = []
    records = {
        "https://allowed.example/": [("GET", "/")],
        "https://blocked.example/": [],
    }
    monkeypatch.setattr(
        coverage_v2,
        "_runner_controls",
        lambda urls, methods: controls.append((urls, methods)),
    )
    monkeypatch.setattr(coverage_network, "outside", lambda urls: [True] * len(urls))
    monkeypatch.setattr(
        coverage_v2, "_guest_http", lambda *_: ([True, True, False], ["a", "b", "c"])
    )
    monkeypatch.setattr(coverage_v2, "_records", lambda url, token: records[url])
    urls = {
        "allowed_url": "https://allowed.example/",
        "allowed_ip_url": "https://192.0.2.1/",
        "denied_url": "https://blocked.example/",
    }
    assert coverage_v2.allowlist(StaticDriver({}), {}, urls) == {
        "listed_name_allowed": True,
        "listed_address_allowed": True,
        "unlisted_denied": True,
    }
    assert controls == [(["https://allowed.example/", "https://blocked.example/"], ["GET", "GET"])]


def test_deny_wins_proves_allowed_receiver_and_denied_non_arrival(
    receiver: tuple[Receiver, str],
) -> None:
    server, base = receiver
    server.mode = "deny_wins"
    result = coverage_v2.deny_wins(
        LocalDriver(server),
        {},
        {"allowed_url": base + "/allowed", "denied_url": base + "/denied"},
    )
    assert result == {
        "denied_refused": True,
        "allowed_succeeded": True,
        "denied_receiver_not_reached": True,
    }


def test_http_rules_observes_only_the_matching_request_at_the_receiver(
    receiver: tuple[Receiver, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server, base = receiver
    server.mode = "http_rules"
    monkeypatch.setattr(coverage_v2, "_same_receiver", lambda _: None)
    result = coverage_v2.http_rules(
        LocalDriver(server),
        {},
        {
            "allowed_url": base + "/allowed/x",
            "wrong_method_url": base + "/allowed/x",
            "outside_path_url": base + "/other",
        },
    )
    assert result == {
        "matching_get_succeeded": True,
        "wrong_method_failed": True,
        "outside_path_failed": True,
        "receiver_saw_only_matching_request": True,
    }


def test_http_rule_deny_observes_unmatched_get_and_absent_matching_post(
    receiver: tuple[Receiver, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server, base = receiver
    server.mode = "http_rule_deny"
    monkeypatch.setattr(coverage_v2, "_same_receiver", lambda _: None)
    result = coverage_v2.http_rule_deny(
        LocalDriver(server),
        {},
        {"get_url": base + "/allowed/x", "post_url": base + "/allowed/x"},
    )
    assert result == {
        "unmatched_get_succeeded": True,
        "matching_post_failed": True,
        "receiver_saw_only_unmatched_request": True,
    }


def test_network_check_requires_tokened_recorder_for_allowed_and_blocked_requests(
    receiver: tuple[Receiver, str],
) -> None:
    server, base = receiver
    server.mode = "deny_wins"
    result = coverage_network.network_checks(
        LocalDriver(server),
        {},
        {
            "requests": [
                {"url": base + "/allowed", "reachable": True},
                {"url": base + "/denied", "reachable": False, "recorder": "absent"},
            ]
        },
    )
    assert result == {
        "passed": True,
        "observations": [
            {"reached": True, "recorded": True},
            {"reached": False, "recorded": False},
        ],
    }


def test_http_rule_fixture_requires_one_https_receiver() -> None:
    with pytest.raises(ValueError, match="one HTTPS receiver"):
        coverage_v2._same_receiver(["http://127.0.0.1:1/allowed/x"])
    with pytest.raises(ValueError, match="one HTTPS receiver"):
        coverage_v2._same_receiver(
            ["https://one.example/allowed/x", "https://two.example/allowed/x"]
        )


def test_harness_health_reports_all_five_runner_controls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = {
        "http_url": "http://harness.example/health",
        "https_url": "https://harness.example/health",
        "tls_host": "harness.example",
        "tls_port": 7443,
        "tcp_host": "harness.example",
        "tcp_port": 7000,
        "udp_host": "harness.example",
        "udp_port": 7001,
    }
    observed = {"http": True, "https": True, "tls": True, "tcp": True, "udp": True}
    monkeypatch.setattr(coverage_v2, "_runner_harness", lambda _: observed)
    assert coverage_v2.harness_health(StaticDriver({}), None, {"harness": harness}) == {
        "all_transports_healthy": True
    }
    observed["udp"] = False
    with pytest.raises(NotRun, match="network_unrestricted_control_unavailable"):
        coverage_v2.harness_health(StaticDriver({}), None, {"harness": harness})


def test_domain_traffic_checks_runner_controls_twice_and_classifies_guest_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = {
        "http_url": "http://harness.example/health",
        "https_url": "https://harness.example/health",
        "tls_host": "harness.example",
        "tls_port": 7443,
        "tcp_host": "harness.example",
        "tcp_port": 7000,
        "udp_host": "harness.example",
        "udp_port": 7001,
    }
    checks: list[object] = []

    def healthy(value: object) -> dict[str, bool]:
        checks.append(value)
        return {"http": True, "https": True, "tls": True, "tcp": True, "udp": True}

    monkeypatch.setattr(coverage_v2, "_runner_harness", healthy)
    monkeypatch.setattr(
        coverage_v2,
        "_records",
        lambda url, _token: [("GET", "/health")] if url == harness["https_url"] else [],
    )
    guest = {"http": False, "https": True, "tls": False, "tcp": False, "udp": False}
    driver = StaticDriver(guest)
    assert coverage_v2.domain_traffic(driver, {}, {"harness": harness}) == {
        "domain_traffic": "https"
    }
    assert len(checks) == 2
    assert [operation for operation, _ in driver.calls] == ["files.write", "run"]
    assert (
        coverage_v2._domain_traffic(
            {"http": True, "https": True, "tls": False, "tcp": False, "udp": False}
        )
        == "http_and_https"
    )
    assert (
        coverage_v2._domain_traffic(
            {"http": False, "https": True, "tls": True, "tcp": False, "udp": False}
        )
        == "tls"
    )
    assert (
        coverage_v2._domain_traffic(
            {"http": True, "https": True, "tls": True, "tcp": True, "udp": True}
        )
        == "all"
    )
    assert (
        coverage_v2._domain_traffic(
            {"http": False, "https": True, "tls": False, "tcp": True, "udp": False}
        )
        == "other"
    )


def test_domain_traffic_does_not_run_without_healthy_controls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = {
        "http_url": "http://harness.example/health",
        "https_url": "https://harness.example/health",
        "tls_host": "harness.example",
        "tls_port": 7443,
        "tcp_host": "harness.example",
        "tcp_port": 7000,
        "udp_host": "harness.example",
        "udp_port": 7001,
    }
    monkeypatch.setattr(
        coverage_v2,
        "_runner_harness",
        lambda _: {"http": True, "https": True, "tls": True, "tcp": True, "udp": False},
    )
    driver = StaticDriver({})
    with pytest.raises(NotRun, match="network_unrestricted_control_unavailable"):
        coverage_v2.domain_traffic(driver, {}, {"harness": harness})
    assert driver.calls == []
