# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Runner fixtures for mixed egress policy and transport coverage."""

from __future__ import annotations

import base64
import json
import socket
import ssl
import time
import urllib.parse
from collections.abc import Mapping
from typing import cast
from uuid import uuid4

from sandbox_provider_spec import coverage_network
from sandbox_provider_spec.coverage_network_probe import (
    guest_http as _guest_http,
)
from sandbox_provider_spec.coverage_network_probe import (
    guest_json as _guest_json,
)
from sandbox_provider_spec.coverage_network_probe import (
    records as _records,
)
from sandbox_provider_spec.coverage_network_probe import (
    runner_controls as _runner_controls,
)
from sandbox_provider_spec.driver import Driver, NativeFailure, NotRun

TRAFFIC_SCRIPT_PATH = "/tmp/sps-coverage-v2-traffic.py"
TRAFFIC_ENV = "SPS_COVERAGE_V2_TRAFFIC_B64"
TRAFFIC_SCRIPT = r"""import base64, json, os, socket, ssl, urllib.error, urllib.request
config = json.loads(base64.b64decode(os.environ["SPS_COVERAGE_V2_TRAFFIC_B64"]))
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_): return None
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
def http(url, token):
    request = urllib.request.Request(url, headers={"X-SPS-Probe": token})
    try:
        with opener.open(request, timeout=8) as response:
            response.read(1)
            return 200 <= response.status < 300
    except (urllib.error.URLError, TimeoutError, OSError):
        return False
def tls(host, port):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=host):
                return True
    except (OSError, ssl.SSLError):
        return False
def tcp(host, port):
    payload = os.urandom(24)
    try:
        with socket.create_connection((host, port), timeout=5) as connection:
            connection.settimeout(5)
            connection.sendall(payload)
            received = bytearray()
            deadline = __import__("time").monotonic() + 5
            while len(received) < len(payload) and __import__("time").monotonic() < deadline:
                part = connection.recv(len(payload) - len(received))
                if not part: break
                received.extend(part)
            return bytes(received) == payload
    except OSError:
        return False
def udp(host, port):
    payload = os.urandom(24)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
            connection.settimeout(5)
            connection.sendto(payload, (host, port))
            received, _ = connection.recvfrom(256)
            return received == payload
    except OSError:
        return False
h = config
tokens = config["http_tokens"]
result = {
    "http": http(h["http_url"], tokens["http"]),
    "https": http(h["https_url"], tokens["https"]),
    "tls": tls(h["tls_host"], h["tls_port"]),
    "tcp": tcp(h["tcp_host"], h["tcp_port"]),
    "udp": udp(h["udp_host"], h["udp_port"]),
}
print(json.dumps(result, separators=(",", ":")))
"""


def _url(inputs: Mapping[str, object], key: str) -> str:
    return coverage_network.urls([inputs[key]])[0]


def _path(url: str) -> str:
    path = urllib.parse.urlsplit(url).path or "/"
    return path


def allowlist(driver: Driver, target: object, inputs: Mapping[str, object]) -> Mapping[str, object]:
    """Observe listed names and addresses succeeding and an unlisted URL failing."""
    targets = [
        _url(inputs, "allowed_url"),
        _url(inputs, "allowed_ip_url"),
        _url(inputs, "denied_url"),
    ]
    if len(set(targets)) != len(targets):
        raise ValueError("allowlist fixture URLs must be distinct")
    _runner_controls([targets[0], targets[2]], ["GET", "GET"])
    if not all(coverage_network.outside([targets[1]])):
        raise NotRun("network_unlisted_control_unavailable")
    succeeded, tokens = _guest_http(driver, target, [(url, "GET") for url in targets])
    records = [
        _records(url, token) if index != 1 else None
        for index, (url, token) in enumerate(zip(targets, tokens, strict=True))
    ]
    return {
        "listed_name_allowed": succeeded[0] and records[0] == [("GET", _path(targets[0]))],
        "listed_address_allowed": succeeded[1],
        "unlisted_denied": not succeeded[2] and records[2] == [],
    }


def deny_wins(driver: Driver, target: object, inputs: Mapping[str, object]) -> Mapping[str, object]:
    """Verify deny precedence and confirm a refused request did not reach its receiver."""
    allowed_url, denied_url = _url(inputs, "allowed_url"), _url(inputs, "denied_url")
    if allowed_url == denied_url:
        raise ValueError("deny-wins fixture URLs must be distinct")
    urls = [allowed_url, denied_url]
    _runner_controls(urls, ["GET", "GET"])
    reached, tokens = _guest_http(driver, target, [(url, "GET") for url in urls])
    allowed_records = _records(allowed_url, tokens[0])
    denied_records = _records(denied_url, tokens[1])
    return {
        "denied_refused": not reached[1],
        "allowed_succeeded": reached[0] and allowed_records == [("GET", _path(allowed_url))],
        "denied_receiver_not_reached": not denied_records,
    }


def _same_receiver(urls: list[str]) -> None:
    origins = set()
    for url in urls:
        parts = urllib.parse.urlsplit(url)
        origins.add((parts.scheme, parts.netloc.lower()))
    if len(origins) != 1 or any(urllib.parse.urlsplit(url).scheme != "https" for url in urls):
        raise ValueError("HTTP-rule fixture URLs must share one HTTPS receiver")


def http_rules(
    driver: Driver, target: object, inputs: Mapping[str, object]
) -> Mapping[str, object]:
    """Observe one allowed request and two refused requests to the same HTTPS receiver."""
    urls = [
        _url(inputs, "allowed_url"),
        _url(inputs, "wrong_method_url"),
        _url(inputs, "outside_path_url"),
    ]
    _same_receiver(urls)
    if [_path(url) for url in urls] != ["/allowed/x", "/allowed/x", "/other"]:
        raise ValueError("HTTP-rule fixture paths do not match the conformance case")
    methods = ["GET", "POST", "GET"]
    _runner_controls(urls, methods)
    reached, tokens = _guest_http(driver, target, list(zip(urls, methods, strict=True)))
    records = [_records(url, token) for url, token in zip(urls, tokens, strict=True)]
    return {
        "matching_get_succeeded": reached[0],
        "wrong_method_failed": not reached[1],
        "outside_path_failed": not reached[2],
        "receiver_saw_only_matching_request": records == [[("GET", "/allowed/x")], [], []],
    }


def http_rule_deny(
    driver: Driver, target: object, inputs: Mapping[str, object]
) -> Mapping[str, object]:
    """Observe an unmatched GET succeeding and a matching POST refused."""
    urls = [_url(inputs, "get_url"), _url(inputs, "post_url")]
    _same_receiver(urls)
    if _path(urls[0]) != "/allowed/x" or _path(urls[1]) != "/allowed/x":
        raise ValueError("HTTP-rule deny fixture paths do not match the conformance case")
    methods = ["GET", "POST"]
    _runner_controls(urls, methods)
    reached, tokens = _guest_http(driver, target, list(zip(urls, methods, strict=True)))
    records = [_records(url, token) for url, token in zip(urls, tokens, strict=True)]
    return {
        "unmatched_get_succeeded": reached[0],
        "matching_post_failed": not reached[1],
        "receiver_saw_only_unmatched_request": records == [[("GET", "/allowed/x")], []],
    }


def _harness(value: object) -> dict[str, object]:
    required = {
        "http_url",
        "https_url",
        "tls_host",
        "tls_port",
        "tcp_host",
        "tcp_port",
        "udp_host",
        "udp_port",
    }
    if not isinstance(value, Mapping) or not required.issubset(value):
        raise ValueError("egress harness is incomplete")
    urls: dict[str, str] = {}
    for key, scheme in (("http_url", "http"), ("https_url", "https")):
        url = coverage_network.urls([value[key]])[0]
        if urllib.parse.urlsplit(url).scheme != scheme:
            raise ValueError("egress harness URL uses the wrong transport")
        urls[key] = url
    result: dict[str, object] = {**value, **urls}
    for name in ("tls_host", "tcp_host", "udp_host"):
        host = result[name]
        if not isinstance(host, str) or not host or any(char.isspace() for char in host):
            raise ValueError("egress harness host is invalid")
    for name in ("tls_port", "tcp_port", "udp_port"):
        port = result[name]
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise ValueError("egress harness port is invalid")
    return result


def _tls_probe(host: str, port: int) -> bool:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=host):
                return True
    except (OSError, ssl.SSLError):
        return False


def _echo_probe(host: str, port: int, *, udp: bool) -> bool:
    payload = uuid4().bytes
    try:
        if udp:
            family = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)[0][0]
            with socket.socket(family, socket.SOCK_DGRAM) as connection:
                connection.settimeout(5)
                connection.sendto(payload, (host, port))
                reply, _ = connection.recvfrom(256)
                return reply == payload
        with socket.create_connection((host, port), timeout=5) as connection:
            connection.settimeout(5)
            connection.sendall(payload)
            received = bytearray()
            deadline = time.monotonic() + 5
            while len(received) < len(payload) and time.monotonic() < deadline:
                part = connection.recv(len(payload) - len(received))
                if not part:
                    break
                received.extend(part)
            return bytes(received) == payload
    except OSError:
        return False


def _runner_harness(value: object) -> dict[str, bool]:
    harness = _harness(value)
    http_urls = [cast(str, harness["http_url"]), cast(str, harness["https_url"])]
    _runner_controls(http_urls, ["GET", "GET"])
    return {
        "http": True,
        "https": True,
        "tls": _tls_probe(cast(str, harness["tls_host"]), cast(int, harness["tls_port"])),
        "tcp": _echo_probe(
            cast(str, harness["tcp_host"]), cast(int, harness["tcp_port"]), udp=False
        ),
        "udp": _echo_probe(
            cast(str, harness["udp_host"]), cast(int, harness["udp_port"]), udp=True
        ),
    }


def harness_health(
    driver: Driver, target: object, inputs: Mapping[str, object]
) -> Mapping[str, object]:
    del driver, target
    if not all(_runner_harness(inputs["harness"]).values()):
        raise NotRun("network_unrestricted_control_unavailable")
    return {"all_transports_healthy": True}


def _guest_traffic(
    driver: Driver, target: object, harness: Mapping[str, object]
) -> tuple[dict[str, bool], dict[str, str]]:
    tokens = {"http": uuid4().hex, "https": uuid4().hex}
    config = {**harness, "http_tokens": tokens}
    driver.call(
        "files.write",
        target,
        {"path": TRAFFIC_SCRIPT_PATH, "data": base64.b64encode(TRAFFIC_SCRIPT.encode()).decode()},
    )
    result = driver.call(
        "run",
        target,
        {
            "bash_script": "python3 " + TRAFFIC_SCRIPT_PATH,
            "environment": {TRAFFIC_ENV: base64.b64encode(json.dumps(config).encode()).decode()},
            "timeout_ms": 60000,
        },
    )
    observations = _guest_json(result, max_length=1024)
    expected = {"http", "https", "tls", "tcp", "udp"}
    if (
        not isinstance(observations, dict)
        or set(observations) != expected
        or any(not isinstance(value, bool) for value in observations.values())
    ):
        raise NativeFailure("network_guest_probe_invalid")
    observed = cast(dict[str, bool], observations)
    for transport, url in (
        ("http", cast(str, harness["http_url"])),
        ("https", cast(str, harness["https_url"])),
    ):
        records = _records(url, tokens[transport])
        expected_records = [("GET", _path(url))] if observed[transport] else []
        if records != expected_records:
            raise NotRun("network_receiver_observation_mismatch")
    return observed, tokens


def _domain_traffic(observations: Mapping[str, bool]) -> str:
    profile = (
        observations["http"],
        observations["https"],
        observations["tls"],
        observations["tcp"],
        observations["udp"],
    )
    classes = {
        (False, True, False, False, False): "https",
        (True, True, False, False, False): "http_and_https",
        (False, True, True, False, False): "tls",
        (True, True, True, True, True): "all",
    }
    return classes.get(profile, "other")


def domain_traffic(
    driver: Driver, target: object, inputs: Mapping[str, object]
) -> Mapping[str, object]:
    harness = _harness(inputs["harness"])
    if not all(_runner_harness(harness).values()):
        raise NotRun("network_unrestricted_control_unavailable")
    observed, _ = _guest_traffic(driver, target, harness)
    if not all(_runner_harness(harness).values()):
        raise NotRun("network_unrestricted_control_unavailable")
    return {"domain_traffic": _domain_traffic(observed)}
