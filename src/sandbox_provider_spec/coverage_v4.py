# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Observe secret header, body, host-list and wildcard injection without recording values."""

from __future__ import annotations

import base64
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from typing import Any, cast
from uuid import uuid4

from sandbox_provider_spec import coverage_network_probe as network_probe
from sandbox_provider_spec.driver import Driver, NativeFailure, NotRun, text

_METHODS = ("POST", "PUT", "PATCH")
_HEADER = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_RECEIVER = r"""import json, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

config = json.loads(Path("/tmp/sps-v4-receiver.json").read_text())
lock = threading.Lock()
header_results = []
body_results = {}

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send_json(self, status, value):
        payload = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path == "/health/" + config["nonce"]:
            self.send_response(200)
            self.send_header("Content-Length", "5")
            self.end_headers()
            self.wfile.write(b"ready")
            return
        if config["mode"] == "header" and self.path == "/header/" + config["nonce"]:
            values = self.headers.get_all(config["header"], [])
            result = {
                "header_count": len(values),
                "carries_secret": len(values) == 1 and values[0] == config["value"],
            }
            with lock:
                header_results.append(result)
            self.send_json(200, {"accepted": True})
            return
        if (
            self.path != "/result/" + config["nonce"]
            or self.headers.get("X-SPS-Observer") != config["observer"]
        ):
            self.send_response(403)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        with lock:
            if config["mode"] == "header":
                result = (
                    header_results[-1]
                    if header_results
                    else {"header_count": 0, "carries_secret": False}
                )
            else:
                result = {
                    "all_methods_injected": len(body_results) == len(config["methods"])
                    and all(row["injected"] for row in body_results.values()),
                    "other_fields_unchanged": len(body_results) == len(config["methods"])
                    and all(row["unchanged"] for row in body_results.values()),
                }
        self.send_json(200, result)

    def do_POST(self):
        self.observe_body()

    def do_PUT(self):
        self.observe_body()

    def do_PATCH(self):
        self.observe_body()

    def observe_body(self):
        method = self.command
        if (
            config["mode"] != "body"
            or self.path != "/body/" + config["nonce"]
            or method not in config["methods"]
        ):
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0 or length > 65536:
                raise ValueError
            document = json.loads(self.rfile.read(length))
            if not isinstance(document, dict):
                raise ValueError
        except (ValueError, UnicodeDecodeError):
            document = {}
        field = config["field"]
        other_fields = {key: value for key, value in document.items() if key != field}
        row = {
            "injected": document.get(field) == config["value"],
            "unchanged": other_fields == config["other_fields"],
        }
        with lock:
            body_results[method] = row
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

server = ThreadingHTTPServer(("0.0.0.0", 7777), Handler)
Path("/tmp/sps-v4-receiver-ready").touch()
threading.Timer(240, server.shutdown).start()
server.serve_forever()
"""

_HEADER_CLIENT = r"""import json, urllib.error, urllib.request
from pathlib import Path

config = json.loads(Path("/tmp/sps-v4-client.json").read_text())
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None
opener = urllib.request.build_opener(urllib.request.ProxyHandler(), NoRedirect)
request = urllib.request.Request(config["url"], headers={config["header"]: "dummy"})
try:
    response = opener.open(request, timeout=10)
except urllib.error.HTTPError as error:
    response = error
with response:
    response.read(4096)
"""

_BODY_CLIENT = r"""import json, urllib.error, urllib.request
from pathlib import Path

config = json.loads(Path("/tmp/sps-v4-client.json").read_text())
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None
opener = urllib.request.build_opener(urllib.request.ProxyHandler(), NoRedirect)
for method in config["methods"]:
    request = urllib.request.Request(
        config["url"], data=json.dumps(config["other_fields"]).encode(),
        headers={"Content-Type": "application/json"}, method=method,
    )
    try:
        response = opener.open(request, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        response.read(4096)
"""


def write(driver: Driver, target: object, path: str, data: bytes) -> None:
    driver.call("files.write", target, {"path": path, "data": base64.b64encode(data).decode()})


def _request(url: str, headers: Mapping[str, str] | None = None) -> tuple[int, bytes]:
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args: Any, **kwargs: Any) -> None:
            del args, kwargs

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)
    request = urllib.request.Request(url, headers=dict(headers or {}))
    try:
        with opener.open(request, timeout=8) as response:
            return response.status, response.read(8192)
    except urllib.error.HTTPError as error:
        return error.code, error.read(8192)
    except (urllib.error.URLError, TimeoutError):
        raise NotRun("secret_endpoint_unreachable") from None


def _check_receiver_health(url: str) -> None:
    status, body = _request(url)
    if status != 200 or body != b"ready":
        raise NotRun("secret_receiver_unhealthy")


def _receiver(driver: Driver, config: Mapping[str, object]) -> Mapping[str, object]:
    receiver = driver.call(
        "create",
        None,
        {
            "lifetime_seconds": 300,
            "requirements": {"previews": {"access": "public", "ports": [7777]}},
        },
    )
    write(driver, receiver, "/tmp/sps-v4-receiver.py", _RECEIVER.encode())
    write(driver, receiver, "/tmp/sps-v4-receiver.json", json.dumps(dict(config)).encode())
    driver.call(
        "process.start",
        receiver,
        {"bash_script": "python3 /tmp/sps-v4-receiver.py", "timeout_ms": 270000},
    )
    deadline = time.monotonic() + 30
    while not driver.call("files.exists", receiver, {"path": "/tmp/sps-v4-receiver-ready"}).get(
        "exists"
    ):
        if time.monotonic() >= deadline:
            raise NativeFailure("secret_receiver_not_ready")
        time.sleep(0.2)
    link = driver.call("preview.link", receiver, {"port": 7777, "access": "public"})
    url = link.get("url")
    if not isinstance(url, str):
        raise NativeFailure("secret_receiver_link_invalid")
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise NativeFailure("secret_receiver_link_invalid")
    base = url.rstrip("/")
    return {
        "host": parsed.hostname,
        "health_url": base + "/health/" + str(config["nonce"]),
        "result_url": base + "/result/" + str(config["nonce"]),
    }


def _result(url: str, observer: str, mode: str) -> Mapping[str, object]:
    status, payload = _request(url, {"X-SPS-Observer": observer})
    if status != 200 or len(payload) > 4096:
        raise NativeFailure("secret_receiver_observation_invalid")
    try:
        value = json.loads(payload)
    except (TypeError, json.JSONDecodeError):
        raise NativeFailure("secret_receiver_observation_invalid") from None
    if not isinstance(value, dict):
        raise NativeFailure("secret_receiver_observation_invalid")
    if mode == "header":
        count, carries = value.get("header_count"), value.get("carries_secret")
        if (
            set(value) != {"header_count", "carries_secret"}
            or (not isinstance(count, int) or isinstance(count, bool) or not 0 <= count <= 32)
            or not isinstance(carries, bool)
        ):
            raise NativeFailure("secret_receiver_observation_invalid")
        return {"header_count": count, "carries_secret": carries}
    injected, unchanged = value.get("all_methods_injected"), value.get("other_fields_unchanged")
    if (
        set(value) != {"all_methods_injected", "other_fields_unchanged"}
        or not isinstance(injected, bool)
        or not isinstance(unchanged, bool)
    ):
        raise NativeFailure("secret_receiver_observation_invalid")
    return {"all_methods_injected": injected, "other_fields_unchanged": unchanged}


def _send(driver: Driver, box: object, script: str, config: Mapping[str, object]) -> None:
    write(driver, box, "/tmp/sps-v4-client.py", script.encode())
    write(driver, box, "/tmp/sps-v4-client.json", json.dumps(dict(config)).encode())
    result = driver.call(
        "run", box, {"bash_script": "python3 /tmp/sps-v4-client.py", "timeout_ms": 30000}
    )
    if result.get("exit_code") != 0:
        raise NativeFailure("secret_guest_request_failed")


def _secret_box(driver: Driver, *, value: str, host: str, injection: str) -> object:
    secret = driver.call("secret.create", None, {"value": value, "hosts": []})
    return driver.call(
        "create",
        None,
        {
            "lifetime_seconds": 300,
            "secret": secret,
            "requirements": {"hidden_secrets": {"inject_into": [host], "injection": injection}},
        },
    )


def secret_header(driver: Driver, inputs: Mapping[str, object], nonce: str) -> Mapping[str, object]:
    header = text(inputs, "header")
    if not _HEADER.fullmatch(header):
        raise ValueError("invalid header name")
    value, observer = uuid4().hex + uuid4().hex, uuid4().hex
    receiver = _receiver(
        driver,
        {"mode": "header", "nonce": nonce, "observer": observer, "header": header, "value": value},
    )
    health_url = str(receiver["health_url"])
    _check_receiver_health(health_url)
    box = _secret_box(driver, value=value, host=str(receiver["host"]), injection="sets_header")
    _send(
        driver,
        box,
        _HEADER_CLIENT,
        {"url": health_url.replace("/health/", "/header/"), "header": header},
    )
    _check_receiver_health(health_url)
    return _result(str(receiver["result_url"]), observer, "header")


def secret_body(driver: Driver, inputs: Mapping[str, object], nonce: str) -> Mapping[str, object]:
    field = text(inputs, "field")
    if not field or len(field) > 128:
        raise ValueError("invalid body field")
    value, observer = uuid4().hex + uuid4().hex, uuid4().hex
    marker_key, number_key = f"sps_v4_marker_{nonce}", f"sps_v4_number_{nonce}"
    while field in {marker_key, number_key}:
        marker_key += "_"
        number_key += "_"
    other_fields: dict[str, object] = {marker_key: nonce, number_key: 17}
    methods = list(_METHODS)
    receiver = _receiver(
        driver,
        {
            "mode": "body",
            "nonce": nonce,
            "observer": observer,
            "field": field,
            "value": value,
            "other_fields": other_fields,
            "methods": methods,
        },
    )
    health_url = str(receiver["health_url"])
    _check_receiver_health(health_url)
    box = _secret_box(driver, value=value, host=str(receiver["host"]), injection="adds_body_field")
    _send(
        driver,
        box,
        _BODY_CLIENT,
        {
            "url": health_url.replace("/health/", "/body/"),
            "methods": methods,
            "other_fields": other_fields,
        },
    )
    _check_receiver_health(health_url)
    return _result(str(receiver["result_url"]), observer, "body")


def _https_hostname(url: str) -> str | None:
    parsed = urllib.parse.urlsplit(url)
    if not all(
        (
            parsed.scheme == "https",
            parsed.hostname is not None,
            parsed.username is None,
            parsed.password is None,
            not parsed.fragment,
        )
    ):
        return None
    return parsed.hostname


def _targets(hosts: object, urls: object) -> list[str]:
    if not isinstance(hosts, list) or not hosts or len(hosts) > 128:
        raise ValueError("invalid hidden-secret endpoint list")
    if any(not isinstance(host, str) or not host for host in hosts):
        raise ValueError("invalid hidden-secret endpoint list")
    host_values = cast(list[str], hosts)
    if len(set(host_values)) != len(host_values):
        raise ValueError("invalid hidden-secret endpoint list")
    if not isinstance(urls, list) or len(urls) != len(host_values):
        raise ValueError("invalid hidden-secret endpoint list")
    if any(not isinstance(url, str) for url in urls):
        raise ValueError("invalid hidden-secret endpoint list")
    result = cast(list[str], urls)
    for host, url in zip(host_values, result, strict=True):
        if _https_hostname(url) != host:
            raise ValueError("hidden-secret URL must match its host")
    return result


_HOST_CLIENT = r"""import json, urllib.error, urllib.request
from pathlib import Path

config = json.loads(Path("/tmp/sps-v4-hosts.json").read_text())
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None
# Honour the sandbox proxy variables. Hidden-secret injection uses that path.
opener = urllib.request.build_opener(urllib.request.ProxyHandler(), NoRedirect)
for item in config["requests"]:
    request = urllib.request.Request(item["url"], headers={"X-SPS-Probe": item["token"]})
    try:
        response = opener.open(request, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    except (urllib.error.URLError, TimeoutError, OSError):
        continue
    with response:
        response.read(4096)
"""
_RECORD_LIMIT = 64 * 1024


def _send_host_requests(driver: Driver, target: object, requests: list[tuple[str, str]]) -> None:
    """One ordinary proxied GET per URL. The guest never receives the secret."""
    payload = {
        "requests": [{"url": url, "token": token} for url, token in requests],
    }
    write(driver, target, "/tmp/sps-v4-hosts.py", _HOST_CLIENT.encode())
    write(driver, target, "/tmp/sps-v4-hosts.json", json.dumps(payload).encode())
    result = driver.call(
        "run",
        target,
        {
            "bash_script": "python3 /tmp/sps-v4-hosts.py",
            "timeout_ms": len(requests) * 12000 + 5000,
        },
    )
    if result.get("exit_code") != 0:
        raise NativeFailure("secret_guest_request_failed")


def _records_document(url: str, token: str) -> Mapping[str, object]:
    parts = urllib.parse.urlsplit(url)
    records_url = urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, "/records/" + urllib.parse.quote(token, safe=""), "", "")
    )

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args: Any, **kwargs: Any) -> None:
            del args, kwargs

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)
    request = urllib.request.Request(records_url)
    try:
        with opener.open(request, timeout=8) as response:
            status = response.status
            payload = response.read(_RECORD_LIMIT + 1)
    except urllib.error.HTTPError:
        raise NotRun("network_receiver_observer_unavailable") from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise NotRun("network_receiver_observer_unavailable") from None
    if not isinstance(status, int) or not 200 <= status < 300 or len(payload) > _RECORD_LIMIT:
        raise NativeFailure("secret_receiver_observation_invalid")
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise NativeFailure("secret_receiver_observation_invalid") from None
    if not isinstance(document, dict):
        raise NativeFailure("secret_receiver_observation_invalid")
    return cast(Mapping[str, object], document)


def _headers_carry_secret(row: Mapping[str, object], secret: str) -> bool:
    headers = row.get("headers")
    if not isinstance(headers, Mapping):
        raise NativeFailure("secret_receiver_observation_invalid")
    carried = False
    for name, raw in headers.items():
        if not isinstance(name, str) or not isinstance(raw, str):
            raise NativeFailure("secret_receiver_observation_invalid")
        if name.lower() == "x-sps-secret" and raw == secret:
            carried = True
    return carried


def _host_received_secret(url: str, token: str, secret: str) -> bool:
    """True only when the one recorded GET carries the secret. The value is not returned."""
    document = _records_document(url, token)
    rows = document.get("requests", document.get("records"))
    if not isinstance(rows, list) or len(rows) > 128:
        raise NativeFailure("secret_receiver_observation_invalid")
    expected = network_probe.path(url)
    matched: list[Mapping[str, object]] = []
    for row in rows:
        method, record_path = network_probe.record_row(row, "secret_receiver_observation_invalid")
        if method == "GET" and network_probe.path(record_path) == expected:
            matched.append(cast(Mapping[str, object], row))
    if len(matched) != 1:
        raise NotRun("secret_receiver_observation_mismatch")
    return _headers_carry_secret(matched[0], secret)


def _guest_statuses(driver: Driver, target: object, urls: list[str], secret: str) -> list[bool]:
    """Each boolean is whether that controlled receiver recorded this run's secret."""
    if not secret or len(secret) > 4096 or any(secret in url for url in urls):
        raise ValueError("invalid hidden-secret value")
    network_probe.runner_controls(urls, ["GET"] * len(urls))
    tokens = [uuid4().hex for _ in urls]
    _send_host_requests(driver, target, list(zip(urls, tokens, strict=True)))
    return [
        _host_received_secret(url, token, secret) for url, token in zip(urls, tokens, strict=True)
    ]


def secret_hosts(
    driver: Driver, target: object, inputs: Mapping[str, object], nonce: str
) -> Mapping[str, object]:
    secret = "sps-v4-" + nonce
    urls = _targets(inputs["hosts"], inputs["urls"])
    statuses = _guest_statuses(driver, target, urls, secret)
    return {"every_host_received": len(statuses) == len(urls) and all(statuses)}


def secret_wildcard(
    driver: Driver, target: object, inputs: Mapping[str, object], nonce: str
) -> Mapping[str, object]:
    del nonce
    secret = text(inputs, "value")
    host = text(inputs, "host")
    urls = inputs["urls"]
    if (
        not isinstance(urls, list)
        or len(urls) != 2
        or not all(isinstance(url, str) for url in urls)
    ):
        raise ValueError("wildcard URLs must contain a direct and deeper subdomain")
    suffix = host[2:] if host.startswith("*.") else ""
    if not suffix:
        raise ValueError("wildcard URL must be a subdomain of its host")
    hostnames = [_https_hostname(url) for url in urls]
    if any(hostname is None or not hostname.endswith("." + suffix) for hostname in hostnames):
        raise ValueError("wildcard URLs must be subdomains of their host")
    labels = [hostname[: -(len(suffix) + 1)].split(".") for hostname in hostnames if hostname]
    if sorted(map(len, labels)) != [1, 2]:
        raise ValueError("wildcard URLs must include a direct and deeper subdomain")
    statuses = _guest_statuses(driver, target, urls, secret)
    return {"every_wildcard_host_received": len(statuses) == 2 and all(statuses)}
