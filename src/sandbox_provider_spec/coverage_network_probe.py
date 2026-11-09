# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Tokened HTTP probes that verify runner and guest traffic in the receiver recorder."""

from __future__ import annotations

import base64
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from typing import Any, cast
from uuid import uuid4

from sandbox_provider_spec.driver import Driver, NativeFailure, NotRun

HTTP_SCRIPT_PATH = "/tmp/sps-coverage-v2-http.py"
HTTP_ENV = "SPS_COVERAGE_V2_HTTP_B64"
HTTP_DEADLINE_ENV = "SPS_COVERAGE_V2_HTTP_DEADLINE_SECONDS"
HTTP_WORKER_ENV = "SPS_COVERAGE_V2_HTTP_WORKER_B64"
HTTP_WORKER_REQUEST_ENV = "SPS_COVERAGE_V2_HTTP_WORKER_REQUEST_B64"
HTTP_REQUEST_DEADLINE_SECONDS = 30
HTTP_RUN_TIMEOUT_MARGIN_MS = 10_000
RESPONSE_LIMIT = 64 * 1024

HTTP_WORKER_SCRIPT = r"""import base64, json, os, ssl, urllib.error, urllib.request
item = json.loads(base64.b64decode(os.environ["SPS_COVERAGE_V2_HTTP_WORKER_REQUEST_B64"]))
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_): return None
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
request = urllib.request.Request(
    item["url"], method=item["method"], headers={"X-SPS-Probe": item["token"]}
)
try:
    with opener.open(request, timeout=8) as response:
        response.read(1)
        result = {"succeeded": 200 <= response.status < 300, "ambiguous": False}
except urllib.error.HTTPError:
    result = {"succeeded": False, "ambiguous": False}
except urllib.error.URLError as error:
    result = {"succeeded": False, "ambiguous": isinstance(error.reason, ssl.SSLError)}
except ssl.SSLError:
    result = {"succeeded": False, "ambiguous": True}
except (TimeoutError, OSError):
    result = {"succeeded": False, "ambiguous": False}
print(json.dumps(result, separators=(",", ":")))
"""

HTTP_SCRIPT = r"""import base64, json, os, subprocess, sys
requests = json.loads(base64.b64decode(os.environ["SPS_COVERAGE_V2_HTTP_B64"]))
deadline_seconds = float(os.environ.get("SPS_COVERAGE_V2_HTTP_DEADLINE_SECONDS", "30"))
worker_script = base64.b64decode(os.environ["SPS_COVERAGE_V2_HTTP_WORKER_B64"]).decode("utf-8")
results = []
for item in requests:
    worker_env = os.environ.copy()
    worker_env["SPS_COVERAGE_V2_HTTP_WORKER_REQUEST_B64"] = base64.b64encode(
        json.dumps(item).encode()
    ).decode()
    try:
        process = subprocess.run(
            [sys.executable, "-c", worker_script],
            capture_output=True,
            check=False,
            env=worker_env,
            text=True,
            timeout=deadline_seconds,
        )
    except subprocess.TimeoutExpired:
        results.append({"succeeded": False, "ambiguous": False, "error": True})
        continue
    try:
        result = json.loads(process.stdout)
    except json.JSONDecodeError:
        result = None
    if (
        process.returncode != 0
        or not isinstance(result, dict)
        or set(result) != {"succeeded", "ambiguous"}
        or not isinstance(result["succeeded"], bool)
        or not isinstance(result["ambiguous"], bool)
    ):
        results.append({"succeeded": False, "ambiguous": False, "error": True})
        continue
    results.append({**result, "error": False})
print(json.dumps(results, separators=(",", ":")))
"""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_: Any, **__: Any) -> None:
        return None


def path(url: str) -> str:
    return urllib.parse.urlsplit(url).path or "/"


def guest_json(result: Mapping[str, object], *, max_length: int) -> object:
    if result.get("exit_code") != 0:
        raise NotRun("network_guest_probe_inconclusive")
    output = result.get("stdout")
    if isinstance(output, bytes):
        try:
            output = output.decode("utf-8")
        except UnicodeDecodeError:
            raise NativeFailure("network_guest_probe_invalid") from None
    if not isinstance(output, str) or len(output) > max_length:
        raise NativeFailure("network_guest_probe_invalid")
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        raise NativeFailure("network_guest_probe_invalid") from None


def _request(url: str, method: str, token: str) -> bool:
    request = urllib.request.Request(url, method=method, headers={"X-SPS-Probe": token})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(request, timeout=8) as response:
            response.read(1)
            return 200 <= cast(int, response.status) < 300
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


def _records_url(url: str, token: str) -> str:
    parts = urllib.parse.urlsplit(url)
    record_path = "/records/" + urllib.parse.quote(token, safe="")
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, record_path, "", ""))


def _observer_detail(error: BaseException, token: str) -> str:
    if isinstance(error, urllib.error.HTTPError):
        return f"HTTP status {error.code}"
    cause = error.reason if isinstance(error, urllib.error.URLError) else error
    error_type = (
        "URLError"
        if isinstance(error, urllib.error.URLError) and not isinstance(cause, BaseException)
        else type(cause).__name__
    )
    message = re.sub(r"https?://[^\s<>]+", "<url>", str(cause))
    message = message.replace(token, "<redacted>")
    message = re.sub(r"(/records/)[^\s/?#]+", r"\1<namespace>", message)
    message = " ".join(message.split())[:240] or "no message"
    return f"{error_type}: {message}"


def records(url: str, token: str, *, ca_pem: str | None = None) -> list[tuple[str, str]]:
    records_url = _records_url(url, token)
    request = urllib.request.Request(records_url)
    handlers: list[urllib.request.BaseHandler] = [
        urllib.request.ProxyHandler({}),
        _NoRedirect(),
    ]
    if ca_pem is not None:
        handlers.append(
            urllib.request.HTTPSHandler(context=ssl.create_default_context(cadata=ca_pem))
        )
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(request, timeout=8) as response:
            if not 200 <= cast(int, response.status) < 300:
                raise NotRun(
                    "network_receiver_observer_unavailable",
                    detail=f"HTTP status {response.status}",
                )
            payload = response.read(RESPONSE_LIMIT + 1)
    except urllib.error.HTTPError as error:
        raise NotRun(
            "network_receiver_observer_unavailable", detail=_observer_detail(error, token)
        ) from None
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise NotRun(
            "network_receiver_observer_unavailable", detail=_observer_detail(error, token)
        ) from None
    if len(payload) > RESPONSE_LIMIT:
        raise NativeFailure("network_receiver_response_invalid")
    try:
        value = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise NativeFailure("network_receiver_response_invalid") from None
    rows = value.get("requests", value.get("records")) if isinstance(value, dict) else value
    if not isinstance(rows, list) or len(rows) > 128:
        raise NativeFailure("network_receiver_response_invalid")
    result: list[tuple[str, str]] = []
    for row in rows:
        method, record_path = record_row(row, "network_receiver_response_invalid")
        result.append((method, path(record_path)))
    return result


def record_row(row: object, failure: str) -> tuple[str, str]:
    """A recorder row's upper-cased method and raw path; `failure` when the row is malformed."""
    if not isinstance(row, Mapping):
        raise NativeFailure(failure)
    method, record_path = row.get("method"), row.get("path")
    if not isinstance(method, str) or not isinstance(record_path, str) or len(record_path) > 2048:
        raise NativeFailure(failure)
    return method.upper(), record_path


def runner_controls(urls: list[str], methods: list[str]) -> None:
    """Prove each receiver and its recorder from outside the sandbox."""
    tokens = [uuid4().hex for _ in urls]
    for url, method, token in zip(urls, methods, tokens, strict=True):
        if not _request(url, method, token):
            raise NotRun("network_control_unavailable")
    for url, method, token in zip(urls, methods, tokens, strict=True):
        if records(url, token) != [(method, path(url))]:
            raise NotRun("network_receiver_control_unavailable")


def guest_http_observations(
    driver: Driver, target: object, requests: list[tuple[str, str]]
) -> tuple[list[Mapping[str, bool]], list[str]]:
    """Keep per-request TLS ambiguity available to recorder-backed policy checks."""
    tokens = [uuid4().hex for _ in requests]
    payload = [
        {"url": url, "method": method, "token": token}
        for (url, method), token in zip(requests, tokens, strict=True)
    ]
    driver.call(
        "files.write",
        target,
        {"path": HTTP_SCRIPT_PATH, "data": base64.b64encode(HTTP_SCRIPT.encode()).decode()},
    )
    result = driver.call(
        "run",
        target,
        {
            "bash_script": "python3 " + HTTP_SCRIPT_PATH,
            "environment": {
                HTTP_ENV: base64.b64encode(json.dumps(payload).encode()).decode(),
                HTTP_DEADLINE_ENV: str(HTTP_REQUEST_DEADLINE_SECONDS),
                HTTP_WORKER_ENV: base64.b64encode(HTTP_WORKER_SCRIPT.encode()).decode(),
            },
            "timeout_ms": (
                len(payload) * HTTP_REQUEST_DEADLINE_SECONDS * 1000 + HTTP_RUN_TIMEOUT_MARGIN_MS
            ),
        },
    )
    observations = guest_json(result, max_length=2048)
    if (
        not isinstance(observations, list)
        or len(observations) != len(payload)
        or any(
            not isinstance(item, dict)
            or set(item) != {"succeeded", "ambiguous", "error"}
            or not isinstance(item["succeeded"], bool)
            or not isinstance(item["ambiguous"], bool)
            or not isinstance(item["error"], bool)
            for item in observations
        )
    ):
        raise NativeFailure("network_guest_probe_invalid")
    if any(item["error"] for item in observations):
        raise NotRun("network_guest_probe_inconclusive")
    return cast(list[Mapping[str, bool]], observations), tokens


def guest_http(
    driver: Driver, target: object, requests: list[tuple[str, str]]
) -> tuple[list[bool], list[str]]:
    """Return simple reachability for probes that have no recorder to resolve TLS errors."""
    observations, tokens = guest_http_observations(driver, target, requests)
    if any(item["ambiguous"] for item in observations):
        raise NotRun("network_tls_observation_ambiguous")
    return [item["succeeded"] for item in observations], tokens
