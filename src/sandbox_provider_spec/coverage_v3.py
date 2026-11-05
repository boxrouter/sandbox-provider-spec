# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Observe an existing HTTPS stream across a native network-policy update."""

from __future__ import annotations

import base64
import json
import shlex
import threading
import time
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast
from uuid import uuid4

from sandbox_provider_spec import coverage_network_probe as network_probe
from sandbox_provider_spec.driver import Driver, NativeFailure, NotRun, resource

WINDOW_SECONDS = 10
OBSERVATION_WINDOW_SECONDS = float(WINDOW_SECONDS)
CONNECT_TIMEOUT_SECONDS = 30.0
POLL_SECONDS = 0.25
AFTER_WINDOW_SECONDS = 5.0
STATE_LIMIT = 4096
# Body reads wait until the next byte or a close. A false result needs data
# after the ten-second window, and a live stream may be quiet until then.
STREAM_READ_TIMEOUT_SECONDS: float | None = None

_CLIENT = r"""import http.client, json, os, ssl, sys, urllib.parse

config_path, state_path = sys.argv[1:]
connected = False
received = 0

def save(*, is_connected=connected, is_closed=False, failed=False):
    temporary = state_path + ".tmp"
    with open(temporary, "w", encoding="utf-8") as stream:
        json.dump({"connected": is_connected, "received": received,
                   "closed": is_closed, "failed": failed}, stream)
    os.replace(temporary, state_path)

def main():
    global connected, received
    config = json.load(open(config_path, encoding="utf-8"))
    url = urllib.parse.urlsplit(config["stream_url"])
    ca_pem = config.get("ca_pem")
    context = ssl.create_default_context(cadata=ca_pem) if ca_pem else ssl.create_default_context()
    connection = http.client.HTTPSConnection(
        url.hostname, url.port or 443, timeout=8, context=context
    )
    path = urllib.parse.urlunsplit(("", "", url.path or "/", url.query, ""))
    try:
        connection.request(
            "GET",
            path,
            headers={"X-Token": config["token"], "X-SPS-Probe": config["probe_token"]},
        )
        response = connection.getresponse()
        if not 200 <= response.status < 300:
            save(failed=True)
            return
        sock = connection.sock or response.fp.raw._sock
        if sock is not None:
            sock.settimeout(config.get("read_timeout"))
        data = response.read(1)
        if not data:
            save(failed=True)
            return
        received = len(data)
        connected = True
        save(is_connected=True)
        while True:
            data = response.read(1)
            if not data:
                save(is_connected=True, is_closed=True)
                return
            received += len(data)
            save(is_connected=True)
    except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError, ssl.SSLError):
        if connected:
            save(is_connected=True, is_closed=True)
        else:
            save(failed=True)
    except (OSError, TimeoutError, http.client.HTTPException, ValueError):
        save(is_connected=connected, failed=True)
    finally:
        connection.close()

main()
"""


@dataclass
class _Connection:
    target: object
    process: Mapping[str, object]
    state_path: str


class _WindowObserver:
    def __init__(self, driver: Driver, target: object, connection: _Connection) -> None:
        self._resources = (driver, target, connection)
        self.deadline = 0.0
        self.started = threading.Event()
        self.stopped = threading.Event()
        self.outcome: str | None = None
        self.thread = threading.Thread(
            target=self._observe, name="sps-v3-connection-observer", daemon=True
        )

    def start(self) -> None:
        self.thread.start()

    def arm(self, started: float) -> None:
        self.deadline = started + OBSERVATION_WINDOW_SECONDS
        self.started.set()

    def stop(self) -> None:
        self.stopped.set()

    def join(self, timeout: float | None = None) -> None:
        self.thread.join(timeout)

    def _observe(self) -> None:
        self.started.wait()
        driver, target, connection = self._resources
        post_window_count: int | None = None
        end = self.deadline + AFTER_WINDOW_SECONDS
        while not self.stopped.is_set():
            read_started_at = time.monotonic()
            try:
                state = _read_state(driver, target, connection.state_path)
            except (NativeFailure, NotRun, ValueError):
                self.outcome = "unobservable"
                return
            # Completion bounds when the state became observable; starting a read
            # before the deadline cannot prove when a later closure happened.
            observed_at = time.monotonic()
            if state["failed"]:
                self.outcome = "unobservable"
                return
            if read_started_at >= self.deadline and not state["closed"]:
                if post_window_count is None:
                    post_window_count = cast(int, state["received"])
                elif cast(int, state["received"]) > post_window_count:
                    self.outcome = "continued"
                    return
            if state["closed"]:
                if observed_at <= self.deadline:
                    self.outcome = "closed"
                elif (
                    post_window_count is not None
                    and cast(int, state["received"]) > post_window_count
                ):
                    self.outcome = "continued"
                else:
                    self.outcome = "unobservable"
                return
            if observed_at >= end:
                self.outcome = "unobservable"
                return
            self.stopped.wait(min(POLL_SECONDS, max(0.0, end - observed_at)))
        self.outcome = "stopped"


def _write_file(driver: Driver, target: object, path: str, data: bytes) -> None:
    driver.call("files.write", target, {"path": path, "data": base64.b64encode(data).decode()})


def _read_state(driver: Driver, target: object, path: str) -> dict[str, object]:
    result = driver.call("files.read_bytes", target, {"path": path})
    payload = result.get("data")
    if isinstance(payload, str):
        payload = payload.encode()
    if not isinstance(payload, bytes) or len(payload) > STATE_LIMIT:
        raise NativeFailure("connection_state_invalid")
    try:
        state = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise NativeFailure("connection_state_invalid") from None
    if not isinstance(state, dict):
        raise NativeFailure("connection_state_invalid")
    if set(state) != {"connected", "received", "closed", "failed"}:
        raise NativeFailure("connection_state_invalid")
    if any(not isinstance(state[key], bool) for key in ("connected", "closed", "failed")):
        raise NativeFailure("connection_state_invalid")
    received = state["received"]
    if not isinstance(received, int) or isinstance(received, bool) or received < 0:
        raise NativeFailure("connection_state_invalid")
    return cast(dict[str, object], state)


def _connection(value: object) -> _Connection:
    if not isinstance(value, Mapping) or not isinstance(value.get("handle"), _Connection):
        raise ValueError("live connection required")
    return cast(_Connection, value["handle"])


def _stream_config(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise NotRun("connection_harness_missing")
    stream_url = value.get("stream_url")
    token = value.get("token")
    ca_pem = value.get("ca_pem", "")
    if not isinstance(stream_url, str) or not isinstance(token, str) or not token:
        raise ValueError("invalid connection harness")
    if len(token) > 4096 or any(ord(char) < 32 or ord(char) == 127 for char in token):
        raise ValueError("invalid connection harness")
    if not isinstance(ca_pem, str) or len(ca_pem) > 65536:
        raise ValueError("invalid connection harness")
    try:
        parsed = urllib.parse.urlsplit(stream_url)
        port = parsed.port
    except ValueError:
        raise ValueError("invalid connection harness") from None
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("invalid connection harness")
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise ValueError("invalid connection harness")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("invalid connection harness")
    return {"stream_url": stream_url, "token": token, "ca_pem": ca_pem}


def open_connection(
    driver: Driver, target: object, inputs: Mapping[str, object]
) -> Mapping[str, object]:
    config = _stream_config(inputs.get("harness"))
    identifier = uuid4().hex
    config["probe_token"] = identifier
    payload = {**config, "read_timeout": STREAM_READ_TIMEOUT_SECONDS}
    root = f"/tmp/sps-v3-connection-{identifier}"
    script_path = f"{root}.py"
    config_path = f"{root}.json"
    state_path = f"{root}.state"
    initial = json.dumps(
        {"connected": False, "received": 0, "closed": False, "failed": False}
    ).encode()
    _write_file(driver, target, script_path, _CLIENT.encode())
    _write_file(driver, target, config_path, json.dumps(payload).encode())
    _write_file(driver, target, state_path, initial)
    process = driver.call(
        "process.start",
        target,
        {
            "bash_script": "python3 "
            + " ".join(shlex.quote(path) for path in (script_path, config_path, state_path)),
            "timeout_ms": 0,
        },
    )
    resource(process)
    connection = _Connection(target=target, process=process, state_path=state_path)
    deadline = time.monotonic() + CONNECT_TIMEOUT_SECONDS
    while True:
        state = _read_state(driver, target, state_path)
        if state["connected"] and cast(int, state["received"]) > 0:
            if network_probe.records(
                config["stream_url"], identifier, ca_pem=config.get("ca_pem")
            ) != [("GET", network_probe.path(config["stream_url"]))]:
                raise NotRun("connection_harness_recorder_unavailable")
            return {"handle": connection}
        if state["failed"] or time.monotonic() >= deadline:
            raise NotRun("connection_stream_unavailable")
        time.sleep(min(POLL_SECONDS, max(0.0, deadline - time.monotonic())))


def connection_update(
    driver: Driver, target: object, inputs: Mapping[str, object]
) -> Mapping[str, object]:
    connection = _connection(inputs.get("connection"))
    if connection.target is not target:
        raise ValueError("connection target changed")
    state = _read_state(driver, target, connection.state_path)
    if not state["connected"] or state["closed"] or state["failed"]:
        raise NotRun("connection_stream_unavailable")
    new_policy = inputs.get("new_policy")
    if not isinstance(new_policy, Mapping):
        raise ValueError("new network policy required")
    observer = _WindowObserver(driver, target, connection)
    observer.start()
    started = time.monotonic()
    observer.arm(started)
    try:
        driver.call("network.update", target, cast(Mapping[str, object], new_policy))
    except Exception:
        observer.stop()
        observer.join(1)
        raise
    return {
        "handle": connection,
        "deadline": observer.deadline,
        "window_seconds": WINDOW_SECONDS,
        "observer": observer,
    }


def connection_closed(
    driver: Driver, target: object, inputs: Mapping[str, object]
) -> Mapping[str, object]:
    del driver
    updated = inputs.get("connection")
    if not isinstance(updated, Mapping):
        raise ValueError("updated connection required")
    connection = _connection(updated)
    if connection.target is not target:
        raise ValueError("connection target changed")
    window = inputs.get("window_seconds")
    if (
        not isinstance(window, int)
        or isinstance(window, bool)
        or window != WINDOW_SECONDS
        or updated.get("window_seconds") != WINDOW_SECONDS
    ):
        raise ValueError("connection observation window must be ten seconds")
    observer = updated.get("observer")
    deadline = updated.get("deadline")
    if not isinstance(observer, _WindowObserver) or not isinstance(deadline, (int, float)):
        raise ValueError("connection deadline required")
    observer.join(max(0.0, deadline - time.monotonic()) + AFTER_WINDOW_SECONDS + 1)
    if observer.thread.is_alive():
        observer.stop()
        observer.join(1)
        raise NotRun("connection_window_observation_unavailable")
    if observer.outcome == "closed":
        return {"closed_within_window": True}
    if observer.outcome == "continued":
        return {"closed_within_window": False}
    raise NotRun("connection_window_observation_unavailable")
