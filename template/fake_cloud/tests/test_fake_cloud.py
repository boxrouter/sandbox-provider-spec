# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Black-box tests for Example Cloud over its HTTP API."""

from __future__ import annotations

import hashlib
import os
import time
import urllib.parse
from typing import Any

import pytest
from conftest import call, call_json

pytestmark = [pytest.mark.loopback, pytest.mark.integration]


def test_api_key_required(server: Any) -> None:
    status, _ = call(server.port, "POST", "/machines", key=None, body={})
    assert status == 401
    status, _ = call(server.port, "GET", "/machines", key=None)
    assert status == 401
    status, _ = call(server.port, "GET", "/healthz", key=None)
    assert status == 200


def test_create_get_list_delete(server: Any) -> None:
    status, created = call_json(
        server.port,
        "POST",
        "/machines",
        body={
            "cpu": 1,
            "memory_mb": 256,
            "ttl_seconds": 600,
            "env": {"GREETING": "hi"},
            "tags": {"suite": "c3", "color": "blue"},
        },
    )
    assert status == 201, created
    assert sorted(created) == ["created", "expires", "machine_id", "status"]
    assert created["status"] == "running"
    machine_id = created["machine_id"]

    status, got = call_json(server.port, "GET", f"/machines/{machine_id}")
    assert status == 200
    assert got == created

    status, page = call_json(
        server.port,
        "GET",
        "/machines?" + urllib.parse.urlencode({"tag": "suite:c3"}),
    )
    assert status == 200
    assert machine_id in {item["machine_id"] for item in page["machines"]}

    status, page = call_json(
        server.port,
        "GET",
        "/machines?" + urllib.parse.urlencode({"tag": "suite:other"}),
    )
    assert machine_id not in {item["machine_id"] for item in page["machines"]}

    status, deleted = call_json(server.port, "DELETE", f"/machines/{machine_id}")
    assert status == 200
    assert deleted == {"status": "ended"}

    status, got = call_json(server.port, "GET", f"/machines/{machine_id}")
    assert status == 200
    assert got["status"] == "ended"

    status, deleted = call_json(server.port, "DELETE", f"/machines/{machine_id}")
    assert status == 200
    assert deleted == {"status": "ended"}

    status, page = call_json(server.port, "GET", "/machines")
    assert machine_id not in {item["machine_id"] for item in page["machines"]}


def test_exec(server: Any, machine: str) -> None:
    status, result = call_json(
        server.port,
        "POST",
        f"/machines/{machine}/exec",
        body={"cmd": ["bash", "-c", "echo hello; echo oops >&2; exit 3"]},
    )
    assert status == 200, result
    assert result["code"] == 3
    assert result["out"] == "hello\n"
    assert result["err"] == "oops\n"
    assert result["killed"] is False

    status, result = call_json(
        server.port,
        "POST",
        f"/machines/{machine}/exec",
        body={
            "cmd": ["bash", "-c", "pwd; echo $MARK"],
            "dir": "/tmp",
            "env": {"MARK": "set"},
        },
    )
    assert result["out"] == "/tmp\nset\n"


def test_exec_timeout_kills(server: Any, machine: str) -> None:
    status, result = call_json(
        server.port,
        "POST",
        f"/machines/{machine}/exec",
        body={"cmd": ["sleep", "60"], "timeout_s": 0.5},
    )
    assert status == 200, result
    assert result["killed"] is True
    assert result["code"] is None


def test_files_roundtrip(server: Any, machine: str) -> None:
    payload = os.urandom(4 * 1024 * 1024)
    status, _ = call(server.port, "PUT", f"/machines/{machine}/fs?path=/tmp/blob", raw=payload)
    assert status == 200
    status, data = call(server.port, "GET", f"/machines/{machine}/fs?path=/tmp/blob")
    assert status == 200
    assert hashlib.sha256(data).hexdigest() == hashlib.sha256(payload).hexdigest()

    status, _ = call(server.port, "GET", f"/machines/{machine}/fs?path=/tmp/nope")
    assert status == 404


def test_job_log(server: Any, machine: str) -> None:
    status, started = call_json(
        server.port,
        "POST",
        f"/machines/{machine}/jobs",
        body={
            "cmd": [
                "bash",
                "-c",
                "echo first; echo warn >&2; sleep 0.5; echo second; exit 7",
            ]
        },
    )
    assert status == 200, started
    job_id = started["job_id"]

    status, log = call_json(server.port, "GET", f"/machines/{machine}/jobs/{job_id}/log?wait=5")
    assert status == 200
    for _ in range(50):
        if log["done"]:
            break
        time.sleep(0.1)
        status, log = call_json(
            server.port,
            "GET",
            f"/machines/{machine}/jobs/{job_id}/log?offset={log['offset']}&wait=2",
        )
    assert log["done"] is True
    assert log["code"] == 7

    status, replay = call_json(server.port, "GET", f"/machines/{machine}/jobs/{job_id}/log")
    assert "first\n" in replay["out"]
    assert "second\n" in replay["out"]
    assert "warn\n" in replay["err"]


def test_usage_and_ttl(server: Any) -> None:
    status, created = call_json(
        server.port,
        "POST",
        "/machines",
        body={"cpu": 2, "memory_mb": 128, "ttl_seconds": 2},
    )
    assert status == 201, created
    machine_id = created["machine_id"]

    status, usage = call_json(server.port, "GET", f"/machines/{machine_id}/usage")
    assert status == 200
    assert usage["cpu"] == 2
    assert usage["memory_mb"] == 128
    assert usage["ended"] is None

    for _ in range(100):
        time.sleep(0.2)
        status, got = call_json(server.port, "GET", f"/machines/{machine_id}")
        if status == 200 and got["status"] == "ended":
            break
    assert got["status"] == "ended", "machine did not end at its ttl"

    status, usage = call_json(server.port, "GET", f"/machines/{machine_id}/usage")
    assert status == 200
    assert usage["ended"] is not None


def test_unknown_machine_404(server: Any) -> None:
    for method, path, body in [
        ("GET", "/machines/m-0000000000000000", None),
        ("DELETE", "/machines/m-0000000000000000", None),
        ("POST", "/machines/m-0000000000000000/exec", {"cmd": ["true"]}),
        ("GET", "/machines/m-0000000000000000/usage", None),
        ("GET", "/machines/m-0000000000000000/fs?path=/x", None),
    ]:
        status, _ = call(server.port, method, path, body=body)
        assert status == 404, (method, path)


def test_bad_requests(server: Any, machine: str) -> None:
    status, _ = call(server.port, "POST", "/machines", body={"ttl_seconds": "abc"})
    assert status == 400
    status, _ = call(server.port, "POST", f"/machines/{machine}/exec", body={"cmd": "notalist"})
    assert status == 400
    status, _ = call(server.port, "POST", "/machines", raw=b"{not json")
    assert status == 400
