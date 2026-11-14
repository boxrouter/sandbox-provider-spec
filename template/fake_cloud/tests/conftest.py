# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Black-box fixtures: a real server subprocess against the local Docker daemon."""

from __future__ import annotations

import contextlib
import http.client
import json
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "python:3.13-slim@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f"


def _docker_client() -> Any:
    docker = pytest.importorskip("docker", reason="Example Cloud tests need the docker extra")
    try:
        client = docker.from_env(timeout=5)
        client.ping()
    except docker.errors.DockerException as exc:
        pytest.skip(
            f"Example Cloud tests need a local Docker daemon ({exc})",
            allow_module_level=True,
        )
    return client


DOCKER = _docker_client()


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def call(
    port: int,
    method: str,
    path: str,
    *,
    key: str | None = "dev",
    body: Any = None,
    raw: bytes | None = None,
    timeout: float = 60.0,
) -> tuple[int, bytes]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    headers: dict[str, str] = {}
    if key is not None:
        headers["X-Api-Key"] = key
    payload: bytes | None = raw
    if payload is None and body is not None:
        payload = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if payload is not None:
        headers["Content-Length"] = str(len(payload))
    conn.request(method, path, body=payload, headers=headers)
    try:
        response = conn.getresponse()
        return response.status, response.read()
    finally:
        conn.close()


def call_json(
    port: int, method: str, path: str, *, key: str | None = "dev", body: Any = None
) -> tuple[int, Any]:
    status, data = call(port, method, path, key=key, body=body)
    return status, json.loads(data)


@pytest.fixture(scope="session")
def image() -> str:
    docker = pytest.importorskip("docker", reason="Example Cloud tests need the docker extra")
    try:
        DOCKER.images.get(IMAGE)
    except docker.errors.ImageNotFound:
        DOCKER.images.pull(IMAGE)
    return IMAGE


@pytest.fixture(scope="session")
def server(tmp_path_factory: pytest.TempPathFactory, image: str) -> Any:
    """One Example Cloud server per test session, namespaced by owner label."""
    port = _free_port()
    owner = f"test-{uuid.uuid4().hex[:12]}"
    state_dir = tmp_path_factory.mktemp("example-cloud")
    process = subprocess.Popen(
        [
            sys.executable,
            str(ROOT / "server.py"),
            "--port",
            str(port),
            "--state-dir",
            str(state_dir),
            "--owner",
            owner,
            "--image",
            image,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"server exited early with {process.returncode}")
        with contextlib.suppress(OSError):
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
            conn.request("GET", "/healthz")
            if conn.getresponse().read():
                conn.close()
                break
        time.sleep(0.1)
    else:
        process.kill()
        raise RuntimeError("server did not start within 30 s")

    class Server:
        pass

    handle = Server()
    handle.port = port
    handle.owner = owner
    handle.state_dir = state_dir
    yield handle

    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
    for container in DOCKER.containers.list(all=True, filters={"label": f"example.owner={owner}"}):
        with contextlib.suppress(Exception):
            container.remove(force=True)


@pytest.fixture()
def machine(server: Any) -> Any:
    """Create one machine and always delete it at test end."""
    status, result = call_json(
        server.port,
        "POST",
        "/machines",
        body={"cpu": 1, "memory_mb": 512, "ttl_seconds": 600},
    )
    assert status == 201, result
    yield result["machine_id"]
    with contextlib.suppress(Exception):
        call(server.port, "DELETE", f"/machines/{result['machine_id']}")
