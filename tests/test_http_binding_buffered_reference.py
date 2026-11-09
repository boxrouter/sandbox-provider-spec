# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Offline producer-path coverage; the SDK facade here never contacts Docker."""

from __future__ import annotations

import ast
import base64
import json
import sqlite3
import struct
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import httpx
import pytest

from sandbox_provider_spec import http_binding_validation as CONTRACT
from sandbox_provider_spec.http_reference import Endpoint, EndpointSettings
from sandbox_provider_spec.http_reference import buffered_runner as runner_reference
from sandbox_provider_spec.http_reference import docker_backend as docker_reference
from sandbox_provider_spec.http_reference.test_backend import TestBackend as _TestBackend

NOW = 1792692000
OWNER = "0123456789ab"
HEADER = struct.Struct("!5sBBiQQ")


class ScriptedBufferedBackend(_TestBackend):
    """Endpoint-only test double; native Docker path is covered below as well."""

    def __init__(self) -> None:
        super().__init__()
        self.result: tuple[bytes, bytes, int] = (b"\x00\xff", b"", 17)
        self.entered = threading.Event()
        self.release: threading.Event | None = None

    def run_buffered(self, request: dict[str, Any], *, execution_limit_ms: int) -> dict[str, Any]:
        self.call("run_buffered")
        self.entered.set()
        if self.release is not None:
            self.release.wait()
        stdout, stderr, code = self.result
        limit = request["output_limit_bytes"]
        stdout_truncated, stderr_truncated = len(stdout) > limit, len(stderr) > limit
        stdout, stderr = stdout[:limit], stderr[:limit]
        return {
            "mode": "buffered_commands_v1",
            "encoding": "base64",
            "stdout_base64": base64.b64encode(stdout).decode("ascii"),
            "stderr_base64": base64.b64encode(stderr).decode("ascii"),
            "stdout_bytes": len(stdout),
            "stderr_bytes": len(stderr),
            "stdout_truncated": stdout_truncated,
            "stderr_truncated": stderr_truncated,
            "exit_code": code,
            "output_complete": True,
        }


class FakeContainer:
    def __init__(self, name: str, labels: dict[str, str]) -> None:
        self.id = "native-container-id"
        self.name = name
        self.labels = labels
        self.status = "created"

    def start(self) -> None:
        self.status = "running"

    def reload(self) -> None:
        return None


class FakeContainers:
    def __init__(self) -> None:
        self.rows: dict[str, FakeContainer] = {}

    def create(
        self, image: str, command: list[str], *, name: str, labels: dict[str, str], **kwargs: Any
    ) -> FakeContainer:
        assert image == "sha256:cached-image"
        assert command == ["sleep", "infinity"]
        assert kwargs["network_disabled"] is True
        container = FakeContainer(name, labels)
        self.rows[name] = container
        return container

    def get(self, name: str) -> FakeContainer:
        return self.rows[name]


class FakeDockerApi:
    def __init__(self, stdout: bytes, stderr: bytes, code: int) -> None:
        self.stdout, self.stderr, self.code = stdout, stderr, code
        self.command: list[str] | None = None
        self.options: dict[str, Any] | None = None

    def exec_create(self, container: str, command: list[str], **options: Any) -> dict[str, str]:
        assert container == "native-container-id"
        self.command, self.options = command, options
        return {"Id": "native-exec-id"}

    def exec_start(
        self, identity: str, **options: Any
    ) -> Iterator[tuple[bytes | None, bytes | None]]:
        assert identity == "native-exec-id"
        assert options == {"stream": True, "demux": True, "tty": False}
        framed = HEADER.pack(_magic(), 0, 0, self.code, len(self.stdout), len(self.stderr))
        framed += self.stdout + self.stderr
        yield framed, None

    def exec_inspect(self, identity: str) -> dict[str, Any]:
        assert identity == "native-exec-id"
        return {"Running": False, "ExitCode": 0}


class FakeDockerClient:
    def __init__(self, api: FakeDockerApi) -> None:
        self.api = api
        self.containers = FakeContainers()


def _magic() -> bytes:
    return runner_reference._MAGIC


def test_native_inline_runner_has_valid_python_syntax() -> None:
    compile(runner_reference._RUNNER, "<buffered-runner>", "exec")


def test_buffered_runner_bounds_capture_and_uses_term_relative_grace() -> None:
    runner = runner_reference._RUNNER
    assert "while True:" not in runner
    assert "CAP=32*1024*1024" in runner
    assert "os.ftruncate(fd,CAP)" in runner
    assert "fcntl.fcntl(fd,1033,1|2|4)" in runner
    assert "open('/proc/self/fdinfo/'+str(fd))" in runner
    assert "os.pread(fds[0],min(written(fds[0]),L+1),0)" in runner
    assert "os.pread(fds[1],min(written(fds[1]),L+1),0)" in runner
    assert "os.lseek(" not in runner
    assert "stdout=subprocess.PIPE" not in runner
    assert "os.read(" not in runner
    assert "select." not in runner
    assert "resource.setrlimit" not in runner
    assert "SIGXFSZ" not in runner
    term_attempt = runner.index("os.killpg(group,signal.SIGTERM)")
    grace_clock = runner.index("deadline=time.monotonic()+5")
    kill_attempt = runner.index("os.killpg(group,signal.SIGKILL)")
    assert term_attempt < grace_clock < kill_attempt
    assert "running(group)" in runner
    assert "child.poll() is None" in runner


def test_runner_receipt_failure_after_foreground_exit_preserves_background_group() -> None:
    tree = ast.parse(runner_reference._RUNNER)
    recovery = next(
        node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "recover"
    )
    child = SimpleNamespace(pid=417, poll=lambda: 0)
    settled: list[int] = []
    namespace: dict[str, Any] = {
        "time": SimpleNamespace(monotonic=lambda: 10.0, sleep=lambda _: None),
        "settle": settled.append,
    }
    exec(
        compile(ast.Module(body=[recovery], type_ignores=[]), "<runner-recovery>", "exec"),
        namespace,
    )

    # Inject the receipt-stage exception after ordinary foreground completion.
    namespace["recover"](child, True, False, 20.0)
    assert settled == []


def test_runner_recovery_keeps_original_execution_deadline() -> None:
    tree = ast.parse(runner_reference._RUNNER)
    recovery = next(
        node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "recover"
    )
    now = 4.0
    settled_at: list[float] = []

    class Clock:
        @staticmethod
        def monotonic() -> float:
            return now

        @staticmethod
        def sleep(delay: float) -> None:
            nonlocal now
            now += delay

    child = SimpleNamespace(pid=418, poll=lambda: None)
    namespace: dict[str, Any] = {
        "time": Clock,
        "settle": lambda _pid: settled_at.append(now),
    }
    exec(
        compile(ast.Module(body=[recovery], type_ignores=[]), "<runner-recovery>", "exec"),
        namespace,
    )

    namespace["recover"](child, False, False, 5.0)
    assert settled_at == [5.0]


class WireHarness:
    def __init__(
        self,
        tmp_path: Path,
        backend: Any,
        *,
        buffered: bool,
        output_bytes: int = 1024,
        execution_ms: int = 1000,
        observation_ms: int = 5000,
    ) -> None:
        self.backend = backend
        self.now = NOW
        self.origin = "https://reference.invalid"
        self.tokens = {"token": "account"}
        self.counter = 0
        self.endpoint = Endpoint(
            backend,
            tmp_path / "allocations.sqlite3",
            self.tokens,
            settings=EndpointSettings(
                self.origin,
                clock=lambda: self.now,
                operation_timeout_ms=observation_ms,
                buffered_commands=buffered,
                buffered_command_output_bytes=output_bytes if buffered else None,
                execution_ms=execution_ms if buffered else None,
            ),
        )
        self.client = httpx.Client(
            transport=httpx.WSGITransport(app=self.endpoint), base_url=self.origin
        )

    def close(self) -> None:
        self.client.close()
        self.endpoint.close(timeout=2)

    def restart(self) -> None:
        self.client.close()
        self.endpoint.close(timeout=2)
        self.endpoint = Endpoint(
            self.backend,
            self.endpoint.database,
            self.tokens,
            settings=self.endpoint.settings,
        )
        self.client = httpx.Client(
            transport=httpx.WSGITransport(app=self.endpoint), base_url=self.origin
        )

    def request(self, operation: str, **fields: Any) -> dict[str, Any]:
        self.counter += 1
        return {
            "operation": operation,
            "request_id": f"request-{self.counter}",
            "account_id": "account",
            **fields,
        }

    def create_request(self, **fields: Any) -> dict[str, Any]:
        offering = self.endpoint.discovery("account")["offerings"][0]
        values = {
            "allocation_key": f"{NOW}:{self.counter:032x}",
            "offering_id": "container",
            "declaration_id": offering["declaration_id"],
            "request": {},
            "env": {},
            **fields,
        }
        return self.request(
            "create",
            **values,
        )

    def send(
        self,
        request: dict[str, Any],
        *,
        expected: int = 200,
        validation_discovery: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        body = CONTRACT.body_bytes(request)
        digest = CONTRACT.request_digest(body)
        response = self.client.post(
            "/sps/v1/" + request["operation"],
            content=body,
            headers={
                "Authorization": "Bearer token",
                "Content-Type": "application/json",
                "SPS-Request-Digest": digest,
            },
        )
        assert response.status_code == expected, response.text[:512]
        result = response.json()
        CONTRACT.validate_exchange(
            request,
            result,
            validation_discovery or self.endpoint.discovery("account"),
            status=expected,
            request_body=body,
            digest=digest,
        )
        return cast(dict[str, Any], result)


def _run_request(harness: WireHarness, sandbox: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    return harness.request(
        "run",
        sandbox=sandbox,
        argv=["python3", "-c", "print('fixture')"],
        cwd="/tmp",
        env={"PP2": "test"},
        observation_timeout_ms=overrides.pop("observation_timeout_ms", 100),
        encoding="base64",
        mode="buffered_commands_v1",
        execution_limit_ms=overrides.pop("execution_limit_ms", 500),
        output_limit_bytes=overrides.pop("output_limit_bytes", 128),
        **overrides,
    )


def test_default_backend_stays_on_binding_01_and_refuses_buffered_opt_in(tmp_path: Path) -> None:
    backend = _TestBackend()
    harness = WireHarness(tmp_path, backend, buffered=False)
    try:
        discovery = harness.endpoint.discovery("account")
        assert discovery["binding"] == "sandbox-provider-http/0.1"
        assert discovery["core_modes"] == []
        sandbox = harness.send(harness.create_request())["sandbox"]
        unsupported = harness.send(_run_request(harness, sandbox), expected=422)
        assert unsupported["error"]["code"] == "unsupported_mode"
        assert backend.calls["run"] == 0
        with pytest.raises(ValueError, match="requires a backend implementation"):
            Endpoint(
                backend,
                tmp_path / "unsupported.sqlite3",
                {"token": "account"},
                settings=EndpointSettings(
                    harness.origin,
                    buffered_commands=True,
                    buffered_command_output_bytes=100,
                    execution_ms=100,
                ),
            )
    finally:
        harness.close()


def test_selection_token_is_persisted_and_replay_precedes_current_admission(tmp_path: Path) -> None:
    backend = ScriptedBufferedBackend()
    harness = WireHarness(tmp_path, backend, buffered=True, output_bytes=128)
    try:
        original = harness.create_request()
        created = harness.send(original)
        sandbox = created["sandbox"]
        selected_discovery = harness.endpoint.discovery("account")
        old_token = original["declaration_id"]
        harness.endpoint.settings.buffered_command_output_bytes = 64
        harness.endpoint.settings.operation_timeout_ms = 2000
        current_token = harness.endpoint.discovery("account")["offerings"][0]["declaration_id"]
        assert current_token != old_token
        assert harness.endpoint.discovery("account")["limits"]["observation_ms"] == 2000

        stale = harness.create_request(declaration_id=old_token)
        assert harness.send(stale, expected=409)["error"]["code"] == "conflict"
        assert backend.calls["create"] == 1
        harness.restart()
        assert harness.send(original) == created
        assert backend.calls["create"] == 1

        run = harness.send(
            _run_request(harness, sandbox, output_limit_bytes=128),
            validation_discovery=selected_discovery,
        )
        assert base64.b64decode(run["stdout_base64"]) == b"\x00\xff"
        assert base64.b64decode(run["stderr_base64"]) == b""
        assert run["exit_code"] == 17
        assert backend.calls["run_buffered"] == 1
        with harness.endpoint.connect() as database:
            row = database.execute(
                "SELECT result FROM allocations WHERE account='account'"
            ).fetchone()
        assert row is not None
        _response, persisted = harness.endpoint._stored_allocation(row[0])
        assert persisted is not None
        assert persisted["limits"] == selected_discovery["limits"]
    finally:
        harness.close()


def test_timeout_returns_unknown_while_buffered_worker_retains_ownership(tmp_path: Path) -> None:
    backend = ScriptedBufferedBackend()
    backend.release = threading.Event()
    harness = WireHarness(
        tmp_path,
        backend,
        buffered=True,
    )
    sandbox = harness.send(harness.create_request())["sandbox"]
    # The backend has to be entered before the observation expires for the outcome to be unknown;
    # a loaded machine can starve the worker thread for far longer than a few milliseconds.
    harness.endpoint.settings.operation_timeout_ms = 1000
    try:
        response = harness.send(
            _run_request(harness, sandbox, observation_timeout_ms=1000), expected=504
        )
        assert response["error"]["code"] == "timeout"
        assert response["error"]["outcome"] == "unknown"
        assert backend.entered.is_set()
        assert harness.endpoint._runtime.pending == 1
        with pytest.raises(RuntimeError, match="still in flight"):
            harness.endpoint.close(timeout=0.01)
        backend.release.set()
        assert _wait_until(lambda: harness.endpoint._runtime.pending == 0)
    finally:
        backend.release.set()
        harness.close()


@pytest.mark.parametrize(
    ("stdout", "stderr", "stdout_truncated", "stderr_truncated"),
    [
        (b"x" * 128, b"", False, False),
        (b"x" * 129, b"", True, False),
        (b"x" * 128, b"e" * 500, False, True),
    ],
)
def test_output_over_the_limit_returns_the_exact_prefix_marked_truncated(
    tmp_path: Path, stdout: bytes, stderr: bytes, stdout_truncated: bool, stderr_truncated: bool
) -> None:
    backend = ScriptedBufferedBackend()
    backend.result = (stdout, stderr, 7)
    harness = WireHarness(tmp_path, backend, buffered=True, output_bytes=128)
    try:
        sandbox = harness.send(harness.create_request())["sandbox"]
        response = harness.send(_run_request(harness, sandbox, observation_timeout_ms=5000))
        assert response["exit_code"] == 7
        assert base64.b64decode(response["stdout_base64"]) == stdout[:128]
        assert base64.b64decode(response["stderr_base64"]) == stderr[:128]
        assert response["stdout_truncated"] is stdout_truncated
        assert response["stderr_truncated"] is stderr_truncated
        assert (response["stdout_bytes"], response["stderr_bytes"]) == (
            min(len(stdout), 128),
            min(len(stderr), 128),
        )
    finally:
        harness.close()


def test_uncertain_backend_failure_is_not_recast_as_completion(tmp_path: Path) -> None:
    backend = ScriptedBufferedBackend()
    backend.fail = "run_buffered"
    harness = WireHarness(tmp_path, backend, buffered=True)
    try:
        sandbox = harness.send(harness.create_request())["sandbox"]
        response = harness.send(_run_request(harness, sandbox), expected=502)
        assert response["error"]["outcome"] == "unknown"
        assert response["error"]["exit_code"] is None
        assert backend.calls["run_buffered"] == 1
    finally:
        harness.close()


def test_blocked_selection_store_cannot_dispatch_after_observation_expiry(tmp_path: Path) -> None:
    backend = ScriptedBufferedBackend()
    harness = WireHarness(tmp_path, backend, buffered=True)
    sandbox = harness.send(harness.create_request())["sandbox"]
    # Create under the default budget so a loaded machine cannot expire it; only the run is tight.
    harness.endpoint.settings.operation_timeout_ms = 40
    lock = sqlite3.connect(harness.endpoint.database, timeout=1, isolation_level=None)
    lock.execute("BEGIN EXCLUSIVE")
    lock.execute("UPDATE allocations SET digest=digest WHERE account='account'")
    try:
        result = harness.send(
            _run_request(harness, sandbox, observation_timeout_ms=40), expected=504
        )
        assert result["error"]["outcome"] == "not_dispatched"
        lock.execute("COMMIT")
        assert _wait_until(lambda: harness.endpoint._runtime.pending == 0)
        assert backend.calls["run_buffered"] == 0
    finally:
        if lock.in_transaction:
            lock.execute("ROLLBACK")
        lock.close()
        harness.close()


def test_endpoint_routes_buffered_wire_request_through_docker_backend(tmp_path: Path) -> None:
    stdout, stderr, code = b"\x00\xff\n", b"\x80diagnostic", 23
    api = FakeDockerApi(stdout, stderr, code)
    backend = docker_reference.DockerBackend.__new__(docker_reference.DockerBackend)
    backend.client = FakeDockerClient(api)
    backend.image = "sha256:cached-image"
    backend.run_id = OWNER
    backend.authority = OWNER
    backend.sdks = {"docker": "7.2.0"}
    backend.threads = []
    harness = WireHarness(tmp_path, backend, buffered=True, output_bytes=128)
    try:
        sandbox = harness.send(harness.create_request())["sandbox"]
        request = _run_request(harness, sandbox)
        result = harness.send(request)
        assert base64.b64decode(result["stdout_base64"]) == stdout
        assert base64.b64decode(result["stderr_base64"]) == stderr
        assert (result["stdout_bytes"], result["stderr_bytes"], result["exit_code"]) == (
            len(stdout),
            len(stderr),
            code,
        )
        assert api.command is not None
        assert api.command[:3] == ["python3", "-c", runner_reference._RUNNER]
        assert api.command[-3:] == request["argv"]
        assert api.options == {
            "environment": request["env"],
            "workdir": request["cwd"],
            "stdin": False,
            "tty": False,
        }
    finally:
        harness.close()


def test_full_advertised_capacity_round_trips_both_16_mib_streams(tmp_path: Path) -> None:
    output_limit = 16 * 1024 * 1024
    stdout, stderr = b"o" * output_limit, b"e" * output_limit
    api = FakeDockerApi(stdout, stderr, 0)
    backend = docker_reference.DockerBackend.__new__(docker_reference.DockerBackend)
    backend.client = FakeDockerClient(api)
    backend.image = "sha256:cached-image"
    backend.run_id = OWNER
    backend.authority = OWNER
    backend.sdks = {"docker": "7.2.0"}
    backend.threads = []
    harness = WireHarness(
        tmp_path,
        backend,
        buffered=True,
        observation_ms=5000,
        output_bytes=output_limit,
    )
    try:
        sandbox = harness.send(harness.create_request())["sandbox"]
        result = harness.send(
            _run_request(
                harness,
                sandbox,
                output_limit_bytes=output_limit,
                execution_limit_ms=1000,
                observation_timeout_ms=5000,
            )
        )
        assert result["stdout_bytes"] == result["stderr_bytes"] == output_limit
        assert len(base64.b64decode(result["stdout_base64"])) == output_limit
        assert len(base64.b64decode(result["stderr_base64"])) == output_limit
        assert len(json.dumps(result).encode()) < 64 * 1024 * 1024
    finally:
        harness.close()


def _wait_until(predicate: Any, timeout: float = 1) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.005)
    return bool(predicate())
