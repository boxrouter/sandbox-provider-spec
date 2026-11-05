# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Regressions at native SDK, filesystem and committed Git boundaries."""

from __future__ import annotations

import base64
import builtins
import hashlib
import io
import json
import os
import subprocess
import time as std_time
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import modal as modal_sdk
import pytest

from sandbox_provider_spec import coverage_probe, coverage_ssh, coverage_v3, coverage_v5, evidence
from sandbox_provider_spec.check import check_path
from sandbox_provider_spec.driver import (
    Driver,
    Inputs,
    NativeFailure,
    Observation,
    Resource,
    Unsupported,
)
from sandbox_provider_spec.drivers import blaxel, daytona, modal


@pytest.mark.parametrize(
    "document",
    [
        {"resources": {"arch": {}}},
        {"resources": {"arch": [["amd64"]]}},
        {"requirements": {"pause_resume": {"keeps": {}}}},
    ],
)
def test_malformed_enum_values_are_validation_errors(tmp_path: Path, document: object) -> None:
    path = tmp_path / "request.json"
    path.write_text(json.dumps(document))
    assert check_path(path).errors


@pytest.mark.parametrize("coverage", [False, True])
def test_committed_report_uses_shipped_suite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, coverage: bool
) -> None:
    def git(*args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(tmp_path), *args], check=True, capture_output=True, text=True
        ).stdout.strip()

    git("init", "-q")
    git("config", "user.email", "test@example.invalid")
    git("config", "user.name", "Test")
    suite_dir = tmp_path / "package/conformance"
    suite_dir.mkdir(parents=True)
    monkeypatch.setattr(evidence, "_conformance_root", lambda: suite_dir.parent)
    core = b'{"tests": [{"id": "baseline.one", "rules": []}]}\n'
    extra = b'{"tests": [{"id": "coverage.one", "rules": ["rule"]}]}\n'
    (suite_dir / "suite.yaml").write_bytes(core)
    (suite_dir / "coverage.yaml").write_bytes(extra)
    git("add", ".")
    git("commit", "-qm", "source")
    payload = b"suite.yaml\0" + core + b"\0coverage.yaml\0" + extra + b"\0" if coverage else core
    results = [{"id": "baseline.one", "rules": []}]
    if coverage:
        results.append({"id": "coverage.one", "rules": ["rule"]})
    report: dict[str, Any] = {
        "revision": "f" * 40,
        "suite_digest": "sha256:" + hashlib.sha256(payload).hexdigest(),
        "tests": results,
        "selected_tests": [row["id"] for row in results],
    }
    provider = tmp_path / "packages/provider-example/data"
    provider.mkdir(parents=True)
    path = provider / "report.json"
    path.write_text(json.dumps(report))
    git("add", ".")
    git("commit", "-qm", "report")
    assert evidence.check_report_evidence(report, source_path=path) == []
    assert evidence.check_report_evidence({**report, "suite_digest": "bad"}, source_path=path)


@pytest.mark.parametrize("exit_code", [137, -9, 1, 127, -1])
def test_memory_probe_uses_native_process_binding_and_requires_kill(
    monkeypatch: pytest.MonkeyPatch, exit_code: int
) -> None:
    allocator = SimpleNamespace(wait=lambda: exit_code)
    echo = SimpleNamespace(
        stdout=SimpleNamespace(read=lambda: b"alive\n"),
        stderr=SimpleNamespace(read=lambda: b""),
        wait=lambda: 0,
    )
    processes = iter([allocator, echo])
    sandbox = SimpleNamespace(
        object_id="sb-test", exec=lambda *_args, **_kwargs: next(processes), poll=lambda: None
    )
    monkeypatch.setattr(modal_sdk.Sandbox, "from_id", lambda _identity: sandbox)
    monkeypatch.setattr(std_time, "sleep", lambda _seconds: None)
    driver = modal.ModalDriver()
    target = {"resource": Resource("sandbox", sandbox, lambda: {})}
    inputs = {"probe": "on_memory_exhausted", "memory_mib": 512}
    if exit_code in {137, -9}:
        assert coverage_probe.guest(driver, target, inputs) == {
            "on_memory_exhausted": "process_killed"
        }
    else:
        with pytest.raises(NativeFailure, match="memory_allocator_exit_unproven"):
            coverage_probe.guest(driver, target, inputs)


def test_late_native_state_read_cannot_prove_timely_closure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = 0.0

    def read(_path: str) -> bytes:
        nonlocal now
        now = 11.0
        return b'{"connected":true,"received":1,"closed":true,"failed":false}'

    sandbox = SimpleNamespace(filesystem=SimpleNamespace(read_bytes=read))
    target = {"resource": Resource("sandbox", sandbox, lambda: {})}
    monkeypatch.setattr(coverage_v3, "time", SimpleNamespace(monotonic=lambda: now))
    observer = coverage_v3._WindowObserver(
        modal.ModalDriver(), target, coverage_v3._Connection(target, {}, "state")
    )
    observer.arm(0.0)
    observer._observe()
    assert observer.outcome == "unobservable"


def test_daytona_ssh_binding_is_consumable_by_probe() -> None:
    sandbox = SimpleNamespace(
        create_ssh_access=lambda **_kwargs: SimpleNamespace(token="test-token")
    )
    driver = daytona.DaytonaDriver.__new__(daytona.DaytonaDriver)
    # No client is needed: this SDK operation belongs to the sandbox handle.
    driver.resources = []
    result = driver.ssh_access(
        {"resource": Resource("sandbox", sandbox, lambda: {})}, {"credential": "token"}
    )
    connection = coverage_ssh.connection(result)
    assert connection.kind == "token" and connection.secret == "test-token"
    assert connection.host_key is None


@pytest.mark.parametrize("source", ["environ", "cmdline", "mem"])
def test_identity_token_probe_hashes_other_process_candidate_values(
    monkeypatch: pytest.MonkeyPatch, source: str
) -> None:
    token = "sps-identity-token-visible-in-procfs"

    class ProcDriver(Driver):
        def __init__(self) -> None:
            super().__init__()
            self.files: dict[str, bytes] = {}

        def call(self, operation: str, _target: object, inputs: Inputs) -> Observation:
            if operation == "files.write":
                self.files[str(inputs["path"])] = base64.b64decode(str(inputs["data"]))
                return {}
            if operation != "run":
                raise AssertionError(operation)
            script = self.files["/tmp/sps-v5-identity-visible.py"].decode()
            digest = hashlib.sha256(token.encode()).hexdigest()
            proc_data = {
                "environ": b"SPS_TOKEN=" + token.encode() + b"\0",
                "cmdline": b"worker\0--token=" + token.encode() + b"\0",
                "mem": b'{"token":"' + token.encode() + b'"}',
            }[source]
            original_open = cast(Any, builtins.open)

            def proc_open(path: object, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
                del args, kwargs
                if path == "/tmp/sps-v5-identity-check.json":
                    return io.BytesIO(json.dumps({"sha256": digest}).encode())
                if path == "/proc/self/environ":
                    return io.BytesIO(b"HOME=/tmp\0")
                if path == f"/proc/99/{source}":
                    return io.BytesIO(proc_data)
                return original_open(path, mode)

            monkeypatch.setattr(builtins, "open", proc_open)
            monkeypatch.setattr(os, "listdir", lambda _path: ["99"])
            output = io.StringIO()
            with redirect_stdout(output):
                exec(compile(script, "guest-identity-probe.py", "exec"), {"__name__": "__main__"})
            return {"exit_code": 0, "stdout": output.getvalue()}

    assert coverage_v5._token_is_environment_readable(ProcDriver(), object(), token) is True


@pytest.mark.parametrize("operation", ["process.write_stdin", "process.close_stdin"])
def test_blaxel_absent_native_stdin_is_classified(operation: str) -> None:
    native_process = SimpleNamespace()
    command = blaxel.Command(cast(Any, SimpleNamespace(process=native_process)), "test")
    driver = blaxel.BlaxelDriver()
    with pytest.raises(Unsupported, match="stdin"):
        driver.call(
            operation, {"resource": Resource("process", command, lambda: {})}, {"data": "YQ=="}
        )
