# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Public inline runner exercised by a minimal subprocess-backed SPS driver."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import threading
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import pytest

from sandbox_provider_spec import coverage_http_buffered as probe
from sandbox_provider_spec.driver import Differs, Driver, NativeFailure
from sandbox_provider_spec.http_reference import (
    BUFFERED_RUNNER_TERM_ALLOWANCE_S,
    buffered_runner_argv,
    decode_buffered_runner_result,
)


class SubprocessBackend(Driver):
    """Backend double that sends the public inline wrapper to local exec."""

    def __init__(self) -> None:
        super().__init__()
        self.processes: list[subprocess.Popen[bytes]] = []
        self.threads: list[threading.Thread] = []
        self.responses: list[Mapping[str, Any]] = []

    def _record(self, response: Mapping[str, Any]) -> Mapping[str, Any]:
        self.responses.append(response)
        return response

    def http_buffered_run(self, target: object, inputs: Mapping[str, Any]) -> Mapping[str, Any]:
        del target
        process = subprocess.Popen(
            buffered_runner_argv(
                inputs["argv"],
                execution_limit_ms=inputs["execution_limit_ms"],
                output_limit_bytes=inputs["output_limit_bytes"],
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        self.processes.append(process)
        finished = threading.Event()
        received: dict[str, bytes] = {}

        def collect() -> None:
            stdout, stderr = process.communicate()
            received["stdout"], received["stderr"] = stdout, stderr
            finished.set()

        reader = threading.Thread(target=collect, daemon=True)
        self.threads.append(reader)
        reader.start()
        if not finished.wait(inputs["observation_timeout_ms"] / 1000):
            return self._record({"ok": False, "code": "timeout", "outcome": "unknown"})
        if process.returncode != 0 or received["stderr"]:
            return self._record({"ok": False, "code": "provider_error", "outcome": "unknown"})
        try:
            result = decode_buffered_runner_result(received["stdout"])
        except ValueError:
            return self._record({"ok": False, "code": "provider_error", "outcome": "unknown"})
        if result.state == "terminated":
            return self._record({"ok": False, "code": "timeout", "outcome": "completed"})
        if result.state != "completed":
            return self._record({"ok": False, "code": "provider_error", "outcome": "unknown"})
        return self._record(
            {
                "ok": True,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "stdout_truncated": result.stdout_truncated,
                "stderr_truncated": result.stderr_truncated,
                "exit_code": result.exit_code,
            }
        )

    def reap(self) -> None:
        for process in self.processes:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=10)
        for thread in self.threads:
            thread.join(timeout=10)


def test_public_runner_argv_and_frame_round_trip() -> None:
    argv = buffered_runner_argv(
        ["sh", "-c", "printf 'out'; printf 'err' >&2; exit 7"],
        execution_limit_ms=1000,
        output_limit_bytes=64,
    )
    assert argv[:2] == ["python3", "-c"]
    completed = subprocess.run(argv, capture_output=True, check=True, timeout=10)
    frame = decode_buffered_runner_result(completed.stdout)
    assert (frame.state, frame.stdout, frame.stderr, frame.exit_code) == (
        "completed",
        b"out",
        b"err",
        7,
    )


def test_public_runner_returns_each_streams_first_bytes_marked_truncated() -> None:
    argv = buffered_runner_argv(
        [
            "sh",
            "-c",
            "printf 'abcdefghij'; printf 'ABCDEFGH' >&2; printf 'zzz' >&2; exit 3",
        ],
        execution_limit_ms=5000,
        output_limit_bytes=8,
    )
    completed = subprocess.run(argv, capture_output=True, check=True, timeout=10)
    frame = decode_buffered_runner_result(completed.stdout)
    assert (frame.state, frame.exit_code) == ("completed", 3)
    assert (frame.stdout, frame.stdout_truncated) == (b"abcdefgh", True)
    assert (frame.stderr, frame.stderr_truncated) == (b"ABCDEFGH", True)

    exact = subprocess.run(
        buffered_runner_argv(
            ["sh", "-c", "printf 'abcdefgh'; printf 'x' >&2"],
            execution_limit_ms=5000,
            output_limit_bytes=8,
        ),
        capture_output=True,
        check=True,
        timeout=10,
    )
    frame = decode_buffered_runner_result(exact.stdout)
    assert (frame.stdout, frame.stdout_truncated) == (b"abcdefgh", False)
    assert (frame.stderr, frame.stderr_truncated) == (b"x", False)


def _diagnostic(
    check: Callable[[Driver, object, Mapping[str, object]], None],
    backend: Driver,
    target: object,
    inputs: Mapping[str, object],
    unproven: list[str],
) -> bool:
    try:
        check(backend, target, inputs)
    except NativeFailure as error:
        if not error.code.startswith("http_buffered_unproven_"):
            raise
        unproven.append(error.code)
        return False
    return True


@pytest.mark.parametrize(
    "error",
    [Differs("term_before_execution_limit"), NativeFailure("provider_error")],
)
def test_local_timing_uncertainty_never_hides_a_contract_or_provider_failure(
    error: Exception,
) -> None:
    def failure(_driver: Driver, _target: object, _inputs: Mapping[str, object]) -> None:
        raise error

    with pytest.raises(type(error)):
        _diagnostic(failure, Driver(), object(), {}, [])


def test_local_timing_uncertainty_is_recorded_without_a_passing_observation() -> None:
    code = "http_buffered_unproven_term_time_crosses_execution_limit"

    def uncertain(_driver: Driver, _target: object, _inputs: Mapping[str, object]) -> None:
        raise NativeFailure(code)

    observations: list[str] = []
    assert _diagnostic(uncertain, Driver(), object(), {}, observations) is False
    assert observations == [code]


def test_public_runner_preserves_deadlines_and_reaps_the_process_group(tmp_path: Path) -> None:
    """Check the public helper without assuming bounded workload startup latency.

    The diagnostic deliberately reports overlapping clock bounds as unproven. Under
    contention that is a valid result, including for a correct helper. Always check
    the observed process, group and observation-expiry behavior; report an unproven
    timing measurement as a skip rather than a successful conformance observation.
    """
    unproven: list[str] = []
    backend = SubprocessBackend()
    target = object()
    inputs = {"workdir_root": str(tmp_path)}
    try:
        term_proven = _diagnostic(probe.execution_term, backend, target, inputs, unproven)
        assert backend.responses[0] == {"ok": False, "code": "timeout", "outcome": "completed"}
        term_witness = json.loads(backend.responses[-1]["stdout"])
        assert term_witness["leader_alive"] is False and term_witness["T"] is not None
        # The workload's own start-to-TERM time is at least E plus the checked handler margin,
        # and the allowance keeps the TERM far inside the check's resolution.
        if term_proven:
            assert 3.0 + probe.HANDLER_MARGIN_S <= term_witness["T"] - term_witness["S"]
            assert term_witness["T"] - term_witness["S"] < 3.0 + probe.TERM_RESOLUTION_S

        group_start = len(backend.responses)
        group_proven = _diagnostic(probe.group_kill, backend, target, inputs, unproven)
        group_witness = json.loads(backend.responses[-1]["stdout"])
        assert group_witness["leader_alive"] is False and group_witness["child_alive"] is False
        if group_proven:
            assert probe.judge_kill_gap(group_witness["hb"] - group_witness["T"]) in (
                None,
                "ambiguous",
            )
        assert backend.responses[group_start]["outcome"] == "completed"

        observation_start = len(backend.responses)
        _diagnostic(probe.observation_versus_execution, backend, target, inputs, unproven)
        assert backend.responses[observation_start] == {
            "ok": False,
            "code": "timeout",
            "outcome": "unknown",
        }
        early_witness = json.loads(backend.responses[observation_start + 1]["stdout"])
        assert early_witness["leader_alive"] is True and early_witness["T"] is None
        final_witness = json.loads(backend.responses[-1]["stdout"])
        assert final_witness["leader_alive"] is False and final_witness["T"] is not None
    finally:
        backend.reap()

    if unproven:
        pytest.skip("Local timing observation remains unproven: " + ", ".join(unproven))


def test_public_runner_times_e_from_the_child_not_before_it_exists(tmp_path: Path) -> None:
    started = tmp_path / "child-started"
    script = (
        f"import time;t=time.monotonic();open({str(started)!r},'w').write(repr(t));time.sleep(30)"
    )
    argv = buffered_runner_argv(
        ["python3", "-c", script], execution_limit_ms=1000, output_limit_bytes=64
    )
    begun = time.monotonic()
    completed = subprocess.run(argv, capture_output=True, check=True, timeout=20)
    elapsed = time.monotonic() - begun
    assert decode_buffered_runner_result(completed.stdout).state == "terminated"
    # Never before E after the child exists, and only the fixed allowance later.
    assert (
        1.0 + BUFFERED_RUNNER_TERM_ALLOWANCE_S
        <= elapsed
        < 1.0 + BUFFERED_RUNNER_TERM_ALLOWANCE_S + 1.5
    )
