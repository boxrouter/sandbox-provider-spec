# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""HTTP buffered-command diagnostics: local fault and positive controls, plus report checks.

The guests run finite python3 workloads as real local processes. Every process is started in its
own session, recorded by exact group id and killed and reaped in `finally`; nothing else is
signalled. No provider, container or network is used.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import math
import os
import signal
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import pytest

from sandbox_provider_spec import coverage_http_buffered as probe
from sandbox_provider_spec.check import check_report
from sandbox_provider_spec.check_digests import test_dependencies as dependencies_of
from sandbox_provider_spec.driver import Differs, Driver, NativeFailure, NotRun
from sandbox_provider_spec.evidence import (
    DEVELOPMENT_REVISION,
    _source_suite_rules,
    check_report_evidence,
)
from sandbox_provider_spec.report import report
from sandbox_provider_spec.runner import Runner
from sandbox_provider_spec.suite import read_suite, suite_path

# Coverage suite digest published as 0.3.118, archived before the http.buffered rows were added.
PRE_BUFFERED_SUITE = "sha256:231ace69bf225a4613ef6d368215b85e0d4ebf196889dad54a74e534ce868ae2"
CASE_IDS = [f"http.buffered.{name}" for name in probe.CASES]


@dataclass
class _Command:
    process: subprocess.Popen[bytes]
    group: int
    settled: threading.Event
    drained: threading.Event
    stdout_size: Callable[[], int]
    result: dict[str, Any]


TIMER_LAG_S = 0.4
"""Delay between dispatching a command and starting its execution timer in the timeline guest.

The default timeline guest therefore sends TERM `E + 0.4 s` after dispatch, which is after
`start stamp + E + handler margin`: a late-timer endpoint whose TERM can be proven not early. It
is a positive control for the judgement logic and is NOT the binding's exact behaviour (E from
dispatch). A guest that follows the binding exactly (`exact_dispatch`) is reported unproven,
because its startup and handler latency cannot be bounded; nothing here is tuned to avoid that.
"""


MAX_HOST_WORKERS = 4
"""Rows run concurrently here; the SPS runner runs them serially."""


class LocalGuest(Driver):
    """Runs buffered commands locally as real processes under a chosen fault.

    Only rows whose outcome does not depend on wall-clock margins run here (output bytes, limits,
    descendants, and a TERM that never arrives). Every row that judges a TERM or KILL time runs on
    `TimelineGuest` instead: a real process under a loaded host can stall by more than the
    classification's stated margins, which made those rows flaky.
    """

    def __init__(self, fault: str | None = None) -> None:
        super().__init__()
        self.fault = fault
        self._groups: list[int] = []
        self._processes: list[subprocess.Popen[bytes]] = []

    def _kill(self, group: int) -> None:
        try:
            os.killpg(group, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def _spawn(self, argv: list[str], **kwargs: Any) -> subprocess.Popen[bytes]:
        process = cast(
            "subprocess.Popen[bytes]", subprocess.Popen(argv, start_new_session=True, **kwargs)
        )
        self._groups.append(process.pid)
        self._processes.append(process)
        return process

    def reap(self) -> None:
        for group in self._groups:
            try:
                os.killpg(group, signal.SIGKILL)
            except ProcessLookupError:
                pass
        for process in self._processes:
            process.wait(timeout=10)

    def _group_alive(self, command: _Command) -> bool:
        command.process.poll()
        try:
            os.killpg(command.group, 0)
        except ProcessLookupError:
            return False
        return True

    def _wait_group(self, command: _Command, seconds: float) -> bool:
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if not self._group_alive(command):
                return True
            time.sleep(0.02)
        return not self._group_alive(command)

    def _expire(self, command: _Command) -> None:
        group = command.group
        if self.fault == "no_term":
            return
        os.killpg(group, signal.SIGTERM)
        if not self._wait_group(command, 5.15):
            os.killpg(group, signal.SIGKILL)
        self._wait_group(command, 2.0)

    def _supervise(self, command: _Command, execution_ms: int, limit: int) -> None:
        fault, process = self.fault, command.process
        end = time.monotonic() + execution_ms / 1000 + TIMER_LAG_S
        while time.monotonic() < end:
            if process.poll() is not None:
                break
            if fault == "overflow_early_complete" and command.stdout_size() > limit:
                command.result.update(kind="early")
                command.settled.set()
                return
            if fault == "overflow_kills" and command.stdout_size() > limit:
                self._kill(command.group)
                command.result.update(kind="early")
                command.settled.set()
                return
            time.sleep(0.02)
        if process.poll() is None:
            self._expire(command)
            command.result.update(kind="expired")
        else:
            if self.fault == "eof_wait":
                command.drained.wait()
            if fault == "background_killed":
                self._kill(command.group)
            command.result.update(kind="done")
        command.settled.set()

    def http_buffered_run(self, target: object, inputs: Mapping[str, Any]) -> Mapping[str, Any]:
        del target
        argv, limit = inputs["argv"], inputs["output_limit_bytes"]
        execution_ms, observation_ms = (
            inputs["execution_limit_ms"],
            inputs["observation_timeout_ms"],
        )
        streams = [tempfile.TemporaryFile(), tempfile.TemporaryFile()]
        piped = self.fault == "eof_wait"
        process = self._spawn(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE if piped else streams[0],
            stderr=subprocess.PIPE if piped else streams[1],
        )
        command = _Command(
            process,
            process.pid,
            threading.Event(),
            threading.Event(),
            lambda: os.fstat(streams[0].fileno()).st_size,
            {},
        )
        if piped:
            threading.Thread(target=self._drain, args=(command, streams), daemon=True).start()
        threading.Thread(
            target=self._supervise, args=(command, execution_ms, limit), daemon=True
        ).start()
        if not command.settled.wait(observation_ms / 1000):
            return {"ok": False, "code": "timeout", "outcome": "unknown"}
        kind = command.result["kind"]
        if kind == "expired":
            return {"ok": False, "code": "timeout", "outcome": "completed"}
        return self._finish(command, streams, argv, limit)

    def _drain(self, command: _Command, streams: list[Any]) -> None:
        # EOF-bound capture: the read ends only when every holder of the pipe has closed it.
        out, err = command.process.stdout, command.process.stderr
        assert out is not None and err is not None
        streams[0].write(out.read())
        streams[1].write(err.read())
        command.drained.set()

    def _finish(
        self, command: _Command, streams: list[Any], argv: list[str], limit: int
    ) -> Mapping[str, Any]:
        data = []
        for stream in streams:
            stream.seek(0)
            data.append(stream.read())
        code = command.process.returncode
        if code is None:
            code = 0  # a fault answered before the command finished
        elif code < 0:
            code = 128 - code
        fault = self.fault
        over = max(len(data[0]), len(data[1])) > limit
        if over and fault == "overflow_error":
            return {"ok": False, "code": "limit_exceeded", "outcome": "completed"}
        if over and fault == "overflow_replay":
            self._spawn(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL).wait(20)
        flags = [len(item) > limit for item in data]
        if fault == "exact_flagged":
            flags = [len(item) >= limit for item in data]
        if fault == "overflow_no_flags":
            flags = [False, False]
        if fault == "overflow_whole_output":
            kept = data
        elif fault == "overflow_drops_output":
            kept = [b"" if flag else item for item, flag in zip(data, flags, strict=True)]
        else:
            kept = [item[:limit] for item in data]
        if fault == "overflow_lost_status" and over:
            code = 0
        if self.fault == "code124_timeout" and code in (124, 137, 143):
            return {"ok": False, "code": "timeout", "outcome": "completed"}
        if self.fault == "utf8_replace":
            kept = [item.decode("utf-8", "replace").encode() for item in kept]
        return {
            "ok": True,
            "stdout": kept[0],
            "stderr": kept[1],
            "exit_code": code,
            "stdout_truncated": flags[0],
            "stderr_truncated": flags[1],
        }


# Rows run as real local processes. (case, fault, expected result). None is a pass; a string is
# the Differs reason (or a set). None of them judges a TERM or KILL time against a margin.
MATRIX: list[tuple[str, str | None, str | set[str | None] | None]] = [
    ("bytes_and_exit_codes", None, None),
    ("bytes_and_exit_codes", "utf8_replace", "output_bytes_not_exact"),
    ("bytes_and_exit_codes", "code124_timeout", "ordinary_exit_reported_as_error"),
    ("execution_term", "no_term", "term_not_delivered"),
    ("group_kill", "no_term", "term_not_delivered"),
    ("background_survives", None, None),
    (
        "background_survives",
        "eof_wait",
        {"output_waited_for_descendant_eof", "completed_output_not_final"},
    ),
    ("background_survives", "background_killed", "background_work_did_not_survive_foreground_exit"),
    ("output_limit", None, None),
    ("output_limit", "overflow_error", "output_over_the_limit_returned_as_error"),
    ("output_limit", "overflow_no_flags", "truncation_flag_wrong"),
    ("output_limit", "overflow_whole_output", "output_prefix_not_exact"),
    ("output_limit", "overflow_drops_output", "output_prefix_not_exact"),
    ("output_limit", "overflow_lost_status", "exit_status_not_returned_with_truncated_output"),
    ("output_limit", "exact_flagged", "output_within_the_limit_marked_truncated"),
    ("output_limit", "overflow_kills", "completion_claimed_before_command_finished"),
    ("output_limit", "overflow_replay", "output_limit_replayed_the_command"),
    ("output_limit", "overflow_early_complete", "completion_claimed_before_command_finished"),
]


def _outcome(case: str, fault: str | None, root: Path) -> str | None:
    guest = LocalGuest(fault)
    try:
        probe.run_case(guest, object(), {"case": case, "workdir_root": str(root)})
        return None
    except Differs as error:
        return str(error)
    except NativeFailure as error:
        return f"unproven:{error.code}"
    finally:
        guest.reap()


@pytest.fixture(scope="module")
def matrix_results(tmp_path_factory: pytest.TempPathFactory) -> dict[tuple[str, str | None], Any]:
    root = tmp_path_factory.mktemp("hb")
    with ThreadPoolExecutor(max_workers=MAX_HOST_WORKERS) as pool:
        futures = {
            (case, fault): pool.submit(_outcome, case, fault, root) for case, fault, _ in MATRIX
        }
        return {key: future.result(timeout=120) for key, future in futures.items()}


@pytest.mark.parametrize(("case", "fault", "expected"), MATRIX)
def test_diagnostic_controls_report_each_fault_with_real_local_processes(
    matrix_results: dict[tuple[str, str | None], Any],
    case: str,
    fault: str | None,
    expected: str | set[str] | None,
) -> None:
    observed = matrix_results[(case, fault)]
    if isinstance(expected, set):
        assert observed in expected
    else:
        assert observed == expected


# -- Generated guest programs, executed for real in owned local sessions --------------------------


@contextlib.contextmanager
def _owned(argv: list[str], **kwargs: Any) -> Iterator[subprocess.Popen[bytes]]:
    """Run one program in its own session; its group is killed and the leader reaped on exit."""
    process = cast(
        "subprocess.Popen[bytes]", subprocess.Popen(argv, start_new_session=True, **kwargs)
    )
    try:
        yield process
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=10)


def _lines(path: Path) -> list[str]:
    return path.read_text().split() if path.exists() else []


def _until(predicate: Callable[[], bool], seconds: float = 10.0) -> bool:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.05)
    return predicate()


def test_term_leader_stamps_start_heartbeats_and_term(tmp_path: Path) -> None:
    argv = probe._script(probe._TERM_LEADER, str(tmp_path), "0.05")
    with _owned(argv) as process:
        assert _until(lambda: len(_lines(tmp_path / "hb")) >= 3)
        os.killpg(process.pid, signal.SIGTERM)
        assert process.wait(timeout=10) == 0
    start, term = float(_lines(tmp_path / "S")[0]), float(_lines(tmp_path / "T")[0])
    beats = [float(item) for item in _lines(tmp_path / "hb")]
    assert start <= beats[0] < beats[-1] <= term
    assert len(_lines(tmp_path / "pid.leader")) == 2


def test_group_leader_exits_on_term_while_its_child_ignores_term(tmp_path: Path) -> None:
    argv = probe._script(probe._GROUP_LEADER, str(tmp_path), "0.05", probe._GROUP_CHILD)
    with _owned(argv) as process:
        assert _until(lambda: len(_lines(tmp_path / "hb")) >= 3)
        os.killpg(process.pid, signal.SIGTERM)
        assert process.wait(timeout=10) == 0
        seen = len(_lines(tmp_path / "hb"))
        assert _until(lambda: len(_lines(tmp_path / "hb")) > seen + 2)
        assert (tmp_path / "T").exists() and len(_lines(tmp_path / "pid.child")) == 2
        os.killpg(process.pid, signal.SIGKILL)
        assert _until(lambda: not _group_has_members(process.pid))


def _group_has_members(group: int) -> bool:
    try:
        os.killpg(group, 0)
    except ProcessLookupError:
        return False
    return True


def test_background_program_prints_exact_text_and_leaves_a_late_writer(tmp_path: Path) -> None:
    argv = probe._script(probe._BACKGROUND, str(tmp_path), "1.0", probe._LATE_CHILD)
    with _owned(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
        assert process.stdout is not None
        assert process.stdout.read(3) == b"fg\n"
        assert process.wait(timeout=10) == 0
        assert not (tmp_path / "B").exists()
        assert process.stdout.read() == b"late"
        assert (tmp_path / "B").exists()


def test_output_program_counts_one_run_writes_the_patterns_and_marks_completion(
    tmp_path: Path,
) -> None:
    argv = probe._script(probe._OUTPUT, str(tmp_path), "65", "70", "5")
    with _owned(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
        out, err = process.communicate(timeout=20)
        assert process.returncode == 5
    assert out == probe._output_pattern(1, 65) and err == probe._output_pattern(2, 70)
    assert out[:8] != err[:8]
    assert _lines(tmp_path / "C") == ["x"] and (tmp_path / "D").exists()


def test_witness_program_reports_identity_and_valid_stamps(tmp_path: Path) -> None:
    group = probe._script(probe._GROUP_LEADER, str(tmp_path), "0.05", probe._GROUP_CHILD)
    with _owned(group):
        assert _until(lambda: len(_lines(tmp_path / "hb")) >= 3)
        witness = probe._script(probe._WITNESS, str(tmp_path), "0.3")
        done = subprocess.run(witness, capture_output=True, check=True, timeout=20)
        document = json.loads(done.stdout)
    assert document["proc"] is True and document["hb_ok"] is True
    assert document["leader_alive"] is True and document["child_alive"] is True
    assert document["hbn2"] > document["hbn"] and document["S"] <= document["hb"] <= document["now"]


# -- Pure decisions on a fake clock -------------------------------------------------------------


@pytest.mark.parametrize(
    ("gap", "verdict"),
    [
        (0.0, "early"),
        (4.0, "early"),
        (4.86, "early"),
        (4.879999, "early"),
        (math.nextafter(4.88, 0.0), "ambiguous"),
        (4.88, "ambiguous"),
        (math.nextafter(4.88, 9.0), "ambiguous"),
        (4.880001, "ambiguous"),
        (4.9, "ambiguous"),
        (4.999999, "ambiguous"),
        (4.99, "ambiguous"),
        (5.0, None),
        (math.nextafter(5.0, 0.0), None),
        (5.5, None),
        (math.nextafter(5.5, 9.0), None),
        (5.500001, "late"),
        (5.51, "late"),
        (5.8, "late"),
        (7.5, "late"),
        (8.0, "late"),
    ],
)
def test_kill_gap_is_judged_only_where_its_whole_interval_is_on_one_side(
    gap: float, verdict: str | None
) -> None:
    """A KILL at 4.99, 5.8 or 7.5 seconds is never certified as the five-second KILL."""
    assert probe.judge_kill_gap(gap) == verdict


def test_an_exact_five_second_kill_is_never_a_defect_and_is_unproven_below_the_grace() -> None:
    """Gaps a correct 5.0 s KILL can produce straddle the grace: ambiguous or pass, never early."""
    verdicts = {probe.judge_kill_gap(gap) for gap in (4.97, 4.98, 4.99, 5.0, 5.01)}
    assert verdicts == {"ambiguous", None}


@pytest.mark.parametrize("gap", [float("nan"), float("inf")])
def test_non_finite_kill_gap_is_unproven(gap: float) -> None:
    with pytest.raises(NativeFailure, match="kill_gap_not_finite"):
        probe.judge_kill_gap(gap)


class FakeClock:
    """Host clock; an `idle` answer moves it just before the next exchange is sent."""

    def __init__(self) -> None:
        self.time, self.idle, self.countdown = 100.0, 0.0, 0

    def now(self) -> float:
        if self.countdown:
            self.countdown -= 1
            if not self.countdown:
                self.time, self.idle = self.time + self.idle, 0.0
        return self.time


class ScriptedGuest(Driver):
    """Answers the transport hook from a script; `elapsed` advances the fake host clock."""

    def __init__(self, answers: list[Mapping[str, Any]], clock: FakeClock) -> None:
        super().__init__()
        self.answers, self.clock = answers, clock

    def http_buffered_run(self, target: object, inputs: Mapping[str, Any]) -> Mapping[str, Any]:
        del target, inputs
        answer = dict(self.answers.pop(0))
        self.clock.time += answer.pop("elapsed", 0.0)
        if idle := answer.pop("idle", 0.0):
            self.clock.idle, self.clock.countdown = idle, 2
        return answer


def _scripted(monkeypatch: pytest.MonkeyPatch, answers: list[Mapping[str, Any]]) -> ScriptedGuest:
    clock = FakeClock()
    monkeypatch.setattr(probe, "_now", clock.now)
    monkeypatch.setattr(
        probe, "_pause", lambda seconds: setattr(clock, "time", clock.time + seconds)
    )
    return ScriptedGuest(answers, clock)


# -- Timing rows on a virtual clock --------------------------------------------------------------

STARTUP_S = 0.04
"""Dispatch to the workload's start stamp."""
HANDLER_S = 0.004
"""Signal to the handler's TERM stamp."""
BEAT_LAG_S = 0.01
"""Last heartbeat before the end of a process: half a heartbeat interval."""
WITNESS_START_S = 0.03
"""Witness dispatch to its guest sample."""
WITNESS_EXIT_S = 0.01
"""End of the witness' progress window to its reply."""
DEFAULT_KILL_AFTER_S = 5.15
KILL_AFTER = {"early_kill": 4.0, "kill_5_0": 5.0, "kill_4_9": 4.9, "kill_5_8": 5.8, "kill_7_5": 7.5}
TERM_OFFSET = {
    "early_term": -1.5,
    "term_minus_0_35": -0.35,
    "term_plus_2": 2.0,
    "exact_dispatch": -TIMER_LAG_S,
}


@dataclass(frozen=True)
class _Timeline:
    """When each event of one workload happens, in host-clock seconds."""

    kind: str  # "term" (one heartbeating leader) or "group" (leader plus a TERM-ignoring child)
    start: float
    stamp: float | None
    leader_end: float | None
    beater_start: float
    beater_end: float | None

    def beat(self, at: float) -> tuple[float | None, int]:
        """Last heartbeat at or before `at`, and how many were written by then."""
        last = at if self.beater_end is None else min(at, self.beater_end)
        last -= BEAT_LAG_S
        if last < self.beater_start:
            return None, 0
        return last, int((last - self.beater_start) / probe.HEARTBEAT_S) + 1


class TimelineGuest(Driver):
    """The local guest's behaviour on a virtual clock, so every stamp is exact and repeatable.

    It answers the transport hook with the documents the generated programs produce: the same
    fields, derived from a timeline that is a pure function of the dispatch time and the fault.
    The probe's own code (`group_kill`, `execution_term`, `check_term_time`, `judge_kill_gap`)
    runs unchanged. The programs themselves run for real in the tests above; only their timing
    is modelled here, because real timing under host load is not bounded by the stated margins.
    """

    def __init__(self, fault: str | None, clock: FakeClock) -> None:
        super().__init__()
        self.fault, self.clock = fault, clock
        self.runs: dict[str, _Timeline] = {}

    def http_buffered_run(self, target: object, inputs: Mapping[str, Any]) -> Mapping[str, Any]:
        del target
        argv = inputs["argv"]
        if argv[2] is probe._WITNESS:
            return self._witness(argv[3], float(argv[4]))
        kinds = {probe._TERM_LEADER: "term", probe._GROUP_LEADER: "group"}
        return self._workload(
            kinds[argv[2]],
            argv[3],
            inputs["execution_limit_ms"] / 1000,
            inputs["observation_timeout_ms"] / 1000,
        )

    def _workload(
        self, kind: str, directory: str, limit: float, observed: float
    ) -> Mapping[str, Any]:
        fault, dispatch = self.fault, self.clock.time
        start = dispatch + STARTUP_S
        term = None if fault == "no_term" else dispatch + limit + TIMER_LAG_S
        if term is not None:
            term += TERM_OFFSET.get(fault or "", 0.0)
        stamp = None if term is None else term + HANDLER_S
        kill: float | None = None
        if term is not None and kind == "group":
            if fault == "immediate_kill":
                kill, stamp = term + 0.001, None
            elif fault not in ("never_kill", "cancel_on_leader_exit"):
                kill = term + KILL_AFTER.get(fault or "", DEFAULT_KILL_AFTER_S)
        stopped = dispatch + observed if fault == "o_kills" else None
        ends = [moment for moment in (stamp, kill, stopped) if moment is not None]
        leader_end = min(ends) if ends else None
        if kind == "term":
            beater_start, beater_end = start, leader_end
        else:
            ends = [moment for moment in (kill, stopped) if moment is not None]
            beater_start, beater_end = start + 0.01, min(ends) if ends else None
        self.runs[directory] = _Timeline(kind, start, stamp, leader_end, beater_start, beater_end)
        if fault == "no_term":
            settle = dispatch + limit + TIMER_LAG_S
        elif kind == "term":
            settle = cast("float", stamp)
        elif kill is not None:
            settle = kill
        else:
            settle = cast("float", term) + (2.3 if fault == "never_kill" else 7.15)
        if settle - dispatch > observed:
            self.clock.time = dispatch + observed
            return {"ok": False, "code": "timeout", "outcome": "unknown"}
        self.clock.time = settle
        return {"ok": False, "code": "timeout", "outcome": "completed"}

    def _witness(self, directory: str, gap: float) -> Mapping[str, Any]:
        run, sent = self.runs[directory], self.clock.time
        sample = sent + WITNESS_START_S
        beat, count = run.beat(sample)
        _, later = run.beat(sample + gap)

        def alive(end: float | None, at: float) -> bool:
            return end is None or at < end

        document: dict[str, Any] = {
            "proc": True, "now": sample, "S": run.start, "T": None, "hb": beat, "hb_ok": True,
            "hbn": count, "hbn2": later, "B": None, "C": None, "D": None,
            "leader_alive": alive(run.leader_end, sample + gap),
            "child_alive": (
                alive(run.beater_end, sample + gap) if run.kind == "group" else None
            ),
        }  # fmt: skip
        if run.stamp is not None and run.stamp <= sample:
            document["T"] = run.stamp
        self.clock.time = sample + gap + WITNESS_EXIT_S
        return {
            "ok": True,
            "stdout": json.dumps(document).encode(),
            "stderr": b"",
            "exit_code": 0,
            "stdout_truncated": False,
            "stderr_truncated": False,
        }


CROSSES = "unproven:http_buffered_unproven_term_time_crosses_execution_limit"
AMBIGUOUS = "unproven:http_buffered_unproven_kill_time_ambiguous"
LATE = "unproven:http_buffered_unproven_kill_time_late"

# (case, fault, expected result): the timing rows, each exact because the clock is virtual.
TIMELINE_MATRIX: list[tuple[str, str | None, str | None]] = [
    ("execution_term", None, None),
    ("execution_term", "no_term", "term_not_delivered"),
    ("execution_term", "early_term", "term_before_execution_limit"),
    ("execution_term", "term_minus_0_35", CROSSES),
    (
        "execution_term",
        "term_plus_2",
        "unproven:http_buffered_unproven_term_time_exceeds_measurement_resolution",
    ),
    ("execution_term", "exact_dispatch", CROSSES),
    ("group_kill", None, None),
    ("group_kill", "early_kill", "kill_before_grace"),
    ("group_kill", "exact_dispatch", CROSSES),
    ("group_kill", "kill_5_0", AMBIGUOUS),
    ("group_kill", "kill_4_9", AMBIGUOUS),
    ("group_kill", "kill_5_8", LATE),
    ("group_kill", "kill_7_5", LATE),
    ("group_kill", "immediate_kill", "term_not_delivered"),
    ("group_kill", "never_kill", "kill_missing_after_leader_exit"),
    ("group_kill", "cancel_on_leader_exit", "kill_missing_after_leader_exit"),
    ("observation_versus_execution", None, None),
    ("observation_versus_execution", "o_kills", "observation_expiry_stopped_the_command"),
    (
        "observation_versus_execution",
        "no_term",
        "execution_limit_never_fired_after_observation_expiry",
    ),
]


@pytest.mark.parametrize(("case", "fault", "expected"), TIMELINE_MATRIX)
def test_timing_controls_report_each_fault_and_the_late_timer_positive_control(
    monkeypatch: pytest.MonkeyPatch, case: str, fault: str | None, expected: str | None
) -> None:
    """Exact on every run: no wall clock, thread, process or file is involved."""
    clock = FakeClock()
    monkeypatch.setattr(probe, "_now", clock.now)
    monkeypatch.setattr(
        probe, "_pause", lambda seconds: setattr(clock, "time", clock.time + seconds)
    )
    guest = TimelineGuest(fault, clock)
    try:
        probe.run_case(guest, object(), {"case": case, "workdir_root": "/virtual"})
        observed = None
    except Differs as error:
        observed = str(error)
    except NativeFailure as error:
        observed = f"unproven:{error.code}"
    assert observed == expected


def _witness_answer(now: float, **fields: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "proc": True, "now": now, "S": 99.8, "T": 102.0, "hb": 107.0, "hb_ok": True,
        "hbn": 60, "hbn2": 60, "leader_alive": False, "child_alive": False,
    }  # fmt: skip
    document.update(fields)
    return {
        "ok": True,
        "stdout": json.dumps(document).encode(),
        "stderr": b"",
        "exit_code": 0,
        "stdout_truncated": False,
        "stderr_truncated": False,
    }


def _expiry(outcome: str, elapsed: float, idle: float = 0.0) -> dict[str, Any]:
    return {"ok": False, "code": "timeout", "outcome": outcome, "elapsed": elapsed, "idle": idle}


def test_term_one_second_into_a_two_second_limit_is_early() -> None:
    """Regression: an earlier helper accepted TERM at 1 s for E=2 s inside a 1 s tolerance."""
    early = {"now": 102.0, "S": 100.0, "T": 101.0, "hb": 101.0, "hb_ok": True}
    with pytest.raises(Differs, match="term_before_execution_limit"):
        probe.check_term_time(probe.Witness(early, 101.95, 102.05), 100.0, 2000)
    on_time = {**early, "now": 103.3, "T": 102.3, "hb": 102.3}
    measured = probe.check_term_time(probe.Witness(on_time, 103.25, 103.35), 100.0, 2000)
    assert 2.2 < measured["term_after_send_min"] <= measured["term_after_send_max"] < 2.4


def test_term_interval_that_crosses_the_required_time_is_unproven() -> None:
    """Regression: an interval 1.3..2.1 s around a 2 s requirement used to be accepted."""
    crossing = {"now": 120.0, "S": 100.0, "T": 101.3, "hb": 101.2, "hb_ok": True}
    witness = probe.Witness(crossing, 120.0, 120.8)
    assert witness.host_interval(1 + 100.3) == pytest.approx((101.3, 102.1))
    with pytest.raises(NativeFailure, match="term_time_crosses_execution_limit"):
        probe.check_term_time(witness, 100.0, 2000)


def test_term_after_a_possibly_delayed_dispatch_is_unproven_not_passed() -> None:
    """Regression (SPS 0.3.119 false pass): dispatch may follow the send by up to S - send.

    S=100.5, T=102.1, send=100, E=2: native dispatch at 100.5 requires TERM at 102.5, so a TERM
    at 102.1 can be 0.4 s early. The send time only bounds dispatch from below, so it can prove
    TERM early but never on time.
    """
    document = {"now": 103.0, "S": 100.5, "T": 102.1, "hb": 102.1, "hb_ok": True}
    witness = probe.Witness(document, 102.99, 103.01)
    with pytest.raises(NativeFailure, match="term_time_crosses_execution_limit"):
        probe.check_term_time(witness, 100.0, 2000)


@pytest.mark.parametrize(
    ("after_start", "passes"),
    [(1.9, False), (2.0, False), (2.05, False), (2.099, False), (2.101, True), (2.5, True)],
)
def test_term_is_not_early_only_when_the_handler_margin_is_also_covered(
    after_start: float, passes: bool
) -> None:
    """T - S = E + 0.05 with a 0.1 s margin must not pass: the signal may precede its stamp."""
    document = {"now": 103.0, "S": 100.0, "T": 100.0 + after_start, "hb": 100.0, "hb_ok": True}
    witness = probe.Witness(document, 103.0, 103.02)
    if passes:
        assert probe.check_term_time(witness, 100.0, 2000)["term_after_start"] == pytest.approx(
            after_start
        )
    else:
        with pytest.raises((NativeFailure, Differs)):
            probe.check_term_time(witness, 100.0, 2000)


def test_exact_e_endpoint_is_unproven_by_design() -> None:
    """TERM exactly E after dispatch, dispatch 30 ms before S, 5 ms handler: not provable."""
    document = {"now": 103.0, "S": 100.03, "T": 102.005, "hb": 102.0, "hb_ok": True}
    with pytest.raises(NativeFailure, match="term_time_crosses_execution_limit"):
        probe.check_term_time(probe.Witness(document, 102.99, 103.01), 100.0, 2000)


def _term_witness(term: float, received: float, start: float = 100.0) -> probe.Witness:
    """A witness whose guest sample is the TERM stamp itself, so the host interval ends at
    `received`. Every number is exact in binary, so the comparisons below are exact."""
    document = {"now": term, "S": start, "T": term, "hb": term, "hb_ok": True}
    return probe.Witness(document, received - 0.015625, received)


_STEP = 2.0**-20


@pytest.mark.parametrize(
    ("received", "verdict"),
    [
        (102.0 - _STEP, "term_before_execution_limit"),
        (102.0, None),
        (103.0, None),
        (103.0 + _STEP, "term_time_exceeds_measurement_resolution"),
    ],
)
def test_term_host_interval_boundaries_are_exact(received: float, verdict: str | None) -> None:
    """Send 100 s, E = 2 s: the latest TERM time is early below 102 s and past resolution above
    103 s; both ends themselves are judged, so a stalled but correct guest is never a defect."""
    witness = _term_witness(102.5, received)
    if verdict is None:
        assert probe.check_term_time(witness, 100.0, 2000)
    elif verdict.startswith("term_before"):
        with pytest.raises(Differs, match=verdict):
            probe.check_term_time(witness, 100.0, 2000)
    else:
        with pytest.raises(NativeFailure, match=verdict):
            probe.check_term_time(witness, 100.0, 2000)


@pytest.mark.parametrize("gap", [4.4 + 0.48, 4.7 + 0.18, 5.1 - 0.22, 4.88 + 0.0])
def test_boundary_gaps_built_by_float_arithmetic_are_ambiguous_as_on_paper(gap: float) -> None:
    """Sums and differences that equal 4.88 on paper differ from it in the last bit; the verdict
    must not (4.88 + 0.02 + 0.1 is 4.999999999999999 in floating point)."""
    assert probe.judge_kill_gap(gap) == "ambiguous"


@pytest.mark.parametrize(
    ("elapsed", "outcome"),
    [(3.999999, "ok"), (4.0, "slow"), (4.999999, "slow"), (5.0, "waited")],
)
def test_foreground_result_time_boundaries_are_exact(
    monkeypatch: pytest.MonkeyPatch, elapsed: float, outcome: str
) -> None:
    done = {
        "ok": True, "stdout": b"fg\n", "stderr": b"", "exit_code": 0,
        "stdout_truncated": False, "stderr_truncated": False, "elapsed": elapsed,
    }  # fmt: skip
    guest = _scripted(monkeypatch, [done, _witness_answer(110.0, B=0)])
    if outcome == "ok":
        probe.background_survives(guest, object(), {})
        return
    expected = "result_too_slow" if outcome == "slow" else "output_waited"
    with pytest.raises((Differs, NativeFailure), match=expected):
        probe.background_survives(guest, object(), {})


@pytest.mark.parametrize(
    ("term", "proven"),
    [(102.099999, False), (math.nextafter(102.1, 0.0), True), (102.1, True), (102.100001, True)],
)
def test_term_is_proven_not_early_exactly_at_the_handler_margin(term: float, proven: bool) -> None:
    """S = 100.0, E = 2 s, margin 0.1 s: T = 102.1 gives T - margin - S == E, the first TERM that
    is provably not early whatever the float rounding of the subtraction; a microsecond less is
    unproven."""
    assert probe.HANDLER_MARGIN_S == 0.1
    witness = _term_witness(term, 102.5)
    if proven:
        assert probe.check_term_time(witness, 100.0, 2000)
    else:
        with pytest.raises(NativeFailure, match="term_time_crosses_execution_limit"):
            probe.check_term_time(witness, 100.0, 2000)


def test_term_long_after_the_limit_and_a_wide_bracket_are_unproven() -> None:
    late = {"now": 110.0, "S": 100.0, "T": 108.0, "hb": 108.0, "hb_ok": True}
    with pytest.raises(NativeFailure, match="term_time_exceeds_measurement_resolution"):
        probe.check_term_time(probe.Witness(late, 109.95, 110.05), 100.0, 2000)
    with pytest.raises(NativeFailure, match="clock_bracket_too_wide"):
        probe.check_term_time(probe.Witness(late, 108.0, 110.0), 100.0, 2000)


def test_kill_after_seven_and_a_half_seconds_is_unproven_through_the_case(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: an earlier helper accepted a KILL 7.5 s after TERM as the five-second KILL."""
    guest = _scripted(monkeypatch, [_expiry("completed", 9.5), _witness_answer(109.5, hb=109.5)])
    with pytest.raises(NativeFailure, match="kill_time_late"):
        probe.group_kill(guest, object(), {})


def test_five_second_kill_gap_passes_through_the_case(monkeypatch: pytest.MonkeyPatch) -> None:
    guest = _scripted(monkeypatch, [_expiry("completed", 7.0), _witness_answer(107.0)])
    probe.group_kill(guest, object(), {})


def test_non_finite_stamp_in_a_witness_is_unproven(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression: a NaN stamp in the witness document used to compare as no defect."""
    raw = _witness_answer(107.0)
    raw["stdout"] = raw["stdout"].replace(b"107.0", b"NaN", 1)
    guest = _scripted(monkeypatch, [_expiry("completed", 7.0), raw])
    with pytest.raises(NativeFailure, match="not_finite"):
        probe.group_kill(guest, object(), {})


def test_execution_term_without_heartbeats_is_unproven(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression: S and T present with no heartbeat at all used to pass."""
    missing = _witness_answer(103.1, hb=None, hbn=0, hbn2=0, T=103.05)
    guest = _scripted(monkeypatch, [_expiry("completed", 3.1), missing])
    with pytest.raises(NativeFailure, match="workload_stamps_missing"):
        probe.execution_term(guest, object(), {})


def test_execution_term_needs_the_leader_observed_dead(monkeypatch: pytest.MonkeyPatch) -> None:
    kwargs = {"S": 99.9, "T": 103.05, "hb": 103.05}
    for leader, expected in ((True, "leader_alive_without_progress"), (None, "leader_identity")):
        witness = _witness_answer(103.1, leader_alive=leader, **kwargs)
        guest = _scripted(monkeypatch, [_expiry("completed", 3.1), witness])
        with pytest.raises(NativeFailure, match=expected):
            probe.execution_term(guest, object(), {})
    dead = _witness_answer(103.1, leader_alive=False, **kwargs)
    probe.execution_term(_scripted(monkeypatch, [_expiry("completed", 3.1), dead]), object(), {})


def test_group_kill_requires_term_timing_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    """The group case judges TERM time too: TERM at 1 s of a 2 s limit fails it."""
    early = _witness_answer(109.0, T=101.0, hb=106.0)
    guest = _scripted(monkeypatch, [_expiry("completed", 9.0), early])
    with pytest.raises(Differs, match="term_before_execution_limit"):
        probe.group_kill(guest, object(), {})


def test_unknown_outcome_waits_for_the_scheduled_kill_before_judging(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    polls = [
        _witness_answer(102.6 + 0.5 * n, child_alive=True, hbn2=61, T=102.0, hb=102.5)
        for n in range(10)
    ]
    guest = _scripted(monkeypatch, [_expiry("unknown", 2.6), *polls, _witness_answer(107.6)])
    probe.group_kill(guest, object(), {})
    assert not guest.answers


def test_unknown_outcome_with_a_child_that_never_dies_fails_after_the_bounded_wait(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    polls = [
        _witness_answer(102.6 + 0.5 * n, child_alive=True, hbn2=61, T=102.0, hb=102.5)
        for n in range(60)
    ]
    guest = _scripted(monkeypatch, [_expiry("unknown", 2.6), *polls])
    with pytest.raises(Differs, match="kill_missing_after_leader_exit"):
        probe.group_kill(guest, object(), {})
    assert guest.answers, "the wait is bounded, not exhaustive"


def test_completed_before_the_kill_is_a_defect(monkeypatch: pytest.MonkeyPatch) -> None:
    guest = _scripted(monkeypatch, [_expiry("completed", 4.0, idle=3.0), _witness_answer(107.0)])
    with pytest.raises(Differs, match="completion_claimed_before_kill_settled"):
        probe.group_kill(guest, object(), {})
    alive = _witness_answer(107.0, child_alive=True)
    guest = _scripted(monkeypatch, [_expiry("completed", 4.0, idle=3.0), alive])
    with pytest.raises(Differs, match="kill_missing_after_leader_exit"):
        probe.group_kill(guest, object(), {})


def test_guest_without_process_identity_is_unproven_not_passing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guest = _scripted(monkeypatch, [_expiry("completed", 7.0), _witness_answer(107.0, proc=False)])
    with pytest.raises(NativeFailure, match="process_identity_unobservable"):
        probe.group_kill(guest, object(), {})


def test_unusable_witness_is_unproven_not_passing(monkeypatch: pytest.MonkeyPatch) -> None:
    unusable = {"ok": False, "code": "timeout", "outcome": "unknown"}
    guest = _scripted(monkeypatch, [_expiry("completed", 3.1), unusable])
    with pytest.raises(NativeFailure, match="witness_unavailable"):
        probe.execution_term(guest, object(), {})


@pytest.mark.parametrize(
    ("elapsed", "expected"),
    [(0.5, None), (4.5, "result_too_slow_to_exclude_descendant_wait"), (5.2, "output_waited")],
)
def test_foreground_result_time_is_judged_against_the_descendant_delay(
    monkeypatch: pytest.MonkeyPatch, elapsed: float, expected: str | None
) -> None:
    done = {
        "ok": True,
        "stdout": b"fg\n",
        "stderr": b"",
        "exit_code": 0,
        "stdout_truncated": False,
        "stderr_truncated": False,
        "elapsed": elapsed,
    }
    guest = _scripted(monkeypatch, [done, _witness_answer(110.0, B=0)])
    if expected is None:
        probe.background_survives(guest, object(), {})
    else:
        with pytest.raises((Differs, NativeFailure), match=expected):
            probe.background_survives(guest, object(), {})


def test_missing_transport_hook_is_not_run_never_unsupported() -> None:
    with pytest.raises(NotRun, match="driver_unimplemented"):
        probe.run_case(Driver(), object(), {"case": "output_limit"})
    with pytest.raises(NotRun, match="http_buffered_case_unknown"):
        probe.run_case(Driver(), object(), {"case": "invented"})


# -- Suite, digest and report acceptance on the actual candidate files ---------------------------


def _coverage() -> Any:
    return read_suite(suite_path().with_name("coverage.yaml"))


def test_rows_are_focused_diagnostics_outside_the_baseline() -> None:
    suite = _coverage()
    rows = [test for test in suite.tests if test.id.startswith("http.buffered.")]
    assert [test.id for test in rows] == CASE_IDS
    assert not set(CASE_IDS) & set(suite.baseline_ids)
    for row in rows:
        assert row.rules == () and row.proves == ()
        assert [step["op"] for step in row.steps] == ["create", "http.buffered"]
        assert "coverage_http_buffered.py" in dependencies_of(row)


def test_check_digest_follows_the_case_module_source() -> None:
    row = next(test for test in _coverage().tests if test.id == CASE_IDS[0])
    assert "coverage_http_buffered.py" in dependencies_of(row)


class _Passing(Driver):
    provider = "synthetic-offline"
    execution_class = None
    sdk_versions = {"synthetic-offline": "0"}

    def create(self, target: object, inputs: Mapping[str, Any]) -> Mapping[str, object]:
        del target, inputs
        return {"resource": self.own("sandbox", {}, lambda: {"result": "deleted"})}

    def http_buffered(self, target: object, inputs: Mapping[str, Any]) -> Mapping[str, object]:
        del target, inputs
        return {"verified": True}


def _selected() -> Any:
    suite = _coverage()
    return type(suite)(
        suite.digest, tuple(t for t in suite.tests if t.id in CASE_IDS), suite.baseline_ids
    )


def _document(driver: Driver) -> dict[str, Any]:
    suite = _selected()
    rows = Runner(driver).run(suite)
    return dict(
        report(
            driver,
            suite,
            rows,
            spec_revision="a" * 40,
            started_at="2026-10-26T00:00:00Z",
        )
    )


def test_synthetic_report_over_candidate_files_is_recognized_and_baseline_stays_not_run() -> None:
    """SYNTHETIC: a fake driver answers verified; this shows the suite and digests are admitted."""
    document = _document(_Passing())
    assert document["baseline"] == "not_run"
    assert document["selected_tests"] == CASE_IDS
    assert [row["result"] for row in document["tests"]] == ["passed"] * len(CASE_IDS)
    assert check_report(document).errors == []
    assert check_report_evidence(document) == []


def test_development_revision_report_is_never_evidence() -> None:
    """A consumer's local development run records the null revision; SPS refuses to cite it."""
    document = _document(_Passing())
    development = {**document, "revision": DEVELOPMENT_REVISION}
    assert check_report(development).errors == [
        "report is a local development run (null source revision) and is not evidence"
    ]
    assert check_report_evidence(development) == [
        "report is a local development run (null source revision) and is not evidence"
    ]


def test_native_driver_without_the_operation_reports_not_run() -> None:
    class Native(_Passing):
        http_buffered = None  # type: ignore[assignment]

    document = _document(Native())
    assert {row["result"] for row in document["tests"]} == {"not_run"}
    assert {row["reason"] for row in document["tests"]} == {"driver_unimplemented"}
    assert document["baseline"] == "not_run"


def test_edited_row_digest_is_not_recognized_without_a_bypass() -> None:
    document = _document(_Passing())
    document["suite_digest"] = "sha256:" + "0" * 64
    assert "report suite digest is not recognized by this package" in check_report(document).errors


def test_archived_pre_buffered_suite_still_recognizes_old_reports() -> None:
    rules, errors = _source_suite_rules(PRE_BUFFERED_SUITE)
    assert not errors and rules is not None
    assert len(rules) == 99 and not any(name.startswith("http.buffered.") for name in rules)
    old = {
        "revision": "a" * 40,
        "suite_digest": PRE_BUFFERED_SUITE,
        "selected_tests": ["baseline.run_output"],
        "tests": [{"id": "baseline.run_output", "rules": ["baseline/run"], "result": "passed"}],
    }
    assert check_report_evidence(old) == []
    current, errors = _source_suite_rules(_coverage_digest())
    assert not errors and current is not None
    assert set(CASE_IDS) <= set(current) and current["baseline.run_output"] == ["baseline/run"]


def _coverage_digest() -> str:
    base = suite_path().read_bytes()
    extra = suite_path().with_name("coverage.yaml").read_bytes()
    joined = b"suite.yaml\0" + base + b"\0coverage.yaml\0" + extra + b"\0"
    return "sha256:" + hashlib.sha256(joined).hexdigest()
