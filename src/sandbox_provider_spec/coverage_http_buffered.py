# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Diagnostics for the HTTP binding's `buffered_commands_v1` command semantics.

Each case runs finite workloads through the driver's `http.buffered_run` transport and judges
only what a caller can see: the typed response, host-side timing and later witnesses read by
further buffered commands. Nothing inspects the endpoint or its backend.

Timing is never read from a tolerance on one clock. Guest stamps use the guest's monotonic clock;
each witness command reports one guest sample taken between the host's send and receive times,
which brackets every guest stamp on the host clock:

    host(stamp) in [sent - (sample - stamp), received - (sample - stamp)]

A TERM is proven early only if its latest possible host time precedes the host's send plus the
limit (dispatch cannot precede the send). It is proven not early only against the guest's own
start stamp (dispatch cannot follow it), allowing for handler latency; see `check_term_time`.
A witness whose bracket is wider than
`MAX_BRACKET_S` proves nothing and is reported as unproven. The bracket spans the guest's own
`_SAMPLE_GAP_S` progress-sampling window, so it is about that wide plus one round trip; a
tighter bracket would need a separate no-wait witness for timing.

Limits, stated rather than widened:

- A signal time is judged only where its whole measured interval lies on one side of the
  required time. An interval that crosses it is unproven, never a pass and never a defect. A
  signal later than the stated resolution (`TERM_RESOLUTION_S`, `KILL_RESOLUTION_S`) is also
  unproven: the binding sets no upper bound, and these cases do not certify one.
- Heartbeats are sampled every `HEARTBEAT_S` and a guest handler stamps within
  `HANDLER_MARGIN_S` of its signal; these are stated assumptions about the guest's own
  scheduling. A fast endpoint whose dispatch is not later than the witness bracket is unproven,
  because its TERM cannot then be placed after the limit.
- A guest without `/proc`, a stopped or reused process id, or a malformed, non-finite or
  non-monotonic stamp is unproven, never a pass.
- Escaped process groups, transport disconnect and a lost reply are outside these cases.
"""

from __future__ import annotations

import json
import math
import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from sandbox_provider_spec.driver import Differs, Driver, NativeFailure, NotRun

KILL_GRACE_S = 5.0
"""Binding rule: KILL follows TERM by five seconds for the original process group."""
HEARTBEAT_S = 0.02
HANDLER_MARGIN_S = 0.1
"""Latency between a signal and the guest handler's stamp that may undercut the grace."""
TERM_RESOLUTION_S = 1.0
KILL_RESOLUTION_S = 0.5
MAX_BRACKET_S = 1.0
BACKGROUND_DELAY_S = 5.0
SETTLE_WINDOW_S = 8.0
_WITNESS_LIMIT_MS = 15000
_SAMPLE_GAP_S = 0.1

_now: Callable[[], float] = time.monotonic


def _us(seconds: float) -> int:
    """Whole microseconds nearest to a finite number of seconds.

    Every limit and margin here is a whole number of milliseconds, but sums and differences of
    binary floats are not: `4.88 + 0.02 + 0.1 < 5.0` holds in floating point although the three
    add to exactly 5. A verdict that is ambiguous on paper must be ambiguous in code, so every
    comparison against a limit is made on integers. A microsecond is far below the resolution of
    the margins (0.02 s and up) and of the guest clocks' meaningful readings, so the rounding
    (at most half a microsecond) decides only values that sit on a boundary to within noise,
    where the answer is the boundary's own side: at the limit counts as at the limit.
    """
    return round(seconds * 1_000_000)


_pause: Callable[[float], None] = time.sleep

# Guest programs: python3 only, which the baseline already requires. Descendant programs are
# passed as arguments, so no program embeds another behind a second level of escaping.
_STAMP = r"""
import os, sys, time
D = sys.argv[1]
os.makedirs(D, exist_ok=True)
def put(name, text):
    with open(os.path.join(D, name), "a") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
def identity():
    pid = os.getpid()
    return "%d %s" % (pid, open("/proc/%d/stat" % pid).read().rsplit(")", 1)[1].split()[19])
"""
_TERM_LEADER = (
    _STAMP
    + r"""
import signal
beat = float(sys.argv[2])
put("pid.leader", identity())
put("S", repr(time.monotonic()) + "\n")
def term(*_):
    put("T", repr(time.monotonic()) + "\n")
    os._exit(0)
signal.signal(signal.SIGTERM, term)
while True:
    put("hb", repr(time.monotonic()) + "\n")
    time.sleep(beat)
"""
)
_GROUP_CHILD = (
    _STAMP
    + r"""
import signal
signal.signal(signal.SIGTERM, signal.SIG_IGN)
beat = float(sys.argv[2])
put("pid.child", identity())
while True:
    put("hb", repr(time.monotonic()) + "\n")
    time.sleep(beat)
"""
)
_GROUP_LEADER = (
    _STAMP
    + r"""
import signal, subprocess
put("pid.leader", identity())
put("S", repr(time.monotonic()) + "\n")
subprocess.Popen([sys.executable, "-c", sys.argv[3], D, sys.argv[2]])
def term(*_):
    put("T", repr(time.monotonic()) + "\n")
    os._exit(0)
signal.signal(signal.SIGTERM, term)
while True:
    time.sleep(0.05)
"""
)
_LATE_CHILD = r"""
import os, sys, time
time.sleep(float(sys.argv[2]))
os.write(1, b"late")
os.write(2, b"late")
open(os.path.join(sys.argv[1], "B"), "w").close()
"""
_BACKGROUND = r"""
import os, subprocess, sys
D = sys.argv[1]
os.makedirs(D, exist_ok=True)
subprocess.Popen([sys.executable, "-c", sys.argv[3], D, sys.argv[2]])
sys.stdout.write("fg\n")
sys.stdout.flush()
"""
_OUTPUT = r"""
import os, sys, time
D = sys.argv[1]
os.makedirs(D, exist_ok=True)
open(os.path.join(D, "C"), "a").write("x\n")
for fd, size in ((1, int(sys.argv[2])), (2, int(sys.argv[3]))):
    os.write(fd, bytes(97 + (i * 7 + fd) % 26 for i in range(size)))
time.sleep(1.0)
open(os.path.join(D, "D"), "w").close()
sys.exit(int(sys.argv[4]))
"""
_WITNESS = r"""
import json, os, sys, time
D, gap = sys.argv[1], float(sys.argv[2])
out = {"proc": os.path.isdir("/proc/self")}
def read(name):
    try:
        return open(os.path.join(D, name)).read()
    except OSError:
        return None
def floats(name):
    raw = read(name)
    return [] if raw is None else [float(x) for x in raw.split()]
def alive(name):
    raw = read("pid." + name)
    if raw is None or not out["proc"]:
        return None
    pid, start = raw.split()
    try:
        tail = open("/proc/%s/stat" % pid).read().rsplit(")", 1)[1].split()
    except OSError:
        return False
    return tail[19] == start and tail[0] not in ("Z", "X")
for name in ("S", "T"):
    values = floats(name)
    out[name] = values[-1] if values else None
beats = floats("hb")
out["hbn"] = len(beats)
out["hb"] = beats[-1] if beats else None
out["hb_ok"] = all(b > a for a, b in zip(beats, beats[1:])) and all(b >= 0 for b in beats)
out["now"] = time.monotonic()
time.sleep(gap)
again = floats("hb")
out["hbn2"] = len(again)
out["hb2"] = again[-1] if again else None
out["leader_alive"] = alive("leader")
out["child_alive"] = alive("child")
for name in ("B", "C", "D"):
    value = read(name)
    out[name] = None if value is None else value.count("\n")
print(json.dumps(out))
"""


@dataclass(frozen=True)
class Observation:  # pylint: disable=too-many-instance-attributes
    """A buffered response as the transport hook returned it, with host-side timing.

    The pylint exemption is for this plain record of one response; splitting it would only
    scatter the fields every case reads together. The two argument-count exemptions below are
    for helpers whose parameters are all independent inputs of one exchange.
    """

    ok: bool
    stdout: bytes
    stderr: bytes
    exit_code: int | None
    code: str | None
    outcome: str | None
    sent: float
    elapsed: float
    stdout_truncated: bool = False
    stderr_truncated: bool = False


@dataclass(frozen=True)
class Witness:
    """One witness command's document and the host interval that brackets its guest sample."""

    document: Mapping[str, object]
    sent: float
    received: float

    def number(self, key: str) -> float | None:
        """A finite number, None when absent; anything else is unproven."""
        value = self.document.get(key)
        if value is None:
            return None
        if (
            isinstance(value, bool)
            or not isinstance(value, int | float)
            or not math.isfinite(value)
        ):
            raise _unproven(f"{key}_not_finite")
        return float(value)

    def host_interval(self, stamp: float) -> tuple[float, float]:
        """Host-clock interval holding a guest stamp, from the witness's own guest sample."""
        low, high = self.host_interval_us(stamp)
        return low / 1_000_000, high / 1_000_000

    def host_interval_us(self, stamp: float) -> tuple[int, int]:
        """`host_interval` in whole microseconds, for exact comparison against a limit."""
        sample = self.number("now")
        if sample is None or stamp > sample:
            raise _unproven("stamp_after_witness_sample")
        if _us(self.received) - _us(self.sent) > _us(MAX_BRACKET_S):
            raise _unproven("clock_bracket_too_wide")
        lag = _us(sample) - _us(stamp)
        return _us(self.sent) - lag, _us(self.received) - lag

    @property
    def advancing(self) -> bool:
        return self.document.get("hbn2") != self.document.get("hbn")


def _unproven(reason: str) -> NativeFailure:
    return NativeFailure(f"http_buffered_unproven_{reason}")


def _exchange(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    driver: Driver,
    target: object,
    argv: list[str],
    *,
    execution_ms: int,
    observation_ms: int,
    output_bytes: int,
) -> Observation:
    sent = _now()
    raw = driver.call(
        "http.buffered_run",
        target,
        {
            "argv": argv,
            "execution_limit_ms": execution_ms,
            "observation_timeout_ms": observation_ms,
            "output_limit_bytes": output_bytes,
        },
    )
    elapsed = _now() - sent
    if raw.get("ok") is True:
        stdout, stderr, code = raw.get("stdout"), raw.get("stderr"), raw.get("exit_code")
        out_cut, err_cut = raw.get("stdout_truncated"), raw.get("stderr_truncated")
        if (
            not isinstance(stdout, bytes)
            or not isinstance(stderr, bytes)
            or not isinstance(code, int)
            or isinstance(code, bool)
        ):
            raise _unproven("response_malformed")
        if not isinstance(out_cut, bool) or not isinstance(err_cut, bool):
            raise _unproven("truncation_flags_malformed")
        return Observation(True, stdout, stderr, code, None, None, sent, elapsed, out_cut, err_cut)
    code, outcome = raw.get("code"), raw.get("outcome")
    if not isinstance(code, str) or not isinstance(outcome, str):
        raise _unproven("error_malformed")
    return Observation(False, b"", b"", None, code, outcome, sent, elapsed)


def _script(source: str, *args: str) -> list[str]:
    return ["python3", "-c", source, *args]


def _witness(
    driver: Driver, target: object, directory: str, *, gap: float = _SAMPLE_GAP_S
) -> Witness:
    """Read the workload's public files and process identity through one more buffered command."""
    sent = _now()
    seen = _exchange(
        driver,
        target,
        _script(_WITNESS, directory, repr(gap)),
        execution_ms=_WITNESS_LIMIT_MS,
        observation_ms=_WITNESS_LIMIT_MS,
        output_bytes=65536,
    )
    received = _now()
    if not seen.ok or seen.exit_code != 0:
        raise _unproven("witness_unavailable")
    try:
        document = json.loads(seen.stdout)
    except ValueError:
        raise _unproven("witness_malformed") from None
    if not isinstance(document, dict) or document.get("proc") is not True:
        raise _unproven("process_identity_unobservable")
    return Witness(document, sent, received)


def _directory(inputs: Mapping[str, object]) -> str:
    root = inputs.get("workdir_root", "/tmp")
    if not isinstance(root, str) or not root.startswith("/"):
        raise NotRun("http_buffered_workdir_invalid")
    return f"{root.rstrip('/')}/sps-hb-{secrets.token_hex(8)}"


def judge_kill_gap(gap: float) -> str | None:
    """Classify the interval from the TERM stamp to the last heartbeat.

    The TERM attempt precedes its stamp by at most `HANDLER_MARGIN_S`, and the KILL follows the
    last heartbeat by at most `HEARTBEAT_S`, so the KILL follows the TERM attempt by a time in
    `[gap, gap + HEARTBEAT_S + HANDLER_MARGIN_S]`. Returns "early" when that whole interval is
    below the grace, None when it is at or above the grace and within `KILL_RESOLUTION_S` of it,
    and otherwise "ambiguous" or "late": neither is a pass or a defect.
    """
    if not math.isfinite(gap):
        raise _unproven("kill_gap_not_finite")
    gap_us, grace_us = _us(gap), _us(KILL_GRACE_S)
    if gap_us + _us(HEARTBEAT_S) + _us(HANDLER_MARGIN_S) < grace_us:
        return "early"
    if gap_us < grace_us:
        return "ambiguous"
    if gap_us > grace_us + _us(KILL_RESOLUTION_S):
        return "late"
    return None


def _stamps(witness: Witness) -> tuple[float, float, float]:
    """Finite, ordered start, TERM and last-heartbeat stamps; anything else is unproven."""
    start, term, beat = witness.number("S"), witness.number("T"), witness.number("hb")
    if start is None or beat is None or witness.document.get("hb_ok") is not True:
        raise _unproven("workload_stamps_missing")
    if term is None:
        raise Differs("term_not_delivered")
    now = witness.number("now")
    if now is None or not start <= term <= now or not start <= beat <= now:
        raise _unproven("stamps_not_monotonic")
    return start, term, beat


def check_term_time(
    witness: Witness, dispatch_sent: float, execution_ms: int
) -> Mapping[str, float]:
    """Judge the TERM time against the limit; return the measured intervals on success.

    The binding starts E at native command dispatch. Dispatch is no earlier than the host's send
    and no later than the workload's own start stamp `S`, so:

    - TERM is early if even its latest possible host time precedes `send + E`.
    - TERM is not early only if `T - HANDLER_MARGIN_S >= S + E` (the signal precedes the handler
      stamp `T` by at most the margin, and dispatch is at or before `S`). Both stamps come from
      the guest clock, so no witness-clock translation enters this proof.
    - Anything between is unproven. A correct endpoint that sends TERM exactly E after dispatch
      is therefore usually unproven, because its startup and handler latency cannot be bounded;
      this check does not delay or tune anything to avoid that.
    - A TERM later than `TERM_RESOLUTION_S` after `send + E` is also unproven.
    """
    start, term, _ = _stamps(witness)
    sent_us = _us(dispatch_sent)
    required = sent_us + execution_ms * 1000
    term_low, term_high = witness.host_interval_us(term)
    if term_high < required:
        raise Differs("term_before_execution_limit")
    if _us(term) - _us(HANDLER_MARGIN_S) - _us(start) < execution_ms * 1000:
        raise _unproven("term_time_crosses_execution_limit")
    if term_high > required + _us(TERM_RESOLUTION_S):
        raise _unproven("term_time_exceeds_measurement_resolution")
    return {
        "term_after_send_min": (term_low - sent_us) / 1_000_000,
        "term_after_send_max": (term_high - sent_us) / 1_000_000,
        "term_after_start": term - start,
        "bracket": witness.received - witness.sent,
    }


def _settled(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    driver: Driver,
    target: object,
    directory: str,
    seen: Observation,
    execution_ms: int,
    settled: Callable[[Witness], bool],
) -> Witness:
    """Read the witness after expiry; an unknown outcome may precede the scheduled KILL."""
    witness = _witness(driver, target, directory)
    if seen.outcome == "completed":
        return witness
    deadline = seen.sent + execution_ms / 1000
    deadline += KILL_GRACE_S + KILL_RESOLUTION_S + TERM_RESOLUTION_S + SETTLE_WINDOW_S
    while not settled(witness) and _now() < deadline:
        _pause(0.5)
        witness = _witness(driver, target, directory)
    return witness


def _expired(observation: Observation) -> None:
    if (
        observation.ok
        or observation.code != "timeout"
        or observation.outcome
        not in (
            "completed",
            "unknown",
        )
    ):
        raise Differs("execution_expiry_not_typed_timeout")


def _terminated(witness: Witness) -> bool:
    return witness.document.get("leader_alive") is False and not witness.advancing


def bytes_and_exit_codes(driver: Driver, target: object, inputs: Mapping[str, object]) -> None:
    """Exact bytes per stream, empty streams, nonzero status and ordinary 124/137/143 exits."""
    del inputs
    cases = (
        (b"\x00\xff\n", b"", 7, "import sys;sys.stdout.buffer.write(b'\\x00\\xff\\n');sys.exit(7)"),
        (b"", b"\xfe\x00", 0, "import sys;sys.stderr.buffer.write(b'\\xfe\\x00')"),
        (b"", b"", 0, "pass"),
    ) + tuple((b"", b"", code, f"import sys;sys.exit({code})") for code in (124, 137, 143))
    for stdout, stderr, code, source in cases:
        seen = _exchange(
            driver,
            target,
            ["python3", "-c", source],
            execution_ms=10000,
            observation_ms=10000,
            output_bytes=64,
        )
        if not seen.ok:
            raise Differs("ordinary_exit_reported_as_error")
        if seen.stdout != stdout or seen.stderr != stderr:
            raise Differs("output_bytes_not_exact")
        if seen.exit_code != code:
            raise Differs("exit_code_not_preserved")


def execution_term(driver: Driver, target: object, inputs: Mapping[str, object]) -> None:
    """An execution limit sends TERM at E; the leader is observed dead before completion."""
    limit_ms = 3000
    directory = _directory(inputs)
    seen = _exchange(
        driver,
        target,
        _script(_TERM_LEADER, directory, repr(HEARTBEAT_S)),
        execution_ms=limit_ms,
        observation_ms=20000,
        output_bytes=64,
    )
    _expired(seen)
    witness = _settled(driver, target, directory, seen, limit_ms, _terminated)
    check_term_time(witness, seen.sent, limit_ms)
    leader = witness.document.get("leader_alive")
    if leader is None:
        raise _unproven("leader_identity_unobservable")
    if witness.advancing:
        raise Differs("command_still_running_after_term")
    if leader is True:
        raise _unproven("leader_alive_without_progress")
    _, term, _ = _stamps(witness)
    if (
        seen.outcome == "completed"
        and _us(seen.sent) + _us(seen.elapsed) < (witness.host_interval_us(term)[0])
    ):
        raise Differs("completion_claimed_before_termination")


def group_kill(driver: Driver, target: object, inputs: Mapping[str, object]) -> None:
    """The original group keeps its KILL obligation after the leader exits on TERM."""
    limit_ms = 2000
    directory = _directory(inputs)
    seen = _exchange(
        driver,
        target,
        _script(_GROUP_LEADER, directory, repr(HEARTBEAT_S), _GROUP_CHILD),
        execution_ms=limit_ms,
        observation_ms=30000,
        output_bytes=64,
    )
    _expired(seen)

    def settled(witness: Witness) -> bool:
        return witness.document.get("child_alive") is False and not witness.advancing

    witness = _settled(driver, target, directory, seen, limit_ms, settled)
    alive = witness.document.get("child_alive")
    if alive is None or witness.document.get("leader_alive") is None:
        raise _unproven("process_identity_unobservable")
    check_term_time(witness, seen.sent, limit_ms)
    if witness.document.get("leader_alive") is True:
        raise _unproven("leader_alive_after_term")
    if alive is True or witness.advancing:
        raise Differs("kill_missing_after_leader_exit")
    _, term, beat = _stamps(witness)
    verdict = judge_kill_gap(beat - term)
    if verdict == "early":
        raise Differs("kill_before_grace")
    if verdict is not None:
        raise _unproven(f"kill_time_{verdict}")
    if (
        seen.outcome == "completed"
        and _us(seen.sent) + _us(seen.elapsed) < (witness.host_interval_us(beat)[0])
    ):
        raise Differs("completion_claimed_before_kill_settled")


def observation_versus_execution(
    driver: Driver, target: object, inputs: Mapping[str, object]
) -> None:
    """Observation expiry leaves the command running, and its execution limit still fires."""
    limit_ms = 5000
    directory = _directory(inputs)
    seen = _exchange(
        driver,
        target,
        _script(_TERM_LEADER, directory, repr(HEARTBEAT_S)),
        execution_ms=limit_ms,
        observation_ms=500,
        output_bytes=64,
    )
    if seen.ok or seen.code != "timeout" or seen.outcome != "unknown":
        raise Differs("observation_expiry_not_timeout_unknown")
    early = _witness(driver, target, directory)
    if early.document.get("leader_alive") is None or early.number("hb") is None:
        raise _unproven("workload_not_observable")
    if (
        early.number("T") is not None
        or not early.advancing
        or early.document["leader_alive"] is not True
    ):
        raise Differs("observation_expiry_stopped_the_command")
    deadline = seen.sent + limit_ms / 1000 + TERM_RESOLUTION_S + SETTLE_WINDOW_S
    while True:
        witness = _witness(driver, target, directory)
        if witness.number("T") is not None and _terminated(witness):
            check_term_time(witness, seen.sent, limit_ms)
            return
        if _now() >= deadline:
            raise Differs("execution_limit_never_fired_after_observation_expiry")
        _pause(0.5)


def background_survives(driver: Driver, target: object, inputs: Mapping[str, object]) -> None:
    """Foreground output is final without waiting for a descendant that holds the pipes."""
    directory = _directory(inputs)
    seen = _exchange(
        driver,
        target,
        _script(_BACKGROUND, directory, repr(BACKGROUND_DELAY_S), _LATE_CHILD),
        execution_ms=30000,
        observation_ms=30000,
        output_bytes=64,
    )
    if not seen.ok:
        raise Differs("foreground_completion_not_reported")
    if seen.stdout != b"fg\n" or seen.stderr != b"" or seen.exit_code != 0:
        raise Differs("completed_output_not_final")
    if _us(seen.elapsed) >= _us(BACKGROUND_DELAY_S):
        raise Differs("output_waited_for_descendant_eof")
    if _us(seen.elapsed) >= _us(BACKGROUND_DELAY_S) - _us(1.0):
        raise _unproven("result_too_slow_to_exclude_descendant_wait")
    deadline = _now() + BACKGROUND_DELAY_S + SETTLE_WINDOW_S
    while _witness(driver, target, directory, gap=0.0).document.get("B") is None:
        if _now() >= deadline:
            raise Differs("background_work_did_not_survive_foreground_exit")
        _pause(1.0)


def _output_pattern(fd: int, size: int) -> bytes:
    """The bytes `_OUTPUT` writes to descriptor `fd`; distinct per stream and position."""
    return bytes(97 + (i * 7 + fd) % 26 for i in range(size))


def output_limit(driver: Driver, target: object, inputs: Mapping[str, object]) -> None:
    """Output over L is a success: exit status, each stream's first L bytes, truncated flags.

    No error, no replay, and the command is not stopped or reported complete early.
    """
    limit = 64
    fits = _exchange(
        driver,
        target,
        [
            "python3",
            "-c",
            f"import sys;sys.stdout.buffer.write(b'z'*{limit});sys.stderr.write('e')",
        ],
        execution_ms=10000,
        observation_ms=10000,
        output_bytes=limit,
    )
    if not fits.ok:
        raise Differs("output_at_the_limit_not_returned")
    if fits.stdout != b"z" * limit or fits.stderr != b"e":
        raise Differs("output_at_the_limit_not_returned_exactly")
    if fits.stdout_truncated or fits.stderr_truncated:
        raise Differs("output_within_the_limit_marked_truncated")
    # (stdout size, stderr size, exit status): each stream is over on its own, then both are.
    for out_size, err_size, status in (
        (limit + 37, 3, 5),
        (0, limit + 1, 0),
        (limit * 3, limit * 2, 9),
    ):
        _over_limit_case(driver, target, inputs, limit, out_size, err_size, status)


def _over_limit_case(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    driver: Driver,
    target: object,
    inputs: Mapping[str, object],
    limit: int,
    out_size: int,
    err_size: int,
    status: int,
) -> None:
    directory = _directory(inputs)
    seen = _exchange(
        driver,
        target,
        _script(_OUTPUT, directory, str(out_size), str(err_size), str(status)),
        execution_ms=10000,
        observation_ms=10000,
        output_bytes=limit,
    )
    if not seen.ok:
        raise Differs(
            "output_over_the_limit_returned_as_error"
            if seen.code == "limit_exceeded"
            else "output_over_the_limit_not_a_success"
        )
    witness = _witness(driver, target, directory, gap=0.0)
    if witness.document.get("D") is None:
        raise Differs("completion_claimed_before_command_finished")
    if seen.exit_code != status:
        raise Differs("exit_status_not_returned_with_truncated_output")
    for fd, size, data, flag in (
        (1, out_size, seen.stdout, seen.stdout_truncated),
        (2, err_size, seen.stderr, seen.stderr_truncated),
    ):
        if data != _output_pattern(fd, min(size, limit)):
            raise Differs("output_prefix_not_exact")
        if flag is not (size > limit):
            raise Differs("truncation_flag_wrong")
    if witness.document.get("C") != 1:
        raise Differs("output_limit_replayed_the_command")


CASES: Mapping[str, Callable[[Driver, object, Mapping[str, object]], None]] = {
    "bytes_and_exit_codes": bytes_and_exit_codes,
    "execution_term": execution_term,
    "group_kill": group_kill,
    "observation_versus_execution": observation_versus_execution,
    "background_survives": background_survives,
    "output_limit": output_limit,
}


def run_case(driver: Driver, target: object, inputs: Mapping[str, object]) -> Mapping[str, object]:
    """Run one named case; a definite violation is Differs, anything unproven is an error."""
    case = inputs.get("case")
    if not isinstance(case, str) or case not in CASES:
        raise NotRun("http_buffered_case_unknown")
    CASES[case](driver, target, inputs)
    return {"verified": True}
