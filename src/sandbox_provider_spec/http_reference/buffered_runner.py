# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Inline POSIX-process buffered command wrapper for Linux/Python execution images.

The wrapper source is sent with the command; it is not uploaded or installed in the guest.
"""

from __future__ import annotations

import struct
from collections.abc import Sequence
from dataclasses import dataclass

_HEADER = struct.Struct("!5sBBiQQ")
_MAGIC = b"SPSB2"
BUFFERED_RUNNER_CAPTURE_BYTES = 32 * 1024 * 1024

BUFFERED_RUNNER_TERM_ALLOWANCE_S = 0.25
"""Time added to ``E`` before TERM, measured from the child's exec.

``E`` runs from native command dispatch, which precedes the child's exec, so a TERM sent exactly
``E`` after the exec is never early. The check in ``coverage_http_buffered`` also proves a TERM
late enough only against the workload's own start stamp, which follows the exec by the guest
interpreter's startup, and it subtracts ``HANDLER_MARGIN_S`` (0.1 s) for signal-to-stamp latency.
This allowance covers that margin plus 0.15 s of startup, and stays far inside the check's
``TERM_RESOLUTION_S`` of 1 s."""

# The command stays argv-based. The wrapper owns bounded capture and the finite timer.
# ``subprocess.Popen`` returns only after the child's exec succeeded (its internal close-on-exec
# pipe reports it), so the timer starts once the child exists, never before it is spawned.
_RUNNER = r"""import fcntl,os,signal,struct,subprocess,sys,time
E,L=int(sys.argv[1]),int(sys.argv[2]); CAP=32*1024*1024; ARGV=sys.argv[3:]
def running(group):
    try: entries=os.listdir('/proc')
    except OSError: return None
    for pid in entries:
        if not pid.isdecimal(): continue
        try:
            stat=open('/proc/'+pid+'/stat','rb').read(); fields=stat[stat.rfind(b')')+2:].split()
            if int(fields[2])==group and fields[0] not in (b'Z',b'X'): return True
        except (OSError,ValueError,IndexError): pass
    return False
def emit(state,code,out=b'',err=b'',flags=0):
    sys.stdout.buffer.write(struct.pack('!5sBBiQQ',b'SPSB2',state,flags,code,len(out),len(err)))
    sys.stdout.buffer.write(out); sys.stdout.buffer.write(err); sys.stdout.buffer.flush()
def settle(group):
    try: os.killpg(group,signal.SIGTERM)
    except ProcessLookupError: pass
    # Start the full grace at the actual TERM attempt, never at intended E.
    deadline=time.monotonic()+5
    while running(group) is not False:
        remaining=deadline-time.monotonic()
        if remaining<=0: break
        time.sleep(min(.01,remaining))
    if running(group) is not False:
        try: os.killpg(group,signal.SIGKILL)
        except ProcessLookupError: pass
    deadline=time.monotonic()+2
    while running(group) is not False:
        remaining=deadline-time.monotonic()
        if remaining<=0: break
        time.sleep(min(.01,remaining))
    return running(group) is False
def recover(child,normal_complete,settlement_started,deadline):
    if child is None or normal_complete or settlement_started: return
    if deadline is None: deadline=time.monotonic()
    while child.poll() is None and time.monotonic()<deadline:
        time.sleep(min(.01,max(0,deadline-time.monotonic())))
    if child.poll() is None: settle(child.pid)
fds=[]; child=None; deadline=None; normal_complete=False; settlement_started=False
try:
    for name in ('stdout','stderr'):
        fd=os.memfd_create('sps-buffered-'+name,os.MFD_ALLOW_SEALING); fds.append(fd)
        os.ftruncate(fd,CAP)
        fcntl.fcntl(fd,1033,1|2|4)
    child=subprocess.Popen(ARGV,stdin=subprocess.DEVNULL,stdout=fds[0],stderr=fds[1],start_new_session=True,close_fds=True)
    deadline=time.monotonic()+E/1000+@ALLOWANCE@
    while child.poll() is None and time.monotonic()<deadline:
        time.sleep(min(.01,max(0,deadline-time.monotonic())))
    if child.poll() is None:
        settlement_started=True; settled=settle(child.pid)
        emit(1 if settled else 2,child.wait(timeout=2))
    else:
        normal_complete=True; code=child.wait()
        def written(fd):
            with open('/proc/self/fdinfo/'+str(fd)) as info:
                return int(next(line.split()[1] for line in info if line.startswith('pos:')))
        out=os.pread(fds[0],min(written(fds[0]),L+1),0)
        err=os.pread(fds[1],min(written(fds[1]),L+1),0)
        flags=(len(out)>L)|(len(err)>L)<<1
        emit(0,code,out[:L],err[:L],flags)
except BaseException:
    recover(child,normal_complete,settlement_started,deadline)
    emit(2,0)
finally:
    for fd in fds: os.close(fd)
""".replace("@ALLOWANCE@", repr(BUFFERED_RUNNER_TERM_ALLOWANCE_S))


@dataclass(frozen=True)
class BufferedRunnerResult:
    """One complete framed result emitted by :func:`buffered_runner_argv`."""

    state: str
    exit_code: int
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool = False
    stderr_truncated: bool = False


def buffered_runner_argv(
    command: Sequence[str], *, execution_limit_ms: int, output_limit_bytes: int
) -> list[str]:
    """Wrap argv (for example ``["sh", "-c", script]``) in the canonical runner.

    The target needs Python 3 with Linux ``memfd_create`` and ``/proc`` support. The command
    itself is passed as argv and is not interpolated into the wrapper source.
    """
    if not command or any(not isinstance(part, str) or "\0" in part for part in command):
        raise ValueError("command must be a non-empty sequence of NUL-free strings")
    if execution_limit_ms <= 0 or not 0 < output_limit_bytes <= BUFFERED_RUNNER_CAPTURE_BYTES:
        raise ValueError("execution and output limits must be positive and output must fit capture")
    return ["python3", "-c", _RUNNER, str(execution_limit_ms), str(output_limit_bytes), *command]


def buffered_runner_frame_limit(output_limit_bytes: int) -> int:
    """Maximum valid frame size for the requested per-stream output limit."""
    if output_limit_bytes <= 0:
        raise ValueError("output limit must be positive")
    return _HEADER.size + 2 * output_limit_bytes


def decode_buffered_runner_result(frame: bytes) -> BufferedRunnerResult:
    """Decode one complete runner frame, rejecting truncation and inconsistent lengths."""
    if len(frame) < _HEADER.size:
        raise ValueError("truncated buffered runner frame")
    magic, state, flags, exit_code, stdout_size, stderr_size = _HEADER.unpack_from(frame)
    if magic != _MAGIC or state not in (0, 1, 2) or flags & ~3:
        raise ValueError("invalid buffered runner frame")
    if len(frame) != _HEADER.size + stdout_size + stderr_size:
        raise ValueError("buffered runner frame length mismatch")
    if state != 0 and (stdout_size or stderr_size or flags):
        raise ValueError("non-complete buffered runner frame includes output")
    output_start = _HEADER.size
    stdout = frame[output_start : output_start + stdout_size]
    stderr = frame[output_start + stdout_size :]
    names = {0: "completed", 1: "terminated", 2: "unknown"}
    return BufferedRunnerResult(
        names[state], exit_code, stdout, stderr, bool(flags & 1), bool(flags & 2)
    )
