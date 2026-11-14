# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Example Cloud's machine backend: one Docker container per machine.

Machines are plain Docker containers whose main process is ``sleep <ttl>``
with auto-remove, so a machine ends when its lifetime runs out even if the
fake API server has already stopped. Usage records live in a SQLite file
under the server's state directory and outlive their container.
"""

from __future__ import annotations

import contextlib
import io
import json
import queue
import sqlite3
import stat as statmod
import tarfile
import threading
import time
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any

import docker
from docker.errors import APIError, DockerException, ImageNotFound, NotFound
from requests.exceptions import RequestException

IMAGE = "python:3.13-slim@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f"

EXEC_OUTPUT_CAP = 16 * 1024 * 1024
JOB_OUTPUT_KEEP = 4 * 1024 * 1024
JOB_RETENTION_SECONDS = 600
USAGE_RETENTION_DAYS = 30
_STREAM_CHUNK = 1 << 20

_END = object()
_CANCEL = object()

# Runs inside the machine. Executes the command in its own process group,
# enforces the timeout with TERM-then-KILL, and reports the outcome through
# a file so the command's stdout and stderr stay untouched.
_SUPERVISOR = """
import json, os, signal, subprocess, sys
spec = json.loads(sys.argv[1])
try:
    proc = subprocess.Popen(spec["cmd"], start_new_session=True)
except OSError as exc:
    with open(spec["result"], "w") as handle:
        json.dump({"code": None, "killed": False, "spawn_error": str(exc)}, handle)
    raise SystemExit(0)
killed = False
code = None
try:
    code = proc.wait(timeout=spec["timeout_s"])
except subprocess.TimeoutExpired:
    killed = True
    os.killpg(proc.pid, signal.SIGTERM)
    try:
        code = proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait()
if code is not None and code < 0:
    code = 128 - code
if killed:
    code = None
with open(spec["result"], "w") as handle:
    json.dump({"code": code, "killed": killed}, handle)
"""


class ApiError(Exception):
    """An HTTP-visible failure: status, machine-readable code, human message."""

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def _removing(exc: APIError) -> bool:
    """Docker answers 500/409 instead of 404 for a container whose removal has begun."""
    text = str(exc.explanation or "")
    return "RWLayer" in text or "removal of container" in text


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _parse_time(text: str) -> datetime:
    return datetime.fromisoformat(text)


def _plus(text: str, seconds: float) -> str:
    return (
        (_parse_time(text) + timedelta(seconds=seconds))
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


class _IterRead(io.RawIOBase):
    """A file-like read side over an iterator of byte chunks."""

    def __init__(self, chunks: Iterator[bytes]) -> None:
        self._it = iter(chunks)
        self._buf = b""
        self._done = False

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            parts = [self._buf]
            parts.extend(self._it)
            self._buf = b""
            self._done = True
            return b"".join(parts)
        while len(self._buf) < size and not self._done:
            try:
                self._buf += next(self._it)
            except StopIteration:
                self._done = True
        out, self._buf = self._buf[:size], self._buf[size:]
        return out


class _Sink(io.RawIOBase):
    """A file-like write side that pushes each write into a queue."""

    def __init__(self, out: queue.Queue[bytes | BaseException | None]) -> None:
        self._out = out

    def writable(self) -> bool:
        return True

    def write(self, data: bytes | bytearray | memoryview) -> int:
        self._out.put(bytes(data))
        return len(data)


class _CancelledError(Exception):
    pass


def _drain(incoming: queue.Queue[bytes | object]) -> Iterator[bytes]:
    while True:
        item = incoming.get()
        if item is _END:
            return
        if item is _CANCEL:
            raise _CancelledError("upload cancelled")
        yield item  # type: ignore[misc]


def _untar(chunks: Iterator[bytes]) -> Iterator[bytes]:
    """Yield the content of the first regular member of a tar byte stream."""
    reader = _IterRead(chunks)
    with tarfile.open(fileobj=reader, mode="r|") as archive:
        for member in archive:
            if member.isreg():
                payload = archive.extractfile(member)
                assert payload is not None
                while True:
                    block = payload.read(_STREAM_CHUNK)
                    if not block:
                        return
                    yield block


class _Job:
    def __init__(self, job_id: str, machine_id: str, exec_id: str) -> None:
        self.id = job_id
        self.machine_id = machine_id
        self.exec_id = exec_id
        self.started = _now()
        self.out = bytearray()
        self.err = bytearray()
        self.out_start = 0
        self.err_start = 0
        self.done = False
        self.code: int | None = None
        self.finished_at: str | None = None
        self.cond = threading.Condition()

    def has_new(self, out_pos: int, err_pos: int) -> bool:
        return self.out_start + len(self.out) > out_pos or self.err_start + len(self.err) > err_pos


class ExampleCloud:
    """The whole fake provider: machine lifecycle, exec, files, jobs, usage."""

    def __init__(self, state_dir: Path, owner: str, image: str = IMAGE) -> None:
        state_dir.mkdir(parents=True, exist_ok=True)
        self.owner = owner
        self.image = image
        self.client = docker.from_env(timeout=20)
        self.streams = docker.from_env(timeout=None)
        try:
            self.image_id = self.client.images.get(image).id
        except ImageNotFound:
            self.image_id = self.client.images.pull(image).id
        self.db_path = state_dir / "usage.db"
        self._init_db()
        self.jobs: dict[str, _Job] = {}
        self._jobs_lock = threading.Lock()
        self._closed = threading.Event()
        self._last_prune = 0.0
        self._watcher = threading.Thread(target=self._watch_events, daemon=True)
        self._watcher.start()

    # -- database -----------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.db_path, timeout=30)
        con.row_factory = sqlite3.Row
        return con

    def _init_db(self) -> None:
        with self._connect() as con:
            con.execute("PRAGMA journal_mode=WAL")
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS machines (
                    machine_id TEXT PRIMARY KEY,
                    cpu REAL NOT NULL,
                    memory_mb INTEGER NOT NULL,
                    env_json TEXT NOT NULL,
                    tags_json TEXT NOT NULL,
                    created TEXT NOT NULL,
                    expires TEXT,
                    started TEXT NOT NULL,
                    ended TEXT
                )
                """
            )
        self._prune()

    def _prune(self) -> None:
        cutoff = (
            (datetime.now(UTC) - timedelta(days=USAGE_RETENTION_DAYS))
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )
        with self._connect() as con:
            con.execute("DELETE FROM machines WHERE ended IS NOT NULL AND ended < ?", (cutoff,))
        self._last_prune = time.monotonic()

    def _prune_sometimes(self) -> None:
        if time.monotonic() - self._last_prune > 300:
            self._prune()

    def _mark_ended(self, machine_id: str, when: str | None = None) -> None:
        with self._connect() as con:
            con.execute(
                "UPDATE machines SET ended = ? WHERE machine_id = ? AND ended IS NULL",
                (when or _now(), machine_id),
            )

    def _machine_row(self, machine_id: str) -> sqlite3.Row | None:
        with self._connect() as con:
            return con.execute(
                "SELECT * FROM machines WHERE machine_id = ?", (machine_id,)
            ).fetchone()

    # -- containers ---------------------------------------------------------

    def _container(self, machine_id: str) -> Any:
        try:
            native = self.client.containers.get(f"ec-{machine_id}")
        except NotFound:
            raise ApiError(404, "not_found", f"unknown machine {machine_id}") from None
        if native.labels.get("example.owner") != self.owner:
            raise ApiError(404, "not_found", f"unknown machine {machine_id}")
        return native

    def _describe(self, machine_id: str, status: str, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "machine_id": machine_id,
            "status": status,
            "created": row["created"],
            "expires": row["expires"],
        }

    def _reconcile(self, machine_id: str) -> str:
        """Return 'running' or 'ended', recording an end time if the box is gone."""
        try:
            self._container(machine_id)
            return "running"
        except ApiError:
            self._mark_ended(machine_id)
            return "ended"

    # -- machine operations -------------------------------------------------

    def create_machine(self, spec: dict[str, Any]) -> dict[str, Any]:
        try:
            cpu = float(spec.get("cpu", 1))
            memory_mb = int(spec.get("memory_mb", 512))
            ttl = spec.get("ttl_seconds", 300)
            ttl = int(ttl) if ttl is not None else None
        except (TypeError, ValueError):
            raise ApiError(
                400, "invalid_request", "cpu, memory_mb and ttl_seconds must be numbers"
            ) from None
        env = spec.get("env") or {}
        tags = spec.get("tags") or {}
        if cpu <= 0:
            raise ApiError(400, "invalid_request", "cpu must be positive")
        if memory_mb < 6:
            raise ApiError(400, "invalid_request", "memory_mb must be at least 6")
        if ttl is not None and ttl < 1:
            raise ApiError(400, "invalid_request", "ttl_seconds must be at least 1")
        machine_id = "m-" + uuid.uuid4().hex[:16]
        created = _now()
        expires = _plus(created, int(ttl)) if ttl is not None else None
        labels = {
            "example.owner": self.owner,
            "example.machine": "1",
            "example.machine_id": machine_id,
            "example.created": created,
            "example.expires": expires or "",
        }
        for key, value in tags.items():
            labels[f"example.tag.{key}"] = value
        command = ["sleep", str(int(ttl))] if ttl is not None else ["sleep", "infinity"]
        try:
            native = self.client.containers.create(
                self.image_id,
                command,
                name=f"ec-{machine_id}",
                environment=env,
                labels=labels,
                nano_cpus=max(int(cpu * 1_000_000_000), 10_000_000),
                mem_limit=f"{memory_mb}m",
                auto_remove=True,
                detach=True,
            )
            native.start()
        except APIError as exc:
            raise ApiError(502, "provider_error", f"could not start machine: {exc}") from exc
        with self._connect() as con:
            con.execute(
                "INSERT INTO machines VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)",
                (
                    machine_id,
                    cpu,
                    memory_mb,
                    json.dumps(env, sort_keys=True),
                    json.dumps(tags, sort_keys=True),
                    created,
                    expires,
                    created,
                ),
            )
        return self._describe(machine_id, "running", self._machine_row(machine_id))  # type: ignore[arg-type]

    def describe_machine(self, machine_id: str) -> dict[str, Any]:
        row = self._machine_row(machine_id)
        if row is None:
            raise ApiError(404, "not_found", f"unknown machine {machine_id}")
        status = self._reconcile(machine_id) if row["ended"] is None else "ended"
        return self._describe(machine_id, status, row)

    def list_machines(self, tags: list[tuple[str, str]], offset: int, limit: int) -> dict[str, Any]:
        filters = [f"example.owner={self.owner}", "example.machine=1"]
        filters += [f"example.tag.{key}={value}" for key, value in tags]
        containers = self.client.containers.list(all=False, filters={"label": filters})
        found = []
        for native in containers:
            labels = native.labels
            found.append(
                {
                    "machine_id": labels.get("example.machine_id", ""),
                    "status": "running",
                    "created": labels.get("example.created", ""),
                    "expires": labels.get("example.expires") or None,
                }
            )
        found.sort(key=lambda item: (item["created"], item["machine_id"]))
        page = found[offset : offset + limit]
        nxt = offset + limit
        return {
            "machines": page,
            "next_page_token": str(nxt) if nxt < len(found) else None,
        }

    def delete_machine(self, machine_id: str) -> dict[str, Any]:
        row = self._machine_row(machine_id)
        if row is None:
            raise ApiError(404, "not_found", f"unknown machine {machine_id}")
        try:
            self._container(machine_id).kill()
        except ApiError:
            pass
        except APIError:
            pass
        self._mark_ended(machine_id)
        return {"status": "ended"}

    # -- exec ---------------------------------------------------------------

    def exec_command(
        self,
        machine_id: str,
        cmd: list[str],
        cwd: str | None,
        env: dict[str, str],
        timeout_s: float | None,
    ) -> dict[str, Any]:
        native = self._container(machine_id)
        result_path = f"/tmp/.ec-exec-{uuid.uuid4().hex}.json"
        spec = json.dumps({"cmd": cmd, "timeout_s": timeout_s, "result": result_path})
        try:
            exec_id = self.streams.api.exec_create(
                native.id,
                ["python3", "-c", _SUPERVISOR, spec],
                environment=env,
                workdir=cwd or "/",
                stdin=False,
                tty=False,
            )["Id"]
            stream = self.streams.api.exec_start(exec_id, demux=True, stream=True, tty=False)
        except NotFound:
            raise ApiError(404, "not_found", f"machine {machine_id} has ended") from None
        except APIError as exc:
            raise ApiError(502, "provider_error", f"exec failed: {exc}") from exc
        out = bytearray()
        err = bytearray()
        try:
            for pair in stream:
                stdout_part, stderr_part = pair
                if stdout_part and len(out) < EXEC_OUTPUT_CAP:
                    out += stdout_part[: EXEC_OUTPUT_CAP - len(out)]
                if stderr_part and len(err) < EXEC_OUTPUT_CAP:
                    err += stderr_part[: EXEC_OUTPUT_CAP - len(err)]
        except (DockerException, RequestException) as exc:
            raise ApiError(502, "provider_error", f"exec stream failed: {exc}") from exc
        finally:
            stream.close()
        for _ in range(300):
            try:
                info = self.streams.api.exec_inspect(exec_id)
            except NotFound:
                raise ApiError(
                    404, "not_found", f"machine {machine_id} ended during exec"
                ) from None
            if not info.get("Running"):
                break
            time.sleep(0.1)
        result = self._read_exec_result(native, result_path)
        if "spawn_error" in result:
            raise ApiError(404, "not_found", str(result["spawn_error"]))
        return {
            "code": result["code"],
            "out": out.decode("utf-8", "replace"),
            "err": err.decode("utf-8", "replace"),
            "killed": result["killed"],
        }

    def _read_exec_result(self, native: Any, path: str) -> dict[str, Any]:
        try:
            chunks, _ = native.get_archive(path)
        except NotFound:
            raise ApiError(502, "provider_error", "exec supervisor did not report") from None
        data = b"".join(_untar(chunks))
        try:
            result = json.loads(data)
        except ValueError:
            raise ApiError(502, "provider_error", "exec report unreadable") from None
        return result

    # -- files --------------------------------------------------------------

    def stat_file(self, machine_id: str, path: str) -> int:
        native = self._container(machine_id)
        try:
            _, stat = native.get_archive(path)
        except NotFound:
            raise ApiError(404, "not_found", f"no such file: {path}") from None
        except APIError as exc:
            if _removing(exc):
                raise ApiError(404, "not_found", f"unknown machine {machine_id}") from None
            raise
        if statmod.S_ISDIR(int(stat.get("mode", 0))):
            raise ApiError(400, "invalid_request", f"{path} is a directory")
        return int(stat.get("size", 0))

    def read_file(self, machine_id: str, path: str) -> tuple[int, Iterator[bytes]]:
        native = self._container(machine_id)
        try:
            chunks, stat = native.get_archive(path)
        except NotFound:
            raise ApiError(404, "not_found", f"no such file: {path}") from None
        except APIError as exc:
            if _removing(exc):
                raise ApiError(404, "not_found", f"unknown machine {machine_id}") from None
            raise
        if statmod.S_ISDIR(int(stat.get("mode", 0))):
            close = getattr(chunks, "close", None)
            if close is not None:
                close()
            raise ApiError(400, "invalid_request", f"{path} is a directory")
        return int(stat.get("size", 0)), _untar(chunks)

    def write_file(
        self, machine_id: str, path: str, size: int, body: Iterator[bytes]
    ) -> dict[str, Any]:
        native = self._container(machine_id)
        destination = PurePosixPath(path)
        parent = str(destination.parent)
        name = destination.name
        if not name:
            raise ApiError(400, "invalid_request", f"bad file path: {path}")

        def tar_stream() -> Iterator[bytes]:
            out: queue.Queue[bytes | Exception | None] = queue.Queue(maxsize=32)

            def produce() -> None:
                try:
                    with tarfile.open(fileobj=_Sink(out), mode="w|") as archive:
                        info = tarfile.TarInfo(name)
                        info.size = size
                        info.mode = 0o644
                        info.mtime = int(time.time())
                        archive.addfile(info, _IterRead(body))
                except Exception as exc:  # noqa: BLE001 - forward producer failures to the caller
                    out.put(exc)
                finally:
                    out.put(None)

            threading.Thread(target=produce, daemon=True).start()
            while True:
                chunk = out.get()
                if chunk is None:
                    return
                if isinstance(chunk, Exception):
                    raise chunk
                yield chunk

        try:
            accepted = native.put_archive(parent, tar_stream())
        except NotFound:
            raise ApiError(404, "not_found", f"no such directory: {parent}") from None
        except APIError as exc:
            text = str(exc)
            if "no such file" in text or "not exist" in text or "404" in text:
                raise ApiError(404, "not_found", f"no such directory: {parent}") from exc
            raise ApiError(502, "provider_error", f"write failed: {exc}") from exc
        if not accepted:
            raise ApiError(502, "provider_error", "write was not accepted")
        return {"path": path, "size": size}

    # -- jobs ---------------------------------------------------------------

    def start_job(
        self, machine_id: str, cmd: list[str], cwd: str | None, env: dict[str, str]
    ) -> dict[str, Any]:
        native = self._container(machine_id)
        try:
            exec_id = self.streams.api.exec_create(
                native.id,
                cmd,
                environment=env,
                workdir=cwd or "/",
                stdin=False,
                tty=False,
            )["Id"]
            stream = self.streams.api.exec_start(exec_id, demux=True, stream=True, tty=False)
        except NotFound:
            raise ApiError(404, "not_found", f"machine {machine_id} has ended") from None
        except APIError as exc:
            raise ApiError(502, "provider_error", f"job failed: {exc}") from exc
        job = _Job("j-" + uuid.uuid4().hex[:16], machine_id, exec_id)
        self._sweep_jobs()
        with self._jobs_lock:
            self.jobs[job.id] = job
        threading.Thread(target=self._drain_job, args=(job, stream), daemon=True).start()
        return {"job_id": job.id}

    def _sweep_jobs(self) -> None:
        now = _now()
        with self._jobs_lock:
            stale = [
                job_id
                for job_id, job in self.jobs.items()
                if job.done
                and job.finished_at is not None
                and _parse_time(now).timestamp() - _parse_time(job.finished_at).timestamp()
                > JOB_RETENTION_SECONDS
            ]
            for job_id in stale:
                del self.jobs[job_id]

    def _drain_job(self, job: _Job, stream: Any) -> None:
        try:
            for pair in stream:
                stdout_part, stderr_part = pair
                with job.cond:
                    if stdout_part:
                        job.out += stdout_part
                        drop = len(job.out) - JOB_OUTPUT_KEEP
                        if drop > 0:
                            del job.out[:drop]
                            job.out_start += drop
                    if stderr_part:
                        job.err += stderr_part
                        drop = len(job.err) - JOB_OUTPUT_KEEP
                        if drop > 0:
                            del job.err[:drop]
                            job.err_start += drop
                    job.cond.notify_all()
        except (DockerException, RequestException):
            pass
        finally:
            stream.close()
            code = self._exec_exit_code(job.exec_id)
            with job.cond:
                job.code = code
                job.done = True
                job.finished_at = _now()
                job.cond.notify_all()

    def _exec_exit_code(self, exec_id: str) -> int | None:
        for _ in range(50):
            try:
                info = self.streams.api.exec_inspect(exec_id)
            except (NotFound, DockerException, RequestException):
                return None
            if not info.get("Running"):
                code = info.get("ExitCode")
                return code if isinstance(code, int) else None
            time.sleep(0.1)
        return None

    def job_log(
        self,
        machine_id: str,
        job_id: str,
        out_pos: int,
        err_pos: int,
        wait_s: float,
    ) -> dict[str, Any]:
        with self._jobs_lock:
            job = self.jobs.get(job_id)
        if job is None or job.machine_id != machine_id:
            raise ApiError(404, "not_found", f"unknown job {job_id}")
        self._sweep_jobs()

        def collect() -> dict[str, Any]:
            with job.cond:
                job.cond.wait_for(lambda: job.done or job.has_new(out_pos, err_pos), wait_s)
                out_from = max(out_pos - job.out_start, 0)
                err_from = max(err_pos - job.err_start, 0)
                out_data = bytes(job.out[out_from:])
                err_data = bytes(job.err[err_from:])
                return {
                    "out": out_data.decode("utf-8", "replace"),
                    "err": err_data.decode("utf-8", "replace"),
                    "offset": f"{job.out_start + len(job.out)}.{job.err_start + len(job.err)}",
                    "done": job.done,
                    "code": job.code,
                }

        return collect()

    # -- usage --------------------------------------------------------------

    def get_usage(self, machine_id: str) -> dict[str, Any]:
        self._prune_sometimes()
        row = self._machine_row(machine_id)
        if row is None:
            raise ApiError(404, "not_found", f"unknown machine {machine_id}")
        if row["ended"] is None:
            self._reconcile(machine_id)
            row = self._machine_row(machine_id)
        return {
            "cpu": row["cpu"],  # type: ignore[index]
            "memory_mb": row["memory_mb"],  # type: ignore[index]
            "started": row["started"],  # type: ignore[index]
            "ended": row["ended"],  # type: ignore[index]
        }

    # -- background ---------------------------------------------------------

    def _watch_events(self) -> None:
        filters = {
            "type": "container",
            "event": ["die", "destroy", "kill", "oom", "stop"],
            "label": f"example.owner={self.owner}",
        }
        while not self._closed.is_set():
            try:
                for event in self.streams.events(filters=filters, decode=True):
                    if self._closed.is_set():
                        return
                    attrs = event.get("Actor", {}).get("Attributes", {}) or {}
                    machine_id = attrs.get("example.machine_id")
                    if machine_id:
                        self._mark_ended(machine_id)
            except (DockerException, RequestException):
                time.sleep(1)

    def close(self) -> None:
        self._closed.set()
        for client in (self.client, self.streams):
            with contextlib.suppress(DockerException, RequestException, OSError):
                client.close()
