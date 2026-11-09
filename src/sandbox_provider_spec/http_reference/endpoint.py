# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Private PP1 control-plane example. No host command execution or sandbox claims.

The native backend owns isolation and workloads. This module owns authenticated
wire dispatch, durable allocation reservations and bounded observation buffering.
JSON dictionaries stay at this example's schema-validated interoperability edge.
"""

# The endpoint intentionally keeps wire dispatch, allocation transactions and replay
# ordering together; extracting those paths would obscure their shared invariants.
# pylint: disable=too-many-lines

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import sqlite3
import time
import uuid
from collections import deque
from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import Future
from contextlib import closing, contextmanager
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import date
from http import HTTPStatus
from pathlib import Path
from threading import Condition, Thread
from typing import Any, Protocol, TypeVar, cast

from sandbox_provider_spec import http_binding_validation as validation

SCHEMA = validation.SCHEMA
OPERATIONS = SCHEMA["x-operations"]
T = TypeVar("T")
BUFFERED_COMMANDS = "buffered_commands_v1"
HTTP_BINDING_01 = "sandbox-provider-http/0.1"
HTTP_BINDING_02 = "sandbox-provider-http/0.2"
HTTP_BINDING_03 = "sandbox-provider-http/0.3"
MAX_BUFFERED_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_EXECUTION_MS = 30_000
MAX_EXECUTION_MS_03 = 60_000


def _bounded_positive_integer(value: object, maximum: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= maximum


@dataclass
class EndpointSettings:  # pylint: disable=too-many-instance-attributes
    endpoint_origin: str
    clock: Callable[[], float] = time.time
    operation_timeout_ms: int = 5000
    buffered_commands: bool = False
    buffered_command_output_bytes: int | None = None
    execution_ms: int | None = None
    binding_version: str | None = None
    control_response_cap: int = validation.BOOTSTRAP_CONTROL_RESPONSE_BYTES


@dataclass
class _EndpointRuntime:
    processes: dict[str, tuple[dict[str, Any], Output, Callable[[], tuple[str, int | None]]]] = (
        dataclass_field(default_factory=dict)
    )
    cursors: dict[str, tuple[str, str | None, int]] = dataclass_field(default_factory=dict)
    observations: Condition = dataclass_field(default_factory=Condition)
    pending: int = 0
    closed: bool = False


@dataclass
class _OutputBuffer:
    capacity: int
    retention: int
    clock: Callable[[], float]
    frames: deque[tuple[float, dict[str, Any]]] = dataclass_field(default_factory=deque)
    size: int = 0
    high: int = 0
    terminal: str = "open"


class Failure(Exception):
    """An explicitly classified result; native exception text is never disclosed."""

    def __init__(
        self, code: str, outcome: str = "not_dispatched", exit_code: int | None = None
    ) -> None:
        super().__init__(code)
        self.code = code
        self.outcome = outcome
        self.exit_code = exit_code


class Output:
    """Control-plane ring buffer. Native observations alone set EOF and exit."""

    def __init__(
        self, capacity: int, retention: int, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self.buffer = _OutputBuffer(capacity, retention, clock)
        self.condition = Condition()

    @property
    def clock(self) -> Callable[[], float]:
        return self.buffer.clock

    @clock.setter
    def clock(self, value: Callable[[], float]) -> None:
        self.buffer.clock = value

    @property
    def capacity(self) -> int:
        return self.buffer.capacity

    @capacity.setter
    def capacity(self, value: int) -> None:
        self.buffer.capacity = value

    @property
    def frames(self) -> deque[tuple[float, dict[str, Any]]]:
        return self.buffer.frames

    @property
    def size(self) -> int:
        return self.buffer.size

    @property
    def high(self) -> int:
        return self.buffer.high

    def _expire(self) -> None:
        buffer = self.buffer
        while buffer.frames and (
            buffer.size > buffer.capacity
            or buffer.frames[0][0] + buffer.retention <= buffer.clock()
        ):
            _, frame = buffer.frames.popleft()
            buffer.size -= len(frame["text"].encode())

    def feed(self, stream: str, text: str) -> None:
        # Split at Unicode scalar boundaries, never change an issued frame later.
        with self.condition:
            buffer = self.buffer
            for start in range(0, len(text), 256):
                part = text[start : start + 256]
                if buffer.high >= 2147483647:
                    buffer.terminal = "lost"
                    break
                frame = {"sequence": buffer.high, "stream": stream, "text": part}
                buffer.frames.append((buffer.clock(), frame))
                buffer.high += 1
                buffer.size += len(part.encode())
                self._expire()
            self.condition.notify_all()

    def close(self, *, lost: bool = False) -> None:
        with self.condition:
            self.buffer.terminal = "lost" if lost else "eof"
            self.condition.notify_all()

    def page(
        self,
        request: dict[str, Any],
        state: Callable[[], tuple[str, int | None]],
        *,
        deadline: float | None = None,
    ) -> dict[str, Any]:
        cursor = request["cursor"]
        stop_at = (
            time.monotonic() + float(request["observation_timeout_ms"]) / 1000
            if deadline is None
            else deadline
        )
        # Observe before waiting, sharing the caller deadline. Unknown is not exit.
        try:
            execution, code = state()
        except Failure as failure:
            if failure.code != "timeout":
                raise
            execution, code = "unknown", None
        with self.condition:
            buffer = self.buffer
            if cursor > buffer.high:
                raise Failure("invalid_request")
            while cursor == buffer.high and buffer.terminal == "open":
                remaining = stop_at - time.monotonic()
                if remaining <= 0:
                    break
                self.condition.wait(remaining)
            self._expire()
            if buffer.terminal == "lost":
                raise Failure("output_unavailable", "unknown")
            first = buffer.frames[0][1]["sequence"] if buffer.frames else buffer.high
            frames: list[dict[str, Any]] = []
            size = 0
            for _, frame in buffer.frames:
                if frame["sequence"] < cursor:
                    continue
                amount = len(frame["text"].encode())
                if size + amount > request["limit_bytes"]:
                    if not frames:
                        raise Failure("limit_exceeded")
                    break
                frames.append(dict(frame))
                size += amount
                if len(frames) == request["max_frames"]:
                    break
            next_cursor = frames[-1]["sequence"] + 1 if frames else max(cursor, first)
            eof = {
                stream: buffer.terminal == "eof"
                and not any(
                    f["stream"] == stream and f["sequence"] >= next_cursor for _, f in buffer.frames
                )
                for stream in ("stdout", "stderr")
            }
        end = "page" if frames else "wait_timeout"
        if execution == "exited":
            end = "process_exit"
        elif any(eof.values()):
            end = "stream_end"
        return {
            "frames": frames,
            "first_available_cursor": first,
            "next_cursor": next_cursor,
            "gap": first > cursor,
            "stdout_eof": eof["stdout"],
            "stderr_eof": eof["stderr"],
            "execution_state": execution,
            "exit_code": code,
            "observation_end": end,
        }


class Backend(Protocol):
    """Only provider-native work; wire authority and retry policy live above it."""

    kind: str
    authority: str
    sdks: dict[str, str]

    def create(self, identity: dict[str, Any], env: dict[str, str]) -> None: ...
    def get(self, identity: dict[str, Any]) -> str: ...
    def destroy(self, identity: dict[str, Any]) -> str: ...
    def run(self, request: dict[str, Any], *, deadline: float) -> dict[str, Any]: ...
    def read(self, request: dict[str, Any]) -> bytes: ...
    def write(self, request: dict[str, Any], data: bytes) -> None: ...
    def start(
        self, request: dict[str, Any], output: Output
    ) -> tuple[str, Callable[[], tuple[str, int | None]]]: ...


class BufferedCommandBackend(Protocol):
    """Optional native execution extension; baseline backends need not implement it."""

    def run_buffered(
        self, request: dict[str, Any], *, execution_limit_ms: int
    ) -> dict[str, Any]: ...


class AdmissionBackend(Protocol):
    """Requestful create and retained observations required by HTTP binding 0.3.

    ``labels`` in observations are the authoritative caller-visible public map.
    Provider ownership, identity, grants and other internal metadata belong in a
    separate backend field and are never serialized as public labels.
    """

    def offerings(self, account: str) -> list[dict[str, Any]]: ...
    def create_admitted(
        self,
        identity: dict[str, Any],
        request: dict[str, Any],
        env: dict[str, str],
        labels: dict[str, Any],
        admission: dict[str, Any],
    ) -> dict[str, Any]: ...
    def observe_admitted(self, identity: dict[str, Any]) -> dict[str, Any]: ...


class Endpoint:
    """Reference WSGI handler for the SPS HTTP protocol.

    The integrating service owns hosting, transport security and Cloud admission.
    """

    def __init__(
        self,
        backend: Backend,
        database: Path,
        tokens: dict[str, str],
        *,
        settings: EndpointSettings,
    ) -> None:
        self.backend, self.database, self.tokens = backend, database, tokens
        self.settings = settings
        if settings.binding_version not in (None, "0.1", "0.2", "0.3"):
            raise ValueError("Unsupported HTTP binding version")
        if settings.binding_version == "0.1" and settings.buffered_commands:
            raise ValueError("Binding 0.1 cannot enable buffered commands")
        if settings.binding_version == "0.2" and not settings.buffered_commands:
            raise ValueError("Binding 0.2 requires buffered_commands=True")
        if not _bounded_positive_integer(
            settings.control_response_cap, validation.BOOTSTRAP_CONTROL_RESPONSE_BYTES
        ):
            raise ValueError("Control response cap must be positive and at most 4 MiB")
        if settings.binding_version == "0.3" and not all(
            callable(getattr(backend, name, None))
            for name in ("offerings", "create_admitted", "observe_admitted")
        ):
            raise ValueError("Binding 0.3 requires requestful admission backend support")
        if settings.binding_version == "0.3" and not callable(
            getattr(backend, "run_buffered", None)
        ):
            raise ValueError("Binding 0.3 requires buffered command backend support")
        if self._buffered_enabled:
            if not callable(getattr(backend, "run_buffered", None)):
                raise ValueError("Buffered command mode requires a backend implementation")
            output_limit = settings.buffered_command_output_bytes
            execution_limit = settings.execution_ms
            execution_maximum = (
                MAX_EXECUTION_MS_03 if settings.binding_version == "0.3" else MAX_EXECUTION_MS
            )
            if not _bounded_positive_integer(output_limit, MAX_BUFFERED_OUTPUT_BYTES) or not (
                _bounded_positive_integer(execution_limit, execution_maximum)
            ):
                raise ValueError("Buffered command mode requires bounded output and execution caps")
        elif (
            settings.buffered_command_output_bytes is not None or settings.execution_ms is not None
        ):
            raise ValueError("Buffered command caps require buffered_commands=True")
        self._runtime = _EndpointRuntime()
        validation.validate_discovery(
            self.discovery(
                "endpoint-origin-validation",
                include_offerings=settings.binding_version != "0.3",
            )
        )
        with self.connect() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS allocations (account TEXT, key TEXT, "
                "digest TEXT, result TEXT, PRIMARY KEY(account,key))"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS clock "
                "(id INTEGER PRIMARY KEY CHECK(id=1), floor INTEGER)"
            )
            db.execute("INSERT OR IGNORE INTO clock VALUES (1,0)")
            db.execute(
                "CREATE TABLE IF NOT EXISTS authority "
                "(id INTEGER PRIMARY KEY CHECK(id=1), value TEXT)"
            )
            authority = json.dumps([backend.kind, backend.authority])
            db.execute("INSERT OR IGNORE INTO authority VALUES (1,?)", (authority,))
            if db.execute("SELECT value FROM authority WHERE id=1").fetchone()[0] != authority:
                raise ValueError("Native authority does not match the allocation store")
            if settings.binding_version == "0.3":
                rows = db.execute("SELECT result FROM allocations").fetchall()
                if any(self._stored_metadata(row[0])["admission"] is None for row in rows):
                    raise ValueError(
                        "Binding 0.3 cannot adopt allocation rows without retained admission"
                    )

    @staticmethod
    def before_native(deadline: float) -> None:
        if time.monotonic() >= deadline:
            raise Failure("timeout")

    def observe(
        self, call: Callable[[], T], deadline: float, *, timeout_outcome: str = "unknown"
    ) -> T:
        """Bound caller waiting, never cancel/retry native work or free its slot early."""
        with self._runtime.observations:
            if self._runtime.closed or self._runtime.pending >= 8:
                raise Failure("provider_error")
            if time.monotonic() >= deadline:
                raise Failure("timeout")
            self._runtime.pending += 1
        result: Future[T] = Future()

        def work() -> None:
            try:
                # Scheduling consumes this deadline; do not dispatch a queued late call.
                if time.monotonic() >= deadline:
                    raise Failure("timeout")
                result.set_result(call())
            except BaseException as error:  # pylint: disable=broad-exception-caught
                # Transfer even process-control exceptions to the waiting caller thread.
                result.set_exception(error)
            finally:
                with self._runtime.observations:
                    self._runtime.pending -= 1
                    self._runtime.observations.notify_all()

        try:
            Thread(target=work, daemon=True).start()
        except RuntimeError:
            with self._runtime.observations:
                self._runtime.pending -= 1
                self._runtime.observations.notify_all()
            raise
        try:
            return result.result(timeout=max(0, deadline - time.monotonic()))
        except TimeoutError:
            raise Failure("timeout", timeout_outcome) from None

    def close(self, timeout: float | None = None) -> None:
        """Explicit owner shutdown; never called on the request-timeout path."""
        # A buffered native call can outlive the HTTP observation deadline while
        # it completes its own execution and termination bounds.
        close_timeout = timeout
        if close_timeout is None:
            execution_ms = self.settings.execution_ms or 0
            observation_ms = self.settings.operation_timeout_ms
            close_timeout = max(15.0, execution_ms / 1000 + 8, observation_ms / 1000 + 2)
        with self._runtime.observations:
            self._runtime.closed = True
            if not self._runtime.observations.wait_for(
                lambda: self._runtime.pending == 0, close_timeout
            ):
                raise RuntimeError("Native observations still in flight; backend remains owned")

    @property
    def _buffered_enabled(self) -> bool:
        return self.settings.buffered_commands or self.settings.binding_version == "0.3"

    @property
    def _admission_backend(self) -> AdmissionBackend:
        return cast(AdmissionBackend, self.backend)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        with closing(sqlite3.connect(self.database, timeout=10)) as db:
            with db:
                yield db

    def discovery(self, account: str, *, include_offerings: bool = True) -> dict[str, Any]:
        # Empty facts/evidence/gates deliberately establish NO baseline or optional claim.
        declaration = {
            "spec": "sandbox-provider-spec/0.1",
            "provider": self.backend.kind,
            "class": "container",
            "verified": {"date": date.today().isoformat(), "sdks": self.backend.sdks},
            "resources": {},
            "gates": {},
            "evidence": {},
        }
        binding = (
            HTTP_BINDING_03
            if self.settings.binding_version == "0.3"
            else HTTP_BINDING_02
            if self.settings.buffered_commands
            else HTTP_BINDING_01
        )
        core_modes = [BUFFERED_COMMANDS] if self._buffered_enabled else []
        limits = {
            "request_bytes": 1048576,
            "response_bytes": 1048576,
            "command_output_bytes": 65536,
            "file_bytes": 65536,
            "page_size": 100,
            "output_frames": 100,
            "observation_ms": self.settings.operation_timeout_ms,
            "process_buffer_bytes": 65536,
        }
        if binding == HTTP_BINDING_03:
            limits["file_bytes"] = 16 * 1024 * 1024
        if self._buffered_enabled:
            output_cap = self.settings.buffered_command_output_bytes
            execution_cap = self.settings.execution_ms
            if output_cap is None or execution_cap is None:
                raise ValueError("Buffered command mode requires bounded output and execution caps")
            limits.update(
                request_bytes=32 * 1024 * 1024,
                response_bytes=64 * 1024 * 1024,
                buffered_command_output_bytes=output_cap,
                execution_ms=execution_cap,
            )
        if binding in (HTTP_BINDING_02, HTTP_BINDING_03):
            token_content = {
                "declaration": declaration,
                "binding": binding,
                "core_modes": core_modes,
                "limits": limits,
            }
            token_bytes = json.dumps(token_content, sort_keys=True, separators=(",", ":")).encode()
        else:
            # Keep 0.1 declaration identities byte-for-byte compatible with the original.
            token_bytes = json.dumps(declaration, sort_keys=True).encode()
        declaration_id = "sha256:" + hashlib.sha256(token_bytes).hexdigest()
        offering = {
            "offering_id": "container",
            "declaration_id": declaration_id,
            "declaration": declaration,
        }
        return {
            "binding": binding,
            "endpoint_origin": self.settings.endpoint_origin,
            "provider_id": self.backend.kind,
            "account_id": account,
            "server_revision": "private-reference-1",
            "operations": list(OPERATIONS),
            "limits": limits,
            "create_key_window_seconds": 86400,
            "process_retention_seconds": 60,
            "process_addressability": "endpoint_lifetime",
            "core_modes": core_modes,
            "offerings": (
                self._admission_backend.offerings(account)
                if binding == HTTP_BINDING_03 and include_offerings
                else []
                if binding == HTTP_BINDING_03
                else [offering]
            ),
        }

    @staticmethod
    def _stored_allocation(raw: str) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """Read current records and legacy 0.1 rows from the same ownership table."""
        value = json.loads(raw)
        if isinstance(value, dict) and "_selection" in value:
            selection = value["_selection"]
            return {
                key: item
                for key, item in value.items()
                if key not in ("_selection", "_failure", "_admission")
            }, selection
        return value, None

    @staticmethod
    def _stored_metadata(raw: str) -> dict[str, Any]:
        value = json.loads(raw)
        return {"admission": value.get("_admission")}

    @staticmethod
    def _stored_failure(raw: str) -> dict[str, Any] | None:
        """Return only the private structured refusal retained with an allocation row."""
        value = json.loads(raw)
        return value.get("_failure") if isinstance(value, dict) else None

    def _selection(self, account: str, discovery: dict[str, Any] | None = None) -> dict[str, Any]:
        current = discovery or self.discovery(account)
        selection = {
            "binding": current["binding"],
            "core_modes": current["core_modes"],
            "limits": dict(current["limits"]),
            "offering": current["offerings"][0],
        }
        if current["binding"] == HTTP_BINDING_03:
            selection.update(
                process_retention_seconds=current["process_retention_seconds"],
                process_addressability=current["process_addressability"],
            )
        return selection

    def _discovery_for_selection(self, account: str, selection: dict[str, Any]) -> dict[str, Any]:
        current = self.discovery(account, include_offerings=selection["binding"] != HTTP_BINDING_03)
        return {
            **current,
            "binding": selection["binding"],
            "core_modes": selection["core_modes"],
            "limits": selection["limits"],
            "offerings": [selection["offering"]],
            **(
                {
                    "process_retention_seconds": selection["process_retention_seconds"],
                    "process_addressability": selection["process_addressability"],
                }
                if selection["binding"] == HTTP_BINDING_03
                else {}
            ),
        }

    @staticmethod
    def envelope(request: dict[str, Any]) -> dict[str, Any]:
        return {key: request.get(key) for key in ("operation", "request_id", "account_id")}

    def authenticate(self, authorization: str) -> str:
        for token, account in self.tokens.items():
            if hmac.compare_digest(authorization.encode(), ("Bearer " + token).encode()):
                return account
        raise Failure("unauthenticated")

    def create(
        self, request: dict[str, Any], raw: bytes, digest: str, *, deadline: float
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        discovery = self.discovery(request["account_id"], include_offerings=False)
        if digest != "sha256:" + hashlib.sha256(raw).hexdigest():
            raise Failure("invalid_request")
        key, account = request["allocation_key"], request["account_id"]
        issued = int(key.split(":", 1)[0])
        result = {
            **self.envelope(request),
            "allocation_key": key,
            "request_digest": digest,
            "key_expires_at": issued + 86400,
            "state": "unknown",
            "sandbox": None,
        }
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            now = max(
                int(self.settings.clock()),
                db.execute("SELECT floor FROM clock WHERE id=1").fetchone()[0],
            )
            db.execute("UPDATE clock SET floor=? WHERE id=1", (now,))
            db.commit()  # Clock rollback cannot resurrect expired keys, including after restart.
            if now >= issued + 86400:
                raise Failure("expired_key")
            if issued > now + 60:
                raise Failure("invalid_request")
            db.execute("BEGIN IMMEDIATE")
            prior = db.execute(
                "SELECT digest,result FROM allocations WHERE account=? AND key=?", (account, key)
            ).fetchone()
            if prior:
                if prior[0] != digest:
                    raise Failure("conflict")
                result, selection = self._stored_allocation(prior[1])
                failure = self._stored_failure(prior[1])
                if failure is not None:
                    raise Failure(failure["code"], failure["outcome"], failure["exit_code"])
                if selection is None:
                    selected_discovery = self._legacy_discovery(account)
                else:
                    selected_discovery = self._discovery_for_selection(account, selection)
                if result["sandbox"] is not None:
                    self.before_native(deadline)
                    if selected_discovery["binding"] == HTTP_BINDING_03:
                        observation = self._admission_backend.observe_admitted(result["sandbox"])
                        result.update(
                            state={
                                "active": "ready",
                                "ready": "ready",
                                "pending": "pending",
                                "unknown": "unknown",
                            }.get(observation["state"], "unavailable"),
                            admission=self._stored_metadata(prior[1])["admission"],
                            labels=observation["labels"],
                            lifetime=observation["lifetime"],
                        )
                        try:
                            validation.validate_exchange(
                                request,
                                result,
                                selected_discovery,
                                request_body=raw,
                                digest=digest,
                                replay_admission=self._stored_metadata(prior[1])["admission"],
                                control_response_cap=self.settings.control_response_cap,
                            )
                        except ValueError:
                            raise Failure("provider_error", "unknown") from None
                    else:
                        observed = self.backend.get(result["sandbox"])
                        result["state"] = (
                            "ready"
                            if observed == "active"
                            else "unknown"
                            if observed == "unknown"
                            else "unavailable"
                        )
                return result, selected_discovery
            admission = None
            if discovery["binding"] == HTTP_BINDING_03:
                discovery = self.discovery(account)
                try:
                    admission = validation.validate_new_create_03(
                        request, discovery, request_body=raw
                    )
                except ValueError as failure:
                    raise Failure(getattr(failure, "code", "invalid_request")) from None
                selection = admission["selection"]
                result.update(admission=None, labels=None, lifetime=None)
            else:
                try:
                    validation.validate_request(request, discovery, request_body=raw)
                except ValueError as failure:
                    raise Failure(getattr(failure, "code", "invalid_request")) from None
                current_offering = next(
                    (
                        offering
                        for offering in discovery["offerings"]
                        if offering["offering_id"] == request["offering_id"]
                    ),
                    None,
                )
                if (
                    current_offering is None
                    or request["declaration_id"] != current_offering["declaration_id"]
                ):
                    raise Failure("conflict")
                if request["request"]:
                    raise Failure("unsupported_mode")
                selection = self._selection(account, discovery)
            record = {**result, "_selection": selection}
            if admission is not None:
                record["_admission"] = admission
            db.execute(
                "INSERT INTO allocations VALUES (?,?,?,?)",
                (account, key, digest, json.dumps(record)),
            )
        # Reservation commits BEFORE native dispatch. A crash leaves unknown, never a second create.
        identity = {
            "provider_id": self.backend.kind,
            "account_id": account,
            "offering_id": request["offering_id"],
            "sandbox_id": uuid.uuid4().hex,
            "incarnation": uuid.uuid4().hex,
        }
        try:
            self.before_native(deadline)
            if admission is None:
                self.backend.create(identity, request["env"])
            else:
                observation = self._admission_backend.create_admitted(
                    copy.deepcopy(identity),
                    copy.deepcopy(request["request"]),
                    copy.deepcopy(request["env"]),
                    copy.deepcopy(request["labels"]),
                    copy.deepcopy(admission),
                )
                if observation["state"] not in ("active", "ready"):
                    raise Failure("provider_error", "unknown")
                result.update(
                    state="ready",
                    sandbox=identity,
                    admission=admission,
                    labels=observation["labels"],
                    lifetime=observation["lifetime"],
                )
                try:
                    validation.validate_exchange(
                        request,
                        result,
                        discovery,
                        request_body=raw,
                        digest=digest,
                        control_response_cap=self.settings.control_response_cap,
                    )
                except ValueError:
                    uncertain = {
                        **result,
                        "state": "unknown",
                        "sandbox": identity,
                        "admission": admission,
                        "labels": None,
                        "lifetime": None,
                    }
                    record = {
                        **uncertain,
                        "_selection": selection,
                        "_admission": admission,
                    }
                    with self.connect() as db:
                        db.execute(
                            "UPDATE allocations SET result=? WHERE account=? AND key=?",
                            (json.dumps(record), account, key),
                        )
                    raise Failure("provider_error", "unknown") from None
        except Failure as failure:
            # A settled typed result remains definitive after the observer deadline; unknown
            # failures keep the reservation uncertain and never authorize another create.
            if failure.outcome != "unknown":
                record = {
                    **result,
                    "_selection": selection,
                    **({"_admission": admission} if admission is not None else {}),
                    "_failure": {
                        "code": failure.code,
                        "outcome": failure.outcome,
                        "exit_code": failure.exit_code,
                    },
                }
                with self.connect() as db:
                    db.execute(
                        "UPDATE allocations SET result=? WHERE account=? AND key=? AND digest=?",
                        (json.dumps(record), account, key, digest),
                    )
            raise
        if admission is None:
            result.update(state="ready", sandbox=identity)
        record = {**result, "_selection": selection}
        if admission is not None:
            record["_admission"] = admission
        with self.connect() as db:
            db.execute(
                "UPDATE allocations SET result=? WHERE account=? AND key=?",
                (json.dumps(record), account, key),
            )
        return result, discovery

    def check_identity(self, identity: dict[str, Any], account: str) -> dict[str, Any]:
        if identity["account_id"] != account or identity["provider_id"] != self.backend.kind:
            raise Failure("forbidden")
        # Verify the entire incarnation before any backend call; never authorize a guessed ID.
        with self.connect() as db:
            rows = db.execute(
                "SELECT result FROM allocations WHERE account=?", (account,)
            ).fetchall()
        for row in rows:
            response, selection = self._stored_allocation(row[0])
            if response["sandbox"] == identity:
                return selection or self._selection(account, self._legacy_discovery(account))
        raise Failure("invalid_request")

    def _admission_for_identity(self, identity: dict[str, Any], account: str) -> dict[str, Any]:
        with self.connect() as db:
            rows = db.execute(
                "SELECT result FROM allocations WHERE account=?", (account,)
            ).fetchall()
        for row in rows:
            result, _selection = self._stored_allocation(row[0])
            if result.get("sandbox") == identity and result.get("admission") is not None:
                return cast(dict[str, Any], result["admission"])
        raise Failure("invalid_request")

    def _legacy_discovery(self, account: str) -> dict[str, Any]:
        """Build the original baseline selection used by pre-0.2 allocation rows."""
        current = self.discovery(account)
        offering = current["offerings"][0]
        declaration_id = (
            "sha256:"
            + hashlib.sha256(
                json.dumps(offering["declaration"], sort_keys=True).encode()
            ).hexdigest()
        )
        return {
            **current,
            "binding": HTTP_BINDING_01,
            "core_modes": [],
            "limits": {
                "request_bytes": 1048576,
                "response_bytes": 1048576,
                "command_output_bytes": 65536,
                "file_bytes": 65536,
                "page_size": 100,
                "output_frames": 100,
                "observation_ms": 5000,
                "process_buffer_bytes": 65536,
            },
            "offerings": [{**offering, "declaration_id": declaration_id}],
        }

    def inventory(self, request: dict[str, Any], *, deadline: float) -> dict[str, Any]:
        account, offering = request["account_id"], request["offering_id"]
        offset = 0
        if request["cursor"] is not None:
            scope = self._runtime.cursors.get(request["cursor"])
            if scope is None or scope[:2] != (account, offering):
                raise Failure("invalid_request")
            offset = scope[2]
        with self.connect() as db:
            rows = db.execute(
                "SELECT result FROM allocations WHERE account=? ORDER BY key", (account,)
            ).fetchall()
        items = []
        for row in rows:
            allocation, _selection = self._stored_allocation(row[0])
            identity = allocation["sandbox"]
            if identity is None or offering not in (None, identity["offering_id"]):
                continue
            self.before_native(deadline)
            if self.settings.binding_version == "0.3":
                observation = self._admission_backend.observe_admitted(identity)
                if observation["state"] != "absent":
                    items.append(
                        {
                            "sandbox": identity,
                            "state": observation["state"],
                            "labels": observation["labels"],
                            "lifetime": observation["lifetime"],
                        }
                    )
            else:
                state = self.backend.get(identity)
                if state != "absent":
                    items.append({"sandbox": identity, "state": state})
        page = items[offset : offset + request["page_size"]]
        end = offset + len(page)
        cursor = None
        if end < len(items):
            cursor = uuid.uuid4().hex
            self._runtime.cursors[cursor] = (account, offering, end)
        return {"items": page, "next_cursor": cursor}

    def dispatch(
        self, request: dict[str, Any], raw: bytes, digest: str
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        operation = request["operation"]
        deadline = (
            time.monotonic()
            + request.get("observation_timeout_ms", self.settings.operation_timeout_ms) / 1000
        )
        result = self.envelope(request)
        if operation == "create":
            return self.observe(
                lambda: self.create(request, raw, digest, deadline=deadline), deadline
            )
        if operation == "list":
            discovery = self.discovery(
                request["account_id"],
                include_offerings=self.settings.binding_version != "0.3",
            )
            try:
                validation.validate_request(request, discovery)
            except ValueError as failure:
                raise Failure(getattr(failure, "code", "invalid_request")) from None
            return (
                {
                    **result,
                    **self.observe(lambda: self.inventory(request, deadline=deadline), deadline),
                },
                discovery,
            )
        identity = (
            request["process"]["sandbox"] if operation == "process.output" else request["sandbox"]
        )
        selection = self.observe(
            lambda: self.check_identity(identity, request["account_id"]),
            deadline,
            timeout_outcome="not_dispatched",
        )
        selected_discovery = self._discovery_for_selection(request["account_id"], selection)
        try:
            validation.validate_request(request, selected_discovery)
        except ValueError as failure:
            raise Failure(getattr(failure, "code", "invalid_request")) from None
        if operation == "process.output":
            retained = self._runtime.processes.get(request["process"]["process_id"])
            if retained is None or retained[0] != request["process"]:
                raise Failure("output_unavailable", "unknown")
            return {
                **result,
                "process": retained[0],
                **retained[1].page(
                    request, lambda: self.observe(retained[2], deadline), deadline=deadline
                ),
            }, selected_discovery
        if operation == "process.start":
            output = Output(
                selection["limits"]["process_buffer_bytes"],
                selection.get("process_retention_seconds", 60),
            )
            native, observe = self.observe(lambda: self.backend.start(request, output), deadline)
            process = {"sandbox": identity, "process_id": native, "incarnation": uuid.uuid4().hex}
            self._runtime.processes[native] = (process, output, observe)
            return {**result, "process": process}, selected_discovery
        result["sandbox"] = identity
        if operation == "get" and selection["binding"] == HTTP_BINDING_03:
            observation = self.observe(
                lambda: self._admission_backend.observe_admitted(identity), deadline
            )
            result.update(
                state=observation["state"],
                admission=self._admission_for_identity(identity, request["account_id"]),
                labels=observation["labels"],
                lifetime=observation["lifetime"],
            )
            try:
                validation.validate_exchange(
                    request,
                    result,
                    selected_discovery,
                    control_response_cap=self.settings.control_response_cap,
                )
            except ValueError:
                raise Failure("provider_error", "unknown") from None
        elif operation in ("get", "destroy"):
            result["state"] = self.observe(
                lambda: getattr(self.backend, operation)(identity), deadline
            )
        elif operation == "run":
            if request.get("mode") == BUFFERED_COMMANDS:
                if BUFFERED_COMMANDS not in selection["core_modes"]:
                    raise Failure("unsupported_mode")
                run_buffered = getattr(self.backend, "run_buffered", None)
                if not callable(run_buffered):
                    raise Failure("unsupported_mode")
                run_buffered_call = cast(Callable[..., dict[str, Any]], run_buffered)
                result.update(
                    self.observe(
                        lambda: run_buffered_call(
                            request, execution_limit_ms=request["execution_limit_ms"]
                        ),
                        deadline,
                    )
                )
            else:
                result.update(
                    self.observe(lambda: self.backend.run(request, deadline=deadline), deadline)
                )
        elif operation == "files.read_bytes":
            data = self.observe(lambda: self.backend.read(request), deadline)
            if len(data) > request["limit_bytes"]:
                raise Failure("limit_exceeded", "completed")
            result.update(
                data_base64=base64.b64encode(data).decode(), byte_count=len(data), complete=True
            )
        elif operation == "files.write":
            data = base64.b64decode(request["data_base64"], validate=True)
            self.observe(lambda: self.backend.write(request, data), deadline)
            result["written_bytes"] = len(data)
        return result, selected_discovery

    def handle(
        self,
        method: str,
        path: str,
        authorization: str,
        raw: bytes,
        headers: dict[str, str],
    ) -> tuple[int, bytes]:
        path_operation = next(
            (name for name, value in OPERATIONS.items() if value["path"] == path), None
        )
        request: dict[str, Any] = {"operation": path_operation}
        discovery_path = path == "/.well-known/sandbox-provider-spec.json"
        try:
            account = self.authenticate(authorization)
            discovery = self.discovery(account, include_offerings=False)
            if discovery_path and method == "GET":
                discovery = self.discovery(account)
                validation.validate_message("Discovery", discovery)
                return 200, json.dumps(discovery).encode()
            if method != "POST" or path not in [op["path"] for op in OPERATIONS.values()]:
                raise Failure("invalid_request")
            if headers.get("content_type", "application/json") != "application/json":
                raise Failure("invalid_request")
            # Decode against the protocol-wide maximum. The selected allocation's stored
            # limits are checked inside dispatch under the operation deadline.
            request = validation.decode_json(raw, 32 * 1024 * 1024)
            if not isinstance(request, dict):
                request = {"operation": path_operation}
                raise Failure("invalid_request")
            operation = request.get("operation")
            if (
                not isinstance(operation, str)
                or operation not in OPERATIONS
                or OPERATIONS[operation]["path"] != path
            ):
                raise Failure("invalid_request")
            validation.validate_message(
                validation.message_shape(discovery["binding"], operation, "request"), request
            )
            if request["account_id"] != account:
                raise Failure("forbidden")
            identity = request.get("sandbox") or request.get("process", {}).get("sandbox")
            if identity and (
                identity["account_id"] != account or identity["provider_id"] != self.backend.kind
            ):
                raise Failure("forbidden")
        except Failure as failure:
            return self.error({**request, "operation": path_operation}, failure, discovery_path)
        except ValueError as failure:
            return self.error(
                {**request, "operation": path_operation},
                Failure(getattr(failure, "code", "invalid_request")),
                discovery_path,
            )
        try:
            digest = headers.get("digest", "")
            response, selected_discovery = self.dispatch(request, raw, digest)
            payload = json.dumps(response).encode()
            response_limit = selected_discovery["limits"]["response_bytes"]
            if (
                request.get("operation") == "get"
                and selected_discovery["binding"] == HTTP_BINDING_03
            ):
                response_limit = min(
                    response_limit,
                    validation.BOOTSTRAP_CONTROL_RESPONSE_BYTES,
                    self.settings.control_response_cap,
                )
            if len(payload) > response_limit:
                raise Failure("limit_exceeded", "completed")
            validation.validate_exchange(
                request,
                response,
                selected_discovery,
                request_body=raw,
                digest=digest,
                control_response_cap=self.settings.control_response_cap,
            )
            return 200, payload
        except Failure as failure:
            return self.error(request, failure)
        except Exception:  # pylint: disable=broad-exception-caught
            # The PP1 boundary classifies every unexpected native failure without exposing it.
            return self.error(request, Failure("provider_error", "unknown"))

    def error(
        self, request: dict[str, Any], failure: Failure, discovery: bool = False
    ) -> tuple[int, bytes]:
        # Status mapping is consumed from PP1, not independently defined here.
        status = validation.STATUS[failure.code]
        if discovery and status in (401, 403):
            return status, b""
        envelope = self.envelope(request)
        if envelope["operation"] not in list(OPERATIONS):
            return 404, b""
        for field in ("request_id", "account_id"):
            try:
                validation.validate_message("Identifier", envelope[field])
            except ValueError:
                envelope[field] = None
        response = {
            **envelope,
            "error": {
                "code": failure.code,
                "outcome": failure.outcome,
                "message": "Reference operation could not satisfy the requested contract",
                "exit_code": failure.exit_code,
            },
        }
        return status, json.dumps(response).encode()

    def __call__(
        self, environ: dict[str, Any], start_response: Callable[..., Any]
    ) -> Iterable[bytes]:
        # The test transport is HTTPX WSGITransport: no listener, TLS or external access.
        try:
            length = int(environ.get("CONTENT_LENGTH") or "0")
        except ValueError:
            length = -1
        request_limit = 32 * 1024 * 1024 if self._buffered_enabled else 1048576
        if length < 0 or length > request_limit:
            operation = next(
                (
                    name
                    for name, value in OPERATIONS.items()
                    if value["path"] == environ["PATH_INFO"]
                ),
                None,
            )
            status, body = self.error({"operation": operation}, Failure("limit_exceeded"))
        else:
            status, body = self.handle(
                environ["REQUEST_METHOD"],
                environ["PATH_INFO"],
                environ.get("HTTP_AUTHORIZATION", ""),
                environ["wsgi.input"].read(length),
                {
                    "digest": environ.get("HTTP_SPS_REQUEST_DIGEST", ""),
                    "content_type": environ.get("CONTENT_TYPE", ""),
                },
            )
        start_response(
            f"{status} {HTTPStatus(status).phrase}",
            [("Content-Type", "application/json"), ("Content-Length", str(len(body)))],
        )
        return [body]
