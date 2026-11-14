# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Run the shared conformance tests against a 1.0 `Provider`.

The suite's runner is synchronous and speaks the `Driver` contract: one method per operation,
named after the operation with dots replaced by underscores. `ProviderDriver` implements those
methods by calling a `Provider`, whether that is an adapter or an `HttpProvider`.
"""

from __future__ import annotations

import asyncio
import base64
import builtins
import threading
import time
from collections.abc import AsyncIterator, Awaitable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from importlib.metadata import version
from typing import Any, TypeVar, cast
from uuid import uuid4

from sandbox_provider_spec.driver import (
    Driver,
    Inputs,
    NativeFailure,
    NotRun,
    Observation,
    Unsupported,
    number,
    resource,
    strings,
    text,
)
from sandbox_provider_spec.v1.errors import SpsError
from sandbox_provider_spec.v1.provider import Provider
from sandbox_provider_spec.v1.types import (
    Cost,
    CreateRequest,
    FileLinkRequest,
    ProcessStartRequest,
    RunRequest,
    Sandbox,
)
from sandbox_provider_spec.v1.wire import WireError, to_json

T = TypeVar("T")

RUN_LABEL = "sps.test.run"
"""Every sandbox that a test run creates carries this label, with the run id as its value."""

# Operations that the 1.0 interface has no counterpart for. A test that needs one is
# `unsupported`, and a provider is never told to implement it.
NOT_IN_1_0 = {
    "process.reattach": "SPS 1.0 has no operation to reattach to a process",
    "process.disconnect": "SPS 1.0 has no operation to disconnect from a process",
    "preview.revoke": "SPS 1.0 has no operation to revoke a preview link",
}

# Create inputs that SPS 1.0 maps to a field of `CreateRequest`.
CREATE_INPUTS = frozenset(
    {
        "environment",
        "requirements",
        "resources",
        "lifetime_seconds",
        "at_end",
        "image",
        "labels",
        "idempotency_key",
    }
)

# An id that no provider has issued: it fits the id syntax (contract section 3) and names nothing.
UNKNOWN_SANDBOX_ID = "sps-test-no-such-sandbox"

_ONE_GIB = 1 << 30
_COST_WAIT_MS = 120_000  # how long cost.final waits for a final cost when a test names no limit

_OUTPUT_WAIT_MS = 1000
_WAIT_MS = 60_000  # how long process.wait waits for an exit when a test names no limit

# Provider-fault codes that a retry can outlast.
RETRYABLE = frozenset({"provider_error", "unavailable", "timeout", "rate_limited"})


@dataclass
class SandboxHandle:
    """What a sandbox resource keeps in memory."""

    id: str
    cost: Cost | None = None
    """The cost that the first destroy returned, when it returned one."""


@dataclass
class ProcessHandle:  # pylint: disable=too-many-instance-attributes
    """A background process and the output read from it so far."""

    sandbox_id: str
    process_id: str
    cursor: str | None = None
    stdout: bytearray = field(default_factory=bytearray)
    stderr: bytearray = field(default_factory=bytearray)
    stdout_closed: bool = False
    stderr_closed: bool = False
    state: str = "running"
    exit_code: int | None = None


def _iso(moment: datetime | None) -> str | None:
    return None if moment is None else moment.isoformat().replace("+00:00", "Z")


class ProviderDriver(Driver):  # pylint: disable=too-many-public-methods
    """A `Driver` whose operations call a `Provider`.

    `SpsError("unsupported")` becomes `Unsupported`; any other `SpsError` becomes
    `NativeFailure(code)`. The provider is async, so the driver runs its own event loop in a
    background thread and waits for each call.
    """

    implementation = "sandbox_provider_spec.v1.suite_driver.ProviderDriver"

    def __init__(
        self,
        provider: Provider,
        *,
        provider_id: str | None = None,
        run: str | None = None,
        unsupported: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__()
        self.api = provider
        self.provider = provider_id or str(getattr(type(provider), "provider_id", "unknown"))
        self.run_id = run or uuid4().hex
        self.sdk_versions = {"sandbox-provider-spec": version("sandbox-provider-spec")}
        self.unsupported = {**NOT_IN_1_0, **(unsupported or {})}
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True)
        self._thread.start()

    # Plumbing

    def wait(self, call: Awaitable[T]) -> T:
        """Run one provider call to its end and return the result."""

        async def guarded() -> T:
            return await call

        try:
            return asyncio.run_coroutine_threadsafe(guarded(), self._loop).result()
        except SpsError as error:
            if error.code == "unsupported":
                raise Unsupported(
                    "the provider reports that it does not support the operation"
                ) from None
            raise NativeFailure(error.code) from None

    def close(self) -> None:
        """Release the provider's clients and stop the loop."""
        try:
            self.wait(self.api.aclose())
        finally:
            self._loop.call_soon_threadsafe(self._loop.stop)
            self._thread.join(timeout=10)

    @staticmethod
    def _sandbox(target: object) -> str:
        native = resource(target).native
        if not isinstance(native, SandboxHandle):
            raise ValueError("operation requires a sandbox")
        return native.id

    @staticmethod
    def _process(target: object) -> ProcessHandle:
        native = resource(target).native
        if not isinstance(native, ProcessHandle):
            raise ValueError("operation requires a process")
        return native

    # Sandboxes

    def create(self, target: object, inputs: Inputs) -> Observation:
        del target
        extra = sorted(set(inputs) - CREATE_INPUTS)
        if extra:
            raise Unsupported("a create input that SPS 1.0 does not define")
        image = inputs.get("image")
        if image is not None and not isinstance(image, (str, Mapping)):
            raise Unsupported("an image that SPS 1.0 cannot name")
        request = CreateRequest(
            resources=cast(Mapping[str, object], inputs.get("resources", {})),
            requirements=cast(Mapping[str, object], inputs.get("requirements", {})),
            image=cast("str | Mapping[str, str] | None", image),
            at_end=cast(Any, inputs.get("at_end", "destroyed")),
            env=strings(inputs, "environment"),
            labels={**strings(inputs, "labels"), RUN_LABEL: self.run_id},
            lifetime_seconds=cast("int | None", inputs.get("lifetime_seconds", 300)),
        )
        created = self.wait(self.api.create(request, idempotency_key=self._key(inputs)))
        handle = SandboxHandle(created.id)
        owned = self.own("sandbox", handle, lambda: self._destroy(handle.id, handle))
        return {"resource": owned, "identity": created.id}

    def _key(self, inputs: Inputs) -> str:
        """The idempotency key of a create: fresh, or derived from the run and a test's name for
        it, so that two creates of one test share a key and no other test or run does."""
        name = inputs.get("idempotency_key")
        if name is None:
            return str(uuid4())
        if not isinstance(name, str) or not name:
            raise ValueError("idempotency_key must name the key")
        return f"sps-{self.run_id[:20]}-{name}"

    def _destroy(self, sandbox_id: str, handle: SandboxHandle | None = None) -> Observation:
        try:
            result = self.wait(self.api.destroy(sandbox_id))
            if handle is not None and result.cost is not None and handle.cost is None:
                handle.cost = result.cost
        except NativeFailure as error:
            if error.code != "not_found":
                raise
        return {"result": "deleted"}

    def get(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        try:
            sandbox = self.wait(self.api.get(self._sandbox(target)))
        except NativeFailure as error:
            if error.code == "not_found":
                return {"state": "destroyed"}
            raise
        labels = dict(sandbox.labels)
        if labels.get(RUN_LABEL) == self.run_id:
            del labels[RUN_LABEL]  # the tester's own label; a test names only the labels it set
        return {
            "state": "active" if sandbox.state == "running" else sandbox.state,
            "labels": labels,
        }

    def list(self, target: object, inputs: Inputs) -> Observation:
        del target
        wanted = {**strings(inputs, "labels"), RUN_LABEL: self.run_id}
        found: builtins.list[Sandbox] = []
        cursor: str | None = None
        while True:
            page = self.wait(self.api.list(labels=wanted, cursor=cursor))
            found.extend(page.sandboxes)
            cursor = page.next_cursor
            if cursor is None:
                break
        return {"sandboxes": [{"identity": item.id} for item in found], "count": len(found)}

    def destroy(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        return self.release(resource(target))

    def destroy_again(self, target: object, inputs: Inputs) -> Observation:
        """Destroy a sandbox that an earlier step already destroyed, and report the state."""
        del inputs
        return {"state": self.wait(self.api.destroy(self._sandbox(target))).state}

    def destroy_unknown(self, target: object, inputs: Inputs) -> Observation:
        """Destroy an id that the provider has never issued. The contract answers `not_found`."""
        del target, inputs
        return {"state": self.wait(self.api.destroy(UNKNOWN_SANDBOX_ID)).state}

    # Discovery and cost

    def discovery(self, target: object, inputs: Inputs) -> Observation:
        """Read the discovery document and judge it: a valid 1.0 document, a price on every
        class, and a file limit of at least 1 GiB (contract section 8)."""
        del target, inputs
        found = self.wait(self.api.discovery())
        try:
            to_json(found)
            valid = True
        except WireError:
            valid = False
        return {
            "valid": valid,
            "priced": bool(found.classes) and all(item.prices for item in found.classes),
            "file_limit_floor": found.limits.file_bytes >= _ONE_GIB,
        }

    def cost_final(self, target: object, inputs: Inputs) -> Observation:
        """Read the cost of a destroyed sandbox until it is final, and check what a final cost
        promises: it names the sandbox, a calculated total is the sum of its lines, and a second
        read states the same total. A provider that returns the final cost in the destroy result
        may no longer know the sandbox, and then the destroy result is the only read."""
        native = resource(target).native
        if not isinstance(native, SandboxHandle):
            raise ValueError("operation requires a sandbox")
        deadline = time.monotonic() + number(inputs, "timeout_ms", _COST_WAIT_MS) / 1000
        cost = native.cost if native.cost is not None and native.cost.status == "final" else None
        while cost is None:
            read = self.wait(self.api.cost(native.id))
            if read.status == "final":
                cost = read
            elif time.monotonic() >= deadline:
                raise NotRun("cost_not_final_in_window")
            else:
                time.sleep(2)
        try:
            again: Cost | None = self.wait(self.api.cost(native.id))
        except NativeFailure as error:
            if error.code != "not_found" or native.cost is None:
                raise
            again = None  # the destroy result carried the cost; the provider forgot the sandbox
        lines = sum((line.amount_usd for line in cost.lines), start=Decimal(0))
        return {
            "status": cost.status,
            "sandbox_matches": cost.sandbox_id == native.id,
            "total_matches_lines": cost.source == "reported" or lines == cost.total_usd,
            "stable": again is None
            or (again.status == "final" and again.total_usd == cost.total_usd),
        }

    # Commands and files

    def run(self, target: object, inputs: Inputs) -> Observation:
        if "run_as" in inputs or "user" in inputs:
            raise Unsupported("SPS 1.0 has no operation-level user selection")
        request = RunRequest(
            argv=["bash", "-c", text(inputs, "bash_script")],
            cwd=cast("str | None", inputs.get("cwd")),
            env=strings(inputs, "environment"),
            timeout_ms=number(inputs, "timeout_ms", 60_000),
        )
        result = self.wait(self.api.run(self._sandbox(target), request))
        return {
            "stdout": result.stdout.encode(),
            "stderr": result.stderr.encode(),
            "exit_code": result.exit_code,
            "timed_out": result.timed_out,
        }

    def files_read_bytes(self, target: object, inputs: Inputs) -> Observation:
        sandbox_id, path = self._sandbox(target), text(inputs, "path")

        async def read() -> bytes:
            stream = await self.api.files_read(sandbox_id, path)
            try:
                return b"".join([chunk async for chunk in stream.chunks])
            finally:
                closer = getattr(stream.chunks, "aclose", None)
                if closer is not None:
                    await closer()

        return {"data": self.wait(read())}

    def files_exists(self, target: object, inputs: Inputs) -> Observation:
        result = self.wait(
            self.api.run(
                self._sandbox(target), RunRequest(argv=["test", "-e", text(inputs, "path")])
            )
        )
        if result.exit_code not in (0, 1):
            raise NativeFailure("exists_check_failed")
        return {"exists": result.exit_code == 0}

    def files_write(self, target: object, inputs: Inputs) -> Observation:
        data = base64.b64decode(text(inputs, "data"), validate=True)

        async def chunks() -> AsyncIterator[bytes]:
            yield data

        self.wait(
            self.api.files_write(
                self._sandbox(target), text(inputs, "path"), chunks(), size=len(data)
            )
        )
        return {}

    def files_write_stream(self, target: object, inputs: Inputs) -> Observation:
        source = cast("Iterator[bytes]", iter(cast(Any, inputs["chunks"])))
        size = number(inputs, "size", 0)

        async def chunks() -> AsyncIterator[bytes]:
            for chunk in source:
                yield bytes(chunk)

        info = self.wait(
            self.api.files_write(self._sandbox(target), text(inputs, "path"), chunks(), size=size)
        )
        return {"written_bytes": info.size}

    def files_read_stream(self, target: object, inputs: Inputs) -> Observation:
        stream = self.wait(self.api.files_read(self._sandbox(target), text(inputs, "path")))
        chunks = aiter(stream.chunks)

        def read() -> Iterator[bytes]:
            try:
                while True:
                    try:
                        yield self.wait(_next(chunks))
                    except StopAsyncIteration:
                        return
            finally:
                closer = getattr(chunks, "aclose", None)
                if closer is not None:
                    self.wait(closer())

        return {"chunks": read(), "size": stream.size}

    def files_link(self, target: object, inputs: Inputs) -> Observation:
        if "user" in inputs:
            raise Unsupported("SPS 1.0 has no user selection for file links")
        request = FileLinkRequest(
            path=text(inputs, "path"),
            operation=cast(Any, text(inputs, "operation")),
            lifetime_seconds=number(inputs, "lifetime_seconds", 300),
            size=cast("int | None", inputs.get("size")),
        )
        link = self.wait(self.api.files_link(self._sandbox(target), request))
        return {
            "url": link.url,
            "method": link.method,
            "headers": dict(link.headers),
            "form_field": link.form_field,
            "expires_at": _iso(link.expires_at),
            "reusable": link.reusable,
        }

    # Background processes

    def process_start(self, target: object, inputs: Inputs) -> Observation:
        sandbox_id = self._sandbox(target)
        request = ProcessStartRequest(
            argv=["bash", "-c", text(inputs, "bash_script")],
            cwd=cast("str | None", inputs.get("cwd")),
            env=strings(inputs, "environment"),
            stdin="process.write_stdin" not in self.unsupported,
        )
        started = self.wait(self.api.process_start(sandbox_id, request))
        handle = ProcessHandle(sandbox_id, started.id)
        owned = self.own("process", handle, lambda: {"result": "already_released"})
        return {"resource": owned, "identity": started.id}

    def _read(self, handle: ProcessHandle, wait_ms: int) -> None:
        page = self.wait(
            self.api.process_output(
                handle.sandbox_id, handle.process_id, cursor=handle.cursor, wait_ms=wait_ms
            )
        )
        handle.cursor = page.next_cursor
        for chunk in page.chunks:
            (handle.stdout if chunk.stream == "stdout" else handle.stderr).extend(
                chunk.data.encode()
            )
        handle.stdout_closed = handle.stdout_closed or page.stdout_closed
        handle.stderr_closed = handle.stderr_closed or page.stderr_closed
        handle.state, handle.exit_code = page.state, page.exit_code

    def process_output(self, target: object, inputs: Inputs) -> Observation:
        handle = self._process(target)
        deadline = time.monotonic() + number(inputs, "timeout_ms", 15000) / 1000
        first_chunk = inputs.get("first_chunk") is True
        while True:
            self._read(handle, _OUTPUT_WAIT_MS)
            heard = bool(handle.stdout or handle.stderr)
            finished = handle.state == "exited" or (handle.stdout_closed and handle.stderr_closed)
            if finished or (first_chunk and heard) or time.monotonic() >= deadline:
                return {"stdout": bytes(handle.stdout), "stderr": bytes(handle.stderr)}

    def process_status(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        handle = self._process(target)
        self._read(handle, 0)
        return {"state": handle.state, "exit_code": handle.exit_code}

    def process_wait(self, target: object, inputs: Inputs) -> Observation:
        handle = self._process(target)
        deadline = time.monotonic() + number(inputs, "timeout_ms", _WAIT_MS) / 1000
        while True:
            self._read(handle, _OUTPUT_WAIT_MS)
            if handle.state == "exited":
                return {"exit_code": handle.exit_code}
            if time.monotonic() >= deadline:
                raise NotRun("native_process_still_running")

    def process_write_stdin(self, target: object, inputs: Inputs) -> Observation:
        handle = self._process(target)
        data = base64.b64decode(text(inputs, "data"), validate=True)
        self.wait(self.api.process_write_stdin(handle.sandbox_id, handle.process_id, data))
        return {}

    def process_close_stdin(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        handle = self._process(target)
        self.wait(self.api.process_close_stdin(handle.sandbox_id, handle.process_id))
        return {}

    def process_cancel(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        handle = self._process(target)
        self.wait(self.api.process_cancel(handle.sandbox_id, handle.process_id))
        return {}

    # Optional sections

    def pause(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        sandbox = self.wait(self.api.pause(self._sandbox(target)))
        return {"state": sandbox.state}

    def resume(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        sandbox = self.wait(self.api.resume(self._sandbox(target)))
        return {"state": "active" if sandbox.state == "running" else sandbox.state}

    def lifetime_extend(self, target: object, inputs: Inputs) -> Observation:
        sandbox = self.wait(
            self.api.lifetime_extend(self._sandbox(target), number(inputs, "lifetime_seconds", 0))
        )
        return {"ends_at": _iso(sandbox.ends_at)}

    def preview_link(self, target: object, inputs: Inputs) -> Observation:
        link = self.wait(self.api.preview_link(self._sandbox(target), number(inputs, "port", 0)))
        return {"url": link.url, "headers": dict(link.headers), "expires_at": _iso(link.expires_at)}

    def tcp_link(self, target: object, inputs: Inputs) -> Observation:
        link = self.wait(self.api.tcp_link(self._sandbox(target), number(inputs, "port", 0)))
        return {"host": link.host, "port": link.port}

    # Cleanup of anything a failed create left behind

    def leftovers(self) -> builtins.list[str]:
        """Ids of this run's sandboxes that the provider still lists.

        A provider fault while listing (for example a list that races with a sandbox that is
        still ending) is retried with a short backoff, since the answer is needed to know that
        nothing is left behind.
        """
        deadline = time.monotonic() + 30
        delay = 0.2
        while True:
            try:
                found = cast("builtins.list[dict[str, str]]", self.list(None, {})["sandboxes"])
                return [item["identity"] for item in found]
            except NativeFailure as error:
                if error.code not in RETRYABLE or time.monotonic() >= deadline:
                    raise
                time.sleep(delay)
                delay = min(delay * 2, 2.0)

    def sweep_run(self) -> builtins.list[Observation]:
        """Destroy every sandbox that still carries this run's label."""
        results: builtins.list[Observation] = []
        for sandbox_id in self.leftovers():
            try:
                results.append({"kind": "sandbox", **self._destroy(sandbox_id)})
            except Exception as error:  # pylint: disable=broad-exception-caught
                results.append(
                    {"kind": "sandbox", "result": "error", "reason": type(error).__name__}
                )
        return results


async def _next(iterator: AsyncIterator[bytes]) -> bytes:
    return await anext(iterator)
