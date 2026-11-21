# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The background-process steps of the shared tests (`process.output`, `process.status`,
`process.wait`, the stdin and cancel steps, and `process.disconnect` and `process.reattach`),
run through the `process_*` operations of a 1.0 `Provider`."""

from __future__ import annotations

import base64
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, TypeVar

from sandbox_provider_spec.driver import (
    Inputs,
    NotRun,
    Observation,
    Resource,
    number,
    text,
)
from sandbox_provider_spec.v1.provider import Provider

T = TypeVar("T")

_OUTPUT_WAIT_MS = 1000
_WAIT_MS = 60_000  # how long process.wait waits for an exit when a test names no limit


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
    client: Provider | None = None
    """The client that reads this process, when it is not the driver's own (a reattach)."""


class ProcessSteps:
    """The background-process steps of `ProviderDriver`, which inherits them."""

    if TYPE_CHECKING:
        api: Provider
        _new_client: Callable[[], Provider] | None
        _clients: list[Provider]

        def wait(self, call: Awaitable[T]) -> T:
            raise NotImplementedError

        def own(self, kind: str, native: object, cleanup: Callable[[], Observation]) -> Resource:
            raise NotImplementedError

        @staticmethod
        def _sandbox(target: object) -> str:
            raise NotImplementedError

        @staticmethod
        def _process(target: object) -> ProcessHandle:
            raise NotImplementedError

    def _read(self, handle: ProcessHandle, wait_ms: int) -> None:
        page = self.wait(
            (handle.client or self.api).process_output(
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

    def process_disconnect(self, target: object, inputs: Inputs) -> Observation:
        """SPS 1.0 has no disconnect: the consumer simply stops reading. This checks that the
        target is a process, and the next step reattaches by a new client."""
        del inputs
        self._process(target)
        return {}

    def process_reattach(self, target: object, inputs: Inputs) -> Observation:
        """Reattach is what a consumer that starts over does: a fresh client (a new `Provider`
        when the run was given a way to make one) reads the process's output from cursor 0."""
        sandbox_id = self._sandbox(target)
        process_id = text(inputs, "identity")
        client = self._new_client() if self._new_client is not None else None
        if client is not None:
            self._clients.append(client)
        handle = ProcessHandle(sandbox_id, process_id, client=client)
        owned = self.own("process", handle, lambda: {"result": "already_released"})
        return {"resource": owned, "identity": process_id}

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
