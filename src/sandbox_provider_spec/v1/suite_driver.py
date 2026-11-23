# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
# pylint: disable=too-many-lines
"""Run the shared conformance tests against a 1.0 `Provider`.

The suite's runner is synchronous and speaks the `Driver` contract: one method per operation,
named after the operation with dots replaced by underscores. `ProviderDriver` implements those
methods by calling a `Provider`, whether that is an adapter or an `HttpProvider`.
"""

from __future__ import annotations

import asyncio
import base64
import builtins
import contextlib
import re
import threading
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator, Mapping
from concurrent.futures import Future
from dataclasses import dataclass, field
from datetime import datetime
from importlib.metadata import version
from typing import Any, TypeVar, cast
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

from sandbox_provider_spec import cost_checks, terminal_ordered
from sandbox_provider_spec.driver import (
    Driver,
    Inputs,
    NativeFailure,
    NotRun,
    Observation,
    Resource,
    Unsupported,
    number,
    resource,
    strings,
    text,
)
from sandbox_provider_spec.v1 import idempotency
from sandbox_provider_spec.v1.errors import SpsError
from sandbox_provider_spec.v1.provider import Provider
from sandbox_provider_spec.v1.suite_driver_account import AccountSteps
from sandbox_provider_spec.v1.suite_driver_images import ImageSteps, image_reference
from sandbox_provider_spec.v1.suite_driver_processes import ProcessHandle, ProcessSteps
from sandbox_provider_spec.v1.two_instances import provider_class
from sandbox_provider_spec.v1.types import (
    CreateRequest,
    FileLinkRequest,
    ProcessStartRequest,
    RunRequest,
    Sandbox,
    Secret,
    SecretHeader,
    Snapshot,
    SnapshotRequest,
    Terminal,
    TerminalRequest,
)
from sandbox_provider_spec.v1.wire import WireError, to_json
from sandbox_provider_spec.v1.within import within

T = TypeVar("T")

RUN_LABEL = "sps.test.run"
"""Every sandbox that a test run creates carries this label, with the run id as its value."""

# Operations that 1.0 has no counterpart for: a test needing one is `unsupported`.
NOT_IN_1_0: dict[str, str] = {}

# Knobs that a test's `requirements` name for what it proves, which a 1.0 `CreateRequest` does not
# carry (its `requirements` schema lists none of them): the request's `image` is the source, and
# `network_lockdown.cuts_open_connections` is a fact of an update, not of a create. Sent as they
# are, the request is invalid on the wire.
PROOF_ONLY_REQUIREMENTS: Mapping[str, frozenset[str]] = {
    "custom_images": frozenset({"source"}),
    "network_lockdown": frozenset({"cuts_open_connections"}),
}


def _request_requirements(requirements: object) -> Mapping[str, object]:
    """A test's `requirements` as a 1.0 `CreateRequest` carries them: without the knobs that
    only say what the test proves. A section they leave empty stays, since naming it still asks
    for the section."""
    if not isinstance(requirements, Mapping):
        raise ValueError("requirements must be a mapping")
    kept: dict[str, object] = {}
    for section, value in requirements.items():
        drop = PROOF_ONLY_REQUIREMENTS.get(str(section))
        if drop and isinstance(value, Mapping):
            kept[str(section)] = {key: item for key, item in value.items() if key not in drop}
        else:
            kept[str(section)] = value
    return kept


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
        "secret",
    }
)

SECRET_PLACEHOLDER_ENV = "SPS_SECRET_PLACEHOLDER"
"""The environment variable through which the tests read a sandbox's secret placeholder."""

# An id that no provider has issued: it fits the id syntax (contract section 3) and names nothing.
UNKNOWN_SANDBOX_ID = "sps-test-no-such-sandbox"
UNKNOWN_SNAPSHOT_ID = "sps-test-no-such-snapshot"

_SNAPSHOT_WAIT_SECONDS = 900  # how long a snapshot may stay in `saving`

_ONE_GIB = 1 << 30

_TERMINAL_OUTPUT_MS = 15_000  # how long terminal.output waits when a test names no limit
_TERMINAL_WAIT_MS = 60_000  # how long terminal.wait waits for the exit when a test names no limit

# Provider-fault codes that a retry can outlast.
RETRYABLE = frozenset({"provider_error", "unavailable", "timeout", "rate_limited"})


@dataclass
class SandboxHandle:
    """What a sandbox resource keeps in memory."""

    id: str


@dataclass
class SecretHandle:
    """A credential made by `secret.create`, held until a `create` binds it. SPS 1.0 has no secret
    object: the value reaches the provider only in the `secrets` of a create, so there is nothing
    to delete. The value stays out of `repr`."""

    value: str = field(repr=False)
    hosts: tuple[str, ...] = ()
    headers: tuple[SecretHeader, ...] = ()


@dataclass
class PreviewHandle:
    """What a preview link keeps in memory: its sandbox and the id that revokes it."""

    sandbox_id: str
    id: str | None


@dataclass
class SnapshotHandle:
    """What a snapshot resource keeps in memory."""

    id: str
    sandbox_id: str
    sandbox_class: str


@dataclass
class TerminalHandle:
    """An open terminal and the output that its pump has collected from it so far."""

    sandbox_id: str
    terminal: Terminal | None
    output: bytearray = field(default_factory=bytearray)
    error: SpsError | None = None
    """What ended the terminal or refused its start, raised by the next output or wait."""
    ended: bool = False
    pump: Future[None] | None = None
    id: str | None = None
    """The name the terminal was opened under, when its class claims `terminal.reattach`."""


def _default_region_listed(resources: Mapping[str, object]) -> bool:
    """A class that states `default_region` lists it among its `regions` (a list of regions)."""
    default = resources.get("default_region")
    regions = resources.get("regions")
    return default is None or not isinstance(regions, (list, tuple)) or default in regions


def _secret_headers(items: object) -> tuple[SecretHeader, ...]:
    if not isinstance(items, (list, tuple)):
        raise ValueError("headers must be a list")
    return tuple(
        SecretHeader(str(item["name"]), str(item.get("prefix", "")), str(item.get("suffix", "")))
        for item in items
    )


def _iso(moment: datetime | None) -> str | None:
    return None if moment is None else moment.isoformat().replace("+00:00", "Z")


class ProviderDriver(Driver, AccountSteps, ImageSteps, ProcessSteps):  # pylint: disable=too-many-public-methods,too-many-instance-attributes
    """A `Driver` whose operations call a `Provider`: `SpsError("unsupported")` becomes
    `Unsupported`, any other `SpsError` `NativeFailure(code)`. The provider is async, so the
    driver runs its own event loop in a background thread and waits for each call."""

    implementation = "sandbox_provider_spec.v1.suite_driver.ProviderDriver"
    unobservable = {
        "snapshot.restore_begin": "SPS 1.0 restore has no progress handle",
        "snapshot.restore_wait": "SPS 1.0 restore has no progress handle",
    }

    def __init__(
        self,
        provider: Provider,
        *,
        provider_id: str | None = None,
        run: str | None = None,
        unsupported: Mapping[str, str] | None = None,
        new_client: Callable[[], Provider] | None = None,
    ) -> None:
        super().__init__()
        self.api = provider
        self._new_client = new_client
        self.sandbox_class = "default"
        """The class that `create` asks for; the tester sets it to the class that runs a test."""
        self._clients: builtins.list[Provider] = []
        self.provider = provider_id or str(getattr(type(provider), "provider_id", "unknown"))
        self.run_id = run or uuid4().hex
        self.sdk_versions = {"sandbox-provider-spec": version("sandbox-provider-spec")}
        self.unsupported = {**NOT_IN_1_0, **(unsupported or {})}
        # Tests that discovery leaves out of the claim, by id; the runner reports each `not_run`.
        self.not_claimed: Mapping[str, str] = {}
        # Whether the provider keeps the labels of its snapshots (`ImageSteps.image_labels_kept` is
        # the same for images). The tester sets both from discovery's `*_labels_kept_by`.
        self.snapshot_labels_kept = True
        # Operations that have a command to run when discovery does not claim them. Nothing is
        # claimed until the tester has read discovery, so it starts with all of them.
        self.command_fallback: set[str] = {"files.exists"}
        self._snapshots: dict[str, Resource] = {}
        self._images: dict[str, Resource] = {}
        self._image_keys: dict[str, tuple[str, Resource]] = {}
        self._sent_keys: set[str] = set()
        self._terminals: builtins.list[TerminalHandle] = []
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
            for handle in self._terminals:
                with contextlib.suppress(Exception):
                    self._close_terminal(handle)
            for client in self._clients:
                with contextlib.suppress(Exception):
                    self.wait(client.aclose())
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
    def _terminal(target: object) -> TerminalHandle:
        native = resource(target).native
        if not isinstance(native, TerminalHandle):
            raise ValueError("operation requires a terminal")
        return native

    @staticmethod
    def _process(target: object) -> ProcessHandle:
        native = resource(target).native
        if not isinstance(native, ProcessHandle):
            raise ValueError("operation requires a process")
        return native

    # Sandboxes

    def create(self, target: object, inputs: Inputs) -> Observation:
        del target
        return self._create(inputs)

    def _create(self, inputs: Inputs, *, snapshot: SnapshotHandle | None = None) -> Observation:
        extra = sorted(set(inputs) - CREATE_INPUTS)
        if extra:
            raise Unsupported("a create input that SPS 1.0 does not define")
        image = image_reference(inputs.get("image"), self.provider) or inputs.get("image")
        if image is not None and not isinstance(image, (str, Mapping)):
            raise Unsupported("an image that SPS 1.0 cannot name")
        env = strings(inputs, "environment")
        requirements = _request_requirements(inputs.get("requirements", {}))
        secrets = self._secrets(inputs, requirements, env)
        request = CreateRequest(
            sandbox_class=self.sandbox_class if snapshot is None else snapshot.sandbox_class,
            resources=cast(Mapping[str, object], inputs.get("resources", {})),
            requirements=requirements,
            image=cast("str | Mapping[str, str] | None", image),
            at_end=cast(Any, inputs.get("at_end", "destroyed")),
            env=env,
            secrets=secrets,
            labels={**strings(inputs, "labels"), RUN_LABEL: self.run_id},
            lifetime_seconds=cast("int | None", inputs.get("lifetime_seconds", 300)),
            snapshot=None if snapshot is None else snapshot.id,
        )
        key = self._key(inputs)
        with self._sending(key):
            created = self.wait(self.api.create(request, idempotency_key=key))
        handle = SandboxHandle(created.id)
        owned = self.own("sandbox", handle, lambda: self._destroy(handle.id))
        return {"resource": owned, "identity": created.id}

    def secret_create(self, target: object, inputs: Inputs) -> Observation:
        """Make a credential for a later `create` to bind (`create` with `secret`)."""
        del target
        value = text(inputs, "value")
        hosts = inputs.get("hosts") or ()
        headers = inputs.get("headers") or ()
        if not isinstance(hosts, (list, tuple)) or not all(isinstance(h, str) for h in hosts):
            raise ValueError("hosts must be a list of text")
        if not isinstance(headers, (list, tuple)):
            raise ValueError("headers must be a list")
        handle = SecretHandle(value, tuple(hosts), _secret_headers(headers))
        return {"resource": self.own("secret", handle, lambda: {"result": "already_released"})}

    @staticmethod
    def _secrets(
        inputs: Inputs, requirements: Mapping[str, object], env: dict[str, str]
    ) -> tuple[Secret, ...]:
        """The `secrets` of a create that binds a `secret`: its hosts and header templates are
        the ones the request's `hidden_secrets` names, else the ones the secret was made with.
        The placeholder goes into `env` so that code in the sandbox can use it."""
        if "secret" not in inputs:
            return ()
        handle = resource(inputs["secret"]).native
        if not isinstance(handle, SecretHandle):
            raise ValueError("secret must be a secret resource")
        asked = requirements.get("hidden_secrets")
        asked = asked if isinstance(asked, Mapping) else {}
        hosts = asked.get("inject_into") or handle.hosts
        if not isinstance(hosts, (list, tuple)) or not hosts:
            raise ValueError("a secret needs the hosts to inject into")
        headers = _secret_headers(asked.get("headers") or ()) or handle.headers
        placeholder = env.setdefault(SECRET_PLACEHOLDER_ENV, f"sps-placeholder-{uuid4().hex}")
        return (Secret(placeholder, handle.value, tuple(hosts), headers),)

    @contextlib.contextmanager
    def _sending(self, key: str) -> Iterator[None]:
        """Send `key` as a host would: its first use in this run is vouched as a first send
        (`v1.idempotency`), and a later use is a repeat with no hint, so a provider that reads the
        hint is tested on its fast first send and on its safe path for the repeat."""
        if key in self._sent_keys:
            yield
            return
        self._sent_keys.add(key)
        with idempotency.fresh_key(key), idempotency.attempt(key, 1):
            yield

    def _key(self, inputs: Inputs) -> str:
        """A create's idempotency key: fresh, or shared by one test's creates in one run only."""
        name = inputs.get("idempotency_key")
        if name is None:
            return str(uuid4())
        if not isinstance(name, str) or not name:
            raise ValueError("idempotency_key must name the key")
        return f"sps-{self.run_id[:20]}-{name}"

    def _destroy(self, sandbox_id: str) -> Observation:
        try:
            self.wait(self.api.destroy(sandbox_id))
        except NativeFailure as error:
            if error.code != "not_found":
                raise
        return {"result": "deleted"}

    def get(self, target: object, inputs: Inputs) -> Observation:
        try:
            sandbox = self.wait(self.api.get(self._sandbox(target)))
        except NativeFailure as error:
            if error.code == "not_found":
                return {"state": "destroyed"}
            raise
        labels = dict(sandbox.labels)
        if labels.get(RUN_LABEL) == self.run_id:
            del labels[RUN_LABEL]  # the tester's own label; a test names only the labels it set
        observed: dict[str, object] = {
            "state": "active" if sandbox.state == "running" else sandbox.state,
            "labels": labels,
        }
        if inputs.get("size") is True:
            observed["size"] = _size(sandbox.size)  # what a restore is compared with
        return observed

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
        """Judge the discovery document: valid 1.0, file limit >= 1 GiB (8). Prices are optional."""
        del target, inputs
        found = self.wait(self.api.discovery())
        try:
            to_json(found)
            valid = all(_default_region_listed(item.resources) for item in found.classes)
        except WireError:
            valid = False
        return {
            "valid": valid,
            "file_limit_floor": found.limits.file_bytes >= _ONE_GIB,
        }

    def discovery_within_static(self, target: object, inputs: Inputs) -> Observation:
        """Whether the live discovery is within the provider's `static_discovery()`: skipped for a
        provider that does not state one (an HTTP form has no package to read it from)."""
        del target, inputs
        try:
            ceiling = provider_class(self.api).static_discovery()
        except NotImplementedError:
            raise Unsupported("the provider states no static_discovery()") from None
        return {"outside": within(self.wait(self.api.discovery()), ceiling)}

    def cost_final(self, target: object, inputs: Inputs) -> Observation:
        """Read a destroyed sandbox's cost until it is final, within `cost_final_within_seconds`."""
        return cost_checks.final(self, self._sandbox(target), inputs)

    # Commands and files

    def _user(self, inputs: Inputs, operation: str) -> str | None:
        """The user a step names, or Unsupported when discovery does not claim `operation`."""
        user = inputs.get("run_as", inputs.get("user"))
        if user is not None and operation in self.unsupported:
            raise Unsupported(self.unsupported[operation])
        return None if user is None else str(user)

    def run(self, target: object, inputs: Inputs) -> Observation:
        user = self._user(inputs, "run.user")
        base64_output = inputs.get("output") == "base64"
        if base64_output and "run.base64" in self.unsupported:
            raise Unsupported(self.unsupported["run.base64"])
        # A test names `bash_script` (bash is in a provider's default image) or, for an image
        # that a plain OCI base supplies, `sh_script` (POSIX `sh` is in every OCI base).
        argv = (
            ["sh", "-c", text(inputs, "sh_script")]
            if "sh_script" in inputs
            else ["bash", "-c", text(inputs, "bash_script")]
        )
        request = RunRequest(
            argv=argv,
            cwd=cast("str | None", inputs.get("cwd")),
            env=strings(inputs, "environment"),
            timeout_ms=number(inputs, "timeout_ms", 60_000),
            user=user,
            output="base64" if base64_output else "text",
        )
        result = self.wait(self.api.run(self._sandbox(target), request))
        if base64_output:
            stdout = base64.b64decode(result.stdout_base64 or "", validate=True)
            stderr = base64.b64decode(result.stderr_base64 or "", validate=True)
        else:
            stdout, stderr = result.stdout.encode(), result.stderr.encode()
        return {
            "stdout": stdout,
            "stderr": stderr,
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
        """The native operation when claimed, else `test -e`; `native` steps need the claim."""
        if "files.exists" in self.command_fallback:
            if inputs.get("native") is True:
                raise Unsupported("discovery does not claim the directory operations")
            result = self.wait(
                self.api.run(
                    self._sandbox(target), RunRequest(argv=["test", "-e", text(inputs, "path")])
                )
            )
            if result.exit_code not in (0, 1):
                raise NativeFailure("exists_check_failed")
            return {"exists": result.exit_code == 0}
        info = self.wait(self.api.files_exists(self._sandbox(target), text(inputs, "path")))
        return {"exists": info.exists, "type": info.type}

    # Directory operations (contract section 10.3)

    def files_list(self, target: object, inputs: Inputs) -> Observation:
        cursor = inputs.get("cursor")
        page = self.wait(
            self.api.files_list(
                self._sandbox(target),
                text(inputs, "path"),
                cursor=None if cursor is None else str(cursor),
                limit=number(inputs, "limit", 100),
            )
        )
        return {
            "names": [entry.name for entry in page.entries],
            "types": [entry.type for entry in page.entries],
            "sizes": [entry.size for entry in page.entries],
            "entries": [
                {"name": entry.name, "type": entry.type, "size": entry.size}
                for entry in page.entries
            ],
            "next_cursor": page.next_cursor,
            "has_more": page.next_cursor is not None,
        }

    def files_mkdir(self, target: object, inputs: Inputs) -> Observation:
        self.wait(
            self.api.files_mkdir(
                self._sandbox(target),
                text(inputs, "path"),
                parents=inputs.get("parents") is True,
            )
        )
        return {}

    def files_remove(self, target: object, inputs: Inputs) -> Observation:
        self.wait(
            self.api.files_remove(
                self._sandbox(target),
                text(inputs, "path"),
                recursive=inputs.get("recursive") is True,
            )
        )
        return {}

    def fixture_files_write_missing_parent(self, target: object, inputs: Inputs) -> Observation:
        """Write 4 bytes under a missing parent: parents made and read back, or `not_found`."""
        del inputs
        sandbox_id = self._sandbox(target)
        data = b"sps\n"
        path = "/tmp/sps-np/x/y"

        async def chunks() -> AsyncIterator[bytes]:
            yield data

        try:
            self.wait(self.api.files_write(sandbox_id, path, chunks(), size=len(data)))
        except NativeFailure as error:
            if error.code != "not_found":
                raise
            left = self.wait(
                self.api.run(sandbox_id, RunRequest(argv=["test", "-e", "/tmp/sps-np"]))
            )
            return {"passed": left.exit_code == 1, "stdout": "refused_not_found"}
        return {
            "passed": self.files_read_bytes(target, {"path": path})["data"] == data,
            "stdout": "created_parents",
        }

    def files_write(self, target: object, inputs: Inputs) -> Observation:
        data = base64.b64decode(text(inputs, "data"), validate=True)

        async def chunks() -> AsyncIterator[bytes]:
            yield data

        user = self._user(inputs, "files.write.user")
        extra = {} if user is None else {"user": user}
        self.wait(
            self.api.files_write(
                self._sandbox(target), text(inputs, "path"), chunks(), size=len(data), **extra
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
            user=self._user(inputs, "process.start.user"),
        )
        started = self.wait(self.api.process_start(sandbox_id, request))
        handle = ProcessHandle(sandbox_id, started.id)
        owned = self.own("process", handle, lambda: {"result": "already_released"})
        return {"resource": owned, "identity": started.id}

    # Optional sections

    def pause(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        sandbox = self.wait(self.api.pause(self._sandbox(target)))
        # A provider may return nothing (it read no record): then no state is observed.
        return {} if sandbox is None else {"state": sandbox.state}

    def resume(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        sandbox_id = self._sandbox(target)
        sandbox = self.wait(self.api.resume(sandbox_id))
        # The resumed sandbox is the same one, so a step can bind it (`as:`) and name it as the
        # target of the steps after, as `create` allows.
        observed = {"resource": resource(target), "identity": sandbox_id}
        if sandbox is None:
            return observed
        return {**observed, "state": "active" if sandbox.state == "running" else sandbox.state}

    def lifetime_extend(self, target: object, inputs: Inputs) -> Observation:
        sandbox_id = self._sandbox(target)
        sandbox = self.wait(
            self.api.lifetime_extend(sandbox_id, number(inputs, "lifetime_seconds", 0))
        )
        if sandbox is None:  # the provider read no record for its answer: the tester reads it
            sandbox = self.wait(self.api.get(sandbox_id))
        return {"ends_at": _iso(sandbox.ends_at)}

    def preview_link(self, target: object, inputs: Inputs) -> Observation:
        """Make a link. `access` and `lifetime_seconds` go to the provider only when a test
        sets them; the link is a resource, so `preview.revoke` can name it and a run revokes
        what it made."""
        sandbox_id = self._sandbox(target)
        options: dict[str, Any] = {}
        access = inputs.get("access")
        if access is not None:
            if access not in ("public", "private"):
                raise ValueError("access must be public or private")
            options["access"] = access
        if "lifetime_seconds" in inputs:
            options["lifetime_seconds"] = number(inputs, "lifetime_seconds", 0)
        link = self.wait(self.api.preview_link(sandbox_id, number(inputs, "port", 0), **options))
        handle = PreviewHandle(sandbox_id, link.id)
        owned = self.own("preview", handle, lambda: self._revoke_preview(handle))
        unauthorized = (
            {"unauthorized_url": _without_credential(link.url, link.credential)}
            if link.access == "private"
            else {}
        )
        return {
            "resource": owned,
            "url": link.url,
            "headers": dict(link.headers),
            "expires_at": _iso(link.expires_at),
            "access": link.access,
            "credential": link.credential,
            **unauthorized,
        }

    def _revoke_preview(self, handle: PreviewHandle) -> Observation:
        """Cleanup for a link: nothing to do when it has no id, and a link that is already
        gone (or whose sandbox is) counts as revoked."""
        if handle.id is not None:
            try:
                self.wait(self.api.preview_revoke(handle.sandbox_id, handle.id))
            except NativeFailure as error:
                if error.code != "not_found":
                    raise
            except Unsupported:
                pass  # a link that cannot be revoked ends with its sandbox
        return {"result": "deleted"}

    def preview_revoke(self, target: object, inputs: Inputs) -> Observation:
        """Revoke the link and wait for nothing: the test probes the URL itself."""
        del inputs
        handle = resource(target).native
        if not isinstance(handle, PreviewHandle):
            raise ValueError("operation requires a preview link")
        if handle.id is None:
            raise Unsupported("the provider returned no id for this link, so it cannot be revoked")
        self.wait(self.api.preview_revoke(handle.sandbox_id, handle.id))
        return {}

    def labels_update(self, target: object, inputs: Inputs) -> Observation:
        """Set and remove labels, and report what the sandbox now carries (not the run's own)."""
        sandbox = self.wait(
            self.api.labels_update(self._sandbox(target), strings(inputs, "labels"))
        )
        labels = dict(sandbox.labels)
        if labels.get(RUN_LABEL) == self.run_id:
            del labels[RUN_LABEL]
        return {"labels": labels}

    def network_update(self, target: object, inputs: Inputs) -> Observation:
        """Replace the running sandbox's network policy; `inputs` is the new policy and entries."""
        self.wait(
            self.api.network_update(
                self._sandbox(target),
                text(inputs, "policy"),
                allow=cast("list[str]", inputs.get("allow") or ()),
                deny=cast("list[str]", inputs.get("deny") or ()),
            )
        )
        return {}

    def tcp_link(self, target: object, inputs: Inputs) -> Observation:
        link = self.wait(self.api.tcp_link(self._sandbox(target), number(inputs, "port", 0)))
        return {"host": link.host, "port": link.port}

    # Snapshots (section `snapshots`)

    @staticmethod
    def _snapshot_handle(target: object) -> SnapshotHandle:
        native = resource(target).native
        if not isinstance(native, SnapshotHandle):
            raise ValueError("operation requires a snapshot")
        return native

    def _own_snapshot(self, snapshot: Snapshot) -> Resource:
        """The resource of a snapshot, made once: a repeated create returns the same snapshot."""
        known = self._snapshots.get(snapshot.id)
        if known is not None:
            return known
        handle = SnapshotHandle(snapshot.id, snapshot.sandbox_id, snapshot.sandbox_class)
        owned = self.own("snapshot", handle, lambda: self._delete_snapshot(handle.id))
        self._snapshots[snapshot.id] = owned
        return owned

    def _delete_snapshot(self, snapshot_id: str) -> Observation:
        try:
            self.wait(self.api.snapshot_delete(snapshot_id))
        except NativeFailure as error:
            if error.code != "not_found":
                raise
        except Unsupported:
            # A provider whose snapshots cannot be deleted lets them expire.
            expires = self.wait(self.api.snapshot_get(snapshot_id)).expires_at
            if expires is None:
                raise NativeFailure("cleanup_not_confirmed") from None
            return {"result": "expires", "expires_at": _iso(expires)}
        return {"result": "deleted"}

    def snapshot_take(self, target: object, inputs: Inputs) -> Observation:
        """Save a sandbox and wait until the snapshot is `ready`."""
        keeps = inputs.get("keeps")
        if keeps not in (None, "files_only", "files_and_memory"):
            raise ValueError("keeps must be files_only or files_and_memory")
        request = SnapshotRequest(
            keeps=cast(Any, keeps), labels={**strings(inputs, "labels"), RUN_LABEL: self.run_id}
        )
        key = str(uuid4())
        with self._sending(key):
            created = self.wait(
                self.api.snapshot_create(self._sandbox(target), request, idempotency_key=key)
            )
        owned = self._own_snapshot(created)  # owned before the wait, so a failed wait cleans up
        deadline = time.monotonic() + _SNAPSHOT_WAIT_SECONDS
        snapshot = created
        while snapshot.state != "ready":
            if snapshot.state == "failed":
                raise NativeFailure("snapshot_failed")
            if time.monotonic() >= deadline:
                raise NotRun("snapshot_not_ready_in_window")
            time.sleep(1)
            snapshot = self.wait(self.api.snapshot_get(created.id))
        return {"resource": owned, "identity": created.id}

    def snapshot_restore(self, target: object, inputs: Inputs) -> Observation:
        return self._create(inputs, snapshot=self._snapshot_handle(target))

    def snapshot_delete(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        return self.release(resource(target))

    def snapshot_delete_again(self, target: object, inputs: Inputs) -> Observation:
        """Delete a snapshot that an earlier step already deleted, and report the state."""
        del inputs
        result = self.wait(self.api.snapshot_delete(self._snapshot_handle(target).id))
        return {"native_delete_attempted": True, "state": result.state}

    def snapshot_get(self, target: object, inputs: Inputs) -> Observation:
        """Read one snapshot. `unknown: true` reads an id that no provider has issued."""
        snapshot_id = (
            UNKNOWN_SNAPSHOT_ID
            if inputs.get("unknown") is True
            else self._snapshot_handle(target).id
        )
        snapshot = self.wait(self.api.snapshot_get(snapshot_id))
        labels = dict(snapshot.labels)
        if labels.get(RUN_LABEL) == self.run_id:
            del labels[RUN_LABEL]  # the tester's own label
        return {
            "state": snapshot.state,
            "keeps": snapshot.keeps,
            "sandbox_id": snapshot.sandbox_id,
            "labels": labels,
            "size": _size(snapshot.size),
        }

    def snapshot_list(self, target: object, inputs: Inputs) -> Observation:
        """The run's snapshots that match the given labels and source sandbox."""
        del target
        # A provider that keeps no snapshot labels is not asked for them: the run's snapshots
        # are the ones this driver made, found among what the provider lists for the sandbox.
        kept = self.snapshot_labels_kept
        wanted = {**strings(inputs, "labels"), RUN_LABEL: self.run_id} if kept else None
        sandbox_id = inputs.get("sandbox_id")
        if sandbox_id is not None and not isinstance(sandbox_id, str):
            raise ValueError("sandbox_id must be text")
        ids: builtins.list[str] = []
        cursor: str | None = None
        while True:
            page = self.wait(
                self.api.snapshot_list(labels=wanted, sandbox_id=sandbox_id, cursor=cursor)
            )
            ids.extend(item.id for item in page.snapshots if kept or item.id in self._snapshots)
            cursor = page.next_cursor
            if cursor is None:
                break
        return {"count": len(ids), "ids": ids}

    def snapshot_create_keyed(self, target: object, inputs: Inputs) -> Observation:
        """Save a sandbox with an explicit key and labels, without waiting; a repeat returns it."""
        keeps = inputs.get("keeps")
        request = SnapshotRequest(
            keeps=cast(Any, keeps), labels={**strings(inputs, "labels"), RUN_LABEL: self.run_id}
        )
        key = self._key(inputs)
        with self._sending(key):
            created = self.wait(
                self.api.snapshot_create(self._sandbox(target), request, idempotency_key=key)
            )
        self._own_snapshot(created)
        return {"id": created.id}

    def snapshot_retention(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        snapshot = self.wait(self.api.snapshot_get(self._snapshot_handle(target).id))
        if snapshot.expires_at is None:
            raise NotRun("snapshot_has_no_expiry")
        return {
            "retention_seconds": int((snapshot.expires_at - snapshot.created_at).total_seconds())
        }

    def snapshot_cost(self, target: object, inputs: Inputs) -> Observation:
        """Read a snapshot's cost; `final: true` reads until final, up to `timeout_ms` (else
        `cost_final_within_seconds`)."""
        handle = self._snapshot_handle(target)
        cost = cost_checks.read_cost(self, lambda: self.api.snapshot_cost(handle.id), inputs)
        return {
            "status": cost.status,
            "snapshot_matches": cost.snapshot_id == handle.id,
            "sandbox_matches": cost.sandbox_id == handle.sandbox_id,
            # No lines is fine only while nothing is metered yet.
            "only_snapshot_lines": all(line.item == "snapshot" for line in cost.lines)
            and (bool(cost.lines) or cost.status == "accruing"),
        }

    # Terminals

    def terminal_open(self, target: object, inputs: Inputs) -> Observation:
        """Open a terminal. A provider that refuses the start (a missing working directory, for
        one) may refuse it here, in the Python form, or in the first message of the connection,
        in the HTTP form; both are reported by the first output read or wait."""
        sandbox_id = self._sandbox(target)
        argv = inputs.get("argv")
        request = TerminalRequest(
            argv=None if argv is None else tuple(cast("list[str]", argv)),
            cwd=cast("str | None", inputs.get("cwd")),
            env=strings(inputs, "environment"),
            columns=number(inputs, "columns", 80),
            rows=number(inputs, "rows", 24),
            term=cast(str, inputs.get("term", "xterm-256color")),
            # A test that disconnects and reattaches asks for a named terminal (`reattachable`).
            id=f"sps-test-{uuid4().hex}" if inputs.get("reattachable") is True else None,
        )
        handle = TerminalHandle(sandbox_id, None, id=request.id)
        self._attach(handle, self.api.terminal_open(sandbox_id, request))
        owned = self.own("terminal", handle, lambda: self._close_terminal(handle))
        return {"resource": owned}

    def _attach(self, handle: TerminalHandle, opening: Awaitable[Terminal]) -> None:
        try:
            handle.terminal = self.wait(opening)
        except NativeFailure as error:
            handle.error, handle.ended = SpsError(cast(Any, error.code), "refused"), True
        else:
            handle.pump = asyncio.run_coroutine_threadsafe(self._pump(handle), self._loop)
            self._terminals.append(handle)

    def terminal_disconnect(self, target: object, inputs: Inputs) -> Observation:
        """Close the connection of a terminal that has an id: its program keeps running."""
        del inputs
        handle = self._terminal(target)
        if handle.id is None or handle.terminal is None:
            raise Unsupported("the terminal has no id, so closing it ends it")
        self.wait(handle.terminal.close())
        if handle.pump is not None:
            with contextlib.suppress(Exception):
                handle.pump.result(timeout=10)
        return {}

    def terminal_reattach(self, target: object, inputs: Inputs) -> Observation:
        """Connect to the terminal again. The result is a new terminal resource on the same id. A
        terminal that is no longer running is reported by the first output read or wait, as a
        refused start is."""
        del inputs
        old = self._terminal(target)
        if old.id is None:
            raise Unsupported("the terminal has no id")
        handle = TerminalHandle(old.sandbox_id, None, id=old.id)
        self._attach(handle, self.api.terminal_reattach(old.sandbox_id, old.id))
        owned = self.own("terminal", handle, lambda: self._close_terminal(handle))
        return {"resource": owned}

    def terminal_end(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        handle = self._terminal(target)
        if handle.id is None:
            raise Unsupported("the terminal has no id")
        self.wait(self.api.terminal_end(handle.sandbox_id, handle.id))
        return {}

    async def _pump(self, handle: TerminalHandle) -> None:
        """Collect a terminal's output until it ends, so that nothing waits on the reader."""
        assert handle.terminal is not None
        try:
            async for chunk in handle.terminal.output():
                handle.output.extend(chunk)
        except SpsError as error:
            handle.error = error
        finally:
            handle.ended = True

    def _close_terminal(self, handle: TerminalHandle) -> Observation:
        if handle.terminal is not None:
            self.wait(handle.terminal.close())
            if handle.pump is not None:
                with contextlib.suppress(Exception):
                    handle.pump.result(timeout=10)  # the pump ends once the terminal is closed
        if handle.id is not None:  # closing only detached it
            with contextlib.suppress(NativeFailure, Unsupported):
                self.wait(self.api.terminal_end(handle.sandbox_id, handle.id))
        return {"result": "deleted"}

    def terminal_write(self, target: object, inputs: Inputs) -> Observation:
        handle = self._terminal(target)
        data = base64.b64decode(text(inputs, "data"), validate=True)
        if handle.terminal is None:
            raise NativeFailure("terminal_not_open")
        self.wait(handle.terminal.write(data))
        return {}

    def terminal_output(self, target: object, inputs: Inputs) -> Observation:
        """The bytes collected so far, once the wanted text is in them, a first chunk has come,
        the terminal has ended, or the time is up."""
        handle = self._terminal(target)
        deadline = time.monotonic() + number(inputs, "timeout_ms", _TERMINAL_OUTPUT_MS) / 1000
        first_chunk = inputs.get("first_chunk") is True
        wanted = inputs.get("until_contains")
        needle = None if wanted is None else text(inputs, "until_contains").encode()
        while True:
            if needle is not None and needle in handle.output:
                break
            if first_chunk and handle.output:
                break
            if handle.error is not None:
                raise NativeFailure(handle.error.code)
            if handle.ended or time.monotonic() >= deadline:
                break
            time.sleep(0.02)
        return {"terminal": bytes(handle.output)}

    def terminal_resize(self, target: object, inputs: Inputs) -> Observation:
        handle = self._terminal(target)
        if handle.terminal is None:
            raise NativeFailure("terminal_not_open")
        self.wait(handle.terminal.resize(number(inputs, "columns", 80), number(inputs, "rows", 24)))
        return {}

    def terminal_wait(self, target: object, inputs: Inputs) -> Observation:
        """Wait for the program to exit and return its exit code."""
        handle = self._terminal(target)
        deadline = time.monotonic() + number(inputs, "timeout_ms", _TERMINAL_WAIT_MS) / 1000
        while not handle.ended:
            if time.monotonic() >= deadline:
                raise NotRun("native_terminal_still_running")
            time.sleep(0.02)
        if handle.error is not None:
            raise NativeFailure(handle.error.code)
        assert handle.terminal is not None
        return {"exit_code": handle.terminal.exit_code}

    def terminal_close(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        self._close_terminal(self._terminal(target))
        return {}

    def terminal_link_reuse(self, target: object, inputs: Inputs) -> Observation:
        """Connect to one terminal link twice. The link is single-use, so the second connection
        must be refused with an HTTP status from 400 to 499 before the upgrade."""
        del inputs
        link_of = getattr(self.api, "terminal_link", None)
        connect = getattr(self.api, "terminal_connect", None)
        if link_of is None or connect is None:
            raise NotRun("the Python form has no link")
        sandbox_id = self._sandbox(target)

        async def reuse() -> bool:
            link = await link_of(sandbox_id, TerminalRequest())
            first: Terminal = await connect(link)
            try:
                try:
                    second: Terminal = await connect(link)
                except SpsError as error:
                    return 400 <= error.http_status <= 499
                await second.close()
                return False
            finally:
                await first.close()

        return {"second_refused": self.wait(reuse())}

    def fixture_terminal_ordered_output(self, target: object, inputs: Inputs) -> Observation:
        """The shared fixture of `terminal.v1.ordered_output`, run through this driver's
        `terminal.*` operations."""
        return terminal_ordered.observe(self, target, inputs)

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

    def snapshot_leftovers(self) -> builtins.list[str]:
        """Ids of this run's snapshots that the provider still lists; none when it has no
        snapshots section."""
        if not self.snapshot_labels_kept:
            return []  # nothing marks the run's snapshots; each one this driver made is released
        try:
            return cast("builtins.list[str]", self.snapshot_list(None, {})["ids"])
        except Unsupported:
            return []

    def sweep_run(self) -> builtins.list[Observation]:
        """Destroy every sandbox and delete every snapshot that still carries this run's label."""
        results: builtins.list[Observation] = []
        for sandbox_id in self.leftovers():
            try:
                results.append({"kind": "sandbox", **self._destroy(sandbox_id)})
            except Exception as error:  # pylint: disable=broad-exception-caught
                results.append(
                    {"kind": "sandbox", "result": "error", "reason": type(error).__name__}
                )
        try:
            snapshot_ids = self.snapshot_leftovers()
        except Exception as error:  # pylint: disable=broad-exception-caught
            return [
                *results,
                {"kind": "snapshot", "result": "error", "reason": type(error).__name__},
            ]
        for snapshot_id in snapshot_ids:
            try:
                results.append({"kind": "snapshot", **self._delete_snapshot(snapshot_id)})
            except Exception as error:  # pylint: disable=broad-exception-caught
                results.append(
                    {"kind": "snapshot", "result": "error", "reason": type(error).__name__}
                )
        return results + self.sweep_images()


def _without_credential(url: str, credential: str | None) -> str:
    """A private link's URL as a request without its credential sends it: a `header` credential
    is not in the URL; a `link` credential (or none reported) is in the query or fragment."""
    if credential == "header":
        return url
    parts = urlsplit(url)
    plain = urlunsplit(parts._replace(query="", fragment=""))
    if plain != url or credential != "link":
        return plain
    # The credential is in the host or the path: spoil its longest run of letters and digits.
    runs = re.findall(r"[A-Za-z0-9]{16,}", f"{parts.netloc}{parts.path}")
    if not runs:
        return plain
    token = max(runs, key=len)
    return url.replace(token, "x" * len(token), 1)


def _size(size: Any) -> dict[str, object]:
    return {"cpu": size.cpu, "memory_mib": size.memory_mib, "disk_mib": size.disk_mib}


async def _next(iterator: AsyncIterator[bytes]) -> bytes:
    return await anext(iterator)
