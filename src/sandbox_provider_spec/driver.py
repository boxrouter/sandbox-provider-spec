# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Conformance test-driver contract. This is not a provider API specification."""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Generic, TypeVar, cast

Inputs = Mapping[str, object]
Observation = Mapping[str, object]

# These gates are configured by their native operations, without create options.
OPERATION_GATES = frozenset(
    {
        "pause_resume",
        "snapshots",
        "volumes",
        "custom_images",
        "processes",
        "terminal",
    }
)

# Opt in only after auditing the native SDK; these are missing observations,
# never evidence that the provider lacks the corresponding feature.
UNOBSERVABLE_METADATA = {
    "lifetime.observe_paused_countdown": "native_paused_timer_countdown_unobservable",
    "snapshot.retention": "native_snapshot_retention_unobservable",
    "snapshot.restore_begin": "native_restore_progress_unobservable",
}


class Unsupported(Exception):
    """A native SDK has no operation or result needed by a test.

    The reason must be a fixed, public explanation, never an upstream error message.
    """


class Differs(Exception):
    """Native behavior contradicts an assertion or the requested contract.

    The reason and observations must be controlled public values, never SDK payloads.
    """

    def __init__(self, field: str) -> None:
        super().__init__(field)
        self.observation: dict[str, object] = {}


class NotRun(Exception):
    """The driver mapping or a fixture has not been supplied; this proves nothing."""

    def __init__(self, reason: str, *, detail: str | None = None) -> None:
        self.detail = detail
        super().__init__(reason)


class NativeFailure(Exception):
    """A classified native response; no credential-bearing message is retained."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(eq=False)
class Resource:
    """An opaque native handle, registered immediately after native allocation.

    Handles and identifiers stay in memory and never enter a report.
    """

    kind: str
    native: object
    cleanup: Callable[[], Observation]
    released: bool = False
    unreturned_create: bool = False
    create_settled: bool = False


class Driver:
    """Subclass with one method per operation, replacing dots with underscores.

    Only a documented absence belongs in ``unsupported``. An absent method otherwise
    produces ``not_run``. ``own`` must precede result conversion and assertions.
    """

    provider = ""
    execution_class: str | None = None
    sdk_versions: Mapping[str, str] = {}
    implementation: str | None = None
    """Optional driver implementation name for tooling that records source provenance."""
    unsupported: Mapping[str, str] = {}
    unobservable: Mapping[str, str] = {}

    def __init__(self) -> None:
        self.resources: list[Resource] = []

    def own(self, kind: str, native: object, cleanup: Callable[[], Observation]) -> Resource:
        owned = Resource(kind, native, cleanup)
        self.resources.append(owned)
        return owned

    def call(self, operation: str, target: object, inputs: Inputs) -> Observation:
        if operation in self.unsupported:
            raise Unsupported(self.unsupported[operation])
        if operation in self.unobservable:
            raise NotRun(self.unobservable[operation])
        method = getattr(self, operation.replace(".", "_"), None)
        if not callable(method) or operation in {"own", "release", "call", "settle_create"}:
            raise NotRun("driver_unimplemented")
        invoke = cast(Callable[[object, Inputs], Observation], method)
        return invoke(target, inputs)

    def network_private_address(self, target: object, inputs: Inputs) -> Observation:
        """Return the private endpoint used by other members of a native network."""
        del target, inputs
        raise Unsupported("provider SDK does not expose a private network address")

    def sweep_stale(self, ttl_seconds: float) -> list[str]:
        """Delete what a crashed run of this suite left behind, and nothing else.

        Only a resource whose native name or label carries a run id and whose age exceeds the
        TTL is deleted; every other resource in the account belongs to someone else. Returns
        `<kind>:<name>` for each resource deleted.
        """
        del ttl_seconds
        return []

    def release(self, owned: Resource) -> Observation:
        if owned.released:
            return {"kind": owned.kind, "result": "already_released"}
        self.settle_create(owned)
        result = owned.cleanup()
        if result.get("result") not in {"deleted", "already_released", "expires"}:
            raise NativeFailure("cleanup_not_confirmed")
        if result.get("result") == "expires":
            expires = result.get("expires_at")
            if not isinstance(expires, str) or datetime.fromisoformat(expires).tzinfo is None:
                raise NativeFailure("cleanup_expiry_unknown")
        owned.released = True
        return {"kind": owned.kind, **result}

    @staticmethod
    def settle_create(owned: Resource) -> None:
        """Wait after a failed marked create, before native absence can release it."""
        if owned.unreturned_create and not owned.create_settled:
            deadline = time.monotonic() + 120
            while (remaining := deadline - time.monotonic()) > 0:
                time.sleep(min(1, remaining))
            owned.create_settled = True


class ImageSnapshotDriver(Driver):
    """Opt in when native snapshots are native create-image bindings with delete.

    This shares binding/ownership mechanics only; create and cleanup still invoke
    each provider's own SDK. Drivers with memory snapshots choose their own mapping.
    """

    def snapshot_restore(self, target: object, inputs: Inputs) -> Observation:
        return self.call("create", None, {**inputs, "image": target})

    def snapshot_delete(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        return self.release(resource(target))


def resource(target: object) -> Resource:
    if not isinstance(target, Mapping) or not isinstance(target.get("resource"), Resource):
        raise ValueError("operation requires a resource binding")
    return cast(Resource, target["resource"])


def text(inputs: Inputs, key: str) -> str:
    value = inputs[key]
    if not isinstance(value, str):
        raise ValueError(f"{key} must be text")
    return value


def number(inputs: Inputs, key: str, default: int) -> int:
    value = inputs.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{key} must be a nonnegative integer")
    return value


def strings(inputs: Inputs, key: str) -> dict[str, str]:
    value = inputs.get(key, {})
    if not isinstance(value, Mapping) or any(
        not isinstance(k, str) or not isinstance(v, str) for k, v in value.items()
    ):
        raise ValueError(f"{key} must map text to text")
    return dict(value)


#: Gates a request names without any native creation setting: what a provider's SDK lacks
#: for them is reported by the operation a test uses (a PTY, a TCP link, a desktop).
NO_CREATION_SETTING = frozenset({"processes", "terminal", "docker", "tcp_ports", "desktop"})


def confirmed_absent(gone: Callable[[], bool], *, seconds: float) -> Observation:
    """Poll a native lookup until it reports the resource gone, or fail the cleanup."""
    deadline = time.monotonic() + seconds
    while not gone():
        if time.monotonic() >= deadline:
            raise NativeFailure("cleanup_not_confirmed")
        time.sleep(1)
    return {"result": "deleted"}


Native = TypeVar("Native")


@dataclass
class Reserved(Generic[Native]):
    """A unique native name, owned with its cleanup before an SDK call that creates the
    object and waits for it, so a failed wait cannot strand it."""

    name: str
    native: Native | None = None


def reserved(target: object) -> Reserved[object]:
    held = resource(target).native
    if not isinstance(held, Reserved):
        raise ValueError("operation requires a reserved native name")
    return cast(Reserved[object], held)


def created(target: object) -> object:
    native = reserved(target).native
    if native is None:
        raise ValueError("the reserved object was not created")
    return native
