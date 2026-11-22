# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The `Provider` base class: the 1.0 operations, one method for each."""

from __future__ import annotations

import sys
from abc import ABC, abstractmethod
from collections.abc import AsyncIterable, Mapping, Sequence
from datetime import datetime
from importlib.metadata import entry_points
from importlib.resources import as_file, files
from types import MappingProxyType
from typing import Any, ClassVar

from jsonschema import Draft202012Validator

from sandbox_provider_spec.load import load
from sandbox_provider_spec.v1._spec_files import document
from sandbox_provider_spec.v1.errors import SpsError
from sandbox_provider_spec.v1.types import (
    AccountCapacity,
    AccountCost,
    Cost,
    CreateRequest,
    CredentialField,
    DestroyResult,
    DirectoryPage,
    Discovery,
    FileInfo,
    FileLink,
    FileLinkRequest,
    FileStream,
    ImageDeleteResult,
    ImagePage,
    ImageRequest,
    OutputPage,
    PathInfo,
    PreparedImage,
    PreviewAccess,
    PreviewLink,
    Process,
    ProcessStartRequest,
    RunRequest,
    RunResult,
    Sandbox,
    SandboxPage,
    Snapshot,
    SnapshotDeleteResult,
    SnapshotPage,
    SnapshotRequest,
    TcpLink,
    Terminal,
    TerminalRequest,
)

PROVIDERS_GROUP = "sandbox_provider_spec.providers"

MANIFEST_NAME = "sps-provider.yaml"
MANIFEST_SCHEMA = "sps-provider.schema.json"


def _package_of(cls: type) -> str:
    """The Python package that holds the class: the module itself when it is a package."""
    module = sys.modules[cls.__module__]
    if hasattr(module, "__path__"):
        return module.__name__
    return module.__name__.rpartition(".")[0]


def read_manifest(package: str) -> dict[str, Any]:
    """Load and validate `sps-provider.yaml` from a Python package, without importing the code
    of any provider. Raises `ValueError` when the file is missing or invalid."""
    if not package:
        raise ValueError(f"{MANIFEST_NAME} must be inside a Python package, not a top-level module")
    try:
        resource = files(package).joinpath(MANIFEST_NAME)
        with as_file(resource) as path:
            manifest = load(path)
    except (FileNotFoundError, ModuleNotFoundError) as error:
        raise ValueError(f"package {package!r} has no {MANIFEST_NAME}") from error
    errors = sorted(
        Draft202012Validator(document(MANIFEST_SCHEMA)).iter_errors(manifest),
        key=lambda error: list(error.path),
    )
    if errors:
        details = "; ".join(
            f"{'/'.join(map(str, e.path)) or '(root)'}: {e.message}" for e in errors
        )
        raise ValueError(f"{package}/{MANIFEST_NAME} is not valid: {details}")
    assert isinstance(manifest, dict)
    return manifest


class Provider(ABC):  # pylint: disable=too-many-public-methods
    """A sandbox provider, as the 1.0 standard sees it.

    A subclass lives in a Python package that holds `sps-provider.yaml`. The facts in that file
    become the class attributes below when the subclass is defined, and a missing or invalid
    file fails the definition. A subclass that is only a client of some provider's API, with no
    manifest of its own, defines itself with `class Name(Provider, manifest=False)`.

    The adapter is async and keeps no state between calls other than HTTP clients. It receives
    its credentials only through its constructor, never from the environment.
    """

    provider_id: ClassVar[str]
    name: ClassVar[str]
    spec_version: ClassVar[str]  # "1.0"
    # Both are empty for a class defined with `manifest=False`.
    credential_fields: ClassVar[tuple[CredentialField, ...]] = ()
    api_domains: ClassVar[tuple[str, ...]] = ()  # every host name the adapter connects to

    def __init_subclass__(cls, *, manifest: bool = True, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if not manifest:
            return
        data = read_manifest(_package_of(cls))
        fields = tuple(
            CredentialField(
                name=item["name"],
                secret=item.get("secret", True),
                required=item.get("required", True),
                required_for_managed=item.get("required_for_managed", False),
                default=item.get("default"),
                description=item.get("description", ""),
                public_prefix=item.get("public_prefix"),
            )
            for item in data["credential_fields"]
        )
        names = [item.name for item in fields]
        if len(names) != len(set(names)):
            raise ValueError(f"{MANIFEST_NAME} repeats a credential field name")
        cls.provider_id = data["provider_id"]
        cls.name = data["name"]
        cls.spec_version = data["spec_version"]
        cls.credential_fields = fields
        cls.api_domains = tuple(data["api_domains"])

    def __init__(self, credentials: Mapping[str, str]) -> None:
        """Raises SpsError("unauthenticated") when a declared field is missing or empty."""
        values: dict[str, str] = {}
        for item in type(self).credential_fields:
            value = credentials.get(item.name)
            if value is None or value == "":
                value = item.default
            if value is None or value == "":
                if item.required:
                    raise SpsError("unauthenticated", f"Credential field {item.name!r} is missing")
                continue
            values[item.name] = value
        self.credentials: Mapping[str, str] = MappingProxyType(values)

    def __repr__(self) -> str:
        return f"<{type(self).__name__} (credentials hidden)>"

    # Required operations

    @abstractmethod
    async def discovery(self) -> Discovery: ...

    @classmethod
    def static_discovery(cls) -> Discovery:
        """Optional. What the provider's code says about every account: the ceiling that each
        account's `discovery()` stays within (rule `provider-api/discovery-within-static`).

        No I/O and no credentials, so a caller reads the facts from the installed package alone.
        A provider that does not state it leaves this unimplemented, and the caller sees
        `NotImplementedError`."""
        raise NotImplementedError(f"{cls.__name__} states no static discovery")

    @abstractmethod
    async def create(self, request: CreateRequest, *, idempotency_key: str) -> Sandbox: ...

    @abstractmethod
    async def get(self, sandbox_id: str) -> Sandbox: ...

    @abstractmethod
    async def list(
        self,
        *,
        labels: Mapping[str, str] | None = None,
        cursor: str | None = None,
        limit: int = 100,
    ) -> SandboxPage: ...

    @abstractmethod
    async def destroy(self, sandbox_id: str) -> DestroyResult: ...

    @abstractmethod
    async def run(self, sandbox_id: str, request: RunRequest) -> RunResult: ...

    @abstractmethod
    async def files_read(self, sandbox_id: str, path: str) -> FileStream: ...

    @abstractmethod
    async def files_write(
        self,
        sandbox_id: str,
        path: str,
        data: AsyncIterable[bytes],
        *,
        size: int,
        user: str | None = None,
    ) -> FileInfo: ...

    @abstractmethod
    async def process_start(self, sandbox_id: str, request: ProcessStartRequest) -> Process: ...

    @abstractmethod
    async def process_output(
        self, sandbox_id: str, process_id: str, *, cursor: str | None = None, wait_ms: int = 0
    ) -> OutputPage: ...

    # Optional operations. Each default refuses with `unsupported`; a provider overrides the
    # ones whose section it claims and the tester passes. `cost` is one of them: a provider
    # offers it by stating `limits.cost_final_within_seconds` (and `account.cost`, by stating
    # `limits.account_cost_window_seconds`).

    def _unsupported(self, operation: str) -> SpsError:
        provider = getattr(type(self), "provider_id", type(self).__name__)
        return SpsError("unsupported", f"{provider} does not support {operation}")

    async def cost(self, sandbox_id: str, *, created_at: datetime | None = None) -> Cost:
        """The sandbox's cost. `created_at` is a lookup hint only: use it to bound where to look
        for records, never report a cost from before it, and ignore it when the time is known."""
        raise self._unsupported("cost")

    async def account_cost(self, start: datetime, end: datetime) -> AccountCost:
        """The account's cost for the window from `start` up to `end` (`account.cost`). A provider
        offers it by stating `limits.account_cost_window_seconds`."""
        raise self._unsupported("account.cost")

    async def cost_capture(self, sandbox_id: str, *, idempotency_key: str) -> Cost:
        """Fix the sandbox's cost before it is destroyed (`cost.capture`). After it the sandbox
        allows `get`, a repeated capture and `destroy` only, and the cost need not stay
        readable once the sandbox ends."""
        raise self._unsupported("cost.capture")

    async def account_capacity(self) -> AccountCapacity:
        """What the credential's account may still start, run and spend (`account.capacity`).
        A field the provider does not know is `None`."""
        raise self._unsupported("account.capacity")

    async def files_link(self, sandbox_id: str, request: FileLinkRequest) -> FileLink:
        raise self._unsupported("files.link")

    async def pause(self, sandbox_id: str) -> Sandbox:
        raise self._unsupported("pause")

    async def resume(self, sandbox_id: str) -> Sandbox:
        raise self._unsupported("resume")

    async def lifetime_extend(self, sandbox_id: str, seconds: int) -> Sandbox:
        raise self._unsupported("lifetime.extend")

    async def process_write_stdin(self, sandbox_id: str, process_id: str, data: bytes) -> None:
        raise self._unsupported("process.write_stdin")

    async def process_close_stdin(self, sandbox_id: str, process_id: str) -> None:
        raise self._unsupported("process.close_stdin")

    async def process_cancel(self, sandbox_id: str, process_id: str) -> None:
        raise self._unsupported("process.cancel")

    async def preview_link(
        self,
        sandbox_id: str,
        port: int,
        *,
        access: PreviewAccess = "public",
        lifetime_seconds: int | None = None,
    ) -> PreviewLink:
        """A provider written before `access` and `lifetime_seconds` may keep the shorter
        signature `(sandbox_id, port)`: the server passes the two only when a caller sets them."""
        raise self._unsupported("preview.link")

    async def preview_revoke(self, sandbox_id: str, preview_id: str) -> None:
        """Stop the link that `preview_link` returned under this `id` from serving. An id that is
        already revoked, expired or gone succeeds."""
        raise self._unsupported("preview.revoke")

    async def labels_update(self, sandbox_id: str, labels: Mapping[str, str]) -> Sandbox:
        """Set each given label; an empty value removes the key. Returns the sandbox. A provider
        may refuse a label that is part of the sandbox's identity with `conflict`."""
        raise self._unsupported("labels.update")

    async def tcp_link(self, sandbox_id: str, port: int) -> TcpLink:
        raise self._unsupported("tcp.link")

    async def files_list(
        self, sandbox_id: str, path: str, *, cursor: str | None = None, limit: int = 100
    ) -> DirectoryPage:
        raise self._unsupported("files.list")

    async def files_mkdir(self, sandbox_id: str, path: str, *, parents: bool = False) -> None:
        raise self._unsupported("files.mkdir")

    async def files_remove(self, sandbox_id: str, path: str, *, recursive: bool = False) -> None:
        raise self._unsupported("files.remove")

    async def files_exists(self, sandbox_id: str, path: str) -> PathInfo:
        raise self._unsupported("files.exists")

    async def snapshot_create(
        self, sandbox_id: str, request: SnapshotRequest, *, idempotency_key: str
    ) -> Snapshot:
        raise self._unsupported("snapshot.create")

    async def snapshot_get(self, snapshot_id: str) -> Snapshot:
        raise self._unsupported("snapshot.get")

    async def snapshot_list(
        self,
        *,
        labels: Mapping[str, str] | None = None,
        sandbox_id: str | None = None,
        cursor: str | None = None,
        limit: int = 100,
    ) -> SnapshotPage:
        raise self._unsupported("snapshot.list")

    async def snapshot_delete(self, snapshot_id: str) -> SnapshotDeleteResult:
        raise self._unsupported("snapshot.delete")

    async def snapshot_cost(self, snapshot_id: str) -> Cost:
        raise self._unsupported("snapshot.cost")

    async def image_prepare(
        self,
        request: ImageRequest,
        *,
        context: AsyncIterable[bytes] | None = None,
        context_size: int | None = None,
        idempotency_key: str,
    ) -> PreparedImage:
        """Prepare an image ahead of creation. `context` is the build context (a tar archive) as
        a stream that the adapter reads once; `context_size` is its size when the caller says it."""
        raise self._unsupported("image.prepare")

    async def image_get(self, image_id: str) -> PreparedImage:
        raise self._unsupported("image.get")

    async def image_list(
        self,
        *,
        labels: Mapping[str, str] | None = None,
        cursor: str | None = None,
        limit: int = 100,
    ) -> ImagePage:
        raise self._unsupported("image.list")

    async def image_delete(self, image_id: str) -> ImageDeleteResult:
        raise self._unsupported("image.delete")

    async def image_cost(self, image_id: str, *, created_at: datetime | None = None) -> Cost:
        """What preparing the image cost (`image.cost`). `created_at` is a lookup hint only: the
        time that the caller started the preparation."""
        raise self._unsupported("image.cost")

    async def terminal_open(self, sandbox_id: str, request: TerminalRequest) -> Terminal:
        """Start the program and return its terminal. With `request.id`, closing the terminal only
        detaches it (a class that claims `terminal` with `reattach: true`); without, it ends."""
        raise self._unsupported("terminal.open")

    async def terminal_reattach(self, sandbox_id: str, terminal_id: str) -> Terminal:
        """Connect to the terminal that `terminal_open` started under this `id` and that is still
        running; `not_found` when it is not. An earlier connection to it is closed."""
        raise self._unsupported("terminal.reattach")

    async def terminal_end(self, sandbox_id: str, terminal_id: str) -> None:
        """End the terminal that was opened under this `id`, as a closed connection ends a
        terminal that has none. An id that is already gone succeeds."""
        raise self._unsupported("terminal.end")

    async def network_update(
        self,
        sandbox_id: str,
        policy: str,
        *,
        allow: Sequence[str | Mapping[str, object]] = (),
        deny: Sequence[str | Mapping[str, object]] = (),
    ) -> None:
        """Replace the running sandbox's network policy (`deny_all`, `allowlist`, `denylist` or
        `open`) and its `allow` or `deny` entries; the sandbox keeps its processes and files.
        The new policy holds when the call returns. A policy or entries that the sandbox's
        `network_lockdown` variant does not allow (`switches_to`, `changeable`) are refused with
        `unsupported`."""
        raise self._unsupported("network.update")

    async def aclose(self) -> None:
        """Release HTTP clients; the host calls it once when it is done with the adapter."""
        return None


def installed() -> Mapping[str, type[Provider]]:
    """Every installed `Provider` by provider id: the one resolver of the
    `sandbox_provider_spec.providers` entry-point group. Loads each package. An id named twice,
    or an entry that is not a `Provider` subclass, is a `ValueError`."""
    found: dict[str, type[Provider]] = {}
    for entry in entry_points(group=PROVIDERS_GROUP):
        if entry.name in found:
            raise ValueError(f"provider id {entry.name!r} is registered twice in {PROVIDERS_GROUP}")
        loaded = entry.load()
        if not (isinstance(loaded, type) and issubclass(loaded, Provider)):
            raise ValueError(f"{PROVIDERS_GROUP} entry {entry.name!r} is not a Provider subclass")
        found[entry.name] = loaded
    return MappingProxyType(found)
