# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The data types of the 1.0 provider API. Each one mirrors an object in the OpenAPI file."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from typing import Literal

from sandbox_provider_spec.v1.errors import SpsError

# These types mirror the objects of the OpenAPI file field for field, so their size is set by
# the contract.
# pylint: disable=too-many-instance-attributes

SandboxState = Literal["running", "paused", "stopped", "destroyed"]
EndState = Literal["destroyed", "paused"]
PriceItem = Literal[
    "cpu",
    "memory",
    "disk",
    "gpu",
    "machine",
    "create",
    "egress",
    "snapshot",
    "volume",
    "start",
    "request",
    "feature",
]
PreviewAccess = Literal["public", "private"]
PreviewCredential = Literal["link", "header"]
PriceBasis = Literal["allocated", "used", "max_allocated_used", "fixed", "count"]


@dataclass(frozen=True)
class CredentialField:
    name: str  # for example "api_key"; a-z 0-9 _, 1 to 32 characters
    secret: bool = True
    required: bool = True
    default: str | None = None  # only for a field that is not secret
    description: str = ""


@dataclass(frozen=True)
class Size:
    cpu: float
    memory_mib: int
    disk_mib: int | None = None


TimeKind = Literal[
    "created",
    "started",
    "ready",
    "paused",
    "resumed",
    "stopped",
    "ended",
    "deadline",
    "billed_start",
    "billed_end",
    "requested",
    "stop_requested",
    "updated",
    "checkpointed",
]


@dataclass(frozen=True)
class ProviderTime:
    """One time that the provider's own records state for a sandbox."""

    kind: TimeKind
    at: datetime
    source: str  # the provider's own name for the field that held the time


@dataclass(frozen=True)
class Sandbox:
    id: str
    sandbox_class: str
    state: SandboxState
    size: Size
    region: str | None
    image: str | None
    labels: Mapping[str, str]
    created_at: datetime
    ends_at: datetime | None
    at_end: EndState | None
    times: Sequence[ProviderTime] = ()  # `get` returns them when the provider keeps any


@dataclass(frozen=True)
class SandboxPage:
    sandboxes: Sequence[Sandbox]
    next_cursor: str | None


@dataclass(frozen=True)
class SecretHeader:
    name: str  # an HTTP header name
    prefix: str = ""
    suffix: str = ""


@dataclass(frozen=True)
class Secret:
    """One write-only credential of a create (needs the `hidden_secrets` section). The value is
    never returned, logged or put in an error, and is left out of `repr`."""

    placeholder: str  # what code in the sandbox sees
    value: str = field(repr=False)
    hosts: Sequence[str]
    headers: Sequence[SecretHeader] = ()


@dataclass(frozen=True)
class CreateRequest:
    sandbox_class: str = "default"
    resources: Mapping[str, object] = field(default_factory=dict)  # SPS request resources
    requirements: Mapping[str, object] = field(default_factory=dict)  # SPS request requirements
    image: str | Mapping[str, str] | None = None  # SPS request image
    lifetime_seconds: int | None = 300
    at_end: EndState = "destroyed"
    env: Mapping[str, str] = field(default_factory=dict)
    labels: Mapping[str, str] = field(default_factory=dict)
    snapshot: str | None = None  # restore from this snapshot (needs the `snapshots` section)
    secrets: Sequence[Secret] = field(default=(), repr=False)  # write-only; see `Secret`


@dataclass(frozen=True)
class Price:
    item: PriceItem
    price_usd: Decimal
    unit: str  # one of the units of the OpenAPI file's PriceUnit
    basis: PriceBasis
    included: bool = False
    states: Sequence[SandboxState] | None = None  # None: running only, other states unknown
    increment_seconds: int | None = None
    minimum_seconds: int | None = None
    minimum_quantity: Decimal | None = None
    allowance: Mapping[str, object] | None = None
    size: Size | None = None
    region: str | None = None
    gpu_model: str | None = None
    variant: str | None = None


@dataclass(frozen=True)
class CostLine:
    item: str
    amount_usd: Decimal
    quantity: Decimal | None = None  # required when the cost is `calculated`
    unit: str | None = None  # required when the cost is `calculated`
    start: datetime | None = None  # both null: no period (a fee); `end` null alone: open
    end: datetime | None = None


@dataclass(frozen=True)
class Cost:
    sandbox_id: str
    status: Literal["accruing", "final"]
    total_usd: Decimal | None  # null only while `accruing` and nothing is metered yet
    source: Literal["reported", "calculated"]
    lines: Sequence[CostLine]
    as_of: datetime  # when the provider stated the figures
    snapshot_id: str | None = None  # set by `snapshot_cost` only


@dataclass(frozen=True)
class AccountCost:
    """What the account was charged between `start` and `end`; money only."""

    start: datetime
    end: datetime
    status: Literal["accruing", "final"]
    total_usd: Decimal | None  # null only while `accruing` and nothing is metered yet
    source: Literal["reported", "calculated"]
    lines: Sequence[CostLine]
    as_of: datetime


@dataclass(frozen=True)
class DestroyResult:
    sandbox_id: str
    state: Literal["destroying", "destroyed"]


SnapshotKeeps = Literal["files_only", "files_and_memory"]


@dataclass(frozen=True)
class SnapshotRequest:
    keeps: SnapshotKeeps | None = None  # None: what the sandbox's variant keeps
    labels: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Snapshot:
    id: str
    sandbox_id: str
    sandbox_class: str
    state: Literal["saving", "ready", "failed"]
    keeps: SnapshotKeeps
    size: Size
    stored_bytes: int | None
    labels: Mapping[str, str]
    created_at: datetime
    expires_at: datetime | None


@dataclass(frozen=True)
class SnapshotPage:
    snapshots: Sequence[Snapshot]
    next_cursor: str | None


@dataclass(frozen=True)
class SnapshotDeleteResult:
    snapshot_id: str
    state: Literal["deleting", "deleted"]


@dataclass(frozen=True)
class ImageConfig:
    """The image's own settings, resolved by the caller. The provider reaches no registry."""

    env: Mapping[str, str] = field(default_factory=dict)
    workdir: str | None = None
    user: str | None = None
    entrypoint: Sequence[str] | None = None
    cmd: Sequence[str] | None = None


@dataclass(frozen=True)
class RegistryCredentials:
    """Registry credentials: write-only, never returned, logged or shown in a repr."""

    username: str = field(repr=False)
    password: str = field(repr=False)


@dataclass(frozen=True)
class OciSource:
    oci: str
    digest: str  # `sha256:` and 64 lowercase hex digits
    config: ImageConfig


@dataclass(frozen=True)
class PrivateOciSource:
    private_oci: str
    digest: str
    config: ImageConfig
    credentials: RegistryCredentials


@dataclass(frozen=True)
class DockerfileSource:
    dockerfile: str  # the text; the build context is `image_prepare`'s `context`


ImageSource = OciSource | PrivateOciSource | DockerfileSource


@dataclass(frozen=True)
class ImageResources:
    """A size. A field that is `None` is not bound."""

    cpu: float | None = None
    memory_mib: int | None = None
    disk_mib: int | None = None


@dataclass(frozen=True)
class ImageRequest:
    source: ImageSource
    resources: ImageResources | None = None  # the size a sandbox from the image must start with
    labels: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class PreparedImage:
    """A prepared image (not to be confused with `Image`, a ready-made image in discovery)."""

    id: str
    state: Literal["preparing", "ready", "failed"]
    error: SpsError | None  # why it failed; set only when `state` is `failed`
    resources: ImageResources | None  # the size it is bound to; None: any size
    stored_bytes: int | None
    labels: Mapping[str, str]
    created_at: datetime


@dataclass(frozen=True)
class ImagePage:
    images: Sequence[PreparedImage]
    next_cursor: str | None


@dataclass(frozen=True)
class ImageDeleteResult:
    id: str
    state: Literal["deleting", "deleted"]


@dataclass(frozen=True)
class RunRequest:
    argv: Sequence[str]
    cwd: str | None = None
    env: Mapping[str, str] = field(default_factory=dict)
    timeout_ms: int = 60_000
    output_limit_bytes: int = 16 * 1024 * 1024
    user: str | None = None  # None is the class's default user
    output: Literal["text", "base64"] = "text"


@dataclass(frozen=True)
class RunResult:
    exit_code: int | None
    stdout: str
    stderr: str
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    timed_out: bool = False
    # With `RunRequest.output == "base64"` these hold the exact bytes of each stream, and
    # `stdout` and `stderr` are empty. They are None when the output is text.
    stdout_base64: str | None = None
    stderr_base64: str | None = None


@dataclass(frozen=True)
class FileStream:
    size: int | None  # None when the provider does not know it up front
    chunks: AsyncIterator[bytes]  # the caller iterates to the end or calls chunks.aclose()


@dataclass(frozen=True)
class FileInfo:
    path: str
    size: int


@dataclass(frozen=True)
class ProcessStartRequest:
    argv: Sequence[str]
    cwd: str | None = None
    env: Mapping[str, str] = field(default_factory=dict)
    stdin: bool = False
    user: str | None = None  # None is the class's default user


@dataclass(frozen=True)
class Process:
    id: str
    sandbox_id: str
    started_at: datetime


@dataclass(frozen=True)
class OutputChunk:
    stream: Literal["stdout", "stderr"]
    data: str


@dataclass(frozen=True)
class OutputPage:
    chunks: Sequence[OutputChunk]
    next_cursor: str
    gap: bool
    stdout_closed: bool
    stderr_closed: bool
    state: Literal["running", "exited"]
    exit_code: int | None


@dataclass(frozen=True)
class FileLinkRequest:
    path: str
    operation: Literal["read", "write"]
    lifetime_seconds: int
    size: int | None = None


@dataclass(frozen=True)
class FileLink:
    method: str
    url: str  # sensitive: never log it
    headers: Mapping[str, str]
    form_field: str | None
    expires_at: datetime
    reusable: bool = False


@dataclass(frozen=True)
class PreviewLink:
    url: str  # sensitive: never log it
    headers: Mapping[str, str]
    expires_at: datetime | None
    id: str | None = None  # names the link for `preview_revoke`; None when it cannot be revoked
    access: PreviewAccess = "public"
    credential: PreviewCredential | None = None  # where a private link's credential travels


@dataclass(frozen=True)
class TcpLink:
    host: str
    port: int


EntryType = Literal["file", "directory", "symlink", "other"]


@dataclass(frozen=True)
class DirectoryEntry:
    name: str
    type: EntryType
    size: int


@dataclass(frozen=True)
class DirectoryPage:
    entries: Sequence[DirectoryEntry]
    next_cursor: str | None


@dataclass(frozen=True)
class PathInfo:
    exists: bool
    type: EntryType | None


@dataclass(frozen=True)
class TerminalRequest:
    argv: Sequence[str] | None = None  # None: the default user's login shell
    cwd: str | None = None
    env: Mapping[str, str] = field(default_factory=dict)
    columns: int = 80
    rows: int = 24
    term: str = "xterm-256color"


@dataclass(frozen=True)
class TerminalLink:
    """What `terminal.open` returns over HTTP: a single-use WebSocket link."""

    url: str  # sensitive: never log it
    headers: Mapping[str, str]
    expires_at: datetime


class Terminal(ABC):
    """An open terminal (contract section 10.1), returned by `terminal_open` with its program
    started. The caller owns it and closes it; errors after the start are raised as SpsError."""

    exit_code: int | None  # set once output() has ended because the program exited

    @abstractmethod
    async def write(self, data: bytes) -> None: ...

    @abstractmethod
    async def resize(self, columns: int, rows: int) -> None: ...

    @abstractmethod
    def output(self) -> AsyncIterator[bytes]:
        """The bytes that the terminal produces, in order; ends at the exit or at close."""

    @abstractmethod
    async def close(self) -> None:
        """End the terminal as a closed connection does. Closing twice succeeds."""


@dataclass(frozen=True)
class Limits:
    file_bytes: int
    run_timeout_ms: int
    output_bytes: int
    wait_ms: int
    process_output_bytes: int
    process_retention_seconds: int
    list_limit: int
    cost_final_within_seconds: int | None = None  # stating it offers `cost`
    image_context_bytes: int | None = None  # the largest build context `image_prepare` accepts
    account_cost_window_seconds: int | None = None  # stating it offers `account.cost`


@dataclass(frozen=True)
class ProviderInfo:
    id: str
    name: str
    docs_url: str | None = None


@dataclass(frozen=True)
class Image:
    id: str
    default: bool
    description: str


@dataclass(frozen=True)
class SandboxClass:
    id: str
    name: str
    ready: bool
    # `resources`, `lifetime_timer` and `gates` are the bodies that an SPS declaration defines;
    # they stay plain mappings and are validated against the SPS declaration schema.
    resources: Mapping[str, object]
    lifetime_timer: Mapping[str, object]
    images: Sequence[Image]
    prices: Sequence[Price]
    gates: Mapping[str, object] | None = None
    unavailable_regions: Sequence[str] = ()
    # Optional operations that no SPS gate covers: all four of `files.list`, `files.mkdir`,
    # `files.remove` and `files.exists`, or none (contract section 10.3); and `labels.update`.
    operations: Sequence[str] = ()


@dataclass(frozen=True)
class Discovery:
    spec_version: str  # "1.<minor>"
    provider: ProviderInfo
    limits: Limits
    classes: Sequence[SandboxClass]
