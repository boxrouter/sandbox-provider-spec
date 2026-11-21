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
LifetimeEnforcer = Literal["provider", "router"]
LabelKeeper = Literal["provider", "router"]
SnapshotCostMode = Literal["offered", "unavailable"]
ImageDeleteInUse = Literal["accepted", "conflict"]
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
# What a prepared image can be tied to: a size or a place (`classes[].image_binds`).
ImageBind = Literal["cpu_min", "memory_min_mib", "disk_min_mib", "region", "kernel"]


@dataclass(frozen=True)
class CredentialField:
    name: str  # for example "api_key"; a-z 0-9 _, 1 to 32 characters
    secret: bool = True
    required: bool = True
    default: str | None = None  # only for a field that is not secret
    description: str = ""
    # How a secret's values start (`dtn_`, `ak-`): 2 to 8 lowercase letters or digits and `_` or
    # `-`. A consumer checks a key against it before any call and redacts what starts with it.
    public_prefix: str | None = None


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
    amount_usd: Decimal | None  # null exactly when the cost's source is `usage`
    quantity: Decimal | None = None  # required unless the cost is `reported`
    unit: str | None = None  # required unless the cost is `reported`
    start: datetime | None = None  # both null: no period (a fee); `end` null alone: open
    end: datetime | None = None


@dataclass(frozen=True)
class Cost:
    sandbox_id: str | None  # null only for an image's cost, which sets `image_id`
    status: Literal["accruing", "final"]
    # null while `accruing` with nothing metered yet, and always when `source` is `usage`
    total_usd: Decimal | None
    source: Literal["reported", "calculated", "usage"]
    lines: Sequence[CostLine]
    as_of: datetime  # when the provider stated the figures
    snapshot_id: str | None = None  # set by `snapshot_cost` only
    image_id: str | None = None  # set by `image_cost` only


@dataclass(frozen=True)
class AccountCost:
    """What the account was charged, or used, between `start` and `end`."""

    start: datetime
    end: datetime
    status: Literal["accruing", "final"]
    # null while `accruing` with nothing metered yet, and always when `source` is `usage`
    total_usd: Decimal | None
    source: Literal["reported", "calculated", "usage"]
    lines: Sequence[CostLine]
    as_of: datetime


@dataclass(frozen=True)
class StartWindow:
    window_seconds: int
    used: int
    limit: int
    remaining: int


@dataclass(frozen=True)
class Concurrency:
    active: int
    limit: int


@dataclass(frozen=True)
class Prepaid:
    balance_usd: Decimal
    past_due: bool


@dataclass(frozen=True)
class StoredArtifacts:
    """The prepared images and snapshots, counted together, that the account holds (`used`) and may
    hold (`limit`). A `None` field is not reported, never a zero or a guess."""

    used: int | None
    limit: int | None


@dataclass(frozen=True)
class AccountCapacity:
    """What `account_capacity` returns. A `None` field is unknown, never a zero or a guess."""

    as_of: datetime
    starts: Sequence[StartWindow]
    can_start: bool | None
    paid_overage_enabled: bool | None
    concurrency: Concurrency | None
    prepaid: Prepaid | None
    # Optional: a provider whose API does not report it leaves it out, which reads as None.
    stored_artifacts: StoredArtifacts | None = None


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
    init: bool | None = None  # the image's CMD starts a machine init as process 1
    user_name: str | None = None  # the name of a numeric `user`, resolved from the image
    home: str | None = None  # the home directory of `user`, resolved from the image


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
    base: OciSource | None = None  # the caller's resolution of the Dockerfile's single FROM


ImageSource = OciSource | PrivateOciSource | DockerfileSource


@dataclass(frozen=True)
class ImageResources:
    """A size. A field that is `None` is not bound."""

    cpu: float | None = None
    memory_mib: int | None = None
    disk_mib: int | None = None
    region: str | None = None
    kernel: str | None = None


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
    id: str | None = None  # names the terminal for `terminal_reattach` and `terminal_end`


@dataclass(frozen=True)
class TerminalLink:
    """What `terminal.open` returns over HTTP: a single-use WebSocket link."""

    url: str  # sensitive: never log it
    headers: Mapping[str, str]
    expires_at: datetime


class Terminal(ABC):
    """An open terminal (contract section 10.1), returned by `terminal_open` or `terminal_reattach`
    with its program started. The caller owns it and closes it; errors after the start are raised
    as SpsError. Closing a terminal opened with a `TerminalRequest.id` only detaches it."""

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
    image_layout_bytes: int | None = None  # largest OCI image layout of `image.prepare.oci_layout`
    # What the provider documents for its default plan: the most prepared images and snapshots,
    # counted together, that an account may keep. Display only: a consumer never enforces it, never
    # evicts on it and never treats it as a ceiling (the account's own figure is
    # `AccountCapacity.stored_artifacts.limit`).
    stored_artifacts_documented: int | None = None


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


LifetimeEnding = Literal["destroyed", "paused", "stopped"]
_ENFORCERS = ("provider", "router", "none")
_ENDINGS = ("destroyed", "paused", "stopped")


@dataclass(frozen=True)
class LifetimeTimerView:
    """A class's declared lifetime timer (`SandboxClass.timer()`). `enforced_by` says who ends a
    sandbox whose lifetime ran out (`none`: nobody), `counts_paused_time` whether the provider's
    timer runs while the sandbox is paused, and `at_end` the states the timer can leave it in:
    one entry for a fixed ending, several where the caller chooses at creation."""

    enforced_by: Literal["provider", "router", "none"]
    counts_paused_time: bool
    at_end: tuple[LifetimeEnding, ...]


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
    # Who ends a sandbox when its lifetime runs out: the provider (the default, rule
    # `provider-api/lifetime-enforced`) or the caller, the router, through its lease and sweeper.
    lifetime_enforced_by: LifetimeEnforcer = "provider"
    # True: commands and `pause`, `resume` and `stop` on one sandbox must not overlap, so the
    # caller orders them (a command's outcome is recorded before the next transition, and a
    # transition's before the next command). False: the provider serves them concurrently.
    ordered_sessions: bool = False
    # True: the memory total a sandbox of the class reports about itself is not the memory it
    # can use (a sandbox runtime that shows the host's), so the caller does not take the total
    # from the sandbox. False (the default): the total is the sandbox's own.
    memory_totals_untrusted: bool = False
    # Optional operations that no SPS gate covers: all four of `files.list`, `files.mkdir`,
    # `files.remove` and `files.exists`, or none (contract section 10.3); and `labels.update`.
    operations: Sequence[str] = ()
    # What a prepared image of this class is tied to; null unless the class lists `image.prepare`.
    # An empty list means that the image fits any size (S15).
    image_binds: Sequence[ImageBind] | None = None
    # Who keeps the labels of a prepared image / a snapshot: the provider (the default, rules
    # `provider-api/image-list` and `provider-api/snapshot-list`) or the caller, the router, which
    # keeps them itself because the provider has nowhere to store them. Both are states of the
    # class's image and snapshot sections; they apply to every class of the provider alike.
    image_labels_kept_by: LabelKeeper = "provider"
    snapshot_labels_kept_by: LabelKeeper = "provider"
    # Whether `snapshot.cost` answers (the default, rule `provider-api/snapshot-cost`) or the
    # provider cannot report what a snapshot costs and answers `unsupported`
    # (`provider-api/snapshot-cost-unavailable`), while `cost` for sandboxes stays offered.
    snapshot_cost: SnapshotCostMode = "offered"
    # Whether `image.delete` is accepted while a sandbox made from the image exists (the default,
    # rule `provider-api/image-delete`) or answers `conflict` until those sandboxes end
    # (`provider-api/image-delete-in-use`).
    image_delete_in_use: ImageDeleteInUse = "accepted"

    # Typed views of the plain-mapping fields above. Pure, no I/O.
    def claims(self, gate: str) -> tuple[Mapping[str, object], ...]:
        """The variants this class claims for `gate`, in order: a gate's body is one mapping or a
        list of them. Empty when the gate is unclaimed; non-mapping entries are dropped."""
        value = (self.gates or {}).get(gate)
        if value is None:
            return ()
        items = value if isinstance(value, Sequence) and not isinstance(value, str) else (value,)
        return tuple(entry for entry in items if isinstance(entry, Mapping))

    def lists(self, *operations: str) -> bool:
        """Whether this class lists every one of `operations` in `operations`."""
        return set(operations) <= set(self.operations)

    def labels_kept_by(self, kind: Literal["image", "snapshot"]) -> LabelKeeper:
        """Who keeps the labels of this class's prepared images or snapshots: the provider, or the
        router (which then keeps them itself)."""
        return self.image_labels_kept_by if kind == "image" else self.snapshot_labels_kept_by

    def timer(self) -> LifetimeTimerView | None:
        """The lifetime timer, or None where the declaration is not one the spec defines (an
        unknown enforcer or ending says nothing, so nothing is enforced). A missing `enforced_by`
        is `none`, a missing `at_end` is `destroyed`."""
        body = self.lifetime_timer
        enforced_by = body.get("enforced_by", "none")
        at_end = body.get("at_end", "destroyed")
        endings = (
            tuple(at_end)
            if isinstance(at_end, Sequence) and not isinstance(at_end, str)
            else (at_end,)
        )
        paused = body.get("counts_paused_time", False)
        if (
            enforced_by not in _ENFORCERS
            or not endings
            or any(entry not in _ENDINGS for entry in endings)
            or not isinstance(paused, bool)
        ):
            return None
        return LifetimeTimerView(enforced_by, paused, endings)  # type: ignore[arg-type]


@dataclass(frozen=True)
class Discovery:
    spec_version: str  # "1.<minor>"
    provider: ProviderInfo
    limits: Limits
    classes: Sequence[SandboxClass]
