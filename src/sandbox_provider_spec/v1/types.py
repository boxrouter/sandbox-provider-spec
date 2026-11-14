# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The data types of the 1.0 provider API. Each one mirrors an object in the OpenAPI file."""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from typing import Literal

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


@dataclass(frozen=True)
class SandboxPage:
    sandboxes: Sequence[Sandbox]
    next_cursor: str | None


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
    quantity: Decimal
    unit: str
    amount_usd: Decimal
    start: datetime | None
    end: datetime | None


@dataclass(frozen=True)
class Cost:
    sandbox_id: str
    status: Literal["accruing", "final"]
    total_usd: Decimal
    source: Literal["reported", "calculated"]
    lines: Sequence[CostLine]
    as_of: datetime


@dataclass(frozen=True)
class DestroyResult:
    sandbox_id: str
    state: Literal["destroying", "destroyed"]
    cost: Cost | None = None


@dataclass(frozen=True)
class RunRequest:
    argv: Sequence[str]
    cwd: str | None = None
    env: Mapping[str, str] = field(default_factory=dict)
    timeout_ms: int = 60_000
    output_limit_bytes: int = 16 * 1024 * 1024


@dataclass(frozen=True)
class RunResult:
    exit_code: int | None
    stdout: str
    stderr: str
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    timed_out: bool = False


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


@dataclass(frozen=True)
class TcpLink:
    host: str
    port: int


@dataclass(frozen=True)
class Limits:
    file_bytes: int
    run_timeout_ms: int
    output_bytes: int
    wait_ms: int
    process_output_bytes: int
    process_retention_seconds: int
    list_limit: int


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


@dataclass(frozen=True)
class Discovery:
    spec_version: str  # "1.<minor>"
    provider: ProviderInfo
    limits: Limits
    classes: Sequence[SandboxClass]
