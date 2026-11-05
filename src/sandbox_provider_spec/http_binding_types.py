# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Generated HTTP binding wire shapes; validate values before trusting them.

Do not edit: tooling/http_binding/generate.py. These types are not an HTTP client.
"""

from __future__ import annotations

from typing import Literal, NotRequired, TypedDict

Identifier = str

Path = str

Environment = dict[str, str]

Base64 = str

Digest = str

AllocationKey = str


class SandboxIdentity(TypedDict):
    provider_id: Identifier
    account_id: Identifier
    offering_id: Identifier
    sandbox_id: Identifier
    incarnation: Identifier


class ProcessIdentity(TypedDict):
    sandbox: SandboxIdentity
    process_id: Identifier
    incarnation: Identifier


class Limits(TypedDict):
    request_bytes: int
    response_bytes: int
    command_output_bytes: int
    file_bytes: int
    page_size: int
    output_frames: int
    observation_ms: int
    process_buffer_bytes: int
    buffered_command_output_bytes: NotRequired[int]
    execution_ms: NotRequired[int]


class Offering(TypedDict):
    offering_id: Identifier
    declaration_id: Identifier
    declaration: dict[str, object]


class Discovery(TypedDict):
    binding: Literal[
        "sandbox-provider-http/0.1", "sandbox-provider-http/0.2", "sandbox-provider-http/0.3"
    ]
    endpoint_origin: str
    provider_id: Identifier
    account_id: Identifier
    server_revision: Identifier
    operations: list[str]
    limits: Limits
    create_key_window_seconds: Literal[86400]
    process_retention_seconds: int
    process_addressability: Literal["endpoint_lifetime"]
    core_modes: list[Literal["buffered_commands_v1"]]
    offerings: list[Offering]


class CreateRequest(TypedDict):
    operation: Literal["create"]
    request_id: Identifier
    account_id: Identifier
    allocation_key: AllocationKey
    offering_id: Identifier
    declaration_id: Identifier
    request: dict[str, object]
    env: Environment


class CreateResult(TypedDict):
    operation: Literal["create"]
    request_id: Identifier
    account_id: Identifier
    allocation_key: AllocationKey
    request_digest: Digest
    key_expires_at: int
    state: Literal["pending", "ready", "unknown", "unavailable"]
    sandbox: SandboxIdentity | None


class GetRequest(TypedDict):
    operation: Literal["get"]
    request_id: Identifier
    account_id: Identifier
    sandbox: SandboxIdentity


class GetResult(TypedDict):
    operation: Literal["get"]
    request_id: Identifier
    account_id: Identifier
    sandbox: SandboxIdentity
    state: Literal["active", "paused", "destroyed", "absent", "unknown"]


class ListRequest(TypedDict):
    operation: Literal["list"]
    request_id: Identifier
    account_id: Identifier
    offering_id: Identifier | None
    cursor: str | None
    page_size: int


class InventoryItem(TypedDict):
    sandbox: SandboxIdentity
    state: Literal["active", "paused", "destroyed", "unknown"]


class ListResult(TypedDict):
    operation: Literal["list"]
    request_id: Identifier
    account_id: Identifier
    items: list[InventoryItem]
    next_cursor: str | None


class DestroyRequest(TypedDict):
    operation: Literal["destroy"]
    request_id: Identifier
    account_id: Identifier
    sandbox: SandboxIdentity


class DestroyResult(TypedDict):
    operation: Literal["destroy"]
    request_id: Identifier
    account_id: Identifier
    sandbox: SandboxIdentity
    state: Literal["accepted", "destroyed", "absent"]


class RunRequest(TypedDict):
    operation: Literal["run"]
    request_id: Identifier
    account_id: Identifier
    sandbox: SandboxIdentity
    argv: list[str]
    cwd: Path | None
    env: Environment
    observation_timeout_ms: int
    encoding: Literal["utf8", "base64"]
    mode: NotRequired[str]
    execution_limit_ms: NotRequired[int]
    output_limit_bytes: NotRequired[int]


class RunResult(TypedDict):
    operation: Literal["run"]
    request_id: Identifier
    account_id: Identifier
    sandbox: SandboxIdentity
    stdout: NotRequired[str]
    stderr: NotRequired[str]
    exit_code: int
    output_complete: Literal[True]
    mode: NotRequired[Literal["buffered_commands_v1"]]
    encoding: NotRequired[Literal["base64"]]
    stdout_base64: NotRequired[Base64]
    stderr_base64: NotRequired[Base64]
    stdout_bytes: NotRequired[int]
    stderr_bytes: NotRequired[int]
    stdout_truncated: NotRequired[bool]
    stderr_truncated: NotRequired[bool]


class ReadRequest(TypedDict):
    operation: Literal["files.read_bytes"]
    request_id: Identifier
    account_id: Identifier
    sandbox: SandboxIdentity
    path: Path
    limit_bytes: int


class ReadResult(TypedDict):
    operation: Literal["files.read_bytes"]
    request_id: Identifier
    account_id: Identifier
    sandbox: SandboxIdentity
    data_base64: Base64
    byte_count: int
    complete: Literal[True]


class WriteRequest(TypedDict):
    operation: Literal["files.write"]
    request_id: Identifier
    account_id: Identifier
    sandbox: SandboxIdentity
    path: Path
    data_base64: Base64
    byte_count: int


class WriteResult(TypedDict):
    operation: Literal["files.write"]
    request_id: Identifier
    account_id: Identifier
    sandbox: SandboxIdentity
    written_bytes: int


class StartRequest(TypedDict):
    operation: Literal["process.start"]
    request_id: Identifier
    account_id: Identifier
    sandbox: SandboxIdentity
    argv: list[str]
    cwd: Path | None
    env: Environment
    observation_timeout_ms: int


class StartResult(TypedDict):
    operation: Literal["process.start"]
    request_id: Identifier
    account_id: Identifier
    process: ProcessIdentity


class Frame(TypedDict):
    sequence: int
    stream: Literal["stdout", "stderr"]
    text: str


class OutputRequest(TypedDict):
    operation: Literal["process.output"]
    request_id: Identifier
    account_id: Identifier
    process: ProcessIdentity
    cursor: int
    max_frames: int
    observation_timeout_ms: int
    limit_bytes: int


class OutputResult(TypedDict):
    operation: Literal["process.output"]
    request_id: Identifier
    account_id: Identifier
    process: ProcessIdentity
    frames: list[Frame]
    first_available_cursor: int
    next_cursor: int
    gap: bool
    stdout_eof: bool
    stderr_eof: bool
    execution_state: Literal["running", "exited", "unknown"]
    exit_code: int | None
    observation_end: Literal["page", "wait_timeout", "stream_end", "process_exit", "unavailable"]


class Error(TypedDict):
    operation: Literal[
        "create",
        "get",
        "list",
        "destroy",
        "run",
        "files.read_bytes",
        "files.write",
        "process.start",
        "process.output",
    ]
    request_id: Identifier | None
    account_id: Identifier | None
    error: Failure


class Failure(TypedDict):
    code: Literal[
        "invalid_request",
        "unauthenticated",
        "forbidden",
        "unsupported_mode",
        "conflict",
        "expired_key",
        "limit_exceeded",
        "timeout",
        "provider_error",
        "output_unavailable",
    ]
    outcome: Literal["not_dispatched", "failed", "unknown", "completed"]
    message: str
    exit_code: int | None


Labels = dict[str, str]


class LifetimeObservation(TypedDict):
    ready_at: str | None
    ends_at: str | None


class AdmissionRequirements(TypedDict):
    fuse_mount: NotRequired[dict[str, object]]
    idle_shutdown: NotRequired[dict[str, object]]
    pause_resume: NotRequired[dict[str, object]]
    previews: NotRequired[dict[str, object]]
    network_lockdown: NotRequired[dict[str, object]]
    hidden_secrets: NotRequired[dict[str, object]]
    snapshots: NotRequired[dict[str, object]]
    volumes: NotRequired[dict[str, object]]
    custom_images: NotRequired[dict[str, object]]
    user_selection: NotRequired[dict[str, object]]
    processes: NotRequired[dict[str, object]]
    terminal: NotRequired[dict[str, object]]
    docker: NotRequired[dict[str, object]]
    tcp_ports: NotRequired[dict[str, object]]
    desktop: NotRequired[dict[str, object]]


class SelectedSize(TypedDict):
    cpu: NotRequired[float]
    memory_mib: NotRequired[int]
    disk_mib: NotRequired[int]


class SelectedGpu(TypedDict):
    model: str
    count: int


class SelectedResources(TypedDict):
    size: NotRequired[SelectedSize]
    region: NotRequired[str | None]
    gpu: NotRequired[SelectedGpu]
    root: NotRequired[list[Literal["by_default", "sudo", "per_command"]]]
    arch: NotRequired[Literal["amd64", "arm64"]]
    egress_ips: NotRequired[Literal["published_ranges", "dedicated"]]
    kernel_features: NotRequired[list[Literal["fuse", "ebpf", "nested_cgroups", "netfilter"]]]
    outbound_traffic: NotRequired[list[Literal["http", "any_tcp", "udp"]]]


class AdmissionSelection(TypedDict):
    binding: Literal["sandbox-provider-http/0.3"]
    core_modes: list[str]
    limits: Limits
    process_retention_seconds: int | None
    process_addressability: str
    offering: Offering


class Admission(TypedDict):
    selection: AdmissionSelection
    requirements: AdmissionRequirements
    resources: SelectedResources
    lifetime_seconds: int | None
    at_end: Literal["destroyed", "paused"] | None


class CreateRequest03(TypedDict):
    operation: Literal["create"]
    request_id: Identifier
    account_id: Identifier
    allocation_key: AllocationKey
    offering_id: Identifier
    declaration_id: Identifier
    request: dict[str, object]
    env: Environment
    labels: Labels


class CreateResult03(TypedDict):
    operation: Literal["create"]
    request_id: Identifier
    account_id: Identifier
    allocation_key: AllocationKey
    request_digest: Digest
    key_expires_at: int
    state: Literal["pending", "ready", "unknown", "unavailable"]
    sandbox: SandboxIdentity | None
    admission: Admission | None
    labels: Labels | None
    lifetime: LifetimeObservation | None


class GetResult03(TypedDict):
    operation: Literal["get"]
    request_id: Identifier
    account_id: Identifier
    sandbox: SandboxIdentity
    state: Literal["active", "paused", "destroyed", "absent", "unknown"]
    admission: Admission | None
    labels: Labels | None
    lifetime: LifetimeObservation | None


class InventoryItem03(TypedDict):
    sandbox: SandboxIdentity
    state: Literal["active", "paused", "destroyed", "unknown"]
    labels: Labels | None
    lifetime: LifetimeObservation | None


class ListResult03(TypedDict):
    operation: Literal["list"]
    request_id: Identifier
    account_id: Identifier
    items: list[InventoryItem03]
    next_cursor: str | None
