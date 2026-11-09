# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
# pylint: disable=too-many-lines
"""Direct Daytona SDK observations, retaining its class and timer units."""

from __future__ import annotations

import base64
import ipaddress
import shlex
import time
import urllib.parse
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from importlib.metadata import version
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from typing import TypedDict, cast

from daytona import (
    CreateSandboxFromImageParams,
    CreateSandboxFromSnapshotParams,
    CreateSecretParams,
    CreateSnapshotParams,
    Daytona,
    DaytonaConfig,
    Image,
    PtySize,
    Resources,
    Sandbox,
    SessionExecuteRequest,
    UpdateSecretParams,
    VolumeMount,
)
from daytona.common.errors import (
    DaytonaBadRequestError,
    DaytonaConflictError,
    DaytonaNotFoundError,
    DaytonaTimeoutError,
)
from daytona.common.image import Context
from daytona.common.secret import Secret
from daytona.common.snapshot import Snapshot
from daytona.common.volume import Volume
from daytona.handle.pty_handle import PtyHandle
from daytona_api_client.exceptions import NotFoundException as SecretNotFound
from daytona_api_client_async.models.gpu_type import GpuType
from daytona_api_client_async.models.sandbox_class import SandboxClass
from daytona_toolbox_api_client.models.interpreter_context import InterpreterContext

from sandbox_provider_spec.driver import (
    NO_CREATION_SETTING,
    OPERATION_GATES,
    UNOBSERVABLE_METADATA,
    Driver,
    ImageSnapshotDriver,
    Inputs,
    NativeFailure,
    NotRun,
    Observation,
    Resource,
    Unsupported,
    confirmed_absent,
    number,
    resource,
    strings,
    text,
)
from sandbox_provider_spec.run_id import native_name, own_run, stale

STATES = {
    "started": "active",
    "resizing": "active",
    "snapshotting": "active",
    "stopped": "stopped",
    "stopping": "stopped",
    "archived": "stopped",
    "archiving": "stopped",
    "paused": "paused",
    "pausing": "paused",
    "destroyed": "destroyed",
    "destroying": "destroyed",
}
"""Daytona's sandbox states in the suite's words; a sandbox its timer is deleting is destroyed."""


def box(target: object) -> Sandbox:
    return cast(Sandbox, resource(target).native)


@dataclass
class SessionCommand:
    sandbox: Sandbox
    session: str
    command: str


def command(target: object) -> SessionCommand:
    return cast(SessionCommand, resource(target).native)


@dataclass
class SnapshotReservation:
    name: str
    source: Resource | None = None
    returned: bool = False


def _staged_image(dockerfile: Path) -> Image:
    """The Dockerfile with its whole directory as the context (the SDK's form for `COPY .`).

    `Image.from_dockerfile` collects only COPY sources, so an ADD source never reaches the
    builder; the directory holds only the supplied files, so nothing else is sent.
    """
    image = Image()
    image._dockerfile = dockerfile.read_text(encoding="utf-8")  # pylint: disable=protected-access
    image._context_list = [  # pylint: disable=protected-access
        Context(source_path=str(dockerfile.parent), archive_path=".")
    ]
    return image


class CreateOptions(TypedDict, total=False):
    name: str
    os_user: str
    env_vars: dict[str, str]
    ttl_minutes: int
    auto_stop_interval: int
    auto_pause_interval: int
    auto_delete_interval: int
    public: bool
    network_block_all: bool
    network_allow_list: str
    domain_allow_list: str
    volumes: list[VolumeMount]
    secrets: dict[str, str]
    kvm: bool
    linked_sandbox: str
    ephemeral: bool


def mapping(inputs: Inputs, key: str) -> Mapping[str, object]:
    value = inputs.get(key, {})
    if not isinstance(value, Mapping):
        raise ValueError(f"{key} must be a mapping")
    return value


class DaytonaDriver(ImageSnapshotDriver):  # pylint: disable=too-many-public-methods
    provider = "daytona"
    sdk_versions = {"daytona": version("daytona")}
    unobservable = UNOBSERVABLE_METADATA
    unsupported = {
        "tcp.link": "Daytona SDK exposes HTTP previews, not public raw TCP endpoints",
        "run.as_root": "Daytona exec has no per-command user selector",
        "process.close_stdin": "Daytona session command input has no native EOF operation",
        "snapshot.restore_wait": (
            "Daytona SDK restores synchronously and exposes no pending restore handle"
        ),
        "volume.read_bytes": "Daytona SDK has no direct volume byte-read operation",
        "volume.reload": "Daytona SDK has no mounted-volume reload operation",
    }

    def __init__(self, execution_class: str, fixtures: Mapping[str, object]) -> None:
        super().__init__()
        self.execution_class = execution_class
        self.fixtures = fixtures
        self.capture_sources: set[str] = set()
        target = fixtures.get(f"daytona_{execution_class}_target")
        # Use the SDK's default event streaming and automatic polling fallback.
        self.client = Daytona(DaytonaConfig(target=cast(str | None, target)))

    def _delete(self, identity: str) -> Observation:
        started = time.monotonic()
        deadline = started + (600 if identity in self.capture_sources else 120)
        native_identity = identity
        requested = False
        while True:
            try:
                native = self.client.get(identity, request_timeout=10)
                native_identity = native.id
                attempted_capture = (
                    identity in self.capture_sources or native_identity in self.capture_sources
                )
                if attempted_capture:
                    # Cleanup is reserved by name before create returns its native ID.
                    # Every lookup resolves that name, without resetting the deadline.
                    deadline = started + 600
                capturing = attempted_capture and native.state == "snapshotting"
                if not requested and not capturing:
                    try:
                        self.client.delete(native, timeout=30, wait=True)
                        requested = True
                    except DaytonaConflictError:
                        # Native transitions can temporarily refuse deletion. A new
                        # SDK lookup precedes each retry; no state is synthesized.
                        pass
            except DaytonaNotFoundError:
                self.capture_sources.discard(identity)
                self.capture_sources.discard(native_identity)
                return {"result": "deleted"}
            if time.monotonic() >= deadline:
                raise NativeFailure("cleanup_not_confirmed")
            time.sleep(2 if capturing else 0.5)

    def sweep_stale(self, ttl_seconds: float) -> list[str]:
        swept: list[str] = []
        for native in self.client.list(request_timeout=30):
            if stale(native.name, ttl_seconds):
                self._delete(native.name)
                swept.append(f"sandbox:{native.name}")
        for volume in self.client.volume.list():
            if stale(volume.name, ttl_seconds):
                self._delete_volume(volume.name)
                swept.append(f"volume:{volume.name}")
        cursor: str | None = None
        while True:
            page = self.client.secret.list(limit=200, cursor=cursor)
            for item in page.items:
                if stale(item.name, ttl_seconds):
                    self._delete_secret(item.id)
                    swept.append(f"secret:{item.name}")
            cursor = page.next_cursor
            if cursor is None:
                break
        deadline = time.monotonic() + 600
        for snapshot in self._snapshot_inventory(deadline):
            if stale(snapshot.name, ttl_seconds):
                self.client.snapshot.delete(snapshot)
                swept.append(f"snapshot:{snapshot.name}")
        return swept

    #: How long the end-of-run check waits for its own snapshots to leave the inventory.
    LEFTOVER_SECONDS = 120

    def finish(self) -> list[Observation]:
        """Prove this run's snapshots are gone: delete any that remain, by exact id, and fail.

        The snapshot limit is per organization and a snapshot belongs to no sandbox, so
        a snapshot a test forgot would spend the account's quota until someone swept it. Each
        release proves its own artifact absent; this checks the whole inventory once more for
        the run's own names (the run token is in every name it reserves) after everything was
        released, deletes what it finds by id and reports each as left behind, so a run that
        leaked fails even though the account is clean again. Only names carrying this run's
        token are read as ours: every other snapshot belongs to someone else.
        """
        deadline = time.monotonic() + self.LEFTOVER_SECONDS
        found: dict[str, Snapshot] = {}
        try:
            while True:
                left = [item for item in self._snapshot_inventory(deadline) if own_run(item.name)]
                for item in left:
                    found.setdefault(item.id, item)
                if not left:
                    break
                if time.monotonic() >= deadline:
                    return self._leftovers(found, "run_snapshot_not_removed")
                for item in left:
                    if str(getattr(item.state, "value", item.state)).lower() != "removing":
                        self._request_snapshot_delete(item)
                time.sleep(min(1.0, max(0, deadline - time.monotonic())))
        except Exception:  # pylint: disable=broad-exception-caught
            # An inventory that cannot be read, or that outlasts the budget, proves nothing about
            # what is left: a snapshot already seen and not yet confirmed gone is not removed.
            if found:
                return self._leftovers(found, "run_snapshot_not_removed")
            return [{"kind": "snapshot", "result": "error", "reason": "run_snapshots_unverified"}]
        return self._leftovers(found, "run_snapshot_left_behind")

    @staticmethod
    def _leftovers(found: Mapping[str, Snapshot], reason: str) -> list[Observation]:
        return [{"kind": "snapshot", "result": "error", "reason": reason} for _ in found]

    def _new_name(self) -> str:
        """Tag every owned remote resource with this run and the current conformance task."""
        task_id = self.fixtures.get("sps_task_id")
        if task_id is None:
            return native_name()
        if not isinstance(task_id, str) or not task_id.isascii() or not task_id.isalnum():
            raise ValueError("sps_task_id must contain only ASCII letters and digits")
        return native_name(middle=task_id)

    def create(self, target: object, inputs: Inputs) -> Observation:
        del target
        if self.fixtures.get(f"daytona_{self.execution_class}_available") is False:
            raise NotRun("account_class_condition_unmet")
        if inputs.get("at_end", "destroyed") != "destroyed":
            raise Unsupported("Daytona native wall-clock TTL deletes the sandbox")
        options: CreateOptions = {"env_vars": strings(inputs, "environment")}
        if inputs.get("user") is not None:
            options["os_user"] = text(inputs, "user")
        for gate, settings in mapping(inputs, "requirements").items():
            if not isinstance(settings, Mapping):
                raise ValueError("gate configuration must be a mapping")
            if gate == "idle_shutdown":
                if settings.get("auto_wake") is True:
                    raise Unsupported("Daytona previews do not wake idle sandboxes")
                if settings.get("custom_idle_time") is not False:
                    idle = number(settings, "idle_seconds", 60)
                    if idle % 60:
                        raise Unsupported("Daytona idle timers accept whole minutes")
                    state = settings.get("on_idle", "stopped")
                    if state == "paused":
                        if self.execution_class != "vm":
                            raise Unsupported("Daytona auto-pause requires a VM sandbox")
                        options["auto_pause_interval"] = idle // 60
                        options["auto_stop_interval"] = 0
                    else:
                        options["auto_stop_interval"] = idle // 60
                        options["auto_pause_interval"] = 0
                        if state == "destroyed":
                            options["auto_delete_interval"] = 0
            elif gate == "network_lockdown":
                options.update(cast(CreateOptions, self._network_options(settings)))
            elif gate == "live_resize":
                if settings.get("shrinks") is True:
                    raise Unsupported("Daytona live resize accepts resource increases only")
            elif gate == "nested_virtualization":
                if self.execution_class != "vm":
                    raise Unsupported("Daytona KVM is available only on Linux VM sandboxes")
                options["kvm"] = True
            elif gate == "private_network":
                if settings.get("ip_version", "ipv4") == "ipv6":
                    raise Unsupported("Daytona linked sandboxes have no IPv6 selector")
            elif gate == "volumes":
                if settings.get("read_only_mounts") is True:
                    raise Unsupported("Daytona VolumeMount has no read-only selector")
            elif gate == "ssh":
                if settings.get("credential") != "token":
                    raise Unsupported("Daytona SSH access supplies token credentials only")
            elif gate == "previews":
                options["public"] = settings.get("access", "public") == "public"
                if settings.get("credential") == "header":
                    raise Unsupported("Daytona preview header tokens are sandbox-wide")
            elif gate == "interpreter":
                if any(language != "python" for language in settings.get("languages", ["python"])):
                    raise Unsupported("Pinned Daytona interpreter runs Python only")
                if settings.get("rich_output") is True:
                    raise Unsupported("Pinned Daytona interpreter result exposes text only")
            elif gate == "hidden_secrets":
                secret = cast(Secret, resource(inputs["secret"]).native)
                self.client.secret.update(
                    secret.id, UpdateSecretParams(hosts=cast(list[str], settings["inject_into"]))
                )
                options["secrets"] = {"SPS_SECRET_PLACEHOLDER": secret.name}
            elif gate not in OPERATION_GATES | NO_CREATION_SETTING:
                raise NotRun("gate_mapping_unavailable")
        resources = mapping(inputs, "resources")
        if resources.get("long_running") is True:
            options["auto_stop_interval"] = 0
            options["auto_pause_interval"] = 0
        allocation = {key: value for key, value in resources.items() if key != "long_running"}
        if "gpu_model" in allocation:
            if self.execution_class != "gpu":
                raise Unsupported("GPU allocation requires Daytona's GPU execution class")
            models = allocation.pop("gpu_model")
            native_gpus = {
                "nvidia:h100": GpuType.H100,
                "nvidia:h200": GpuType.H200,
                "nvidia:rtx-4090": GpuType.RTX_4090,
                "nvidia:rtx-5090": GpuType.RTX_5090,
            }
            if not isinstance(models, list) or len(models) != 1 or models[0] not in native_gpus:
                raise Unsupported("Requested GPU model is absent from pinned Daytona SDK")
            selected_gpu = native_gpus[models[0]]
        else:
            selected_gpu = None
        if allocation and "image" in inputs:
            raise Unsupported("Daytona restore from a snapshot has no allocation override")
        sized: Observation | None = None
        if allocation or selected_gpu is not None:
            fields = {"cpu_min": "cpu", "memory_min_mib": "memory", "disk_min_mib": "disk"}
            if any(key not in {*fields, "gpu_count"} for key in allocation):
                raise Unsupported("Requested resource selector is absent from Daytona SDK")
            values: dict[str, int] = {}
            for key, value in allocation.items():
                if key == "gpu_count":
                    continue
                if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                    raise ValueError("Daytona resources require positive integral units")
                values[fields[key]] = value if key == "cpu_min" else (value + 1023) // 1024
            name = self._new_name()
            artifact, reservation = self._reserve_snapshot("image", name)
            created_image = self.client.snapshot.create(
                CreateSnapshotParams(
                    name=name,
                    image=cast(str, self.fixtures.get("daytona_size_image", "python:3.12-slim")),
                    resources=Resources(
                        cpu=values.get("cpu"),
                        memory=values.get("memory"),
                        disk=values.get("disk"),
                        gpu=number(resources, "gpu_count", 1) if selected_gpu is not None else None,
                        gpu_type=selected_gpu,
                    ),
                    sandbox_class=SandboxClass.LINUX_VM
                    if self.execution_class == "vm"
                    else SandboxClass.CONTAINER,
                ),
                timeout=120,
            )
            artifact.native = created_image.id
            reservation.returned = True
            sized = {"resource": artifact}
        if "volumes" in inputs:
            mounts: list[VolumeMount] = []
            for mount in cast(list[dict[str, object]], inputs["volumes"]):
                if mount.get("read_only"):
                    raise Unsupported("Daytona VolumeMount has no read-only selector")
                volume = cast(Volume, resource(mount["volume"]).native)
                mounts.append(VolumeMount(volume_id=volume.id, mount_path=cast(str, mount["path"])))
            options["volumes"] = mounts
        if "join" in inputs:
            if self.execution_class == "gpu":
                raise Unsupported("Daytona GPU sandboxes cannot join a linked network")
            linked = box(inputs["join"])
            options["linked_sandbox"] = linked.id
            options["ephemeral"] = True
            options["auto_delete_interval"] = 0
        # Capture may outlast the SDK's usual minute-long wait. Keep its source
        # alive through capture and observation; explicit timer settings win.
        snapshot_test = "snapshots" in mapping(inputs, "requirements")
        lifetime = number(inputs, "lifetime_seconds", 300 if snapshot_test else 120)
        if lifetime % 60:
            raise Unsupported("Daytona's native TTL accepts whole minutes")
        snapshot = cast(str | None, self.fixtures.get(f"daytona_{self.execution_class}_snapshot"))
        if "image" in inputs:
            snapshot = cast(str, resource(inputs["image"]).native)
        elif sized is not None:
            snapshot = cast(str, resource(sized).native)
        if self.execution_class == "vm" and not snapshot:
            page = self.client.snapshot.list(page=1, limit=100)
            snapshots = list(page.items)
            for index in range(2, (page.total_pages or 1) + 1):
                snapshots.extend(self.client.snapshot.list(page=index, limit=100).items)
            snapshot = next(
                (
                    s.name
                    for s in snapshots
                    if s.sandbox_class == "linux-vm" and s.state == "active"
                ),
                None,
            )
            if not snapshot:
                raise NotRun("vm_class_artifact_unavailable")
        name = self._new_name()
        # SDK create waits for readiness and can raise after allocation. Reserve the
        # known unique name before calling it, so failure still triggers native delete.
        owned = self.own("sandbox", name, lambda: self._delete(name))
        options["name"] = name
        options["ttl_minutes"] = lifetime // 60
        if self.execution_class == "gpu" and not snapshot:
            params = CreateSandboxFromImageParams(
                **options,
                image=cast(str, self.fixtures.get("daytona_gpu_image", "daytonaio/sandbox:latest")),
                resources=Resources(gpu=1),
            )
            native = self.client.create(params, timeout=60)
        else:
            try:
                native = self.client.create(
                    CreateSandboxFromSnapshotParams(**options, snapshot=snapshot), timeout=60
                )
            except DaytonaBadRequestError as error:
                message = str(error).lower()
                if (
                    "domain_allow_list" in options
                    and "domain" in message
                    and "tier" in message
                    and ("cannot" in message or "not" in message)
                ):
                    raise NotRun("account_network_policy_tier_required") from None
                raise
        owned.native = native
        if self.execution_class == "vm" and native.sandbox_class != "linux-vm":
            raise NativeFailure("execution_class_mismatch")
        if self.execution_class == "gpu" and not native.gpu:
            raise NativeFailure("execution_class_mismatch")
        return {"resource": owned, "identity": native.id}

    def get(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        try:
            native = self.client.get(box(target).id, request_timeout=30)
        except DaytonaNotFoundError:
            return {"state": "destroyed"}
        state = str(getattr(native.state, "value", native.state))
        return {"state": STATES.get(state, state)}

    def idle_select_duration(self, target: object, inputs: Inputs) -> Observation:
        seconds = number(inputs, "idle_seconds", 60)
        if seconds % 60:
            raise Unsupported("Daytona idle timers accept whole minutes")
        box(target).set_autostop_interval(seconds // 60, request_timeout=30)
        return {}

    def allocation_observe(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        native = self.client.get(box(target).id, request_timeout=30)
        return {"allocation": {"cpu_min": native.cpu, "memory_min_mib": native.memory * 1024}}

    def volume_observe_kind(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        if not isinstance(resource(target).native, Volume):
            raise ValueError("kind observation requires a native Volume")
        return {"kind": "object_store"}

    def list(self, target: object, inputs: Inputs) -> Observation:
        del target, inputs
        return {"sandboxes": [{"identity": n.id} for n in self.client.list(request_timeout=30)]}

    def destroy(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        return self.release(resource(target))

    def _session(self, native: Sandbox) -> str:
        identity = self._new_name()
        self.own("session", identity, lambda: self._delete_session(native, identity))
        native.process.create_session(identity, request_timeout=30)
        return identity

    @staticmethod
    def _delete_session(native: Sandbox, identity: str) -> Observation:
        try:
            native.process.delete_session(identity, request_timeout=30)
        except DaytonaNotFoundError:
            pass
        try:
            native.process.get_session(identity, request_timeout=30)
        except DaytonaNotFoundError:
            return {"result": "deleted"}
        raise NativeFailure("cleanup_not_confirmed")

    def run(self, target: object, inputs: Inputs) -> Observation:
        native = box(target)
        if inputs.get("run_as") is not None:
            raise Unsupported("Daytona's SDK has no named-user command option")
        payload = text(inputs, "bash_script")
        script = f"bash -c {shlex.quote(payload)}"
        try:
            if inputs.get("separate_streams") is not True:
                result = native.process.exec(
                    script,
                    cwd=cast(str | None, inputs.get("cwd")),
                    env=strings(inputs, "environment"),
                    timeout=(number(inputs, "timeout_ms", 15000) + 999) // 1000,
                )
                return {"stdout": result.result, "exit_code": result.exit_code}
            session = self._session(native)
            output = native.process.execute_session_command(
                session, SessionExecuteRequest(command=script, run_async=False), timeout=15
            )
            return {"stdout": output.stdout, "stderr": output.stderr, "exit_code": output.exit_code}
        except DaytonaTimeoutError:
            raise NativeFailure("timeout") from None

    def network_update(self, target: object, inputs: Inputs) -> Observation:
        native = box(target)
        settings = self._network_options(inputs)
        native.update_network_settings(
            network_block_all=cast(bool | None, settings.get("network_block_all")),
            network_allow_list=cast(str | None, settings.get("network_allow_list")),
            domain_allow_list=cast(str | None, settings.get("domain_allow_list")),
            request_timeout=30,
        )
        return {}

    def network_private_address(self, target: object, inputs: Inputs) -> Observation:
        requested = inputs.get("ip_version")
        if requested not in {None, "ipv4", "ipv6"}:
            raise ValueError("ip_version must be ipv4 or ipv6")
        if requested == "ipv6":
            raise Unsupported("Daytona linked sandboxes have no IPv6 selector")
        address = box(target).id
        if not isinstance(address, str) or not address:
            raise NativeFailure("private_address_response_invalid")
        return {"address": address, "ip_version": None}

    @staticmethod
    def _network_options(settings: Mapping[str, object]) -> dict[str, object]:
        """Map only the egress policies the pinned SDK can express faithfully."""
        if settings.get("deny_wins") is True:
            raise Unsupported("Daytona network settings have no deny-list precedence")
        if settings.get("deny"):
            raise Unsupported("Daytona native egress controls expose allowlists, not denylists")
        if settings.get("http_rules") is True:
            raise Unsupported("Daytona SDK has no HTTP method or path rule setting")
        if "cuts_open_connections" in settings:
            raise Unsupported(
                "Daytona SDK does not guarantee open connections are cut or kept on policy updates"
            )
        if settings.get("domain_traffic") is not None:
            raise Unsupported("Daytona SDK has no per-domain traffic selector")
        switches_to = settings.get("switches_to", [])
        if isinstance(switches_to, list) and "denylist" in switches_to:
            raise Unsupported("Daytona network updates cannot switch to a denylist")

        policy = settings.get("policy")
        if policy == "deny_all":
            return {"network_block_all": True}
        if policy == "open":
            return {"network_block_all": False}
        if policy == "denylist":
            raise Unsupported("Daytona native egress controls expose allowlists, not denylists")
        if policy not in {"allowlist", "allowlist_domains", "allowlist_ips"}:
            raise ValueError("unknown network policy")

        allowed = settings.get("allow", [])
        if not isinstance(allowed, list):
            raise ValueError("allow must be a list")
        domains: list[str] = []
        networks: list[str] = []
        for entry in allowed:
            if not isinstance(entry, str):
                raise Unsupported("Daytona SDK has no HTTP rule allowlist setting")
            try:
                network = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                if entry.startswith("*."):
                    raise Unsupported(
                        "Daytona domain allowlist has no documented wildcard setting"
                    ) from None
                if policy == "allowlist_ips":
                    raise ValueError("allowlist_ips accepts IP networks only") from None
                domains.append(entry)
            else:
                if network.version != 4:
                    raise Unsupported("Daytona network allowlist accepts IPv4 CIDRs only")
                if policy == "allowlist_domains":
                    raise ValueError("allowlist_domains accepts domain names only")
                networks.append(entry if "/" in entry else f"{entry}/32")
        if not domains and not networks:
            return {"network_block_all": True}
        options: dict[str, object] = {}
        if domains:
            options["domain_allow_list"] = ",".join(domains)
        if networks:
            options["network_allow_list"] = ",".join(networks)
        return options

    def resize(self, target: object, inputs: Inputs) -> Observation:
        requested = mapping(inputs, "resources")
        allowed = {"cpu_min", "memory_min_mib"}
        if set(requested) - allowed:
            if "disk_min_mib" in requested:
                raise Unsupported("Daytona disk resize requires a stopped sandbox")
            raise Unsupported("Daytona resize supports CPU and memory, not the requested resource")
        if not requested:
            raise ValueError("resize needs CPU or memory")

        values: dict[str, int] = {}
        if "cpu_min" in requested:
            cpu = requested["cpu_min"]
            if not isinstance(cpu, int) or isinstance(cpu, bool) or cpu <= 0:
                raise ValueError("cpu_min must be a positive integer")
            values["cpu"] = cpu
        memory_mib = requested.get("memory_min_mib")
        if memory_mib is not None:
            if not isinstance(memory_mib, int) or isinstance(memory_mib, bool) or memory_mib <= 0:
                raise ValueError("memory_min_mib must be a positive integer")
            values["memory"] = (memory_mib + 1023) // 1024

        native = box(target)
        for key, value in values.items():
            current = getattr(native, key, None)
            if isinstance(current, int) and value < current:
                raise Unsupported("Daytona live resize accepts resource increases only")
        native.resize(Resources(cpu=values.get("cpu"), memory=values.get("memory")), timeout=60)
        return {}

    @staticmethod
    def _revoke_ssh_access(native: Sandbox, token: str) -> Observation:
        native.revoke_ssh_access(token, request_timeout=30)
        return {"result": "deleted"}

    def ssh_access(self, target: object, inputs: Inputs) -> Observation:
        if inputs.get("credential") != "token":
            raise Unsupported("Daytona SSH access supplies token credentials only")
        native = box(target)
        access = native.create_ssh_access(expires_in_minutes=60, request_timeout=30)
        token = access.token
        owned = self.own("ssh_access", access, lambda: self._revoke_ssh_access(native, token))
        return {
            "host": "ssh.app.daytona.io",
            "port": 22,
            "user": token,
            "credential": "token",
            "token": token,
            "resource": owned,
        }

    def desktop_start(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        box(target).computer_use.start(request_timeout=60)
        return {}

    def desktop_screenshot(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        png = box(target).computer_use.screenshot.take_full_screen(request_timeout=30).screenshot
        if not isinstance(png, str):
            raise NativeFailure("native_desktop_screenshot_missing")
        encoded = png.partition(",")[2] if png.startswith("data:image/png;base64,") else png
        return {"png": base64.b64decode(encoded, validate=True)}

    def desktop_click(self, target: object, inputs: Inputs) -> Observation:
        box(target).computer_use.mouse.click(
            number(inputs, "x", 80), number(inputs, "y", 80), request_timeout=30
        )
        return {}

    def desktop_type(self, target: object, inputs: Inputs) -> Observation:
        box(target).computer_use.keyboard.type(text(inputs, "text"), request_timeout=30)
        return {}

    def desktop_key(self, target: object, inputs: Inputs) -> Observation:
        box(target).computer_use.keyboard.press(text(inputs, "key"), request_timeout=30)
        return {}

    def desktop_live_link(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        link = self.preview_link(
            target,
            {"port": 6080, "access": "private", "credential": "link", "lifetime_seconds": 300},
        )
        parsed = urllib.parse.urlsplit(str(link["url"]))
        query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        query.extend([("autoconnect", "true"), ("resize", "scale")])
        return {
            **link,
            "url": urllib.parse.urlunsplit(
                parsed._replace(path="/vnc.html", query=urllib.parse.urlencode(query))
            ),
        }

    def interpreter_context(self, target: object, inputs: Inputs) -> Observation:
        if inputs.get("language", "python") != "python":
            raise Unsupported("Pinned Daytona interpreter runs Python only")
        native = box(target)
        context = native.code_interpreter.create_context(request_timeout=30)
        owned = self.own(
            "interpreter_context", context, lambda: self._delete_context(native, context)
        )
        return {"resource": owned, "sandbox": native}

    @staticmethod
    def _delete_context(native: Sandbox, context: object) -> Observation:

        typed = cast(InterpreterContext, context)
        try:
            native.code_interpreter.delete_context(typed, request_timeout=30)
        except DaytonaNotFoundError:
            pass
        return confirmed_absent(
            lambda: all(
                item.id != typed.id
                for item in native.code_interpreter.list_contexts(request_timeout=30)
            ),
            seconds=30,
        )

    def interpreter_run(self, target: object, inputs: Inputs) -> Observation:

        if not isinstance(target, Mapping):
            raise ValueError("interpreter run requires a context")
        native = cast(Sandbox, target["sandbox"])
        result = native.code_interpreter.run_code(
            text(inputs, "code"),
            context=cast(InterpreterContext, resource(target).native),
            timeout=30,
        )
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": 0 if result.error is None else 1,
            "image_data": [],
        }

    def files_read_bytes(self, target: object, inputs: Inputs) -> Observation:
        return {"data": box(target).fs.download_file(text(inputs, "path"))}

    def files_write(self, target: object, inputs: Inputs) -> Observation:
        if inputs.get("user") is not None:
            raise Unsupported("Daytona's SDK has no named-user file write option")
        data = base64.b64decode(text(inputs, "data"), validate=True)
        box(target).fs.upload_file(data, text(inputs, "path"), timeout=30)
        return {}

    def files_exists(self, target: object, inputs: Inputs) -> Observation:
        try:
            box(target).fs.get_file_info(text(inputs, "path"), request_timeout=30)
        except DaytonaNotFoundError:
            return {"exists": False}
        return {"exists": True}

    def files_list(self, target: object, inputs: Inputs) -> Observation:
        return {
            "names": sorted(
                f.name for f in box(target).fs.list_files(text(inputs, "path"), request_timeout=30)
            )
        }

    def files_mkdir(self, target: object, inputs: Inputs) -> Observation:
        box(target).fs.create_folder(text(inputs, "path"), "755", request_timeout=30)
        return {}

    def files_remove(self, target: object, inputs: Inputs) -> Observation:
        box(target).fs.delete_file(
            text(inputs, "path"), recursive=bool(inputs.get("recursive", False)), request_timeout=30
        )
        return {}

    def process_start(self, target: object, inputs: Inputs) -> Observation:
        native = box(target)
        if inputs.get("run_as") is not None:
            raise Unsupported("Daytona's SDK has no named-user process option")
        payload = text(inputs, "bash_script")
        session = self._session(native)
        result = native.process.execute_session_command(
            session,
            SessionExecuteRequest(command=f"bash -c {shlex.quote(payload)}", run_async=True),
            timeout=15,
        )
        handle = SessionCommand(native, session, result.cmd_id)
        owned = self.own("process", handle, lambda: self._delete_session(native, session))
        return {"resource": owned, "identity": {"session": session, "command": result.cmd_id}}

    def process_disconnect(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        # Log reads are native request/response calls, with no persistent reader
        # connection. Discard its observer; the original native session owner and
        # its cleanup remain intact. Never claim a transport close or delete here.
        resource(target).native = None
        return {}

    def process_reattach(self, target: object, inputs: Inputs) -> Observation:
        identity = mapping(inputs, "identity")
        session, command_id = text(identity, "session"), text(identity, "command")
        selected = cast(str | None, self.fixtures.get(f"daytona_{self.execution_class}_target"))
        fresh = Daytona(DaytonaConfig(target=selected)).get(box(target).id, request_timeout=30)
        observed_session = fresh.process.get_session(session, request_timeout=30)
        observed_command = fresh.process.get_session_command(
            session, command_id, request_timeout=30
        )
        if observed_command.exit_code is not None:
            raise NativeFailure("native_process_already_ended")
        handle = SessionCommand(fresh, observed_session.session_id, observed_command.id)
        # The SDK getter allocates no remote session or command; it returns a
        # borrowed observer. Only the original session owner deletes that session.
        owned = self.own("observer", handle, lambda: {"result": "already_released"})
        return {"resource": owned}

    def process_output(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        handle = command(target)
        result = handle.sandbox.process.get_session_command_logs(
            handle.session, handle.command, request_timeout=30
        )
        return {"stdout": result.stdout, "stderr": result.stderr}

    def process_write_stdin(self, target: object, inputs: Inputs) -> Observation:
        handle = command(target)
        data = base64.b64decode(text(inputs, "data"), validate=True).decode()
        handle.sandbox.process.send_session_command_input(
            handle.session, handle.command, data, request_timeout=30
        )
        return {}

    def process_cancel(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        handle = command(target)
        return self._delete_session(handle.sandbox, handle.session)

    def process_status(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        handle = command(target)
        code = handle.sandbox.process.get_session_command(
            handle.session, handle.command, request_timeout=30
        ).exit_code
        return {"state": "running" if code is None else "exited", "exit_code": code}

    def process_wait(self, target: object, inputs: Inputs) -> Observation:
        handle = command(target)
        deadline = time.monotonic() + number(inputs, "timeout_ms", 15000) / 1000
        while True:
            try:
                result = handle.sandbox.process.get_session_command(
                    handle.session, handle.command, request_timeout=10
                )
            except DaytonaNotFoundError:
                raise Unsupported(
                    "Deleting a Daytona session removes its command exit status"
                ) from None
            if result.exit_code is not None:
                return {"exit_code": result.exit_code}
            if time.monotonic() >= deadline:
                raise NotRun("native_process_still_running")
            time.sleep(0.1)

    def secret_create(self, target: object, inputs: Inputs) -> Observation:
        del target
        name = self._new_name()
        owned = self.own("secret", name, lambda: self._delete_reserved_secret(name))
        native = self.client.secret.create(
            CreateSecretParams(
                name=name,
                value=text(inputs, "value"),
                hosts=cast(list[str] | None, inputs.get("hosts")),
            )
        )
        owned.native = native
        owned.cleanup = lambda: self._delete_secret(native.id)
        return {"resource": owned}

    def secret_rotate(self, target: object, inputs: Inputs) -> Observation:
        native = cast(Secret, resource(target).native)
        self.client.secret.update(native.id, UpdateSecretParams(value=text(inputs, "value")))
        return {}

    def _delete_secret(self, identity: str) -> Observation:
        try:
            self.client.secret.delete(identity)
        except SecretNotFound:
            pass
        return confirmed_absent(lambda: self._secret_absent(identity), seconds=30)

    def _secret_absent(self, identity: str) -> bool:
        try:
            self.client.secret.get(identity)
        except SecretNotFound:
            return True
        return False

    def _delete_reserved_secret(self, name: str) -> Observation:
        cursor: str | None = None
        while True:
            page = self.client.secret.list(name=name, limit=200, cursor=cursor)
            for item in page.items:
                if item.name == name:
                    self._delete_secret(item.id)
            cursor = page.next_cursor
            if cursor is None:
                break
        # Read again; only this run's exact random name can be removed.
        if any(item.name == name for item in self.client.secret.list(name=name, limit=200).items):
            raise NativeFailure("cleanup_not_confirmed")
        return {"result": "deleted"}

    def pause(self, target: object, inputs: Inputs) -> Observation:
        if inputs.get("keeps", "files_only") == "files_only":
            box(target).stop(timeout=60)
        else:
            if self.execution_class != "vm":
                raise Unsupported("Daytona memory-preserving pause requires a VM sandbox")
            box(target).pause(timeout=60)
        return {}

    def resume(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        box(target).start(timeout=60)
        return cast(Observation, target)

    def terminal_open(self, target: object, inputs: Inputs) -> Observation:
        native = box(target)
        identity = self._new_name()
        handle = native.process.create_pty_session(
            identity,
            pty_size=PtySize(rows=number(inputs, "rows", 24), cols=number(inputs, "columns", 80)),
        )
        owned = self.own("terminal", handle, lambda: self._delete_pty(native, handle))
        handle.wait_for_connection(timeout=15)
        return {"resource": owned, "sandbox": native}

    def terminal_disconnect(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        cast(PtyHandle, resource(target).native).disconnect()
        return {}

    def terminal_reattach(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        if not isinstance(target, Mapping):
            raise ValueError("terminal requires its native sandbox")
        parent = cast(Sandbox, target["sandbox"])
        handle = parent.process.connect_pty_session(
            cast(PtyHandle, resource(target).native).session_id
        )
        owned = self.own("observer", handle, lambda: self._disconnect_pty(handle))
        handle.wait_for_connection(timeout=15)
        return {"resource": owned, "sandbox": parent}

    @staticmethod
    def _disconnect_pty(handle: PtyHandle) -> Observation:
        handle.disconnect()
        return {"result": "deleted"}

    @staticmethod
    def _delete_pty(native: Sandbox, handle: PtyHandle) -> Observation:
        handle.disconnect()
        try:
            native.process.kill_pty_session(handle.session_id, request_timeout=30)
        except DaytonaNotFoundError:
            pass
        try:
            native.process.get_pty_session_info(handle.session_id, request_timeout=30)
        except DaytonaNotFoundError:
            return {"result": "deleted"}
        raise NativeFailure("cleanup_not_confirmed")

    def _reserve_snapshot(
        self, kind: str, name: str, source: Resource | None = None
    ) -> tuple[Resource, SnapshotReservation]:
        reservation = SnapshotReservation(name, source)
        owned = self.own(kind, name, lambda: self._delete_snapshot(owned, reservation))
        return owned, reservation

    def _snapshot_inventory(self, deadline: float) -> Sequence[Snapshot]:
        # The account is shared: another run creating or deleting a snapshot between two
        # pages shifts the pages and the total. That is not an incomplete inventory of this
        # run's artifact, so read again until a consistent pass or the deadline.
        while True:
            try:
                return self._snapshot_inventory_pass(deadline)
            except NativeFailure as failure:
                if failure.code != "cleanup_inventory_incomplete" or time.monotonic() >= deadline:
                    raise
                time.sleep(min(0.5, max(0, deadline - time.monotonic())))

    def _snapshot_inventory_pass(self, deadline: float) -> Sequence[Snapshot]:
        # Name lookup can say NotFound while the native listing still contains
        # the reservation. Only a complete, internally consistent inventory
        # establishes absence; a partial page cannot release an owned artifact.
        first = self.client.snapshot.list(page=1, limit=100)
        snapshots = [
            item if isinstance(item, Snapshot) else Snapshot.from_dto(item) for item in first.items
        ]
        if (
            first.page != 1
            or first.total_pages < 0
            or first.total < 0
            or (first.total > 0 and first.total_pages == 0)
        ):
            raise NativeFailure("cleanup_inventory_incomplete")
        for index in range(2, first.total_pages + 1):
            if time.monotonic() >= deadline:
                raise NativeFailure("cleanup_not_confirmed")
            page = self.client.snapshot.list(page=index, limit=100)
            if (page.page, page.total, page.total_pages) != (index, first.total, first.total_pages):
                raise NativeFailure("cleanup_inventory_incomplete")
            snapshots.extend(
                item if isinstance(item, Snapshot) else Snapshot.from_dto(item)
                for item in page.items
            )
        if len(snapshots) != first.total or len({item.id for item in snapshots}) != first.total:
            raise NativeFailure("cleanup_inventory_incomplete")
        if time.monotonic() >= deadline:
            raise NativeFailure("cleanup_not_confirmed")
        return snapshots

    def _request_snapshot_delete(self, snapshot: Snapshot) -> None:
        """Ask for one snapshot's deletion by its exact id; a racing delete or transition is
        not an error, the caller reads the inventory again."""
        try:
            self.client.snapshot.delete(snapshot)
        except (DaytonaNotFoundError, DaytonaConflictError):
            pass

    def _delete_snapshot(self, owned: Resource, reservation: SnapshotReservation) -> Observation:
        started = time.monotonic()
        failed_create = not reservation.returned
        budget = 600 if failed_create and reservation.source is not None else 30
        deadline = started + budget
        if failed_create and reservation.source is not None:
            # Release the exact failed capture's producer within the existing
            # budget. Its absence alone cannot prove that a queued snapshot
            # will never appear: an artifact ID must still be observed.
            self.release(reservation.source)
        while time.monotonic() < deadline:
            snapshots = self._snapshot_inventory(deadline)
            identity = cast(str, owned.native)
            matches = [
                item
                for item in snapshots
                if (
                    item.name == reservation.name
                    if identity == reservation.name
                    else item.id == identity
                )
            ]
            if len(matches) > 1:
                raise NativeFailure("cleanup_identity_ambiguous")
            if not matches:
                if identity != reservation.name:
                    # Only absence of a previously observed/returned native ID
                    # proves release. An empty listing after an SDK timeout
                    # cannot prove that an unknown artifact will never appear.
                    return {"result": "deleted"}
                time.sleep(min(0.2, max(0, deadline - time.monotonic())))
                continue
            native = matches[0]
            owned.native = native.id
            # The SDK accepts its Snapshot object and sends its exact ID.
            # Never delete a name pattern or an unrelated inventory entry.
            self._request_snapshot_delete(native)
            time.sleep(min(0.2, max(0, deadline - time.monotonic())))
        raise NativeFailure("cleanup_not_confirmed")

    def snapshot_take(self, target: object, inputs: Inputs) -> Observation:
        if inputs.get("keeps", "files_only") != "files_only":
            raise Unsupported("Daytona SDK snapshots capture the filesystem, not process memory")
        name = self._new_name()
        owned, reservation = self._reserve_snapshot("snapshot", name, resource(target))
        source = box(target)
        self.capture_sources.add(source.id)
        # A capture attempt can hold deletion past its public transition state.
        # Waiting longer proves nothing; cleanup still requires native absence.
        source.create_snapshot(name, timeout=180)
        reservation.returned = True
        return {"resource": owned}

    def snapshot_original_after(self, target: object, inputs: Inputs) -> Observation:
        del target, inputs
        raise NotRun("snapshot_freeze_transition_unobservable")

    def snapshot_delete_again(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        owned = resource(target)
        try:
            self.client.snapshot.delete(cast(str, owned.native))
        except DaytonaNotFoundError:
            pass
        owned.cleanup()
        return {"native_delete_attempted": True}

    def volume_create(self, target: object, inputs: Inputs) -> Observation:
        del target, inputs
        name = self._new_name()
        owned = self.own("volume", name, lambda: self._delete_volume(name))
        owned.native = self.client.volume.create(name)
        deadline = time.monotonic() + 60
        while owned.native.state.value != "ready":
            if owned.native.state.value == "error":
                raise NativeFailure("volume_provisioning_failed")
            if time.monotonic() >= deadline:
                raise NativeFailure("volume_readiness_not_confirmed")
            time.sleep(0.3)
            owned.native = self.client.volume.get(name)
        return {"resource": owned}

    def _delete_volume(self, name: str) -> Observation:
        deadline = time.monotonic() + 60
        deletion_requested = False
        while True:
            try:
                native = self.client.volume.get(name)
            except DaytonaNotFoundError:
                return {"result": "deleted"}
            if not deletion_requested and native.state.value in {"ready", "error"}:
                self.client.volume.delete(native)
                deletion_requested = True
            if time.monotonic() >= deadline:
                raise NativeFailure("cleanup_not_confirmed")
            time.sleep(0.3)

    def image_prepare(self, target: object, inputs: Inputs) -> Observation:
        del target
        source = text(inputs, "source")
        if source == "private_oci":
            raise Unsupported("Daytona SDK 0.220.0 has no per-image private registry credentials")
        if source == "dockerfile" and self.execution_class == "vm":
            raise Unsupported("Daytona cannot build Dockerfiles for Linux VM snapshots")
        if "context" in inputs and source != "dockerfile":
            raise ValueError("context requires a dockerfile image")
        if source == "provider_artifact":
            name = text(inputs, "image")
            self.client.snapshot.get(name)
            # An existing fixture is borrowed: the suite must not delete its owner's image.
            return {"resource": Resource("image_reference", name, lambda: {}, released=True)}
        name = self._new_name()
        owned, reservation = self._reserve_snapshot("image", name)
        with TemporaryDirectory(prefix="sps-image-") as context:
            if source == "dockerfile":
                path = Path(context) / "Dockerfile"
                path.write_text(text(inputs, "dockerfile"), encoding="utf-8")
                context_files = inputs.get("context", {})
                if not isinstance(context_files, Mapping) or any(
                    not isinstance(relative, str) or not isinstance(contents, str)
                    for relative, contents in context_files.items()
                ):
                    raise ValueError("context must map relative paths to UTF-8 file text")
                for relative, contents in context_files.items():
                    relative_path = PurePosixPath(relative)
                    if relative_path == PurePosixPath("Dockerfile"):
                        raise ValueError("context cannot replace the supplied Dockerfile")
                    if (
                        not relative
                        or relative_path.is_absolute()
                        or "\\" in relative
                        or any(part in {"", ".", ".."} for part in relative_path.parts)
                    ):
                        raise ValueError("context paths must stay inside the build context")
                    destination = Path(context).joinpath(*relative_path.parts)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_text(contents, encoding="utf-8")
                image: str | Image = _staged_image(path)
            elif source == "oci":
                image = text(inputs, "image")
            else:
                raise ValueError("unknown image source")
            created_image = self.client.snapshot.create(
                CreateSnapshotParams(
                    name=name,
                    image=image,
                    sandbox_class=SandboxClass.LINUX_VM
                    if self.execution_class == "vm"
                    else SandboxClass.CONTAINER,
                    resources=Resources(gpu=1) if self.execution_class == "gpu" else None,
                ),
                timeout=120,
            )
        owned.native = created_image.id
        reservation.returned = True
        return {"resource": owned}

    def preview_link(self, target: object, inputs: Inputs) -> Observation:
        native = box(target)
        port = number(inputs, "port", 3000)
        plain = native.get_preview_link(port, request_timeout=30)
        if inputs.get("access", "public") == "public":
            return {"url": plain.url, "headers": {}}
        if inputs.get("credential", "link") != "link":
            raise Unsupported("Daytona preview header tokens are sandbox-wide")
        signed = native.create_signed_preview_url(
            port, expires_in_seconds=number(inputs, "lifetime_seconds", 60), request_timeout=30
        )
        owned = self.own(
            "preview_credential",
            signed,
            lambda: self._expire_preview(native, port, signed.token),
        )
        return {"resource": owned, "url": signed.url, "unauthorized_url": plain.url, "headers": {}}

    @staticmethod
    def _expire_preview(native: Sandbox, port: int, token: str) -> Observation:
        # Revocation is observed by the shared HTTP probe; this API returns no
        # credential lookup. Destruction of the parent also invalidates its previews.
        try:
            native.expire_signed_preview_url(port, token, request_timeout=30)
        except DaytonaNotFoundError:
            pass
        return {"result": "deleted"}

    def preview_revoke(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        if not isinstance(target, Mapping) or "resource" not in target:
            raise Unsupported("Daytona public preview URLs have no individual revocation")
        return self.release(resource(target))

    def long_running_observe(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        native = self.client.get(box(target).id, request_timeout=30)
        return {"idle_disabled": native.auto_stop_interval == 0 and native.auto_pause_interval == 0}

    def lifetime_extend(self, target: object, inputs: Inputs) -> Observation:
        seconds = number(inputs, "lifetime_seconds", 180)
        if seconds % 60:
            raise Unsupported("Daytona native TTL accepts whole minutes")
        box(target).set_ttl(seconds // 60, request_timeout=30)
        return {}

    def terminal_write(self, target: object, inputs: Inputs) -> Observation:
        cast(PtyHandle, resource(target).native).send_input(
            base64.b64decode(text(inputs, "data"), validate=True)
        )
        return {}

    def terminal_output(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        chunks: list[bytes] = []
        cast(PtyHandle, resource(target).native).wait(on_data=chunks.append, timeout=15)
        return {"terminal": b"".join(chunks)}


def make_driver(*, execution_class: str, fixtures: Mapping[str, object]) -> Driver:
    if execution_class == "default":
        execution_class = "container"
    if execution_class not in {"container", "vm", "gpu"}:
        raise ValueError("unknown Daytona execution class")
    return DaytonaDriver(execution_class, fixtures)
