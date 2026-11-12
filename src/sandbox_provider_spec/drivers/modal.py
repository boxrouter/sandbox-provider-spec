# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Modal SDK sandbox, filesystem, process and PTY observations."""

from __future__ import annotations

import base64
import ipaddress
import time
from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager
from datetime import UTC, datetime, timedelta
from importlib.metadata import version
from os import PathLike
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from typing import Any, TypedDict, cast
from uuid import uuid4

import modal
from modal._utils.async_utils import synchronizer  # pyright: ignore[reportPrivateImportUsage]
from modal.container_process import ContainerProcess
from modal.exception import (
    ImageBuildError,
    InvalidError,
    NotFoundError,
    SandboxFilesystemNotFoundError,
    SandboxTimeoutError,
)
from modal.experimental import image_delete
from modal.snapshot import SandboxSnapshot
from modal.types import SandboxRuntime

from sandbox_provider_spec.driver import (
    NO_CREATION_SETTING,
    OPERATION_GATES,
    UNOBSERVABLE_METADATA,
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
from sandbox_provider_spec.lifetime import DEFAULT_LIFETIME_SECONDS
from sandbox_provider_spec.proofs import GPU_NAMES
from sandbox_provider_spec.run_id import native_name, stale


def box(target: object) -> modal.Sandbox:
    return cast(modal.Sandbox, resource(target).native)


def command(target: object) -> ContainerProcess[bytes]:
    return cast(ContainerProcess[bytes], resource(target).native)


class CreateOptions(TypedDict, total=False):
    runtime: SandboxRuntime
    region: str
    i6pn: bool
    app: modal.App
    env: dict[str, str | None]
    timeout: int
    image: modal.Image
    idle_timeout: int
    block_network: bool
    outbound_cidr_allowlist: list[str]
    outbound_domain_allowlist: list[str]
    encrypted_ports: list[int]
    unencrypted_ports: list[int]
    volumes: dict[str | PathLike[str], modal.Volume | modal.CloudBucketMount]
    cpu: float
    memory: int
    gpu: str
    _experimental_enable_snapshot: bool


class NetworkPolicyOptions(TypedDict, total=False):
    block_network: bool
    outbound_cidr_allowlist: list[str]
    outbound_domain_allowlist: list[str]


_PRIVATE_ADDRESS_SCRIPT = """import socket
print(socket.getaddrinfo("i6pn.modal.local", None, socket.AF_INET6, socket.SOCK_STREAM)[0][4][0])
"""
_I6PN_REGION = "us-east-1"


def _private_address_output(payload: object) -> str:
    if not isinstance(payload, (bytes, str)) or len(payload) > 256:
        raise NativeFailure("private_address_response_invalid")
    try:
        value = payload.decode("ascii") if isinstance(payload, bytes) else payload
        return str(ipaddress.IPv6Address(value.strip()))
    except (UnicodeDecodeError, ValueError):
        raise NativeFailure("private_address_response_invalid") from None


def mapping(inputs: Inputs, key: str) -> Mapping[str, object]:
    value = inputs.get(key, {})
    if not isinstance(value, Mapping):
        raise ValueError(f"{key} must be a mapping")
    return value


class ModalDriver(Driver):  # pylint: disable=too-many-public-methods
    provider = "modal"
    sdk_versions = {"modal": version("modal")}
    unobservable = UNOBSERVABLE_METADATA
    unsupported = {
        "terminal.disconnect": "Modal ContainerProcess has no public PTY disconnect operation",
        "terminal.reattach": "Modal ContainerProcess has no public PTY reattachment constructor",
        "interpreter.context": "Modal SDK has no persistent code-interpreter context API",
        "desktop.screenshot": "Modal SDK has no graphical desktop API",
        "run.as_root": "Modal exec has no per-command user selector",
        "resize": "Modal Sandbox SDK 1.6.0 has no live resize operation",
        "ssh.access": "Modal Sandbox SDK has no sandbox-scoped SSH access operation",
        "pause": "Modal SDK has no in-place pause operation",
        "resume": "Modal SDK has no in-place resume operation",
        "process.cancel": "Modal ContainerProcess has no native cancellation operation",
        "process.disconnect": "Modal ContainerProcess has no public disconnect operation",
        "process.reattach": "Modal ContainerProcess has no public reattachment constructor",
        "secret.create": (
            "Modal secrets inject guest-readable environment values, not hidden egress credentials"
        ),
        "lifetime.extend": "Modal Sandbox SDK has no running-lifetime extension operation",
    }

    def __init__(self, *, execution_class: str = "default") -> None:
        super().__init__()
        if execution_class not in {"default", "vm"}:
            raise ValueError("Modal execution class must be default or vm")
        self.execution_class = execution_class
        self.app_ids: set[str] = set()

    @staticmethod
    def _network_policy_options(
        value: Mapping[str, object], *, create: bool
    ) -> NetworkPolicyOptions:
        rules = value.get("allow", [])
        policy = value.get("policy")
        if not isinstance(policy, str):
            raise ValueError("network policy must be text")
        if policy in {"denylist", "denylist_domains", "denylist_ips"}:
            raise Unsupported("Modal Sandbox egress controls expose allowlists, not denylists")
        if value.get("deny_wins") is True or "deny" in value:
            raise Unsupported("Modal Sandbox egress controls expose allowlists, not deny entries")
        if value.get("http_rules") is True or (
            isinstance(rules, list) and any(isinstance(entry, Mapping) for entry in rules)
        ):
            raise Unsupported("Modal Sandbox egress controls do not filter HTTP methods or paths")
        if value.get("cuts_open_connections") is False:
            raise Unsupported(
                "Modal policy replacement terminates established connections it blocks"
            )
        domain_traffic = value.get("domain_traffic")
        # Spec `tls` is TLS on any port. Modal's domain allowlist is SNI on port 443,
        # which is the `https` class, so a non-443 TLS port would be blocked.
        if domain_traffic is not None and domain_traffic != "https":
            raise Unsupported("Modal domain allowlists restrict TLS traffic on port 443 only")

        switches_to = value.get("switches_to", [])
        if not isinstance(switches_to, list) or any(
            not isinstance(item, str) for item in switches_to
        ):
            raise ValueError("switches_to must be a list of policies")
        unsupported_targets = set(switches_to) - {"allowlist", "deny_all", "open"}
        if unsupported_targets:
            raise Unsupported("Modal Sandbox egress controls do not support switching to denylists")
        dynamic = value.get("switchable") is True or bool(switches_to)
        if policy == "deny_all":
            if create and not dynamic:
                return {"block_network": True}
            return {"outbound_cidr_allowlist": [], "outbound_domain_allowlist": []}
        if policy == "open":
            return {
                "outbound_cidr_allowlist": ["0.0.0.0/0"],
                "outbound_domain_allowlist": ["*"],
            }
        if policy not in {"allowlist", "allowlist_domains", "allowlist_ips"}:
            raise ValueError("unknown network policy")

        entries = value.get("allow", [])
        if not isinstance(entries, list) or any(not isinstance(item, str) for item in entries):
            raise ValueError("allow must be a list of domain names or CIDR ranges")
        domains: list[str] = []
        ranges: list[str] = []
        for entry in cast(list[str], entries):
            if policy == "allowlist_domains":
                domains.append(entry)
            elif policy == "allowlist_ips":
                ranges.append(str(ipaddress.ip_network(entry, strict=False)))
            else:
                try:
                    ranges.append(str(ipaddress.ip_network(entry, strict=False)))
                except ValueError:
                    domains.append(entry)
        return {"outbound_cidr_allowlist": ranges, "outbound_domain_allowlist": domains}

    def create(self, target: object, inputs: Inputs) -> Observation:
        del target
        requirements = mapping(inputs, "requirements")
        private_network = "private_network" in requirements
        if inputs.get("join") is not None and not private_network:
            raise Unsupported("Modal Sandbox.create has no private-network join selector")
        if inputs.get("at_end", "destroyed") != "destroyed":
            raise Unsupported("Modal native lifetime expiry terminates the sandbox")
        options: CreateOptions = {}
        if self.execution_class == "vm":
            options["runtime"] = "vm"
        for gate, value in requirements.items():
            if not isinstance(value, Mapping):
                raise ValueError("gate configuration must be a mapping")
            if gate == "pause_resume":
                raise Unsupported("Modal SDK has no in-place pause and resume")
            if gate == "private_network":
                if value.get("ip_version", "ipv6") != "ipv6":
                    if value.get("ip_version") == "ipv4":
                        raise Unsupported("Modal i6pn private networking uses IPv6")
                    raise ValueError("ip_version must be ipv6")
                options["i6pn"] = True
                # i6pn requires every member to run in the same specific region.
                options["region"] = _I6PN_REGION
                continue
            if gate == "nested_virtualization":
                if self.execution_class != "vm":
                    raise Unsupported("Modal nested virtualization requires the VM runtime")
                options["runtime"] = "vm"
                continue
            if gate == "live_resize":
                raise Unsupported("Modal Sandbox SDK 1.6.0 has no live resize operation")
            if gate == "ssh":
                raise Unsupported("Modal Sandbox SDK has no sandbox-scoped SSH access operation")
            if gate == "idle_shutdown":
                if value.get("on_idle", "destroyed") != "destroyed":
                    raise Unsupported("Modal idle timeout terminates the sandbox")
                if value.get("auto_wake") is True:
                    raise Unsupported("Modal SDK has no preview-triggered sandbox wake")
                if value.get("custom_idle_time") is False:
                    raise Unsupported("Modal idle shutdown requires an explicit idle_timeout")
                options["idle_timeout"] = number(value, "idle_seconds", 60)
            elif gate == "network_lockdown":
                network_options = self._network_policy_options(value, create=True)
                if (block_network := network_options.get("block_network")) is not None:
                    options["block_network"] = block_network
                if (cidr_allowlist := network_options.get("outbound_cidr_allowlist")) is not None:
                    options["outbound_cidr_allowlist"] = cidr_allowlist
                if (
                    domain_allowlist := network_options.get("outbound_domain_allowlist")
                ) is not None:
                    options["outbound_domain_allowlist"] = domain_allowlist
            elif gate == "previews":
                if value["access"] != "public":
                    raise Unsupported(
                        "Modal native port tunnels do not issue per-port private credentials"
                    )
                options["encrypted_ports"] = cast(list[int], value["ports"])
            elif gate == "tcp_ports":
                if value.get("tls", "none") == "none":
                    options["unencrypted_ports"] = cast(list[int], value["ports"])
                else:
                    options["encrypted_ports"] = cast(list[int], value["ports"])
            elif gate == "docker":
                options["runtime"] = "vm"
            elif gate == "hidden_secrets":
                raise Unsupported("Modal Secret exposes values in guest environment variables")
            elif gate == "snapshots":
                if value.get("keeps") == "files_and_memory":
                    options["_experimental_enable_snapshot"] = True
            elif gate == "custom_images":
                if "image" not in inputs:
                    raise Unsupported("Modal custom images require a prepared native Image")
            elif gate not in OPERATION_GATES | NO_CREATION_SETTING:
                raise NotRun("gate_mapping_unavailable")
        resources = mapping(inputs, "resources")
        if private_network and options.get("block_network"):
            # Modal's experimental Sandbox API permits an empty egress allowlist
            # with i6pn, while block_network disables all networking.
            options.pop("block_network")
            options["outbound_cidr_allowlist"] = []
            options["outbound_domain_allowlist"] = []
        if options.get("block_network") and options.get("encrypted_ports"):
            # Both pinned SDK creation paths reject this combination locally,
            # before Sandbox allocation. Neither capability alone is absent.
            raise Unsupported("Modal SDK cannot combine block-all networking with open ports")
        for key, value in resources.items():
            if key == "cpu_min":
                options["cpu"] = float(cast(float, value))
            elif key == "memory_min_mib":
                options["memory"] = cast(int, value)
            elif key == "gpu_model":
                if private_network:
                    raise Unsupported("Modal experimental i6pn Sandboxes do not accept GPU options")
                models = cast(list[str], value)
                names = {
                    model: GPU_NAMES[model]
                    for model in (
                        "nvidia:t4",
                        "nvidia:a10",
                        "nvidia:l4",
                        "nvidia:l40s",
                        "nvidia:h100",
                        "nvidia:h200",
                    )
                }
                if len(models) != 1 or models[0] not in names:
                    raise Unsupported("Requested GPU model is not offered by the pinned Modal SDK")
                options["gpu"] = names[models[0]]
            elif key == "gpu_count":
                if value != 1:
                    raise Unsupported("This Modal SDK Sandbox selector accepts one GPU")
            elif key != "long_running":
                raise Unsupported("Modal Sandbox SDK has no ephemeral disk allocation selector")
        if "image" in inputs:
            image = resource(inputs["image"]).native
            if not isinstance(image, modal.Image):
                raise ValueError("image binding must contain a native Modal Image")
            options["image"] = image
        if mounts := inputs.get("volumes"):
            if not isinstance(mounts, list):
                raise ValueError("volumes must be a list")
            volumes: dict[str | PathLike[str], modal.Volume | modal.CloudBucketMount] = {}
            for mount in mounts:
                volume = resource(mount["volume"]).native
                if mount.get("read_only"):
                    if not isinstance(volume, modal.Volume):
                        raise Unsupported("Modal read-only mount options require a Volume")
                    volume = volume.with_mount_options(read_only=True)
                volumes[mount["path"]] = cast(modal.Volume | modal.CloudBucketMount, volume)
            options["volumes"] = volumes
        context = cast(AbstractContextManager[modal.App], modal.App(native_name()).run())
        app = context.__enter__()  # pylint: disable=unnecessary-dunder-call
        self.own("application_session", context, lambda: self._end_app(context, app.app_id))
        if app.app_id is not None:
            self.app_ids.add(app.app_id)
        options["app"] = app
        options["env"] = cast(dict[str, str | None], strings(inputs, "environment"))
        options["timeout"] = number(inputs, "lifetime_seconds", DEFAULT_LIFETIME_SECONDS)
        if app.app_id is None:
            raise NotRun("native_app_identity_unavailable")
        app_id = app.app_id
        owned = self.own("sandbox", app_id, lambda: self._delete_reserved_sandbox(app_id))
        try:
            if private_network:
                # The pinned SDK exposes i6pn only on its experimental Sandbox API.
                create_i6pn = cast(
                    Callable[..., modal.Sandbox],
                    synchronizer.create_blocking(
                        modal.Sandbox._experimental_create  # pylint: disable=protected-access
                    ),
                )
                native = create_i6pn(**options)
            else:
                native = modal.Sandbox.create(**cast(Any, options))
        except InvalidError as error:
            message = str(error).lower()
            if "gpu" in options and "gpu" in message and "payment method" in message:
                # The explicit native billing refusal precedes Sandbox allocation.
                # A generic InvalidError or readiness error remains uncertain.
                owned.kind = "sandbox_reservation"
                owned.cleanup = lambda: self._confirm_refused_sandbox(app_id)
                raise NotRun("account_gpu_payment_method_required") from None
            raise
        owned.native = native
        owned.cleanup = lambda: self._delete(native, None if private_network else app_id)
        return {"resource": owned, "identity": native.object_id, "app": app}

    def _confirm_refused_sandbox(self, app_id: str) -> Observation:
        if any(modal.Sandbox.list(app_id=app_id)):
            return self._delete_reserved_sandbox(app_id)
        return {"result": "already_released"}

    def _delete_reserved_sandbox(self, app_id: str) -> Observation:
        found = False
        for native in modal.Sandbox.list(app_id=app_id):
            found = True
            self._delete(native)
        if any(modal.Sandbox.list(app_id=app_id)):
            raise NativeFailure("cleanup_not_confirmed")
        if not found:
            raise NativeFailure("allocation_identity_unavailable")
        return {"result": "deleted"}

    def _end_app(
        self, context: AbstractContextManager[modal.App], app_id: str | None
    ) -> Observation:
        context.__exit__(None, None, None)
        if app_id is not None:
            self.app_ids.discard(app_id)
        return {"result": "deleted"}

    @staticmethod
    def _delete(native: modal.Sandbox, app_id: str | None = None) -> Observation:
        try:
            native.terminate(wait=False)
            deadline = time.monotonic() + 120
            while native.poll() is None:
                if app_id is not None and not any(
                    item.object_id == native.object_id for item in modal.Sandbox.list(app_id=app_id)
                ):
                    return {"result": "deleted"}
                if time.monotonic() > deadline:
                    raise NativeFailure("cleanup_not_confirmed")
                time.sleep(1)
        except (NotFoundError, SandboxTimeoutError):
            pass
        return {"result": "deleted"}

    @staticmethod
    def _delete_image(image_id: str, app: modal.App) -> Observation:
        try:
            cast(Callable[[str], None], image_delete)(image_id)
        except NotFoundError:
            pass
        # from_id constructs a lazy handle. This SDK requires an active App load
        # context and build() to resolve it; hydrate() rejects this handle.
        if app.app_id is None:
            with modal.App().run() as lookup_app:
                return ModalDriver._confirm_image_absent(image_id, lookup_app)
        return ModalDriver._confirm_image_absent(image_id, app)

    @staticmethod
    def _confirm_image_absent(image_id: str, app: modal.App) -> Observation:
        deadline = time.monotonic() + 30
        while True:
            try:
                modal.Image.from_id(image_id).build(app)
            except NotFoundError:
                return {"result": "deleted"}
            if time.monotonic() >= deadline:
                raise NativeFailure("cleanup_not_confirmed")
            time.sleep(0.2)

    def snapshot_take(self, target: object, inputs: Inputs) -> Observation:
        keeps = inputs.get("keeps", "files_only")
        if not isinstance(target, Mapping):
            raise ValueError("snapshot requires a sandbox binding")
        parent = box(target)
        if keeps == "files_and_memory":
            if any(r.kind in {"process", "terminal"} and not r.released for r in self.resources):
                raise Unsupported(
                    "Modal memory snapshots cannot restore running Sandbox.exec processes"
                )
            owned = self.own("memory_snapshot_attempt", None, self._unknown_allocation)
            snapshot = parent._experimental_snapshot()  # pylint: disable=protected-access
            owned.native = snapshot
            owned.kind = "memory_snapshot"
            expires = (datetime.now(UTC) + timedelta(days=7)).isoformat()
            owned.cleanup = lambda: {"result": "expires", "expires_at": expires}
        else:
            app = cast(modal.App, target["app"])
            owned = self.own("snapshot_image_attempt", None, self._unknown_allocation)
            image = parent.snapshot_filesystem(timeout=55, ttl=300)
            owned.native = image
            owned.kind = "snapshot_image"
            owned.cleanup = lambda: self._delete_image(image.object_id, app)
        return {"resource": owned, "app": target.get("app")}

    @staticmethod
    def _unknown_allocation() -> Observation:
        # Native readiness may raise after remote allocation but before returning
        # its identity. Never omit that attempt or claim a clean unknown outcome.
        raise NativeFailure("allocation_identity_unavailable")

    def snapshot_restore(self, target: object, inputs: Inputs) -> Observation:
        owned = resource(target)
        if owned.kind == "snapshot_image":
            return self.create(None, {**inputs, "image": target})
        if inputs.get("environment") or inputs.get("resources") or inputs.get("requirements"):
            raise Unsupported("Modal memory restore cannot accept new creation options")
        child = self.own("sandbox_restore_attempt", None, self._unknown_allocation)
        native = modal.Sandbox._experimental_from_snapshot(cast(SandboxSnapshot, owned.native))  # pylint: disable=protected-access
        child.native = native
        child.kind = "sandbox"
        child.cleanup = lambda: self._delete(native)
        return {"resource": child, "identity": native.object_id}

    def snapshot_original_after(self, target: object, inputs: Inputs) -> Observation:
        del target, inputs
        raise NotRun("snapshot_freeze_transition_unobservable")

    def snapshot_delete(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        if resource(target).kind == "memory_snapshot":
            raise Unsupported("Modal memory snapshots have no native delete operation")
        return self.release(resource(target))

    def snapshot_delete_again(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        owned = resource(target)
        if owned.kind == "memory_snapshot":
            raise Unsupported("Modal memory snapshots have no native delete operation")
        assert isinstance(target, Mapping)
        self._delete_image(
            cast(modal.Image, owned.native).object_id, cast(modal.App, target["app"])
        )
        return {"native_delete_attempted": True}

    def image_prepare(self, target: object, inputs: Inputs) -> Observation:
        del target
        context = cast(AbstractContextManager[modal.App], modal.App().run())
        app = context.__enter__()  # pylint: disable=unnecessary-dunder-call
        self.own("application_session", context, lambda: self._end_app(context, app.app_id))
        source = text(inputs, "source")
        if source == "provider_artifact":
            image = modal.Image.from_id(text(inputs, "image")).build(app)
            return {"resource": Resource("image_reference", image, lambda: {}, released=True)}
        # A unique label gives the final native Image a unique definition. Shared
        # provider cache/base layers are not suite-owned artifacts.
        label = f"LABEL sps.run={uuid4().hex}"
        with TemporaryDirectory(prefix="sps-image-") as directory:
            if source in {"oci", "private_oci"}:
                secret = None
                if source == "private_oci":
                    secret = modal.Secret.from_dict(
                        {
                            "REGISTRY_USERNAME": text(inputs, "username"),
                            "REGISTRY_PASSWORD": text(inputs, "password"),
                        }
                    )
                image = modal.Image.from_registry(
                    text(inputs, "image"), secret=secret, setup_dockerfile_commands=[label]
                )
            elif source == "dockerfile":
                path = Path(directory) / "Dockerfile"
                path.write_text(text(inputs, "dockerfile") + "\n" + label + "\n", encoding="utf-8")
                build_context = mapping(inputs, "context")
                for name, contents in build_context.items():
                    if not isinstance(name, str) or not isinstance(contents, str):
                        raise ValueError("context must map relative paths to text")
                    relative = PurePosixPath(name)
                    if relative.is_absolute() or ".." in relative.parts:
                        raise ValueError("context paths must stay inside the build context")
                    if relative == PurePosixPath("Dockerfile"):
                        raise ValueError("context cannot replace the supplied Dockerfile")
                    context_file = Path(directory).joinpath(*relative.parts)
                    context_file.parent.mkdir(parents=True, exist_ok=True)
                    context_file.write_text(contents, encoding="utf-8")
                image = modal.Image.from_dockerfile(path, context_dir=directory)
            else:
                raise ValueError("unknown image source")
            owned = self._build_owned_image(image, app)
        return {"resource": owned}

    def _build_owned_image(self, image: modal.Image, app: modal.App) -> Resource:
        # from_dockerfile adds Modal runtime dependencies in a second native Image.
        # Its first Image contains our unique label too, so both are attributable.
        # Build each native dependency first, retaining its own returned/failure ID.
        for dependency in image._deps_():  # pylint: disable=protected-access
            if isinstance(dependency, modal.Image):
                self._build_owned_image(dependency, app)
        failed_id: list[str] = []
        owned = self.own("image", image, lambda: self._delete_build(image, failed_id, app))
        try:
            image.build(app)
        except ImageBuildError as error:
            failed_id.append(error.image_id)
            raise
        return owned

    def _delete_build(
        self, image: modal.Image, failed_id: list[str], app: modal.App
    ) -> Observation:
        identity = failed_id[0] if failed_id else image.object_id
        return self._delete_image(identity, app)

    def get(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        try:
            native = modal.Sandbox.from_id(box(target).object_id)
            active = native.poll() is None
        except (NotFoundError, SandboxTimeoutError):
            active = False
        return {"state": "active" if active else "destroyed"}

    def allocation_observe(self, target: object, inputs: Inputs) -> Observation:
        del target, inputs
        raise NotRun("native_allocation_metadata_unobservable")

    def long_running_observe(self, target: object, inputs: Inputs) -> Observation:
        del target, inputs
        raise NotRun("native_idle_configuration_unobservable")

    def sweep_stale(self, ttl_seconds: float) -> list[str]:
        # An ephemeral app and its sandboxes end with their client or their own timeout;
        # named volumes are what a crashed run leaves behind.
        swept: list[str] = []
        for native in modal.Volume.objects.list():
            if native.name is not None and stale(native.name, ttl_seconds):
                self._delete_volume(native.name)
                swept.append(f"volume:{native.name}")
        return swept

    def volume_observe_kind(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        if not isinstance(resource(target).native, modal.Volume):
            raise ValueError("kind observation requires a native Volume")
        # The native object identifies Modal's object-store-backed Volume product;
        # it does not implement distributed filesystem locks.
        return {"kind": "object_store"}

    def list(self, target: object, inputs: Inputs) -> Observation:
        del target, inputs
        return {
            "sandboxes": [
                {"identity": n.object_id}
                for app_id in self.app_ids
                for n in modal.Sandbox.list(app_id=app_id)
            ]
        }

    def destroy(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        return self.release(resource(target))

    def run(self, target: object, inputs: Inputs) -> Observation:
        if inputs.get("run_as") is not None:
            raise Unsupported("Modal's SDK has no named-user command option")
        script = text(inputs, "bash_script")
        native = box(target).exec(
            "bash",
            "-c",
            script,
            text=False,
            timeout=((number(inputs, "timeout_ms", 15000) + 999) // 1000) or None,
            workdir=cast(str | None, inputs.get("cwd")),
            env=cast(dict[str, str | None], strings(inputs, "environment")),
        )
        stdout, stderr = native.stdout.read(), native.stderr.read()
        exit_code = native.wait()
        # ContainerProcess.wait catches ExecTimeoutError and returns -1. Signal
        # exits are 128 + signal; this is the SDK's distinct timeout result.
        if exit_code == -1:
            raise NativeFailure("timeout")
        return {"stdout": stdout, "stderr": stderr, "exit_code": exit_code}

    def files_read_bytes(self, target: object, inputs: Inputs) -> Observation:
        return {"data": box(target).filesystem.read_bytes(text(inputs, "path"))}

    def files_write(self, target: object, inputs: Inputs) -> Observation:
        if inputs.get("user") is not None:
            raise Unsupported("Modal's SDK has no named-user file write option")
        data = base64.b64decode(text(inputs, "data"), validate=True)
        box(target).filesystem.write_bytes(data, text(inputs, "path"))
        return {}

    def files_exists(self, target: object, inputs: Inputs) -> Observation:
        try:
            box(target).filesystem.stat(text(inputs, "path"))
        except SandboxFilesystemNotFoundError:
            return {"exists": False}
        return {"exists": True}

    def files_list(self, target: object, inputs: Inputs) -> Observation:
        return {
            "names": sorted(f.name for f in box(target).filesystem.list_files(text(inputs, "path")))
        }

    def files_mkdir(self, target: object, inputs: Inputs) -> Observation:
        box(target).filesystem.make_directory(text(inputs, "path"))
        return {}

    def files_remove(self, target: object, inputs: Inputs) -> Observation:
        box(target).filesystem.remove(
            text(inputs, "path"), recursive=bool(inputs.get("recursive", False))
        )
        return {}

    def volume_create(self, target: object, inputs: Inputs) -> Observation:
        del target
        if inputs.get("kind", "object_store") != "object_store":
            raise Unsupported("Modal Volumes do not provide distributed file locks")
        from_name = native_name()
        owned = self.own("volume", from_name, lambda: self._delete_volume(from_name))
        modal.Volume.objects.create(from_name)
        native = modal.Volume.from_name(from_name)
        native.hydrate()
        owned.native = native
        return {"resource": owned}

    @staticmethod
    def _delete_volume(name: str) -> Observation:
        modal.Volume.objects.delete(name, allow_missing=True)
        try:
            modal.Volume.from_name(name).hydrate()
        except NotFoundError:
            return {"result": "deleted"}
        raise NativeFailure("cleanup_not_confirmed")

    def volume_commit(self, target: object, inputs: Inputs) -> Observation:
        del target, inputs
        raise Unsupported("Modal Sandbox SDK has no remote volume commit call")

    def volume_reload(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        box(target).reload_volumes(timeout=55)
        return {}

    def volume_read_bytes(self, target: object, inputs: Inputs) -> Observation:
        native = cast(modal.Volume, resource(target).native)
        try:
            data = b"".join(native.read_file(text(inputs, "path")))
        except FileNotFoundError:
            # Volume.read_file translates only the native NotFound response.
            return {"exists": False}
        return {"exists": True, "data": data}

    def network_private_address(self, target: object, inputs: Inputs) -> Observation:
        requested = inputs.get("ip_version")
        if requested not in {None, "ipv6"}:
            if requested == "ipv4":
                raise Unsupported("Modal i6pn private networking uses IPv6")
            raise ValueError("ip_version must be ipv6")
        native = box(target).exec(
            "python3",
            "-c",
            _PRIVATE_ADDRESS_SCRIPT,
            text=False,
            timeout=15,
        )
        exit_code = native.wait()
        if exit_code == -1:
            raise NativeFailure("private_address_timeout")
        if exit_code != 0:
            raise NativeFailure("private_address_unavailable")
        return {"address": _private_address_output(native.stdout.read()), "ip_version": 6}

    def network_update(self, target: object, inputs: Inputs) -> Observation:
        native = box(target)
        policy = self._network_policy_options(inputs, create=False)
        native._experimental_set_outbound_network_policy(  # pylint: disable=protected-access
            outbound_cidr_allowlist=policy.get("outbound_cidr_allowlist"),
            outbound_domain_allowlist=policy.get("outbound_domain_allowlist"),
        )
        return {}

    def tcp_link(self, target: object, inputs: Inputs) -> Observation:
        tunnel = box(target).tunnels(timeout=30)[number(inputs, "port", 7777)]
        host, port = tunnel.tcp_socket if inputs.get("tls", "none") == "none" else tunnel.tls_socket
        return {"host": host, "port": port}

    def preview_link(self, target: object, inputs: Inputs) -> Observation:
        if inputs.get("access", "public") != "public":
            raise Unsupported("Modal native tunnels have no per-port private credential")
        tunnels = box(target).tunnels(timeout=30)
        port = number(inputs, "port", 3000)
        if port not in tunnels:
            raise Unsupported("Modal tunnels forward only ports named at creation")
        native = tunnels[port]
        return {"url": native.url, "headers": {}}

    def preview_revoke(self, target: object, inputs: Inputs) -> Observation:
        del target, inputs
        raise Unsupported("Modal tunnels cannot be individually revoked")

    def process_start(self, target: object, inputs: Inputs) -> Observation:
        parent = box(target)
        if inputs.get("run_as") is not None:
            raise Unsupported("Modal's SDK has no named-user process option")
        script = text(inputs, "bash_script")
        native = parent.exec(
            "bash",
            "-c",
            script,
            text=False,
            timeout=((number(inputs, "timeout_ms", 120000) + 999) // 1000) or None,
        )
        # The SDK cannot kill an exec separately. Deleting its containing sandbox is
        # native cleanup, not a promised process-cancellation mapping.
        owned = self.own("process", native, lambda: self._delete(parent))
        return {"resource": owned}

    def process_write_stdin(self, target: object, inputs: Inputs) -> Observation:
        command(target).stdin.write(base64.b64decode(text(inputs, "data"), validate=True))
        command(target).stdin.drain()
        return {}

    def process_close_stdin(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        command(target).stdin.write_eof()
        command(target).stdin.drain()
        return {}

    def process_output(self, target: object, inputs: Inputs) -> Observation:
        if inputs.get("first_chunk") is True:
            # The SDK's native iterator yields a line without waiting for EOF.
            return {"stdout": next(iter(command(target).stdout), b"")}
        return {"stdout": command(target).stdout.read(), "stderr": command(target).stderr.read()}

    def process_status(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        code = command(target).poll()
        return {"state": "running" if code is None else "exited", "exit_code": code}

    def process_wait(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        return {"exit_code": command(target).wait()}

    def terminal_open(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        parent = box(target)
        native = parent.exec(
            "bash",
            pty=True,
            text=False,
            timeout=15,
        )
        owned = self.own("terminal", native, lambda: self._delete(parent))
        return {"resource": owned}

    terminal_write = process_write_stdin

    def terminal_output(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        return {"terminal": command(target).stdout.read()}


def make_driver(*, execution_class: str, fixtures: Mapping[str, object]) -> Driver:
    del fixtures
    if execution_class not in {"default", "vm"}:
        raise ValueError("Modal declaration has no execution class")
    return ModalDriver(execution_class=execution_class)
