# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
# pylint: disable=too-many-lines
"""Direct E2B SDK calls. No byte-capture, guest daemon or lifecycle emulation."""

from __future__ import annotations

import base64
import ipaddress
import re
import time
from collections.abc import Mapping, Sequence
from importlib.metadata import version
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from typing import cast
from uuid import uuid4

from e2b import (
    CommandExitException,
    NotFoundException,
    PtySize,
    Sandbox,
    SandboxLifecycle,
    SandboxNetworkOpts,
    SandboxNetworkUpdate,
    SandboxQuery,
    Secret,
    SecretException,
    SnapshotInfo,
    Template,
    TimeoutException,
    Volume,
    VolumeException,
    VolumeNotFoundException,
)
from e2b.api import encode_path_param
from e2b.api.client.api.templates import delete_templates_template_id, get_templates_template_id
from e2b.api.client.models.sandbox_state import SandboxState
from e2b.api.client_sync import get_api_client
from e2b.connection_config import ConnectionConfig
from e2b.sandbox.sandbox_api import (
    SandboxEgressProxyOpts,
    SandboxIamOpts,
    SandboxNetworkRule,
    SandboxNetworkRules,
    SandboxNetworkTransform,
    SandboxNetworkTransformContext,
)
from e2b.sandbox_sync.commands.command_handle import CommandHandle
from e2b.template.logger import LogEntry
from e2b_code_interpreter import Sandbox as InterpreterSandbox  # type: ignore[import-untyped]
from e2b_code_interpreter.models import Context, RunCodeLanguage  # type: ignore[import-untyped]
from e2b_desktop import Sandbox as DesktopSandbox  # type: ignore[import-untyped]

from sandbox_provider_spec.driver import (
    NO_CREATION_SETTING,
    OPERATION_GATES,
    UNOBSERVABLE_METADATA,
    Differs,
    Driver,
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
from sandbox_provider_spec.lifetime import DEFAULT_LIFETIME_SECONDS
from sandbox_provider_spec.run_id import native_name, run_id, stale


def box(target: object) -> Sandbox:
    return cast(Sandbox, resource(target).native)


def command(target: object) -> CommandHandle:
    return cast(CommandHandle, resource(target).native)


# One thin method per native operation keeps mappings independently auditable.
class E2BDriver(Driver):  # pylint: disable=too-many-public-methods
    provider = "e2b"
    sdk_versions = {
        "e2b": version("e2b"),
        "e2b-code-interpreter": version("e2b-code-interpreter"),
        "e2b-desktop": version("e2b-desktop"),
    }
    unsupported = {
        "tcp.link": "E2B SDK exposes HTTP preview hosts, not public raw TCP endpoints",
        "idle.select_duration": "E2B timeout is a lifetime, not an idle-activity timer",
        "long_running.observe": (
            "E2B exposes no observation that a sandbox remains active indefinitely"
        ),
        "resize": "E2B SDK has no sandbox resize operation",
        "ssh.access": "E2B SDK has no sandbox-scoped SSH access operation",
        "preview.revoke": "E2B SDK cannot revoke one public preview link",
    }
    unobservable = UNOBSERVABLE_METADATA

    def __init__(self, fixtures: Mapping[str, object] | None = None) -> None:
        super().__init__()
        self.fixtures = dict(fixtures or {})
        self._process_parents: dict[int, Sandbox] = {}
        self._network_state: dict[str, dict[str, object]] = {}
        self._network_configs: dict[str, dict[str, object]] = {}

    @staticmethod
    def _entries(settings: Mapping[str, object], key: str) -> list[str]:
        entries = settings.get(key, [])
        if not isinstance(entries, list):
            raise ValueError(f"network {key} must be a list")
        destinations: list[str] = []
        for entry in entries:
            if isinstance(entry, str):
                destinations.append(entry)
                continue
            if not isinstance(entry, Mapping):
                raise ValueError(f"network {key} entries must be text or host mappings")
            if entry.get("methods") or entry.get("paths"):
                raise Unsupported("E2B network rules cannot filter HTTP methods or paths")
            hosts = entry.get("hosts")
            if not isinstance(hosts, list) or any(not isinstance(host, str) for host in hosts):
                raise ValueError(f"network {key} host mappings need a text hosts list")
            destinations.extend(cast(list[str], hosts))
        return destinations

    @classmethod
    def _network_options(cls, settings: Mapping[str, object]) -> SandboxNetworkOpts:
        policy = settings.get("policy")
        allow = cls._entries(settings, "allow")
        deny = cls._entries(settings, "deny")
        if settings.get("deny_wins") is True:
            raise Unsupported("E2B allows a destination that also appears in deny_out")
        if settings.get("http_rules") is True:
            raise Unsupported(
                "E2B network rules transform requests but cannot filter methods or paths"
            )
        has_domain_entries = any(
            not cls._is_ip_range(destination) for destination in [*allow, *deny]
        )
        if settings.get("domain_traffic") is not None and has_domain_entries:
            if settings["domain_traffic"] != "http_and_https":
                raise Unsupported("E2B hostname rules cover HTTP and HTTPS together")

        options: SandboxNetworkOpts = {}
        if policy in {"open", None}:
            return options
        if policy in {"deny_all"}:
            options["deny_out"] = ["0.0.0.0/0"]
            return options
        if policy in {"denylist", "denylist_ips"}:
            if any(not cls._is_ip_range(item) for item in deny):
                raise Unsupported("E2B deny lists accept IP addresses and CIDRs, not domains")
            options["deny_out"] = deny
            return options
        if policy == "denylist_domains":
            raise Unsupported("E2B deny lists accept IP addresses and CIDRs, not domains")
        if policy in {"allowlist", "allowlist_domains", "allowlist_ips"}:
            if any(not cls._is_ip_range(item) for item in deny):
                raise Unsupported("E2B deny lists accept IP addresses and CIDRs, not domains")
            options["allow_out"] = allow
            options["deny_out"] = [*deny, "0.0.0.0/0"]
            return options
        raise ValueError("unknown network policy")

    @staticmethod
    def _is_ip_range(value: str) -> bool:
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError:
            return False
        return True

    def create(self, target: object, inputs: Inputs) -> Observation:
        del target
        ending = inputs.get("at_end", "destroyed")
        if ending not in {"destroyed", "paused"}:
            raise Unsupported("E2B native timeout lifecycle supports kill or pause")
        lifecycle: SandboxLifecycle = {"on_timeout": "pause" if ending == "paused" else "kill"}
        requirements = inputs.get("requirements", {})
        if not isinstance(requirements, Mapping):
            raise ValueError("requirements must be a mapping")
        sandbox_type: type[Sandbox] = Sandbox
        if "interpreter" in requirements and "desktop" in requirements:
            raise Unsupported("E2B companion SDKs use separate interpreter and desktop templates")
        if "interpreter" in requirements:
            sandbox_type = InterpreterSandbox
        elif "desktop" in requirements:
            sandbox_type = DesktopSandbox
        network: SandboxNetworkOpts = {}
        iam: SandboxIamOpts | None = None
        for gate, settings in requirements.items():
            if not isinstance(settings, Mapping):
                raise ValueError("gate configuration must be a mapping")
            if gate == "idle_shutdown":
                raise Unsupported("E2B timeout is a lifetime, not an idle-activity timer")
            if gate == "network_lockdown":
                network.update(self._network_options(settings))
            elif gate == "previews":
                if settings.get("access", "public") != "public":
                    raise Differs("E2B private ingress credentials cover the sandbox, not one port")
                network["allow_public_traffic"] = True
            elif gate == "hidden_secrets":
                name = cast(str, resource(inputs["secret"]).native)
                rules = dict(network.get("rules", {}))
                rules.update(
                    {
                        host: [{"transform": {"headers": {"X-SPS-Secret": Secret.fill(name)}}}]
                        for host in cast(list[str], settings["inject_into"])
                    }
                )
                network["rules"] = rules
            elif gate == "egress_proxy":
                if settings.get("protocol") != "socks5" or settings.get("traffic") != "any_tcp":
                    raise Unsupported("E2B BYOP tunnels TCP through SOCKS5, not an HTTP-only proxy")
                if settings.get("transparent") is False or settings.get("fails_closed") is False:
                    raise Unsupported("E2B BYOP is transparent and fails closed")
                proxy = inputs.get("egress_proxy", self.fixtures.get("egress_proxy"))
                if not isinstance(proxy, Mapping) or not isinstance(proxy.get("address"), str):
                    raise NotRun("egress_proxy_fixture_missing")
                if any(
                    not isinstance(key, str) or not isinstance(value, str)
                    for key, value in proxy.items()
                ):
                    raise NotRun("egress_proxy_fixture_invalid")
                network["egress_proxy"] = cast(SandboxEgressProxyOpts, dict(proxy))
            elif gate == "workload_identity":
                if settings.get("delivery") != "injected":
                    raise Unsupported(
                        "E2B identity tokens are injected into egress requests, not the environment"
                    )
                identity = inputs.get("workload_identity", self.fixtures.get("workload_identity"))
                if not isinstance(identity, Mapping):
                    raise NotRun("workload_identity_fixture_missing")
                audience = identity.get("audience")
                hosts = identity.get("hosts")
                header = identity.get("header", "Authorization")
                token_name = identity.get("token_name", "sps")
                if not isinstance(audience, str) or not audience:
                    raise NotRun("workload_identity_fixture_invalid")
                if (
                    not isinstance(hosts, list)
                    or not hosts
                    or any(not isinstance(host, str) or not host for host in hosts)
                ):
                    raise NotRun("workload_identity_fixture_invalid")
                if not isinstance(header, str) or not header:
                    raise NotRun("workload_identity_fixture_invalid")
                if not isinstance(token_name, str) or not token_name:
                    raise NotRun("workload_identity_fixture_invalid")
                iam = {
                    "tokens": {
                        token_name: Secret.iam_token(audience=audience, token_type="JWT-SVID")
                    }
                }
                identity_rules: dict[str, list[SandboxNetworkRule]] = dict(network.get("rules", {}))

                def transform(
                    ctx: SandboxNetworkTransformContext,
                    header_name: str = header,
                    identity_name: str = token_name,
                ) -> SandboxNetworkTransform:
                    return {"headers": {header_name: f"Bearer {ctx.iam.tokens[identity_name]}"}}

                for host in hosts:
                    identity_rules[host] = [
                        *identity_rules.get(host, []),
                        {"transform": transform},
                    ]
                network["rules"] = identity_rules
            elif gate == "private_network":
                raise Unsupported("E2B SDK has no private-network membership or join option")
            elif gate == "nested_virtualization":
                raise Unsupported("E2B SDK has no nested-virtualization selector")
            elif gate == "live_resize":
                raise Unsupported("E2B SDK has no live sandbox resize operation")
            elif gate == "ssh":
                raise Unsupported("E2B SDK has no sandbox-scoped SSH access operation")
            elif gate == "desktop":
                pass
            elif gate not in OPERATION_GATES | NO_CREATION_SETTING:
                raise NotRun("gate_mapping_unavailable")
        requested = inputs.get("resources", {})
        if not isinstance(requested, Mapping):
            raise ValueError("resources must be a mapping")
        if any(key in requested for key in ("gpu_model", "gpu_count")):
            raise Unsupported("E2B Sandbox and Template SDK have no GPU allocation selector")
        if requested.get("long_running"):
            raise Unsupported("E2B sandboxes have a finite lifetime and no keep-alive selector")
        # Native sizes belong to templates, not per-sandbox create options. Select
        # a prepared artifact and observe its actual allocation before proving it.
        if any(key not in {"cpu_min", "memory_min_mib"} for key in requested):
            raise Unsupported("E2B SDK has no per-sandbox disk allocation selector")
        template = None
        if "image" in inputs:
            template = cast(str, resource(inputs["image"]).native)
        mounts: dict[str, Volume | str] = {}
        if "volumes" in inputs:
            for mount in cast(list[dict[str, object]], inputs["volumes"]):
                if mount.get("read_only"):
                    raise Unsupported("E2B SDK volume mount has no read-only selector")
                mounts[cast(str, mount["path"])] = cast(Volume, resource(mount["volume"]).native)
        volume_settings = requirements.get("volumes")
        if isinstance(volume_settings, Mapping) and volume_settings.get("read_only_mounts") is True:
            raise Unsupported("E2B SDK volume mount has no read-only selector")
        marker = uuid4().hex
        owned = self.own(
            "sandbox", marker, lambda: self._delete_reserved(marker, settled=owned.create_settled)
        )
        owned.unreturned_create = True
        native = sandbox_type.create(
            template=template,
            metadata={"sps.run": marker, "sps.run_id": run_id()},
            envs=strings(inputs, "environment"),
            lifecycle=lifecycle,
            timeout=number(inputs, "lifetime_seconds", DEFAULT_LIFETIME_SECONDS),
            network=network or None,
            iam=iam,
            volume_mounts=mounts or None,
            request_timeout=60,
        )
        owned.native = native
        owned.unreturned_create = False
        owned.cleanup = lambda: self._delete(native)
        if isinstance(requirements.get("network_lockdown"), Mapping):
            policy = cast(Mapping[str, object], requirements["network_lockdown"])
            self._network_state[native.sandbox_id] = {
                "policy": policy.get("policy"),
                "current_policy": policy.get("policy"),
                "changeable": policy.get("changeable"),
                "switchable": policy.get("switchable"),
                "switches_to": policy.get("switches_to", []),
            }
        if network:
            self._network_configs[native.sandbox_id] = dict(network)
        if requested:
            info = native.get_info(request_timeout=30)
            if any(
                value < cast(int, requested[key])
                for key, value in {
                    "cpu_min": info.cpu_count,
                    "memory_min_mib": info.memory_mb,
                }.items()
                if key in requested
            ):
                raise Unsupported("E2B allocation is fixed by the selected native template")
        return {"resource": owned, "identity": native.sandbox_id}

    def sweep_stale(self, ttl_seconds: float) -> list[str]:
        swept: list[str] = []
        now = time.time()
        sandboxes = Sandbox.list(
            query=SandboxQuery(state=[SandboxState.RUNNING, SandboxState.PAUSED]),
            request_timeout=30,
        )
        while sandboxes.has_next:
            for info in sandboxes.next_items():
                # Only a sandbox that names a run, and only by its own id.
                if (
                    "sps.run_id" in info.metadata
                    and now - info.started_at.timestamp() > ttl_seconds
                ):
                    Sandbox.kill(  # pylint: disable=no-value-for-parameter
                        sandbox_id=info.sandbox_id, request_timeout=30
                    )
                    swept.append(f"sandbox:{info.sandbox_id}")
        try:
            for volume in Volume.list(request_timeout=30):
                if stale(volume.name, ttl_seconds):
                    self._delete_named_volume(volume.name)
                    swept.append(f"volume:{volume.name}")
        except VolumeException:
            pass  # The account has no volumes entitlement, so a run left none.
        try:
            secrets = Secret.list(request_timeout=30)
            while secrets.has_next:
                for secret in secrets.next_items():
                    if stale(secret.name, ttl_seconds):
                        self._delete_secret(secret.name)
                        swept.append(f"secret:{secret.name}")
        except SecretException:
            pass  # The account has no secrets entitlement, so a run left none.
        snapshots = Sandbox.list_snapshots(request_timeout=30)  # pylint: disable=no-value-for-parameter
        while snapshots.has_next:
            for snapshot in snapshots.next_items():
                if any(stale(name, ttl_seconds) for name in snapshot.names):
                    Sandbox.delete_snapshot(snapshot.snapshot_id, request_timeout=30)
                    swept.append(f"snapshot:{snapshot.snapshot_id}")
        return swept

    @staticmethod
    def _delete_reserved(marker: str, *, settled: bool = False) -> Observation:
        query = SandboxQuery(
            metadata={"sps.run": marker}, state=[SandboxState.RUNNING, SandboxState.PAUSED]
        )
        paginator = Sandbox.list(query=query, request_timeout=30)
        found = False
        while paginator.has_next:
            for info in paginator.next_items():
                found = True
                Sandbox.kill(  # pylint: disable=no-value-for-parameter
                    sandbox_id=info.sandbox_id, request_timeout=30
                )
        paginator = Sandbox.list(query=query, request_timeout=30)
        while paginator.has_next:
            if paginator.next_items():
                raise NativeFailure("cleanup_not_confirmed")
        if not found:
            if settled:
                return {"result": "already_released"}
            raise NativeFailure("allocation_identity_unavailable")
        return {"result": "deleted"}

    @staticmethod
    def _delete(native: Sandbox) -> Observation:
        try:
            native.kill(request_timeout=30)
        except NotFoundException:
            pass
        try:
            native.get_info(request_timeout=30)
        except NotFoundException:
            return {"result": "deleted"}
        raise NativeFailure("cleanup_not_confirmed")

    def get(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        try:
            info = box(target).get_info(request_timeout=30)
        except NotFoundException:
            return {"state": "destroyed"}
        state = "active" if str(info.state) == "running" else str(info.state)
        return {"state": state}

    def allocation_observe(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        info = box(target).get_info(request_timeout=30)
        # SandboxInfo documents memory_mb in MiB despite the attribute name.
        return {"allocation": {"cpu_min": info.cpu_count, "memory_min_mib": info.memory_mb}}

    def list(self, target: object, inputs: Inputs) -> Observation:
        del target, inputs
        pager = Sandbox.list(request_timeout=30)
        found: list[dict[str, object]] = []
        while pager.has_next:
            found.extend(
                {"identity": info.sandbox_id} for info in pager.next_items(request_timeout=30)
            )
        return {"sandboxes": found}

    def destroy(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        return self.release(resource(target))

    def run(self, target: object, inputs: Inputs) -> Observation:
        native = box(target)
        try:
            result = native.commands.run(
                text(inputs, "bash_script"),
                envs=strings(inputs, "environment"),
                cwd=cast(str | None, inputs.get("cwd")),
                user=cast(str | None, inputs.get("run_as")),
                timeout=number(inputs, "timeout_ms", 15000) / 1000,
            )
        except CommandExitException as error:
            result = error
        except TimeoutException:
            raise NativeFailure("timeout") from None
        return {"stdout": result.stdout, "stderr": result.stderr, "exit_code": result.exit_code}

    def run_as_root(self, target: object, inputs: Inputs) -> Observation:
        try:
            result = box(target).commands.run(
                text(inputs, "bash_script"),
                user="root",
                envs=strings(inputs, "environment"),
                cwd=cast(str | None, inputs.get("cwd")),
                timeout=number(inputs, "timeout_ms", 15000) / 1000,
            )
        except CommandExitException as error:
            result = error
        except TimeoutException:
            raise NativeFailure("timeout") from None
        return {"stdout": result.stdout, "stderr": result.stderr, "exit_code": result.exit_code}

    def network_update(self, target: object, inputs: Inputs) -> Observation:
        policy = inputs.get("policy")
        network = cast(SandboxNetworkUpdate, dict(self._network_options(inputs)))
        native = box(target)
        state = self._network_state.get(native.sandbox_id)
        if state is not None:
            initial_policy = state.get("policy")
            current_policy = state.get("current_policy", initial_policy)
            if policy == current_policy and state.get("changeable") is False:
                raise Unsupported("E2B network policy was created as non-changeable")
            if policy != current_policy and state.get("switchable") is not True:
                raise Unsupported("E2B network policy was not created as switchable")
            switches_to = state.get("switches_to", [])
            if (
                isinstance(switches_to, list)
                and switches_to
                and policy not in switches_to
                and policy != initial_policy
            ):
                raise Unsupported("E2B network update target is outside switches_to")
        current = self._network_configs.get(native.sandbox_id, {})
        if "rules" in current:
            network["rules"] = cast(SandboxNetworkRules, current["rules"])
        if "egress_proxy" in current:
            network["egress_proxy"] = cast(SandboxEgressProxyOpts, current["egress_proxy"])
        native.update_network(network, request_timeout=30)
        self._network_configs[native.sandbox_id] = dict(network)
        if state is not None:
            state["current_policy"] = policy
        return {}

    def desktop_start(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        if not isinstance(box(target), DesktopSandbox):
            raise Unsupported("Desktop controls require the native E2B desktop companion")
        return {}

    def desktop_screenshot(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        return {"png": bytes(cast(DesktopSandbox, box(target)).screenshot())}

    def desktop_click(self, target: object, inputs: Inputs) -> Observation:
        cast(DesktopSandbox, box(target)).left_click(
            number(inputs, "x", 80), number(inputs, "y", 80)
        )
        return {}

    def desktop_type(self, target: object, inputs: Inputs) -> Observation:
        cast(DesktopSandbox, box(target)).write(text(inputs, "text"))
        return {}

    def desktop_key(self, target: object, inputs: Inputs) -> Observation:
        cast(DesktopSandbox, box(target)).press(text(inputs, "key"))
        return {}

    def desktop_live_link(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        native = cast(DesktopSandbox, box(target))
        native.stream.start(require_auth=True)
        return {"url": native.stream.get_url(auth_key=native.stream.get_auth_key())}

    def interpreter_context(self, target: object, inputs: Inputs) -> Observation:
        native = box(target)
        if not isinstance(native, InterpreterSandbox):
            raise ValueError("interpreter context requires the companion SDK sandbox")
        context = native.create_code_context(
            language=cast(RunCodeLanguage, text(inputs, "language"))
        )
        owned = self.own(
            "interpreter_context", context, lambda: self._delete_context(native, context)
        )
        return {"resource": owned, "sandbox": native}

    @staticmethod
    def _delete_context(native: InterpreterSandbox, context: Context) -> Observation:
        try:
            native.remove_code_context(context)
        except NotFoundException:
            pass
        return confirmed_absent(
            lambda: all(item.id != context.id for item in native.list_code_contexts()), seconds=30
        )

    def interpreter_run(self, target: object, inputs: Inputs) -> Observation:
        if not isinstance(target, Mapping):
            raise ValueError("interpreter run requires a context")
        native = cast(InterpreterSandbox, target["sandbox"])
        result = native.run_code(
            text(inputs, "code"),
            context=cast(Context, resource(target).native),
            timeout=30,
            request_timeout=40,
        )
        return {
            "stdout": "".join(result.logs.stdout),
            "stderr": "".join(result.logs.stderr),
            "exit_code": 0 if result.error is None else 1,
            "image_data": [item.png for item in result.results if item.png],
        }

    def files_read_bytes(self, target: object, inputs: Inputs) -> Observation:
        return {
            "data": bytes(
                box(target).files.read(text(inputs, "path"), format="bytes", request_timeout=30)
            )
        }

    def files_write(self, target: object, inputs: Inputs) -> Observation:
        data = base64.b64decode(text(inputs, "data"), validate=True)
        box(target).files.write(
            text(inputs, "path"),
            data,
            user=cast(str | None, inputs.get("user")),
            request_timeout=30,
        )
        return {}

    def files_exists(self, target: object, inputs: Inputs) -> Observation:
        return {"exists": box(target).files.exists(text(inputs, "path"), request_timeout=30)}

    def files_list(self, target: object, inputs: Inputs) -> Observation:
        return {
            "names": sorted(
                f.name for f in box(target).files.list(text(inputs, "path"), request_timeout=30)
            )
        }

    def files_mkdir(self, target: object, inputs: Inputs) -> Observation:
        box(target).files.make_dir(text(inputs, "path"), request_timeout=30)
        return {}

    def files_remove(self, target: object, inputs: Inputs) -> Observation:
        box(target).files.remove(text(inputs, "path"), request_timeout=30)
        return {}

    def process_start(self, target: object, inputs: Inputs) -> Observation:
        native = box(target).commands.run(
            text(inputs, "bash_script"),
            background=True,
            stdin=True,
            user=cast(str | None, inputs.get("run_as")),
            timeout=number(inputs, "timeout_ms", 120000) / 1000,
        )
        self._process_parents[native.pid] = box(target)
        owned = self.own("process", native, lambda: self._kill_process(native))
        return {"resource": owned, "identity": native.pid}

    @staticmethod
    def _kill_process(native: CommandHandle) -> Observation:
        try:
            native.kill()
        except NotFoundException:
            pass
        return {"result": "deleted"}

    def process_write_stdin(self, target: object, inputs: Inputs) -> Observation:
        command(target).send_stdin(
            base64.b64decode(text(inputs, "data"), validate=True), request_timeout=30
        )
        return {}

    def process_close_stdin(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        command(target).close_stdin(request_timeout=30)
        return {}

    def process_output(self, target: object, inputs: Inputs) -> Observation:
        stdout: list[str] = []
        stderr: list[str] = []
        terminal: list[bytes] = []
        try:
            for out, err, tty in command(target):
                if out is not None:
                    stdout.append(out)
                if err is not None:
                    stderr.append(err)
                if tty is not None:
                    terminal.append(tty)
                if inputs.get("first_chunk") is True:
                    break
        except CommandExitException:
            pass
        return {
            "stdout": "".join(stdout),
            "stderr": "".join(stderr),
            "terminal": b"".join(terminal),
        }

    def process_status(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        native = command(target)
        parent = self._process_parents[native.pid]
        if any(item.pid == native.pid for item in parent.commands.list(request_timeout=30)):
            return {"state": "running", "exit_code": None}
        return {"state": "exited", **self.process_wait(target, {})}

    def process_wait(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        try:
            result = command(target).wait()
        except CommandExitException as error:
            result = error
        return {"exit_code": result.exit_code}

    def process_cancel(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        command(target).kill()
        return {}

    def process_disconnect(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        command(target).disconnect()
        return {}

    def process_reattach(self, target: object, inputs: Inputs) -> Observation:
        identity = inputs["identity"]
        if not isinstance(identity, int):
            raise ValueError("E2B process identity must be an integer")
        native = box(target).commands.connect(identity, timeout=15)
        owned = self.own("observer", native, lambda: self._disconnect(native))
        return {"resource": owned}

    @staticmethod
    def _disconnect(native: CommandHandle) -> Observation:
        native.disconnect()
        return {"result": "deleted"}

    def terminal_open(self, target: object, inputs: Inputs) -> Observation:
        native = box(target).pty.create(
            PtySize(rows=number(inputs, "rows", 24), cols=number(inputs, "columns", 80)), timeout=15
        )
        owned = self.own("terminal", native, lambda: self._kill_process(native))
        return {"resource": owned, "identity": native.pid, "sandbox": box(target)}

    terminal_disconnect = process_disconnect

    def terminal_reattach(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        if not isinstance(target, Mapping):
            raise ValueError("terminal requires its native sandbox")
        parent = cast(Sandbox, target["sandbox"])
        native = parent.pty.connect(command(target).pid, timeout=15)
        owned = self.own("observer", native, lambda: self._disconnect(native))
        return {"resource": owned, "sandbox": parent, "identity": native.pid}

    def terminal_write(self, target: object, inputs: Inputs) -> Observation:
        if not isinstance(target, Mapping):
            raise ValueError("terminal requires its native sandbox")
        native = cast(Sandbox, target["sandbox"])
        native.pty.send_stdin(
            command(target).pid,
            base64.b64decode(text(inputs, "data"), validate=True),
            request_timeout=30,
        )
        return {}

    # Native PTY output uses the same handle event stream.
    terminal_output = process_output

    def snapshot_take(self, target: object, inputs: Inputs) -> Observation:
        if inputs.get("keeps", "files_and_memory") == "files_only":
            raise Unsupported("E2B SDK snapshots capture files and memory together")
        native = box(target)
        name = native_name()
        owned = self.own("snapshot", name, lambda: self._delete_named_snapshot(native, name))
        snapshot = native.create_snapshot(name=name, request_timeout=60)
        owned.native = snapshot
        return {"resource": owned}

    @staticmethod
    def _delete_named_snapshot(native: Sandbox, name: str) -> Observation:
        # A named reservation also catches an SDK readiness error before it returns ID.
        # The SDK descriptor supplies a distinct class-call signature. Pylint
        # sees only the instance signature, unlike the SDK's typing overloads.
        paginator = Sandbox.list_snapshots(  # pylint: disable=no-value-for-parameter
            sandbox_id=native.sandbox_id, name=name, request_timeout=30
        )
        while paginator.has_next:
            for snapshot in paginator.next_items():
                Sandbox.delete_snapshot(snapshot.snapshot_id, request_timeout=30)
        paginator = Sandbox.list_snapshots(  # pylint: disable=no-value-for-parameter
            sandbox_id=native.sandbox_id, name=name, request_timeout=30
        )
        while paginator.has_next:
            if paginator.next_items():
                raise NativeFailure("cleanup_not_confirmed")
        return {"result": "deleted"}

    def snapshot_delete(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        return self.release(resource(target))

    def snapshot_delete_again(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        snapshot = cast(SnapshotInfo, resource(target).native)
        try:
            Sandbox.delete_snapshot(snapshot.snapshot_id, request_timeout=30)
        except NotFoundException:
            pass
        return {"native_delete_attempted": True}

    def snapshot_restore(self, target: object, inputs: Inputs) -> Observation:
        snapshot = cast(SnapshotInfo, resource(target).native)
        external = Resource("snapshot_reference", snapshot.snapshot_id, lambda: {}, released=True)
        return self.create(None, {**inputs, "image": {"resource": external}})

    def snapshot_restore_wait(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        info = box(target).get_info(request_timeout=30)
        if str(info.state) != "running":
            raise NotRun("native_snapshot_restore_not_ready")
        return {"ready": True}

    def snapshot_original_after(self, target: object, inputs: Inputs) -> Observation:
        del target, inputs
        raise NotRun("snapshot_freeze_transition_unobservable")

    def preview_link(self, target: object, inputs: Inputs) -> Observation:
        if inputs.get("access", "public") != "public":
            raise Differs("E2B private ingress credentials cover every sandbox port")
        return {
            "url": "https://" + box(target).get_host(number(inputs, "port", 3000)),
            "headers": {},
        }

    def lifetime_extend(self, target: object, inputs: Inputs) -> Observation:
        box(target).set_timeout(number(inputs, "lifetime_seconds", 180), request_timeout=30)
        return {}

    def volume_create(self, target: object, inputs: Inputs) -> Observation:
        del target, inputs
        name = native_name()
        owned = self.own("volume", name, lambda: self._delete_named_volume(name))
        try:
            native = Volume.create(name, request_timeout=60)
        except VolumeException as error:
            # This SDK exception has no status attribute. Match only its explicit
            # account-entitlement response; other 403s remain operational errors.
            if str(error).strip().lower() == "403: use of volumes is not enabled":
                raise NotRun("account_volumes_not_enabled") from None
            raise
        owned.native = native
        return {"resource": owned}

    @staticmethod
    def _delete_named_volume(name: str) -> Observation:
        for native in Volume.list(request_timeout=30):
            if native.name == name:
                Volume.destroy(native.volume_id, request_timeout=30)
                try:
                    Volume.get_info(native.volume_id, request_timeout=30)
                except VolumeNotFoundException:
                    continue
                raise NativeFailure("cleanup_not_confirmed")
        return {"result": "deleted"}

    def volume_commit(self, target: object, inputs: Inputs) -> Observation:
        del target, inputs
        raise Unsupported("E2B mounted volumes have no explicit SDK commit operation")

    def volume_reload(self, target: object, inputs: Inputs) -> Observation:
        del target, inputs
        raise Unsupported("E2B Volume SDK has no mounted-volume refresh operation")

    def volume_observe_kind(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        native = resource(target).native
        if not isinstance(native, Volume):
            raise NotRun("volume_kind_not_exposed_by_e2b_volume")
        # E2B's Team Volume SDK exposes a persistent, mountable path API (read/write,
        # directories and metadata). Cloud buckets use a separate guest FUSE setup.
        Volume.get_info(native.volume_id, request_timeout=30)
        return {"kind": "filesystem"}

    def volume_read_bytes(self, target: object, inputs: Inputs) -> Observation:
        native = cast(Volume, resource(target).native)
        path = text(inputs, "path")
        if not native.exists(path, request_timeout=30):
            return {"exists": False}
        return {
            "exists": True,
            "data": bytes(native.read_file(path, format="bytes", request_timeout=30)),
        }

    def image_prepare(self, target: object, inputs: Inputs) -> Observation:
        del target
        source = text(inputs, "source")
        if source != "dockerfile" and inputs.get("context") not in (None, {}, [], ""):
            raise ValueError("build context requires a Dockerfile image")
        if source == "provider_artifact":
            return {
                "resource": Resource(
                    "image_reference", text(inputs, "image"), lambda: {}, released=True
                )
            }
        with TemporaryDirectory(prefix="sps-e2b-context-") as context_dir:
            if source in {"oci", "private_oci"}:
                if source == "private_oci":
                    username, password = inputs.get("username"), inputs.get("password")
                    if (
                        not isinstance(username, str)
                        or not username
                        or not isinstance(password, str)
                    ):
                        raise NotRun("private_registry_credentials_missing")
                    template = Template().from_image(
                        text(inputs, "image"), username=username, password=password
                    )
                else:
                    template = Template().from_image(text(inputs, "image"))
            elif source == "dockerfile":
                root = Path(context_dir)
                dockerfile = root / "Dockerfile"
                dockerfile.write_text(text(inputs, "dockerfile"), encoding="utf-8")
                context = inputs.get("context", {})
                if not isinstance(context, Mapping):
                    raise ValueError("Dockerfile context must map relative paths to text or bytes")
                for relative, content in context.items():
                    if isinstance(content, Mapping) and set(content) == {"base64"}:
                        encoded = content["base64"]
                        if not isinstance(encoded, str):
                            raise ValueError("Dockerfile context base64 must be text")
                        content = base64.b64decode(encoded, validate=True)
                    if not isinstance(relative, str) or not isinstance(content, (str, bytes)):
                        raise ValueError("Dockerfile context must map paths to text or bytes")
                    path = PurePosixPath(relative)
                    if (
                        path.is_absolute()
                        or not path.parts
                        or ".." in path.parts
                        or any(invalid in relative for invalid in ("\x00", "\\"))
                        or path == PurePosixPath("Dockerfile")
                    ):
                        raise ValueError("Dockerfile context paths must stay inside the context")
                    destination = root.joinpath(*path.parts)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(
                        content.encode("utf-8") if isinstance(content, str) else content
                    )
                template = Template(file_context_path=root).from_dockerfile(str(dockerfile))
            else:
                template = None
            if template is None:
                raise ValueError("unknown image source")
            name = native_name()
            identity: list[str] = []
            owned = self.own("template", name, lambda: self._delete_template(identity))

            def allocated(entry: LogEntry) -> None:
                # The pinned SDK emits this callback immediately after request_build,
                # before upload, trigger and readiness waiting. Consume it privately.
                match = re.fullmatch(
                    r"Template created with ID: ([A-Za-z0-9_-]+), Build ID: [A-Za-z0-9_-]+",
                    entry.message,
                )
                if match:
                    identity.append(match[1])
                    owned.native = match[1]

            built = Template.build(
                template,
                name=name,
                cpu_count=2,
                memory_mb=1024,
                on_build_logs=allocated,
                request_timeout=60,
            )
            if built.template_id not in identity:
                # Register any additional returned allocation rather than assuming
                # a name or build callback and final ID refer to the same artifact.
                identity.append(built.template_id)
            owned.native = built.template_id
            return {"resource": owned}

    @staticmethod
    def _delete_template(identities: Sequence[str]) -> Observation:
        if not identities:
            raise NativeFailure("allocation_identity_unavailable")
        client = get_api_client(ConnectionConfig(request_timeout=30))
        for identity in set(identities):
            encoded = encode_path_param(identity)
            result = delete_templates_template_id.sync_detailed(encoded, client=client)
            if result.status_code not in {204, 404}:
                raise NativeFailure("native_template_delete_failed")
            result = get_templates_template_id.sync_detailed(encoded, client=client)
            if result.status_code != 404:
                raise NativeFailure("cleanup_not_confirmed")
        return {"result": "deleted"}

    def secret_create(self, target: object, inputs: Inputs) -> Observation:
        del target
        name = native_name()
        owned = self.own("secret", name, lambda: self._delete_secret(name))
        try:
            Secret.create(name, text(inputs, "value"), request_timeout=30)
        except SecretException as error:
            message = str(error).lower()
            if message.startswith("403:") and all(
                term in message for term in ("secrets", "not available", "team")
            ):
                # An explicit native creation refusal allocated no secret. The
                # reservation needs no delete API, which this entitlement also denies.
                owned.kind = "secret_reservation"
                owned.cleanup = lambda: {"result": "already_released"}
                raise NotRun("account_secrets_not_available") from None
            raise
        return {"resource": owned}

    def secret_rotate(self, target: object, inputs: Inputs) -> Observation:
        Secret.update(cast(str, resource(target).native), text(inputs, "value"), request_timeout=30)
        return {}

    @staticmethod
    def _delete_secret(name: str) -> Observation:
        Secret.destroy(name, request_timeout=30)
        if Secret.exists(name, request_timeout=30):
            raise NativeFailure("cleanup_not_confirmed")
        return {"result": "deleted"}

    def pause(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        box(target).pause(request_timeout=60)
        return {}

    def resume(self, target: object, inputs: Inputs) -> Observation:
        owned = resource(target)
        owned.native = box(target).connect(
            timeout=120,
            on_resume="reboot" if inputs.get("keeps") == "files_only" else "restore",
            request_timeout=60,
        )
        return cast(Observation, target)


def make_driver(*, execution_class: str, fixtures: Mapping[str, object]) -> Driver:
    if execution_class != "default":
        raise ValueError("E2B declaration has no execution class")
    return E2BDriver(fixtures)
