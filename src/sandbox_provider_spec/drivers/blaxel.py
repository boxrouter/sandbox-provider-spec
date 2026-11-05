# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Direct Blaxel SDK calls. No bundled binary, PTY or lifecycle emulation."""

from __future__ import annotations

import base64
import ipaddress
import shlex
import threading
import urllib.parse
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import partial
from importlib.metadata import version
from typing import Any, cast

from blaxel.core.client import errors
from blaxel.core.client.api.compute.create_sandbox_preview_token import (
    sync as create_sandbox_preview_token,
)
from blaxel.core.client.api.compute.delete_sandbox_preview_token import (
    sync as delete_sandbox_preview_token,
)
from blaxel.core.client.client import client
from blaxel.core.client.models import (
    PreviewToken,
    PreviewTokenMetadata,
    PreviewTokenSpec,
    SandboxLifecycle,
)
from blaxel.core.sandbox.default.sandbox import SandboxAPIError
from blaxel.core.sandbox.sync import SyncSandboxInstance
from blaxel.core.sandbox.sync.interpreter import SyncCodeInterpreter
from blaxel.core.sandbox.sync.preview import SyncSandboxPreview, to_utc_z
from blaxel.core.sandbox.types import ResponseError, SandboxUpdateNetwork
from blaxel.core.volume.volume import SyncVolumeInstance, VolumeAPIError

from sandbox_provider_spec.driver import (
    NO_CREATION_SETTING,
    Driver,
    Inputs,
    NativeFailure,
    NotRun,
    Observation,
    Reserved,
    Resource,
    Unsupported,
    confirmed_absent,
    created,
    number,
    reserved,
    resource,
    strings,
    text,
)
from sandbox_provider_spec.run_id import native_name, stale

#: Blaxel's deployment status, in the suite's state words; any other is passed on lowercase.
STATES = {"DEPLOYED": "active", "ARCHIVED": "stopped", "TERMINATED": "destroyed"}
#: The SDK attaches `delete`, `archive` and `unarchive` to the class at import time, so
#: type checkers cannot see them; they are called through this name.
INSTANCE: Any = SyncSandboxInstance
#: The same, for volumes.
VOLUME: Any = SyncVolumeInstance
# A create Blaxel answers with DEPLOYMENT_FAILED is tried again, this many times in all.
DEPLOYMENT_ATTEMPTS = 3
#: HTTP statuses with which this workspace refuses a feature its plan or quota does not allow.
ENTITLEMENT = {402, 403, 429}
#: How long a streamed output observation waits for its first chunk.
FIRST_CHUNK_SECONDS = 15
#: The header that carries a private preview's token.
PREVIEW_TOKEN_HEADER = "X-Blaxel-Preview-Token"


@dataclass
class Snapshot:
    """A snapshot, addressed through the sandbox it was taken from."""

    sandbox: SyncSandboxInstance
    identity: str


@dataclass
class InterpreterContext:
    """A code context, addressed through the interpreter sandbox that holds it."""

    interpreter: SyncCodeInterpreter
    context: SyncCodeInterpreter.Context


@dataclass
class Link:
    """One preview (one port) and, when private, the token issued for it."""

    sandbox: SyncSandboxInstance
    preview: SyncSandboxPreview
    token: str | None


@dataclass
class Command:
    """A background process, addressed by the name it was started with."""

    sandbox: SyncSandboxInstance
    name: str


def box(target: object) -> SyncSandboxInstance:
    return cast(SyncSandboxInstance, created(target))


def command(target: object) -> Command:
    return cast(Command, resource(target).native)


def _status(error: SandboxAPIError) -> int | None:
    return error.status_code


def _gone(name: str) -> bool:
    """Blaxel keeps a deleted sandbox's record as TERMINATED for minutes, then answers 404."""
    try:
        native = SyncSandboxInstance.get(name)
    except SandboxAPIError as error:
        if _status(error) == 404:
            return True
        raise
    return str(getattr(native.status, "value", native.status)) == "TERMINATED"


def _native_timeout(inputs: Inputs) -> int:
    """A process's native timeout in seconds; the suite's 0 asks for the longest, which is none."""
    milliseconds = number(inputs, "timeout_ms", 15000)
    return 0 if milliseconds == 0 else max(1, (milliseconds + 999) // 1000)


def _ignore_chunk(chunk: str) -> None:
    del chunk


def _timed_out(error: ResponseError) -> bool:
    """Blaxel answers a command that outlives its `timeout` with this distinct 422."""
    data = error.data if isinstance(error.data, Mapping) else {}
    return error.response.status_code == 422 and "timed out" in str(data.get("error", ""))


def _entitled(call: Callable[[], Any]) -> Any:
    """A feature this workspace's plan does not include is not run, never unsupported."""
    try:
        return call()
    except (SandboxAPIError, VolumeAPIError, errors.UnexpectedStatus) as error:
        if error.status_code in ENTITLEMENT:
            raise NotRun("account_entitlement_missing") from None
        raise


def _network(settings: Mapping[str, Any]) -> dict[str, object]:
    """Blaxel filters egress in its proxy; the `proxy` firewall ruleset forces all egress
    through it, so a sandbox cannot bypass the filter by ignoring proxy variables."""
    policy = settings["policy"]
    if settings.get("cuts_open_connections") is True:
        raise Unsupported("Blaxel does not document closing established egress connections")
    traffic = settings.get("domain_traffic")
    if traffic in {"https", "tls", "all"}:
        raise Unsupported("Blaxel filters HTTP(S) domains, not separate traffic classes")
    if traffic not in {None, "http_and_https"}:
        raise Unsupported("Blaxel filters HTTP(S) domains, not separate traffic classes")
    if settings.get("deny_wins") is False:
        raise Unsupported("Blaxel always gives forbidden domain rules precedence")
    if settings.get("deny_wins") is True and policy != "allowlist":
        raise Unsupported("Blaxel's deny-wins behavior applies to allowlist policies")
    if policy == "deny_all":
        proxy: dict[str, object] = {"forbidden_domains": ["*"]}
    elif policy in {"allowlist", "allowlist_domains"}:
        allowed = _domain_patterns(
            settings.get("allow", []), http_rules=settings.get("http_rules") is True
        )
        denied = _domain_patterns(
            settings.get("deny", []), http_rules=settings.get("http_rules") is True
        )
        if allowed:
            proxy = {"allowed_domains": allowed}
        else:
            # Blaxel treats an empty allowedDomains list as unrestricted; the spec's
            # empty allowlist denies every destination instead.
            proxy = {"forbidden_domains": ["*"]}
        if allowed and denied:
            proxy["forbidden_domains"] = denied
    elif policy in {"denylist", "denylist_domains"}:
        proxy = {
            "forbidden_domains": _domain_patterns(
                settings.get("deny", []), http_rules=settings.get("http_rules") is True
            )
        }
    elif policy == "open":
        raise Unsupported("Blaxel's proxy firewall cannot be removed to provide open egress")
    else:
        raise Unsupported("Blaxel's egress filter names domains, not addresses")
    switches_to = settings.get("switches_to", [])
    if settings.get("switchable") is True and not switches_to:
        raise Unsupported("Blaxel policy updates require a declared switches_to policy")
    if isinstance(switches_to, list) and any(
        item not in {"deny_all", "allowlist", "denylist"} for item in switches_to
    ):
        raise Unsupported("Blaxel's proxy firewall cannot be removed to provide open egress")
    return {"proxy": proxy, "firewall": {"rulesets": ["proxy"]}}


def _domain_patterns(entries: object, *, http_rules: bool) -> list[str]:
    if not isinstance(entries, list):
        raise Unsupported("Blaxel's egress filter requires a list of domain rules")
    patterns: list[str] = []
    for entry in entries:
        if isinstance(entry, str):
            try:
                ipaddress.ip_network(entry, strict=False)
            except ValueError:
                patterns.append(entry)
                continue
            raise Unsupported("Blaxel's proxy filter does not match IP ranges")
        if not http_rules or not isinstance(entry, Mapping):
            raise Unsupported("Blaxel's proxy filter accepts host rules only")
        hosts = entry.get("hosts", [])
        methods = entry.get("methods", [])
        paths = entry.get("paths", [])
        if (
            not isinstance(hosts, list)
            or not isinstance(methods, list)
            or not isinstance(paths, list)
        ):
            raise Unsupported("Blaxel's HTTP filter requires host, method and path lists")
        method_prefix = f"{':'.join(str(method).upper() for method in methods)}:" if methods else ""
        path_suffixes = [str(path).replace("**", "*") for path in paths] or [""]
        for host in hosts:
            for path in path_suffixes:
                patterns.append(f"{method_prefix}{host}{path}")
    return patterns


def _idle(settings: Mapping[str, Any]) -> dict[str, object] | None:
    """Blaxel's standby is always on: it keeps memory, wakes on the next request and picks
    its own delay. Deletion when idle is a lifecycle policy with a caller-chosen duration,
    the only idle ending whose timing is selectable."""
    on_idle = settings.get("on_idle")
    if on_idle == "stopped":
        raise Unsupported("Blaxel deletes or suspends an idle sandbox; it never stops one")
    if on_idle == "destroyed" or (on_idle is None and settings.get("custom_idle_time")):
        if "idle_seconds" not in settings:
            # There is no native default interval for deletion to observe.
            raise NotRun("native_idle_duration_required")
        return _delete_when_idle(number(settings, "idle_seconds", 0))
    if settings.get("custom_idle_time"):
        raise Unsupported("Blaxel's standby has no caller-chosen delay")
    if settings.get("keeps") == "files_only":
        raise Unsupported("Blaxel's standby keeps memory")
    if settings.get("auto_wake") is False:
        raise Unsupported("Blaxel wakes a standby sandbox on its next request")
    return None


def _delete_when_idle(seconds: int) -> dict[str, object]:
    return {
        "expiration_policies": [{"type": "ttl-idle", "action": "delete", "value": f"{seconds}s"}]
    }


# One thin method per native operation keeps mappings independently auditable.
class BlaxelDriver(Driver):  # pylint: disable=too-many-public-methods
    provider = "blaxel"
    sdk_versions = {"blaxel": version("blaxel")}
    unobservable = {"secret.rotate": "native_secret_rotation_unimplemented"}
    unsupported = {
        "process.write_stdin": "Blaxel SDK has no process stdin write operation",
        "process.close_stdin": "Blaxel SDK has no process stdin close operation",
        "terminal.open": "Blaxel SDK has no PTY operation",
        "terminal.write": "Blaxel SDK has no PTY operation",
        "terminal.output": "Blaxel SDK has no PTY operation",
        "terminal.disconnect": "Blaxel SDK has no PTY operation",
        "terminal.reattach": "Blaxel SDK has no PTY operation",
        "run.as_root": "Blaxel SDK exposes no per-command user selector",
        "tcp.link": "Blaxel previews route HTTP only; the SDK has no raw TCP link",
        "desktop.screenshot": "Blaxel SDK has no desktop operation",
        "desktop.click": "Blaxel SDK has no desktop operation",
        "desktop.type": "Blaxel SDK has no desktop operation",
        "desktop.key": "Blaxel SDK has no desktop operation",
        "desktop.start": "Blaxel SDK has no desktop operation",
        "desktop.live_link": "Blaxel SDK has no desktop operation",
        "lifetime.observe_paused_countdown": "Blaxel does not expose its standby countdown",
        "long_running.observe": (
            "Blaxel process keep_alive does not expose a sandbox-wide idle-disable setting"
        ),
        "resize": "Blaxel sandbox updates may reset state and do not guarantee live resize",
        "ssh.access": "Blaxel SDK has no SSH access or credential operation",
        "snapshot.restore_begin": "Blaxel exposes snapshot fork as one synchronous operation",
        "snapshot.restore_wait": "Blaxel exposes snapshot fork as one synchronous operation",
        "snapshot.retention": "Blaxel snapshots have no caller-selected retention setting",
        "volume.observe_kind": "Blaxel's volume SDK does not report mounted volume kind",
        "volume.read_bytes": "Blaxel's volume SDK has no direct file read operation",
        "volume.reload": "Blaxel's volume SDK has no reload operation",
    }

    def create(self, target: object, inputs: Inputs) -> Observation:
        del target
        config = self._config(inputs)
        requirements = cast(Mapping[str, object], inputs.get("requirements", {}))
        for attempt in range(DEPLOYMENT_ATTEMPTS):
            name = native_name(16)
            holder: Reserved[SyncSandboxInstance] = Reserved(name)
            owned = self.own("sandbox", holder, partial(self._delete, name))
            try:
                holder.native = _entitled(partial(self._deploy, name, config, requirements))
            except SandboxAPIError as error:
                # Blaxel's answer is "Sandbox deployment failed. Please try again": the
                # failed sandbox is deleted (confirmed) and a fresh name deploys again.
                if error.code != "DEPLOYMENT_FAILED" or attempt == DEPLOYMENT_ATTEMPTS - 1:
                    raise
                # Each failed deployment stays in the test's report as its own cleanup
                # entry, so the report shows how often Blaxel failed to deploy.
                owned.kind = "failed_deployment"
                self.release(owned)
                continue
            return {"resource": owned, "identity": name}
        raise AssertionError("unreachable")

    @staticmethod
    def _deploy(
        name: str, config: Mapping[str, object], requirements: Mapping[str, object]
    ) -> SyncSandboxInstance:
        if "interpreter" in requirements:
            # The SDK's code interpreter is a sandbox on its jupyter-server image; it takes
            # the name, environment and memory, and sets its own image, ports and lifecycle.
            chosen: dict[str, object] = {k: config[k] for k in ("envs", "memory") if k in config}
            return SyncCodeInterpreter.create({"name": name, **chosen})
        return SyncSandboxInstance.create({"name": name, **config})

    @staticmethod
    def _config(inputs: Inputs) -> dict[str, object]:
        """Every gate is chosen here, at creation."""
        if inputs.get("at_end", "destroyed") != "destroyed":
            raise Unsupported("Blaxel's lifetime (ttl) deletes the sandbox")
        if "join" in inputs:
            raise Unsupported("Blaxel's SDK has no documented sandbox join interface")
        config: dict[str, object] = {
            "envs": [
                {"name": key, "value": value}
                for key, value in strings(inputs, "environment").items()
            ],
            "ttl": f"{number(inputs, 'lifetime_seconds', 300)}s",
        }
        requirements = cast(Mapping[str, Mapping[str, Any]], inputs.get("requirements", {}))
        for gate, settings in requirements.items():
            if gate == "network_lockdown":
                # Kept beside any secret routing hidden_secrets adds, whichever comes first.
                network = cast(dict[str, Any], config.setdefault("network", {}))
                locked = _network(settings)
                proxy = cast(dict[str, Any], network.setdefault("proxy", {}))
                proxy.update(cast(dict[str, Any], locked["proxy"]))
                network["firewall"] = locked["firewall"]
            elif gate == "private_network":
                if settings.get("ip_version") in {"ipv4", "ipv6"}:
                    raise Unsupported("Blaxel's SDK does not configure private-network IP versions")
                raise Unsupported("Blaxel's SDK does not document sandbox private-network joins")
            elif gate == "egress_proxy":
                raise Unsupported("Blaxel exposes no caller-configurable egress proxy")
            elif gate == "workload_identity":
                raise Unsupported("Blaxel's sandbox SDK exposes no workload identity delivery")
            elif gate == "nested_virtualization":
                raise Unsupported("Blaxel's sandbox SDK exposes no nested virtualization setting")
            elif gate == "ssh":
                if settings.get("credential") in {"key", "password", "token"}:
                    raise Unsupported("Blaxel's SDK has no SSH access or credential operation")
                raise Unsupported("Blaxel's SDK has no SSH access or credential operation")
            elif gate == "live_resize":
                if settings.get("shrinks") is True:
                    raise Unsupported("Blaxel sandbox updates do not guarantee live shrinking")
                raise Unsupported(
                    "Blaxel sandbox updates may reset state and do not guarantee live resize"
                )
            elif gate == "custom_images":
                if settings.get("source") == "private_oci":
                    raise Unsupported("Blaxel's SDK has no private OCI pull-credential setting")
                if settings.get("build_context") is True:
                    raise Unsupported(
                        "Blaxel's SDK does not build an image from a supplied context"
                    )
                image_config = settings.get("image_config", [])
                if isinstance(image_config, list) and set(image_config) & {"user", "workdir"}:
                    raise Unsupported(
                        "Blaxel's sandbox SDK cannot set custom image user or workdir"
                    )
                if image_config:
                    raise Unsupported(
                        "Blaxel's sandbox SDK cannot set custom image user or workdir"
                    )
            elif gate == "volumes" and settings.get("read_only_mounts") is True:
                # The SDK maps each requested mount's read_only bit below.
                continue
            elif gate == "idle_shutdown":
                if (lifecycle := _idle(settings)) is not None:
                    config["lifecycle"] = lifecycle
            elif gate == "previews":
                config["ports"] = [{"target": port} for port in cast(list[int], settings["ports"])]
            elif gate == "snapshots":
                config["snapshot_enabled"] = True
            elif gate == "hidden_secrets":
                if settings.get("injection", "sets_header") != "sets_header":
                    raise Unsupported(
                        "Blaxel's proxy adds configured headers; it replaces no placeholder "
                        "a request sends"
                    )
                # The proxy adds the header to requests for these hosts; the value is a
                # write-only routing secret. The proxy firewall keeps egress on the proxy.
                network = cast(dict[str, Any], config.setdefault("network", {}))
                proxy = cast(dict[str, Any], network.setdefault("proxy", {}))
                proxy.setdefault("routing", []).append(
                    {
                        "destinations": list(cast(list[str], settings["inject_into"])),
                        "headers": {"X-SPS-Secret": "{{SECRET:sps-secret}}"},
                        "secrets": {"sps-secret": cast(str, resource(inputs["secret"]).native)},
                    }
                )
                network["firewall"] = {"rulesets": ["proxy"]}
            # These need no native setting at creation; what the SDK lacks is reported by
            # the operation that uses it (a PTY, a TCP link). The
            # interpreter chooses the SDK's interpreter sandbox in `create`.
            elif gate not in NO_CREATION_SETTING | {
                "interpreter",
                "pause_resume",
                "volumes",
                "custom_images",
            }:
                raise NotRun("gate_mapping_unavailable")
        resources = cast(Mapping[str, object], inputs.get("resources", {}))
        if "cpu_min" in resources or "disk_min_mib" in resources:
            raise Unsupported("Blaxel sizes a sandbox by memory; its CPU and disk follow")
        if resources.get("long_running"):
            raise Unsupported(
                "Blaxel keep_alive applies to a running process, not sandbox-wide idle disable"
            )
        if set(resources) - {"memory_min_mib", "long_running"}:
            raise NotRun("resource_mapping_unavailable")
        if "memory_min_mib" in resources:
            config["memory"] = resources["memory_min_mib"]
        if "image" in inputs:
            config["image"] = cast(str, resource(inputs["image"]).native)
        if "volumes" in inputs:
            config["volumes"] = [
                {
                    "name": cast(str, resource(mount["volume"]).native),
                    "mount_path": mount["path"],
                    "read_only": bool(mount.get("read_only", False)),
                }
                for mount in cast(list[Mapping[str, object]], inputs["volumes"])
            ]
        return config

    def sweep_stale(self, ttl_seconds: float) -> list[str]:
        swept: list[str] = []
        page = SyncSandboxInstance.list()
        while True:
            for item in page:
                name = item.metadata.name
                status = str(getattr(item.status, "value", item.status))
                if status != "TERMINATED" and stale(name, ttl_seconds):
                    self._delete(name)
                    swept.append(f"sandbox:{name}")
            if not page.has_more:
                break
            page = page.next_page()
        for volume in SyncVolumeInstance.list():
            if volume.name is not None and stale(volume.name, ttl_seconds):
                self._delete_volume(volume.name)
                swept.append(f"volume:{volume.name}")
        return swept

    @staticmethod
    def _delete(name: str) -> Observation:
        try:
            INSTANCE.delete(name)
        except SandboxAPIError as error:
            if _status(error) != 404:
                raise
        return confirmed_absent(lambda: _gone(name), seconds=90)

    def get(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        try:
            native = SyncSandboxInstance.get(reserved(target).name)
        except SandboxAPIError as error:
            if _status(error) == 404:
                return {"state": "destroyed"}
            raise
        status = str(getattr(native.status, "value", native.status))
        # A deployed sandbox reports standby in its separate runtime state.
        if status == "DEPLOYED" and str(getattr(native.sandbox, "state", "")) == "STANDBY":
            return {"state": "paused"}
        return {"state": STATES.get(status, status.lower())}

    def list(self, target: object, inputs: Inputs) -> Observation:
        del target, inputs
        found: list[dict[str, object]] = []
        page = SyncSandboxInstance.list()
        while True:
            found.extend({"identity": item.metadata.name} for item in page)
            if not page.has_more:
                return {"sandboxes": found}
            page = page.next_page()

    def destroy(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        return self.release(resource(target))

    def run(self, target: object, inputs: Inputs) -> Observation:
        if inputs.get("run_as") is not None:
            raise Unsupported("Blaxel's SDK has no named-user command option")
        script = text(inputs, "bash_script")
        try:
            result = box(target).process.exec(
                {
                    "command": shlex.join(["bash", "-c", script]),
                    "env": strings(inputs, "environment"),
                    "working_dir": inputs.get("cwd"),
                    "timeout": _native_timeout(inputs),
                    "wait_for_completion": True,
                    # A log callback selects the SDK's streaming wait, whose keepalives
                    # hold the request past the gateway's 120 s cut; the returned stdout
                    # and stderr stay exact.
                    "on_stdout": _ignore_chunk,
                }
            )
        except ResponseError as error:
            if _timed_out(error):
                raise NativeFailure("timeout") from None
            raise
        return {"stdout": result.stdout, "stderr": result.stderr, "exit_code": result.exit_code}

    def files_read_bytes(self, target: object, inputs: Inputs) -> Observation:
        return {"data": box(target).fs.read_binary(text(inputs, "path"))}

    def files_write(self, target: object, inputs: Inputs) -> Observation:
        if inputs.get("user") is not None:
            raise Unsupported("Blaxel's SDK has no named-user file write option")
        data = base64.b64decode(text(inputs, "data"), validate=True)
        box(target).fs.write_binary(text(inputs, "path"), data)
        return {}

    def files_exists(self, target: object, inputs: Inputs) -> Observation:
        # The SDK has no stat call; its path read stats the path first and answers 404
        # ("stat <path>: no such file or directory") when nothing is there.
        try:
            box(target).fs.read_binary(text(inputs, "path"))
        except ResponseError as error:
            if error.response.status_code == 404:
                return {"exists": False}
            raise
        return {"exists": True}

    def files_list(self, target: object, inputs: Inputs) -> Observation:
        listed = box(target).fs.ls(text(inputs, "path"))
        entries: list[Any] = [*(listed.files or []), *(listed.subdirectories or [])]
        return {"names": sorted(str(entry.name) for entry in entries)}

    def files_mkdir(self, target: object, inputs: Inputs) -> Observation:
        box(target).fs.mkdir(text(inputs, "path"))
        return {}

    def files_remove(self, target: object, inputs: Inputs) -> Observation:
        box(target).fs.rm(text(inputs, "path"), recursive=bool(inputs.get("recursive", False)))
        return {}

    def process_start(self, target: object, inputs: Inputs) -> Observation:
        if inputs.get("run_as") is not None:
            raise Unsupported("Blaxel's SDK has no named-user process option")
        parent = box(target)
        name = native_name(12)
        native = Command(parent, name)
        owned = self.own("process", native, lambda: self._kill(native))
        parent.process.exec(
            {
                "command": shlex.join(
                    [
                        "bash",
                        "-c",
                        text(inputs, "bash_script"),
                    ]
                ),
                "name": name,
                "stdin": True,
                "wait_for_completion": False,
                **({"timeout": _native_timeout(inputs)} if "timeout_ms" in inputs else {}),
            }
        )
        return {"resource": owned, "identity": name}

    @staticmethod
    def _kill(native: Command) -> Observation:
        try:
            if native.sandbox.process.get(native.name).status == "running":
                native.sandbox.process.kill(native.name)
        except SandboxAPIError as error:
            if _status(error) != 404:
                raise
        return {"result": "deleted"}

    def process_output(self, target: object, inputs: Inputs) -> Observation:
        native = command(target)
        if inputs.get("first_chunk") is True:
            return self._first_chunk(native)
        result = native.sandbox.process.wait(native.name, max_wait=60000, interval=500)
        return {"stdout": result.stdout, "stderr": result.stderr}

    @staticmethod
    def _first_chunk(native: Command) -> Observation:
        """The SDK's native log stream delivers output while the process still runs."""
        chunks: list[str] = []
        arrived = threading.Event()

        def received(content: str) -> None:
            chunks.append(content)
            arrived.set()

        handle = native.sandbox.process.stream_logs(native.name, {"on_stdout": received})
        try:
            if not arrived.wait(FIRST_CHUNK_SECONDS):
                raise NotRun("native_stream_observation_timed_out")
        finally:
            handle.close()
        return {"stdout": chunks[0]}

    def process_status(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        native = command(target)
        status = native.sandbox.process.get(native.name)
        if status.status == "running":
            return {"state": "running", "exit_code": None}
        if status.exit_code is None:
            raise NotRun("native_process_state_unobservable")
        return {"state": "exited", "exit_code": status.exit_code}

    def process_wait(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        native = command(target)
        result = native.sandbox.process.wait(native.name, max_wait=60000, interval=500)
        return {"exit_code": result.exit_code}

    def process_cancel(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        native = command(target)
        native.sandbox.process.kill(native.name)
        return {}

    def process_disconnect(self, target: object, inputs: Inputs) -> Observation:
        # A process started without a log stream holds no client connection: the SDK
        # addresses it by name on every call, so there is nothing to close.
        del target, inputs
        return {}

    def process_reattach(self, target: object, inputs: Inputs) -> Observation:
        identity = inputs["identity"]
        if not isinstance(identity, str):
            raise ValueError("Blaxel process identity must be its name")
        native = Command(box(target), identity)
        native.sandbox.process.get(identity)
        owned = self.own("observer", native, lambda: {"result": "deleted"})
        return {"resource": owned}

    def pause(self, target: object, inputs: Inputs) -> Observation:
        if inputs.get("keeps", "files_only") != "files_only":
            raise Unsupported("Blaxel's caller-driven archive keeps files, not processes")
        _entitled(lambda: INSTANCE.archive(reserved(target).name))
        return {}

    def resume(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        holder = reserved(target)
        if self.get(target, {})["state"] == "paused":
            # Standby wakes on the next request to the sandbox; asking for it resumes it.
            holder.native = SyncSandboxInstance.get(holder.name)
        else:
            holder.native = _entitled(lambda: INSTANCE.unarchive(holder.name))
        return cast(Observation, target)

    def snapshot_take(self, target: object, inputs: Inputs) -> Observation:
        # Blaxel has one snapshot kind; what it keeps is what the test observes.
        del inputs
        parent = box(target)
        native = Snapshot(parent, str(_entitled(parent.snapshot).id))
        owned = self.own("snapshot", native, lambda: self._delete_snapshot(native))
        return {"resource": owned}

    @staticmethod
    def _delete_snapshot(native: Snapshot) -> Observation:
        try:
            native.sandbox.delete_snapshot(native.identity)
        except SandboxAPIError as error:
            if _status(error) != 404:
                raise
        if any(str(item.id) == native.identity for item in native.sandbox.list_snapshots()):
            raise NativeFailure("cleanup_not_confirmed")
        return {"result": "deleted"}

    def snapshot_delete(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        return self.release(resource(target))

    def snapshot_delete_again(self, target: object, inputs: Inputs) -> Observation:
        if inputs:
            raise ValueError("snapshot.delete_again accepts no options")
        snapshot = cast(Snapshot, resource(target).native)
        self._delete_snapshot(snapshot)
        return {"native_delete_attempted": True}

    def snapshot_restore(self, target: object, inputs: Inputs) -> Observation:
        """A fork from a snapshot is a new sandbox; `restore` would roll back the source."""
        if set(inputs) - {"keeps", "original_after"}:
            raise NotRun("restore_option_mapping_unavailable")
        snapshot = cast(Snapshot, resource(target).native)
        name = native_name(16)
        holder: Reserved[SyncSandboxInstance] = Reserved(name)
        owned = self.own("sandbox", holder, lambda: self._delete(name))
        _entitled(lambda: snapshot.sandbox.fork(name, snapshot_id=snapshot.identity))
        holder.native = SyncSandboxInstance.get(name)
        return {"resource": owned, "identity": name}

    def snapshot_original_after(self, target: object, inputs: Inputs) -> Observation:
        del target, inputs
        raise NotRun("snapshot_freeze_transition_unobservable")

    def preview_link(self, target: object, inputs: Inputs) -> Observation:
        parent = box(target)
        port = number(inputs, "port", 3000)
        private = inputs.get("access", "public") == "private"
        name = native_name(8, middle=f"{port}-{'private' if private else 'public'}")
        link = Link(parent, cast(SyncSandboxPreview, None), None)
        owned = self.own("preview", link, lambda: self._delete_preview(link))
        link.preview = parent.previews.create(
            {"metadata": {"name": name}, "spec": {"port": port, "public": not private}}
        )
        url = link.preview.spec.url if link.preview.spec else None
        if not url:
            raise NotRun("observation_unmapped")
        if not private:
            return {"resource": owned, "url": url, "headers": {}}
        requested = native_name(12)
        expires = datetime.now(UTC) + timedelta(seconds=number(inputs, "lifetime_seconds", 3600))
        # The SDK's tokens.create omits the token's required name, so the SDK's generated
        # API call is made with it.
        issued = create_sandbox_preview_token(
            parent.metadata.name,
            link.preview.name,
            body=PreviewToken(
                metadata=PreviewTokenMetadata(name=requested),
                spec=PreviewTokenSpec(expires_at=to_utc_z(expires)),
            ),
            client=client,
        )
        token = issued.spec.token if issued and issued.spec else None
        if not token:
            raise NotRun("observation_unmapped")
        # Blaxel names the token itself; revoking it needs the name it answered with.
        link.token = issued.metadata.name if issued and issued.metadata else requested
        observed: Observation = {"resource": owned, "unauthorized_url": url}
        if inputs.get("credential", "header") == "header":
            return {**observed, "url": url, "headers": {PREVIEW_TOKEN_HEADER: token}}
        # The link form: Blaxel accepts the same token as the bl_preview_token query parameter.
        query = urllib.parse.urlencode({"bl_preview_token": token})
        return {**observed, "url": f"{url}?{query}", "headers": {}}

    @staticmethod
    def _delete_preview(link: Link) -> Observation:
        if link.preview is None:
            return {"result": "deleted"}
        try:
            link.sandbox.previews.delete(link.preview.name)
        except errors.UnexpectedStatus as error:
            if error.status_code != 404:
                raise
        return {"result": "deleted"}

    def preview_revoke(self, target: object, inputs: Inputs) -> Observation:
        """Revoking a private link deletes its token; a public link is its preview."""
        del inputs
        link = cast(Link, resource(target).native)
        if link.token is not None:
            delete_sandbox_preview_token(
                link.sandbox.metadata.name, link.preview.name, link.token, client=client
            )
            return {}
        return self.release(resource(target))

    def lifetime_extend(self, target: object, inputs: Inputs) -> Observation:
        holder = reserved(target)
        holder.native = INSTANCE.update_ttl(
            holder.name, f"{number(inputs, 'lifetime_seconds', 180)}s"
        )
        return {}

    def allocation_observe(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        native = SyncSandboxInstance.get(reserved(target).name)
        return {"allocation": {"memory_min_mib": getattr(native.spec.runtime, "memory", None)}}

    def network_update(self, target: object, inputs: Inputs) -> Observation:
        desired = _network(inputs)
        native = box(target)
        spec = getattr(native.sandbox, "spec", None)
        existing = getattr(spec, "network", None)
        to_dict = getattr(existing, "to_dict", None)
        if callable(to_dict):
            payload = cast(dict[str, Any], to_dict())
        elif isinstance(existing, Mapping):
            payload = dict(existing)
        else:
            payload = {}
        proxy = payload.get("proxy", {})
        if not isinstance(proxy, Mapping):
            proxy_dict: dict[str, Any] = {}
        else:
            proxy_dict = dict(proxy)
        for key in (
            "allowed_domains",
            "allowedDomains",
            "forbidden_domains",
            "forbiddenDomains",
        ):
            proxy_dict.pop(key, None)
        proxy_dict.update(cast(dict[str, Any], desired["proxy"]))
        payload["proxy"] = proxy_dict
        # Firewall rulesets are immutable after creation. Keep the original value while
        # changing only the proxy's live domain-filter configuration.
        if "firewall" not in payload:
            payload["firewall"] = desired["firewall"]
        payload.pop("allowed_domains", None)
        payload.pop("allowedDomains", None)
        payload.pop("forbidden_domains", None)
        payload.pop("forbiddenDomains", None)
        INSTANCE.update_network(reserved(target).name, SandboxUpdateNetwork(network=payload))
        return {}

    def idle_select_duration(self, target: object, inputs: Inputs) -> Observation:
        holder = reserved(target)
        holder.native = INSTANCE.update_lifecycle(
            holder.name,
            SandboxLifecycle.from_dict(_delete_when_idle(number(inputs, "idle_seconds", 300))),
        )
        return {}

    def image_prepare(self, target: object, inputs: Inputs) -> Observation:
        del target
        if any(key in inputs for key in ("context", "password", "username")):
            raise Unsupported("Blaxel's SDK cannot authenticate or build a caller-provided image")
        if inputs.get("source") != "provider_artifact":
            raise Unsupported("Blaxel's SDK cannot authenticate or build a caller-provided image")
        # An existing image is borrowed, never built or deleted by the test.
        return {"resource": Resource("image_reference", text(inputs, "image"), lambda: {}, True)}

    def image_create(self, target: object, inputs: Inputs) -> Observation:
        del target, inputs
        # The SDK builds a Dockerfile only by deploying it as a sandbox, and an image's own
        # ENTRYPOINT replaces the sandbox API that every other operation goes through.
        raise NotRun("image_build_mapping_pending")

    def volume_create(self, target: object, inputs: Inputs) -> Observation:
        del target
        if inputs.get("kind", "filesystem") != "filesystem":
            raise Unsupported("Blaxel volumes are block filesystems")
        name = native_name(16)
        owned = self.own("volume", name, lambda: self._delete_volume(name))
        _entitled(lambda: SyncVolumeInstance.create({"name": name, "size": 1024}))
        return {"resource": owned}

    @staticmethod
    def _delete_volume(name: str) -> Observation:
        def gone() -> bool:
            try:
                SyncVolumeInstance.get(name)
            except VolumeAPIError as error:
                if error.status_code == 404:
                    return True
                raise
            return False

        try:
            VOLUME.delete(name)
        except VolumeAPIError as error:
            if error.status_code != 404:
                raise
        return confirmed_absent(gone, seconds=120)

    def secret_create(self, target: object, inputs: Inputs) -> Observation:
        # Blaxel keeps no secret object: the value is a write-only routing secret of the
        # sandbox that names it, and ends with that sandbox.
        del target
        owned = self.own(
            "secret_value", text(inputs, "value"), lambda: {"result": "already_released"}
        )
        return {"resource": owned}

    def interpreter_context(self, target: object, inputs: Inputs) -> Observation:
        native = box(target)
        if not isinstance(native, SyncCodeInterpreter):
            raise ValueError("an interpreter context needs a sandbox created with interpreter")
        context = native.create_code_context(language=text(inputs, "language"))
        name = reserved(target).name
        # The SDK can neither list nor delete a context; it ends with its sandbox, so its
        # cleanup deletes that sandbox and confirms it gone (the sandbox's own cleanup then
        # finds nothing left).
        owned = self.own(
            "interpreter_context",
            InterpreterContext(native, context),
            lambda: self._delete(name),
        )
        return {"resource": owned, "sandbox": target}

    def interpreter_run(self, target: object, inputs: Inputs) -> Observation:
        held = cast(InterpreterContext, resource(target).native)
        execution = held.interpreter.run_code(
            text(inputs, "code"),
            context=held.context,
            timeout=number(inputs, "timeout_ms", 60000) / 1000,
        )
        # A result carries each representation as an attribute named by its format.
        images = [
            str(vars(result)["png"]) for result in execution.results if vars(result).get("png")
        ]
        return {
            "stdout": "".join(execution.logs.stdout),
            "stderr": "".join(execution.logs.stderr),
            "exit_code": 1 if execution.error is not None else 0,
            "image_data": images,
        }


def make_driver(*, execution_class: str, fixtures: Mapping[str, object]) -> Driver:
    del fixtures
    if execution_class != "default":
        raise ValueError("Blaxel declaration has no execution class")
    return BlaxelDriver()
