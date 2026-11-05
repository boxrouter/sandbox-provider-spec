# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Direct Vercel Sandbox SDK calls. No bundled binary, PTY or lifecycle emulation."""

from __future__ import annotations

import base64
import ipaddress
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
from importlib.metadata import version
from pathlib import PurePosixPath
from typing import Any, cast

from vercel.sandbox.sync import (
    DriveMount,
    NetworkPolicy,
    NetworkPolicyRule,
    NetworkPolicySubnets,
    NetworkPolicyTransform,
    SandboxApiError,
    SandboxResources,
    SnapshotSource,
    SyncDrive,
    SyncProcess,
    SyncSandbox,
    SyncSnapshot,
    create_sandbox,
    delete_drive,
    get_or_create_drive,
    get_sandbox,
    get_snapshot,
    query_drives,
    query_sandboxes,
    query_snapshots,
    resume_sandbox,
)

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

#: How long a create waits for the team's concurrency limit (10 on the Hobby plan).
CONCURRENCY_WAIT_SECONDS = 300
#: Vercel's sandbox status, in the suite's state words; any other status is passed on as is.
STATES = {"running": "active", "stopped": "stopped"}


def box(target: object) -> SyncSandbox:
    return cast(SyncSandbox, created(target))


def process(target: object) -> SyncProcess:
    return cast(SyncProcess, resource(target).native)


def _missing(error: SandboxApiError) -> bool:
    return getattr(error, "status_code", None) == 404


def _within_quota(error: SandboxApiError) -> None:
    """A plan's usage limit (402) is the account's state, not the provider's behavior."""
    if error.status_code == 402:
        raise NotRun("account_quota_exhausted") from None


def _kill_after(inputs: Inputs) -> float | None:
    """Vercel's command deadline in seconds; the suite's 0 asks for the longest, which is none
    (the API refuses a zero deadline), leaving the sandbox's own timeout to bound it."""
    milliseconds = number(inputs, "timeout_ms", 15000)
    return None if milliseconds == 0 else milliseconds / 1000


def _cidrs(entries: list[str]) -> list[str]:
    """Vercel's subnet lists take CIDR ranges; a bare IPv4 address is its own /32."""
    return [str(ipaddress.IPv4Network(entry, strict=False)) for entry in entries]


def _policy(settings: Mapping[str, Any]) -> NetworkPolicy:
    policy = settings["policy"]
    if policy == "deny_all":
        return NetworkPolicy.deny_all()
    if policy == "open":
        if "cuts_open_connections" in settings:
            raise Unsupported(
                "Vercel Sandbox SDK does not specify whether network updates "
                "close existing connections"
            )
        return NetworkPolicy.allow_all()
    if "domain_traffic" in settings:
        raise Unsupported("Vercel Sandbox SDK has no network protocol selector for domain rules")
    if "cuts_open_connections" in settings:
        raise Unsupported(
            "Vercel Sandbox SDK does not specify whether network updates close existing connections"
        )
    if settings.get("http_rules"):
        raise Unsupported(
            "Vercel network policy matchers transform or forward requests; "
            "they do not block matching requests"
        )

    def split(entries: object) -> tuple[list[str], list[str]]:
        domains: list[str] = []
        addresses: list[str] = []
        for entry in cast(list[object], entries):
            if isinstance(entry, Mapping):
                if "methods" in entry or "paths" in entry:
                    raise Unsupported(
                        "Vercel network policy matchers transform or forward requests; "
                        "they do not block matching requests"
                    )
                hosts = entry.get("hosts")
                if not isinstance(hosts, list):
                    raise Unsupported(
                        "Vercel network policy accepts domains and address ranges, not rule objects"
                    )
                domains.extend(cast(list[str], hosts))
                continue
            if not isinstance(entry, str):
                raise Unsupported("Vercel network policy entries must be domains or IPv4 ranges")
            if ":" in entry:
                raise Unsupported("Vercel Sandbox SDK network subnets accept IPv4 ranges only")
            try:
                addresses.append(str(ipaddress.IPv4Network(entry, strict=False)))
            except ValueError:
                domains.append(entry)
        return domains, addresses

    allow = cast(list[object], settings.get("allow", []))
    deny = cast(list[object], settings.get("deny", []))
    if policy in {"allowlist", "allowlist_domains", "allowlist_ips"}:
        domains, addresses = split(allow)
        denied_domains, denied_addresses = split(deny)
        if denied_domains:
            raise Unsupported("Vercel network policies deny address ranges, not domains")
        if policy == "allowlist_domains" and addresses:
            raise Unsupported("Vercel domain policies cannot allow address ranges")
        if policy == "allowlist_ips" and domains:
            raise Unsupported("Vercel subnet policies cannot allow domains")
        if deny and not settings.get("deny_wins"):
            raise Unsupported("Vercel denied address ranges take precedence over allowed entries")
        subnets = (
            NetworkPolicySubnets(
                allow=addresses or None,
                deny=denied_addresses or None,
            )
            if addresses or denied_addresses
            else None
        )
        return NetworkPolicy.custom(allow={domain: () for domain in domains}, subnets=subnets)
    if policy in {"denylist", "denylist_ips"}:
        denied_domains, denied_addresses = split(deny or allow)
        if denied_domains:
            raise Unsupported("Vercel network policies deny address ranges, not domains")
        # Every domain stays allowed; denied address ranges take precedence over allowed ranges.
        return NetworkPolicy.custom(
            allow={"*": ()}, subnets=NetworkPolicySubnets(deny=denied_addresses)
        )
    raise Unsupported(
        "Vercel Sandbox SDK supports allowlist, address denylist, open and deny-all policies"
    )


@dataclass
class SecretValue:
    """A secret Vercel keeps no object for: its value, and the lockdown of the sandbox whose
    network policy carries it, so a rotation can rebuild that same policy."""

    value: str
    lockdown: Mapping[str, Any] | None = None


def _with_secret(value: str, hosts: list[str], lockdown: Mapping[str, Any] | None) -> NetworkPolicy:
    """Vercel injects a header per allowed domain from outside the sandbox. The secret's
    hosts carry the header; the rest of the policy is the requested lockdown, or open."""
    subnets: NetworkPolicySubnets | None = None
    if lockdown is None:
        allowed: dict[str, tuple[NetworkPolicyRule, ...]] = {"*": ()}
    elif lockdown["policy"] == "deny_all":
        allowed = {}
    elif lockdown["policy"] in {"allowlist", "allowlist_domains"}:
        base = _policy(lockdown)
        if base.subnets is not None:
            raise Unsupported("Vercel injects secrets per domain, not with an address policy")
        allowed = dict(base.allow)
    else:
        raise Unsupported("Vercel injects secrets per domain, not with an address policy")
    header = NetworkPolicyTransform(headers={"X-SPS-Secret": value})
    for host in hosts:
        allowed[host] = (NetworkPolicyRule(transform=[header]),)
    return NetworkPolicy.custom(allow=allowed, subnets=subnets)


def _gone(name: str, *, mounted: bool) -> bool:
    """A destroyed sandbox answers 404 at once but keeps its drives attached for a while;
    until they are released no other sandbox can mount them."""
    try:
        get_sandbox(name=name)
    except SandboxApiError as error:
        if not _missing(error):
            raise
        return not mounted or all(drive.current_sandbox_name != name for drive in query_drives())
    return False


def _snapshot_gone(identity: str) -> bool:
    try:
        status = str(get_snapshot(snapshot_id=identity).status)
    except SandboxApiError as error:
        if _missing(error):
            return True
        raise
    return status.rsplit(".", 1)[-1].lower() == "deleted"


def _delete_snapshot(identity: str) -> Observation:
    if not _snapshot_gone(identity):
        try:
            get_snapshot(snapshot_id=identity).delete()
        except SandboxApiError as error:
            if not _missing(error):
                raise
    return confirmed_absent(lambda: _snapshot_gone(identity), seconds=60)


# One thin method per native operation keeps mappings independently auditable.
class VercelDriver(Driver):  # pylint: disable=too-many-public-methods
    provider = "vercel"
    sdk_versions = {"vercel-sandbox": version("vercel-sandbox")}
    unsupported = {
        "resize": (
            "Vercel Sandbox SDK does not document resource updates taking effect "
            "in the current session"
        ),
        "ssh.access": "Vercel Sandbox SDK does not expose sandbox SSH access",
        "process.write_stdin": "Vercel Sandbox SDK does not support process standard input",
        "process.close_stdin": "Vercel Sandbox SDK does not support process standard input",
        "terminal.open": "Vercel Sandbox SDK has no PTY operation",
        "terminal.write": "Vercel Sandbox SDK has no PTY operation",
        "terminal.output": "Vercel Sandbox SDK has no PTY operation",
        "lifetime.observe_paused_countdown": (
            "Vercel SDK exposes no remaining lifetime; each session gets its own time limit"
        ),
        "terminal.disconnect": "Vercel Sandbox SDK has no PTY operation",
        "terminal.reattach": "Vercel Sandbox SDK has no PTY operation",
        "tcp.link": "Vercel previews route HTTP only; the SDK has no raw TCP link",
        "interpreter.context": "Vercel Sandbox SDK has no code interpreter",
        "interpreter.run": "Vercel Sandbox SDK has no code interpreter",
        "desktop.screenshot": "Vercel Sandbox SDK has no desktop operation",
        "desktop.click": "Vercel Sandbox SDK has no desktop operation",
        "desktop.type": "Vercel Sandbox SDK has no desktop operation",
        "desktop.key": "Vercel Sandbox SDK has no desktop operation",
        "desktop.start": "Vercel Sandbox SDK has no desktop operation",
        "desktop.live_link": "Vercel Sandbox SDK has no desktop operation",
        "image.create": "Vercel Sandbox SDK has no image build",
    }

    def create(self, target: object, inputs: Inputs) -> Observation:
        del target
        return self._create(inputs, None)

    def _create(self, inputs: Inputs, source: SnapshotSource | None) -> Observation:
        """One create, fresh or from a snapshot: every gate is chosen here, at creation."""
        options = self._options(inputs)
        name = native_name(16)
        holder: Reserved[SyncSandbox] = Reserved(name)
        mounted = bool(options.get("mounts"))
        owned = self.own("sandbox", holder, lambda: self._delete(name, mounted=mounted))
        deadline = time.monotonic() + CONCURRENCY_WAIT_SECONDS
        while True:
            try:
                holder.native = create_sandbox(name=name, source=source, **options)
                return {"resource": owned, "identity": name}
            except SandboxApiError as error:
                _within_quota(error)
                if error.code == "drive_attached":
                    # Another sandbox holds the drive read-write.
                    raise NativeFailure("volume_in_use") from None
                # The team's concurrency limit refused the create, so nothing exists yet:
                # wait for a slot rather than report the account's load as a result.
                if error.status_code != 429 or time.monotonic() >= deadline:
                    raise
                time.sleep(15)

    @staticmethod
    def _options(inputs: Inputs) -> dict[str, Any]:
        ending = inputs.get("at_end", "destroyed")
        if ending not in {"destroyed", "stopped"}:
            raise Unsupported("Vercel's session limit stops a sandbox; it never leaves it paused")
        requirements = cast(Mapping[str, Mapping[str, Any]], inputs.get("requirements", {}))
        custom_images = requirements.get("custom_images", {})
        if inputs.get("build_context") or custom_images.get("build_context"):
            raise Unsupported(
                "Vercel Sandbox SDK does not build images from a Dockerfile or context"
            )
        if "join" in inputs or "private_network" in requirements:
            raise Unsupported(
                "Vercel Secure Compute network IDs do not provide sandbox-to-sandbox "
                "private networking"
            )
        if "nested_virtualization" in inputs or "nested_virtualization" in requirements:
            raise Unsupported("Vercel Sandbox SDK has no nested virtualization setting")
        if "live_resize" in requirements:
            raise Unsupported(
                "Vercel Sandbox SDK does not document resource updates taking effect "
                "in the current session"
            )
        if "ssh" in requirements:
            raise Unsupported("Vercel Sandbox SDK does not expose sandbox SSH access")
        # A persistent sandbox keeps its files when its session ends (`stopped`) and is the
        # only kind Vercel can stop and resume; a non-persistent one is removed.
        options: dict[str, Any] = {
            "env": strings(inputs, "environment"),
            "execution_time_limit": number(inputs, "lifetime_seconds", 120),
            "persistent": ending == "stopped" or "pause_resume" in requirements,
        }
        for gate, settings in requirements.items():
            if gate == "network_lockdown":
                # With hidden_secrets, that gate composes the lockdown into its policy.
                if "hidden_secrets" not in requirements:
                    options["network_policy"] = _policy(settings)
            elif gate == "previews":
                if settings.get("access", "public") != "public":
                    raise Unsupported("Vercel previews are public URLs with no credential")
                options["ports"] = list(cast(list[int], settings["ports"]))
            elif gate == "idle_shutdown":
                raise Unsupported("Vercel sandboxes do not stop when idle")
            elif gate == "hidden_secrets":
                if settings.get("injection", "sets_header") != "sets_header":
                    raise Unsupported(
                        "Vercel adds configured headers; it replaces no placeholder a request sends"
                    )
                secret = cast(SecretValue, resource(inputs["secret"]).native)
                secret.lockdown = requirements.get("network_lockdown")
                options["network_policy"] = _with_secret(
                    secret.value, cast(list[str], settings["inject_into"]), secret.lockdown
                )
            # processes and terminal need no native setting; a missing operation
            # (standard input, a PTY) is reported where the test uses it.
            # These need no native setting at creation; what the SDK lacks is reported by
            # the operation that uses it (a TCP link, an interpreter).
            elif gate not in NO_CREATION_SETTING | {
                "pause_resume",
                "snapshots",
                "volumes",
                "custom_images",
                "interpreter",
            }:
                raise NotRun("gate_mapping_unavailable")
        resources = cast(Mapping[str, object], inputs.get("resources", {}))
        if "disk_min_mib" in resources:
            raise Unsupported("Vercel Sandbox SDK has no disk size selector")
        if set(resources) - {"cpu_min", "memory_min_mib", "long_running"}:
            raise NotRun("resource_mapping_unavailable")
        if "cpu_min" in resources or "memory_min_mib" in resources:
            options["resources"] = SandboxResources(
                vcpus=cast(int | None, resources.get("cpu_min")),
                memory=cast(int | None, resources.get("memory_min_mib")),
            )
        # `long_running` needs no option: Vercel keeps a session running until its time limit.
        if "image" in inputs:
            options["image"] = cast(str, resource(inputs["image"]).native)
        if "volumes" in inputs:
            options["mounts"] = {
                cast(str, mount["path"]): DriveMount(
                    cast(SyncDrive, resource(mount["volume"]).native).name,
                    mode="snapshot" if mount.get("read_only") else "read-write",
                )
                for mount in cast(list[Mapping[str, object]], inputs["volumes"])
            }
        return options

    def sweep_stale(self, ttl_seconds: float) -> list[str]:
        swept: list[str] = []
        for native in query_sandboxes():
            if stale(native.name, ttl_seconds):
                self._delete(native.name, mounted=True)
                swept.append(f"sandbox:{native.name}")
        for drive in query_drives():
            if stale(drive.name, ttl_seconds):
                self._delete_drive(drive.name)
                swept.append(f"volume:{drive.name}")
        return swept

    @staticmethod
    def _delete(name: str, *, mounted: bool = False) -> Observation:
        # A persistent sandbox leaves an automatic snapshot each time it stops, and
        # destroying the sandbox keeps it and stops listing it; read them first so each
        # one is confirmed gone.
        left = [snapshot.id for snapshot in query_snapshots(name=name)]
        try:
            get_sandbox(name=name).destroy(delete_orphan_snapshots=True)
        except SandboxApiError as error:
            if not _missing(error):
                raise
        confirmed_absent(lambda: _gone(name, mounted=mounted), seconds=120)
        for identity in left:
            _delete_snapshot(identity)
        return {"result": "deleted"}

    def get(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        try:
            native = get_sandbox(name=reserved(target).name)
        except SandboxApiError as error:
            if _missing(error):
                return {"state": "destroyed"}
            raise
        status = str(getattr(native.status, "value", native.status))
        if status == "stopped" and not native.persistent:
            # Vercel discards a non-persistent sandbox's filesystem when it stops and keeps
            # only the record, which cannot be resumed.
            return {"state": "destroyed"}
        return {"state": STATES.get(status, status)}

    def list(self, target: object, inputs: Inputs) -> Observation:
        del target, inputs
        return {"sandboxes": [{"identity": native.name} for native in query_sandboxes()]}

    def destroy(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        return self.release(resource(target))

    def run(self, target: object, inputs: Inputs) -> Observation:
        # kill_after is Vercel's own deadline: it sends SIGKILL and reports the exit status,
        # which is not a distinct timeout result.
        if inputs.get("run_as") is not None:
            raise Unsupported("Vercel's SDK has no named-user command option")
        script = text(inputs, "bash_script")
        result = box(target).run_process(
            "bash",
            ["-c", script],
            cwd=cast(str | None, inputs.get("cwd")),
            env=strings(inputs, "environment"),
            kill_after=_kill_after(inputs),
            capture_output=True,
        )
        return {"stdout": result.stdout, "stderr": result.stderr, "exit_code": result.returncode}

    def secret_create(self, target: object, inputs: Inputs) -> Observation:
        # Vercel keeps no secret object: the value exists only in the network policy of the
        # sandbox that names it, and ends with that sandbox.
        del target
        owned = self.own(
            "secret_value",
            SecretValue(text(inputs, "value")),
            lambda: {"result": "already_released"},
        )
        return {"resource": owned}

    def secret_rotate(self, target: object, inputs: Inputs) -> Observation:
        """The running sandbox's network policy is replaced with the new value in place."""
        secret = cast(SecretValue, resource(target).native)
        secret.value = text(inputs, "value")
        box(inputs["sandbox"]).update_network_policy(
            _with_secret(secret.value, cast(list[str], inputs["hosts"]), secret.lockdown)
        )
        return {}

    def run_as_root(self, target: object, inputs: Inputs) -> Observation:
        result = box(target).run_process(
            "bash",
            ["-c", text(inputs, "bash_script")],
            cwd=cast(str | None, inputs.get("cwd")),
            env=strings(inputs, "environment"),
            sudo=True,
            kill_after=_kill_after(inputs),
            capture_output=True,
        )
        return {"stdout": result.stdout, "stderr": result.stderr, "exit_code": result.returncode}

    def network_update(self, target: object, inputs: Inputs) -> Observation:
        box(target).update_network_policy(_policy(inputs))
        return {}

    def files_read_bytes(self, target: object, inputs: Inputs) -> Observation:
        return {"data": box(target).fs.read_bytes(text(inputs, "path"))}

    def files_write(self, target: object, inputs: Inputs) -> Observation:
        if inputs.get("user") is not None:
            raise Unsupported("Vercel's SDK has no named-user file write option")
        data = base64.b64decode(text(inputs, "data"), validate=True)
        box(target).fs.write_bytes(text(inputs, "path"), data)
        return {}

    def files_exists(self, target: object, inputs: Inputs) -> Observation:
        return {"exists": box(target).fs.exists(text(inputs, "path"))}

    def files_list(self, target: object, inputs: Inputs) -> Observation:
        entries = box(target).fs.listdir(text(inputs, "path"))
        return {"names": sorted(PurePosixPath(entry.path).name for entry in entries)}

    def files_mkdir(self, target: object, inputs: Inputs) -> Observation:
        box(target).fs.mkdir(text(inputs, "path"))
        return {}

    def files_remove(self, target: object, inputs: Inputs) -> Observation:
        box(target).fs.remove(text(inputs, "path"), recursive=bool(inputs.get("recursive", False)))
        return {}

    def process_start(self, target: object, inputs: Inputs) -> Observation:
        if inputs.get("run_as") is not None:
            raise Unsupported("Vercel's SDK has no named-user process option")
        script = text(inputs, "bash_script")
        native = box(target).create_process("bash", ["-c", script])
        owned = self.own("process", native, lambda: self._kill(native))
        return {"resource": owned, "identity": native.id}

    @staticmethod
    def _kill(native: SyncProcess) -> Observation:
        if native.refresh().returncode is None:
            try:
                native.kill()
            except SandboxApiError as error:
                # A refresh can still show no exit code after the command ended; Vercel then
                # answers that it has exited, or that its session stopped, ending it.
                if error.code not in {"command_not_found_or_exited", "sandbox_stopped"}:
                    raise
        return {"result": "deleted"}

    def process_output(self, target: object, inputs: Inputs) -> Observation:
        native = process(target)
        if inputs.get("first_chunk") is True and native.stdout is not None:
            # The SDK's log reader yields a line without waiting for the process to end.
            return {"stdout": native.stdout.readline()}
        stdout, stderr = native.communicate()
        return {"stdout": stdout or "", "stderr": stderr or ""}

    def process_status(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        code = process(target).refresh().returncode
        return {"state": "running" if code is None else "exited", "exit_code": code}

    def process_wait(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        return {"exit_code": process(target).wait()}

    def process_cancel(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        process(target).kill()
        return {}

    def process_disconnect(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        self._close_readers(process(target))
        return {}

    @staticmethod
    def _close_readers(native: SyncProcess) -> Observation:
        for reader in (native.stdout, native.stderr):
            if reader is not None:
                reader.close()
        return {"result": "deleted"}

    def process_reattach(self, target: object, inputs: Inputs) -> Observation:
        identity = inputs["identity"]
        if not isinstance(identity, str):
            raise ValueError("Vercel process identity must be text")
        native = box(target).get_process(identity)
        owned = self.own("observer", native, lambda: self._close_readers(native))
        return {"resource": owned}

    def pause(self, target: object, inputs: Inputs) -> Observation:
        if inputs.get("keeps", "files_only") != "files_only":
            raise Unsupported("Vercel stops a sandbox keeping its files, not its processes")
        native = box(target)
        if not native.persistent:
            # Only a persistent sandbox survives a stop, and persistence is chosen at creation
            # by requesting pause_resume; stopping this one would remove it.
            raise NotRun("pause_resume_not_requested")
        native.stop()
        return {}

    def resume(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        holder = reserved(target)
        holder.native = resume_sandbox(name=holder.name)
        return cast(Observation, target)

    def snapshot_take(self, target: object, inputs: Inputs) -> Observation:
        if inputs.get("keeps", "files_only") != "files_only":
            raise Unsupported("Vercel snapshots keep files only")
        try:
            # Vercel's shortest expiration; the test's cleanup deletes it sooner.
            native = box(target).snapshot(expiration=timedelta(days=1))
        except SandboxApiError as error:
            _within_quota(error)
            raise
        owned = self.own("snapshot", native, lambda: _delete_snapshot(native.id))
        return {"resource": owned}

    def snapshot_delete(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        return self.release(resource(target))

    def snapshot_delete_again(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        try:
            cast(SyncSnapshot, resource(target).native).delete()
        except SandboxApiError as error:
            if not _missing(error):
                raise
        return {"native_delete_attempted": True}

    def snapshot_retention(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        native = cast(SyncSnapshot, resource(target).native)
        if native.expires_at is None:
            return {"retention_seconds": "unlimited"}
        # Both are epoch milliseconds.
        return {"retention_seconds": (native.expires_at - native.created_at) // 1000}

    def snapshot_restore(self, target: object, inputs: Inputs) -> Observation:
        snapshot = cast(SyncSnapshot, resource(target).native)
        return self._create(inputs, SnapshotSource(snapshot_id=snapshot.id))

    def snapshot_original_after(self, target: object, inputs: Inputs) -> Observation:
        del target, inputs
        raise NotRun("snapshot_freeze_transition_unobservable")

    def preview_link(self, target: object, inputs: Inputs) -> Observation:
        if inputs.get("access", "public") != "public":
            raise Unsupported("Vercel previews are public URLs with no credential")
        port = number(inputs, "port", 3000)
        native = box(target)
        if not any(route.port == port and not route.system for route in native.routes):
            # A port not given at creation: the SDK's update exposes it on the running sandbox.
            native.update(ports=[*(r.port for r in native.routes if not r.system), port])
        for route in native.routes:
            if route.port == port and not route.system:
                return {"url": route.url, "headers": {}}
        raise NotRun("observation_unmapped")

    def preview_revoke(self, target: object, inputs: Inputs) -> Observation:
        del target, inputs
        raise Unsupported("Vercel SDK cannot revoke one preview URL")

    def lifetime_extend(self, target: object, inputs: Inputs) -> Observation:
        box(target).extend_execution_time_limit(number(inputs, "lifetime_seconds", 180))
        return {}

    def allocation_observe(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        native = get_sandbox(name=reserved(target).name)
        return {"allocation": {"cpu_min": native.vcpus, "memory_min_mib": native.memory}}

    def long_running_observe(self, target: object, inputs: Inputs) -> Observation:
        del target, inputs
        # A Vercel session has a time limit and no idle setting at all: nothing stops it
        # early for inactivity. The test's wait then observes that it stays active.
        return {"idle_disabled": True}

    def idle_select_duration(self, target: object, inputs: Inputs) -> Observation:
        del target, inputs
        raise Unsupported("Vercel sandboxes do not stop when idle")

    def image_prepare(self, target: object, inputs: Inputs) -> Observation:
        del target
        if inputs.get("source") == "dockerfile" or "context" in inputs:
            raise Unsupported(
                "Vercel Sandbox SDK does not build images from a Dockerfile or context"
            )
        if inputs.get("source") == "private_oci":
            raise Unsupported(
                "Vercel Sandbox SDK accepts image references but has no generic "
                "private registry credentials"
            )
        if "username" in inputs or "password" in inputs:
            raise Unsupported(
                "Vercel Sandbox SDK accepts image references but has no generic "
                "private registry credentials"
            )
        # An existing reference is borrowed, never built or deleted by the test.
        return {"resource": Resource("image_reference", text(inputs, "image"), lambda: {}, True)}

    def volume_create(self, target: object, inputs: Inputs) -> Observation:
        del target
        if inputs.get("kind", "filesystem") != "filesystem":
            raise Unsupported("Vercel drives are block filesystems")
        name = native_name(16)
        owned = self.own("volume", name, lambda: self._delete_drive(name))
        owned.native, _ = get_or_create_drive(name=name)
        return {"resource": owned}

    @staticmethod
    def _delete_drive(name: str) -> Observation:
        def gone() -> bool:
            # Vercel refused to delete a drive right after its sandbox was destroyed and
            # accepted the same call later, so the deletion is retried until it is gone.
            try:
                delete_drive(name=name)
            except SandboxApiError as error:
                if not _missing(error):
                    return False
            return all(drive.name != name for drive in query_drives())

        return confirmed_absent(gone, seconds=120)


def make_driver(*, execution_class: str, fixtures: Mapping[str, object]) -> Driver:
    del fixtures
    if execution_class != "default":
        raise ValueError("Vercel declaration has no execution class")
    return VercelDriver()
