# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Native Docker Engine SDK operations; no guest filesystem/process helpers."""

from __future__ import annotations

import base64
import io
import socket
import tarfile
import time
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from importlib.metadata import version
from pathlib import PurePosixPath
from threading import Event, Timer
from typing import Any, Literal, cast

# Docker's SDK ships no type stubs. Any stays at this native SDK boundary.
import docker  # type: ignore[import-untyped]
from docker.errors import APIError, NotFound  # type: ignore[import-untyped]
from docker.utils.socket import demux_adaptor, frames_iter  # type: ignore[import-untyped]

from sandbox_provider_spec.driver import (
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
    number,
    resource,
    strings,
    text,
)
from sandbox_provider_spec.run_id import native_name, stale


def box(target: object) -> Any:
    return resource(target).native


@dataclass
class Exec:
    identity: str
    parent: Any
    socket: Any
    stream: Iterator[tuple[bytes | None, bytes | None]]
    tty: bool = False


def command(target: object) -> Exec:
    return cast(Exec, resource(target).native)


class DockerDriver(ImageSnapshotDriver):  # pylint: disable=too-many-public-methods
    provider = "docker-engine"
    sdk_versions = {"docker": version("docker")}
    unobservable = UNOBSERVABLE_METADATA
    unsupported = {
        "files.remove": "Docker's filesystem API has no native file removal operation",
        "process.cancel": "Docker's exec API has no individual exec cancellation operation",
        "process.reattach": "Docker's exec API cannot attach a new reader to a running exec",
        "lifetime.extend": "Docker Engine has no native container lifetime timer",
        "secret.create": "Standalone Docker Engine has no hidden HTTP credential injection",
        "idle.select_duration": "Docker Engine has no native idle shutdown timer",
        "ssh.access": "Docker Engine has no SSH access operation; exec is not SSH",
    }
    # Gates a request may name that Docker Engine has no native setting or operation for.
    unsupported_gates = {
        "egress_proxy": "Docker Engine has no native egress proxy",
        "workload_identity": "Docker Engine issues no workload identity token",
        "ssh": "Docker Engine has no SSH access operation; exec is not SSH",
        "nested_virtualization": "Docker Engine has no native nested virtualization option",
    }
    # Policies the native network API cannot express: it joins or leaves networks and
    # has no domain or CIDR filter.
    unsupported_policy = "Docker Engine has no native domain or CIDR egress filter"
    cpu_period = 100_000

    def __init__(self, fixtures: Mapping[str, object]) -> None:
        super().__init__()
        self.fixtures = fixtures
        self._client: Any = None
        self._suite_pulled_images: set[str] = set()
        self._suite_image_pull_failures: set[str] = set()

    @property
    def client(self) -> Any:
        # Defer API negotiation so an unavailable daemon is an error in the report,
        # with no allocated resources, rather than a credential-bearing traceback.
        if self._client is None:
            self._client = docker.from_env(timeout=30)
        return self._client

    def sweep_stale(self, ttl_seconds: float) -> list[str]:
        swept: list[str] = []
        for container in self.client.containers.list(all=True):
            if stale(container.name, ttl_seconds):
                self._delete_container(container.name)
                swept.append(f"sandbox:{container.name}")
        for network in self.client.networks.list():
            if stale(network.name, ttl_seconds):
                self._delete_network(network.name)
                swept.append(f"network:{network.name}")
        return swept

    def _delete_container(self, name: str) -> Observation:
        try:
            self.client.containers.get(name).remove(force=True, v=True)
        except NotFound:
            pass
        try:
            self.client.containers.get(name)
        except NotFound:
            return {"result": "deleted"}
        raise NativeFailure("cleanup_not_confirmed")

    def _delete_image(self, name: str) -> Observation:
        try:
            image = self.client.images.get(name)
        except NotFound:
            return {"result": "deleted"}
        identity = image.id
        self.client.images.remove(identity, force=False)
        try:
            self.client.images.get(identity)
        except NotFound:
            return {"result": "deleted"}
        raise NativeFailure("cleanup_not_confirmed")

    def _image(self, reference: str, auth: Mapping[str, str] | None = None) -> Any:
        if auth is None and reference in self._suite_image_pull_failures:
            raise NotRun("suite_image_pull_failed")
        try:
            image = self.client.images.get(reference)
            if auth is None:
                return image
        except NotFound:
            if auth is None:
                # A suite commonly creates many short-lived containers from the same
                # default image. Keep its one pull cached until all tests finish; deleting
                # it after each test turns a full run into repeated registry pulls and can
                # hit anonymous pull limits before the suite completes.
                self._suite_pulled_images.add(reference)
            else:
                self.own("pulled_image", reference, lambda: self._delete_image(reference))
        # Supplied registry credentials are only exercised by a pull, so a local copy
        # never serves that request.
        try:
            return self.client.images.pull(
                reference, **({"auth_config": dict(auth)} if auth else {})
            )
        except Exception:
            if auth is None:
                self._suite_image_pull_failures.add(reference)
            raise

    def finish(self) -> list[Observation]:
        cleanups: list[Observation] = []
        for reference in sorted(self._suite_pulled_images, reverse=True):
            try:
                cleanups.append({"kind": "pulled_image", **self._delete_image(reference)})
            except Exception as error:  # pylint: disable=broad-exception-caught
                cleanups.append(
                    {"kind": "pulled_image", "result": "error", "reason": type(error).__name__}
                )
        self._suite_pulled_images.clear()
        self._suite_image_pull_failures.clear()
        return cleanups

    def _network_options(self, settings: Mapping[str, object], options: dict[str, object]) -> None:
        policy = settings["policy"]
        if policy == "deny_all":
            options["network_disabled"] = True
        elif policy != "open":
            raise Unsupported(self.unsupported_policy)
        # Leaving every network is the only live change, and it also cuts open
        # connections, so a switchable request needs no creation option.
        if any(target != "deny_all" for target in cast(list[str], settings.get("switches_to", []))):
            raise Unsupported(self.unsupported_policy)

    def _private_network(
        self, settings: Mapping[str, object], join: object, options: dict[str, object]
    ) -> str:
        # network_disabled drops every interface, so members cannot reach one another.
        # Attaching the named network instead would leave outbound connections open.
        if options.get("network_disabled"):
            raise Unsupported(
                "Docker Engine cannot combine a private network with network lockdown deny_all"
            )
        if join is not None:
            joined = cast(str | None, box(join).labels.get("sps.network"))
            if joined is None:
                raise ValueError("join target has no private network")
            options["network"] = joined
            return joined
        name = native_name()
        self.own("network", name, lambda: self._delete_network(name))
        self.client.networks.create(
            name,
            driver="bridge",
            enable_ipv6=settings.get("ip_version") == "ipv6",
            labels={"sps.run": name},
        )
        options["network"] = name
        return name

    def _delete_network(self, name: str) -> Observation:
        try:
            self.client.networks.get(name).remove()
        except NotFound:
            return {"result": "deleted"}
        try:
            self.client.networks.get(name)
        except NotFound:
            return {"result": "deleted"}
        raise NativeFailure("cleanup_not_confirmed")

    def _limits(self, resources: Mapping[str, object]) -> dict[str, object]:
        """Native cgroup limits for the requested size; Docker's limits are ceilings."""
        limits: dict[str, object] = {}
        if "cpu_min" in resources:
            limits["cpu_period"] = self.cpu_period
            limits["cpu_quota"] = int(cast(float, resources["cpu_min"]) * self.cpu_period)
        if "memory_min_mib" in resources:
            memory = f"{resources['memory_min_mib']}m"
            limits["mem_limit"] = memory
            limits["memswap_limit"] = memory
        return limits

    def create(self, target: object, inputs: Inputs) -> Observation:
        del target
        if "lifetime_seconds" in inputs or inputs.get("at_end", "destroyed") != "destroyed":
            raise Unsupported("Docker Engine has no native container lifetime timer")
        options: dict[str, object] = {}
        requirements = inputs.get("requirements", {})
        if not isinstance(requirements, Mapping):
            raise ValueError("requirements must be a mapping")
        private: Mapping[str, object] | None = None
        for gate, settings in requirements.items():
            if not isinstance(settings, Mapping):
                raise ValueError("gate configuration must be a mapping")
            if gate in self.unsupported_gates:
                raise Unsupported(self.unsupported_gates[gate])
            if gate == "idle_shutdown":
                raise Unsupported("Docker Engine has no native idle shutdown timer")
            if gate == "network_lockdown":
                self._network_options(settings, options)
            elif gate == "private_network":
                private = settings
            elif gate == "previews":
                raise Unsupported("Docker Engine port publishing is not a hosted preview link")
            elif gate == "hidden_secrets":
                raise Unsupported("Docker Engine has no hidden HTTP credential injection")
            elif gate not in OPERATION_GATES | {"live_resize"}:
                raise NotRun("gate_mapping_unavailable")
        resources = inputs.get("resources", {})
        if not isinstance(resources, Mapping):
            raise ValueError("resources must be a mapping")
        if any(k not in {"long_running", "cpu_min", "memory_min_mib"} for k in resources):
            raise NotRun("resource_mapping_unavailable")
        options.update(self._limits(resources))
        if "volumes" in inputs:
            options["volumes"] = {
                cast(str, resource(m["volume"]).native): {
                    "bind": m["path"],
                    "mode": "ro" if m.get("read_only") else "rw",
                }
                for m in cast(list[dict[str, object]], inputs["volumes"])
            }
        reference = (
            cast(str, resource(inputs["image"]).native)
            if "image" in inputs
            else cast(str, self.fixtures.get("docker_image", "python:3.12-slim"))
        )
        image = self._image(reference)
        labels = {}
        if private is not None:
            labels["sps.network"] = self._private_network(private, inputs.get("join"), options)
        name = native_name()
        owned = self.own("sandbox", name, lambda: self._delete_container(name))
        native = self.client.containers.create(
            image.id,
            command=["sleep", "infinity"],
            name=name,
            environment=strings(inputs, "environment"),
            labels={"sps.run": name, **labels},
            **options,
        )
        owned.native = native
        native.start()
        return {"resource": owned, "identity": native.id}

    def allocation_observe(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        native = box(target)
        native.reload()
        host = native.attrs["HostConfig"]
        allocation: dict[str, object] = {}
        if host["CpuQuota"] > 0:
            allocation["cpu_min"] = host["CpuQuota"] / (host["CpuPeriod"] or self.cpu_period)
        if host["Memory"] > 0:
            allocation["memory_min_mib"] = host["Memory"] // (1024 * 1024)
        if not allocation:
            raise NotRun("native_allocation_not_limited")
        return {"allocation": allocation}

    def resize(self, target: object, inputs: Inputs) -> Observation:
        resources = inputs["resources"]
        if not isinstance(resources, Mapping):
            raise ValueError("resources must be a mapping")
        limits = self._limits(resources)
        if not limits:
            raise NotRun("resource_mapping_unavailable")
        box(target).update(**limits)
        return {}

    def network_update(self, target: object, inputs: Inputs) -> Observation:
        if inputs["policy"] != "deny_all":
            raise Unsupported(self.unsupported_policy)
        native = box(target)
        native.reload()
        for name in native.attrs["NetworkSettings"]["Networks"]:
            self.client.networks.get(name).disconnect(native, force=True)
        return {}

    def get(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        native = box(target)
        try:
            native.reload()
        except NotFound:
            return {"state": "destroyed"}
        state = cast(str, native.status)
        return {"state": {"running": "active", "exited": "stopped"}.get(state, state)}

    def list(self, target: object, inputs: Inputs) -> Observation:
        del target, inputs
        return {"sandboxes": [{"identity": n.id} for n in self.client.containers.list(all=True)]}

    def destroy(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        return self.release(resource(target))

    def run(self, target: object, inputs: Inputs, *, user: str = "") -> Observation:
        if "timeout_ms" in inputs:
            raise Unsupported("Docker exec has no native guest command deadline")
        result = box(target).exec_run(
            ["bash", "-c", text(inputs, "bash_script")],
            environment=strings(inputs, "environment"),
            workdir=inputs.get("cwd"),
            user=user,
            demux=True,
        )
        stdout, stderr = result.output
        return {"stdout": stdout or b"", "stderr": stderr or b"", "exit_code": result.exit_code}

    def run_as_root(self, target: object, inputs: Inputs) -> Observation:
        return self.run(target, inputs, user="root")

    @staticmethod
    def _archive(native: Any, path: str) -> tuple[tarfile.TarFile, Mapping[str, object]]:
        chunks, stat = native.get_archive(path)
        # The caller owns this archive and closes it, including on assertions.
        return tarfile.open(  # pylint: disable=consider-using-with
            fileobj=io.BytesIO(b"".join(chunks)), mode="r:*"
        ), cast(Mapping[str, object], stat)

    def files_read_bytes(self, target: object, inputs: Inputs) -> Observation:
        archive, _ = self._archive(box(target), text(inputs, "path"))
        with archive:
            member = archive.getmembers()[0]
            payload = archive.extractfile(member)
            if payload is None:
                raise NativeFailure("not_a_file")
            return {"data": payload.read()}

    def files_exists(self, target: object, inputs: Inputs) -> Observation:
        try:
            archive, _ = self._archive(box(target), text(inputs, "path"))
            archive.close()
        except NotFound:
            return {"exists": False}
        return {"exists": True}

    def files_list(self, target: object, inputs: Inputs) -> Observation:
        archive, _ = self._archive(box(target), text(inputs, "path"))
        with archive:
            root = archive.getmembers()[0].name.rstrip("/")
            return {
                "names": sorted(
                    m.name[len(root) + 1 :]
                    for m in archive.getmembers()
                    if m.name.startswith(root + "/")
                    and "/" not in m.name[len(root) + 1 :].rstrip("/")
                )
            }

    @staticmethod
    def _put(native: Any, path: str, data: bytes | None) -> Observation:
        destination = PurePosixPath(path)
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as archive:
            item = tarfile.TarInfo(destination.name)
            item.mode = 0o755 if data is None else 0o644
            if data is None:
                item.type = tarfile.DIRTYPE
                archive.addfile(item)
            else:
                item.size = len(data)
                archive.addfile(item, io.BytesIO(data))
        try:
            accepted = native.put_archive(str(destination.parent), stream.getvalue())
        except APIError as error:
            # This public native condition is classified; raw messages stay private.
            if "read-only file system" in str(error):
                raise NativeFailure("read_only") from None
            raise
        if not accepted:
            raise NativeFailure("archive_not_accepted")
        return {}

    def files_write(self, target: object, inputs: Inputs) -> Observation:
        return self._put(
            box(target), text(inputs, "path"), base64.b64decode(text(inputs, "data"), validate=True)
        )

    def files_mkdir(self, target: object, inputs: Inputs) -> Observation:
        return self._put(box(target), text(inputs, "path"), None)

    def _exec(self, target: object, inputs: Inputs, *, tty: bool) -> Observation:
        parent = box(target)
        created = self.client.api.exec_create(
            parent.id,
            ["bash"] if tty else ["bash", "-c", text(inputs, "bash_script")],
            stdin=True,
            tty=tty,
        )
        identity = cast(str, created["Id"])
        owned = self.own(
            "terminal" if tty else "process", identity, lambda: self._delete_container(parent.id)
        )
        transport = self.client.api.exec_start(identity, socket=True, tty=tty)
        stream = cast(Iterator[tuple[int, bytes]], frames_iter(transport, tty))
        chunks = (
            (data, None)
            if tty
            else cast(
                tuple[bytes | None, bytes | None],
                demux_adaptor(cast(Literal[1, 2], stream_id), data),
            )
            for stream_id, data in stream
        )
        native = Exec(identity, parent, transport, chunks, tty)
        owned.native = native
        owned.cleanup = lambda: self._delete_exec(native)
        if tty:
            self.client.api.exec_resize(
                identity, height=number(inputs, "rows", 24), width=number(inputs, "columns", 80)
            )
        return {"resource": owned, "identity": identity}

    def _delete_exec(self, native: Exec) -> Observation:
        native.socket.close()
        return self._delete_container(native.parent.id)

    def process_start(self, target: object, inputs: Inputs) -> Observation:
        return self._exec(target, inputs, tty=False)

    def process_write_stdin(self, target: object, inputs: Inputs) -> Observation:
        transport = command(target).socket
        write = getattr(transport, "write", None) or getattr(transport, "send", None)
        if not callable(write):
            raise NotRun("native_transport_write_unmapped")
        data = memoryview(base64.b64decode(text(inputs, "data"), validate=True))
        while data:
            sent = write(bytes(data))
            if not isinstance(sent, int) or sent <= 0:
                raise NativeFailure("stdin_write_incomplete")
            data = data[sent:]
        return {}

    def process_close_stdin(self, target: object, inputs: Inputs) -> Observation:
        del target, inputs
        raise Unsupported("Docker SDK exec socket has no portable stdin-only EOF operation")

    def process_output(self, target: object, inputs: Inputs) -> Observation:
        stdout: list[bytes] = []
        stderr: list[bytes] = []
        native = command(target)
        expired = Event()

        def abort_read() -> None:
            expired.set()
            transport = getattr(native.socket, "_sock", native.socket)
            try:
                transport.shutdown(socket.SHUT_RDWR)
            except (OSError, AttributeError):
                transport.close()

        # SDK frames_iter polls with no deadline before recv. Shut down that native
        # transport to wake the poll; this is a client observation bound, not a timer
        # or cancellation capability in Docker Engine.
        timer = Timer(number(inputs, "timeout_ms", 15000) / 1000, abort_read)
        timer.daemon = True
        timer.start()
        try:
            for out, err in native.stream:
                if out is not None:
                    stdout.append(out)
                if err is not None:
                    stderr.append(err)
                if inputs.get("first_chunk") is True:
                    break
        except (OSError, ValueError):
            if not expired.is_set():
                raise
        finally:
            timer.cancel()
        if expired.is_set():
            raise NotRun("native_stream_observation_timed_out")
        return {"stdout": b"".join(stdout), "stderr": b"".join(stderr)}

    def process_status(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        status = self.client.api.exec_inspect(command(target).identity)
        return {
            "state": "running" if status["Running"] else "exited",
            "exit_code": None if status["Running"] else status["ExitCode"],
        }

    def process_wait(self, target: object, inputs: Inputs) -> Observation:
        deadline = time.monotonic() + number(inputs, "timeout_ms", 15000) / 1000
        while True:
            result = self.client.api.exec_inspect(command(target).identity)
            if not result["Running"]:
                return {"exit_code": result["ExitCode"]}
            if time.monotonic() >= deadline:
                raise NotRun("native_process_still_running")
            time.sleep(0.1)

    def process_disconnect(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        command(target).socket.close()
        return {}

    def terminal_open(self, target: object, inputs: Inputs) -> Observation:
        return self._exec(target, inputs, tty=True)

    terminal_write = process_write_stdin

    def terminal_output(self, target: object, inputs: Inputs) -> Observation:
        return {"terminal": self.process_output(target, inputs)["stdout"]}

    def pause(self, target: object, inputs: Inputs) -> Observation:
        if inputs.get("keeps") == "files_only":
            box(target).stop(timeout=10)
        else:
            box(target).pause()
        return {}

    def resume(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        native = box(target)
        native.reload()
        if native.status == "paused":
            native.unpause()
        else:
            native.start()
        return cast(Observation, target)

    def snapshot_take(self, target: object, inputs: Inputs) -> Observation:
        if inputs.get("keeps", "files_only") != "files_only":
            raise Unsupported("Docker commit captures files, not process memory")
        name = native_name()
        owned = self.own("snapshot_image", name, lambda: self._delete_image(name))
        box(target).commit(repository=name, pause=True, changes=f"LABEL sps.run={name}")
        return {"resource": owned}

    def snapshot_original_after(self, target: object, inputs: Inputs) -> Observation:
        del target, inputs
        raise NotRun("snapshot_freeze_transition_unobservable")

    def snapshot_delete_again(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        try:
            self.client.images.remove(resource(target).native, force=False)
        except NotFound:
            pass
        return {"native_delete_attempted": True}

    def volume_create(self, target: object, inputs: Inputs) -> Observation:
        del target
        if inputs.get("kind") == "object_store":
            raise Unsupported("Docker's local volume driver does not expose an object-store kind")
        name = native_name()
        owned = self.own("volume", name, lambda: self._delete_volume(name))
        self.client.volumes.create(name=name, driver="local", labels={"sps.run": name})
        return {"resource": owned}

    def _delete_volume(self, name: str) -> Observation:
        try:
            self.client.volumes.get(name).remove(force=False)
        except NotFound:
            pass
        try:
            self.client.volumes.get(name)
        except NotFound:
            return {"result": "deleted"}
        raise NativeFailure("cleanup_not_confirmed")

    def image_prepare(self, target: object, inputs: Inputs) -> Observation:
        del target
        source = text(inputs, "source")
        if source == "provider_artifact":
            name = text(inputs, "image")
            self.client.images.get(name)
            return {"resource": Resource("image_reference", name, lambda: {}, released=True)}
        if source in {"oci", "private_oci"}:
            name = text(inputs, "image")
            auth = (
                {"username": text(inputs, "username"), "password": text(inputs, "password")}
                if source == "private_oci"
                else None
            )
            self._image(name, auth)
            return {"resource": Resource("image_reference", name, lambda: {}, released=True)}
        if source != "dockerfile":
            raise ValueError("unknown image source")
        if self.fixtures.get("docker_engine_exclusive_daemon") is not True:
            raise NotRun("exclusive_daemon_required_for_build_cleanup")
        previous = {image.id for image in self.client.images.list(all=True)}
        # Native legacy builds can allocate unnamed intermediate and base images.
        # Inventory differences are attributable only on an explicitly exclusive
        # daemon; never prune or infer ownership on a shared daemon.
        self.own("build_images", previous, lambda: self._delete_build_images(previous))
        name = native_name()
        owned = self.own("image", name, lambda: self._delete_image(name))
        context = inputs.get("context")
        if context is None:
            build: dict[str, object] = {"fileobj": io.BytesIO(text(inputs, "dockerfile").encode())}
        else:
            build = {
                "fileobj": self._context(text(inputs, "dockerfile"), context),
                "custom_context": True,
            }
        self.client.images.build(**build, tag=name, rm=True, forcerm=True, labels={"sps.run": name})
        return {"resource": owned}

    @staticmethod
    def _context(dockerfile: str, files: object) -> io.BytesIO:
        """A tar build context of the Dockerfile and the supplied files."""
        if not isinstance(files, Mapping):
            raise ValueError("context must map file names to contents")
        stream = io.BytesIO()
        # A context file named Dockerfile is omitted so it cannot replace this input.
        entries: dict[object, object] = {"Dockerfile": dockerfile}
        entries.update(
            (path, content)
            for path, content in files.items()
            if PurePosixPath(str(path)) != PurePosixPath("Dockerfile")
        )
        with tarfile.open(fileobj=stream, mode="w") as archive:
            for path, content in entries.items():
                data = content if isinstance(content, bytes) else str(content).encode()
                item = tarfile.TarInfo(str(path))
                item.size = len(data)
                item.mode = 0o644
                archive.addfile(item, io.BytesIO(data))
        stream.seek(0)
        return stream

    def _delete_build_images(self, previous: set[str]) -> Observation:
        while True:
            remaining = [
                image for image in self.client.images.list(all=True) if image.id not in previous
            ]
            if not remaining:
                return {"result": "deleted"}
            progress = False
            preserved = False
            for image in remaining:
                tags = getattr(image, "tags", [])
                if tags:
                    # Dockerfile builds may pull a tagged base image that was absent
                    # before this test. Reuse it through the rest of the suite, then
                    # remove it with the other suite-owned pulls in finish().
                    self._suite_pulled_images.add(str(tags[0]))
                    preserved = True
                    continue
                try:
                    self._delete_image(image.id)
                    progress = True
                except APIError:
                    # Parents remain in use until their child image is deleted.
                    continue
            if not progress:
                if preserved:
                    return {"result": "deleted"}
                raise NativeFailure("cleanup_not_confirmed")


def make_driver(*, execution_class: str, fixtures: Mapping[str, object]) -> Driver:
    if execution_class != "default":
        raise ValueError("Docker Engine has one declaration with no class")
    return DockerDriver(fixtures)
