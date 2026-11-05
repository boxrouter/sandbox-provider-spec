# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""SDK-free tests of the HTTP 0.3 Docker native boundary."""

from __future__ import annotations

import copy
import json
import socket
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

import pytest

from sandbox_provider_spec import http_binding_validation as validation
from sandbox_provider_spec.http_reference import (
    Endpoint,
    EndpointSettings,
    Failure,
    docker_backend,
)
from sandbox_provider_spec.http_reference.docker_backend_03 import DockerBackend03


class Native:
    def __init__(self, name: str, labels: dict[str, str]) -> None:
        self.name = name
        self.labels = labels
        self.id = "native-id-1"
        self.status = "running"
        self.attrs = {"State": {"StartedAt": "2026-10-23T12:00:00.000000000Z"}}
        self.removed = False
        self.file_bytes = b""

    def start(self) -> None:
        return None

    def reload(self) -> None:
        return None

    def remove(self, **_: Any) -> None:
        self.removed = True


class Containers:
    def __init__(self) -> None:
        self.created: dict[str, Any] = {}
        self.options: dict[str, Any] | None = None

    def create(self, image: str, **options: Any) -> Native:
        self.options = {"image": image, **options}
        native = Native(options["name"], options["labels"])
        self.created[options["name"]] = native
        return native

    def get(self, name: str) -> Native:
        return self.created[name]  # type: ignore[no-any-return]


class Client:
    def __init__(self) -> None:
        self.containers = Containers()
        self.api = FakeApi(self)
        self.closed = False

    def close(self) -> None:
        self.closed = True


class ExecStream:
    def __init__(self, api: FakeApi, exec_id: str, payload: bytes) -> None:
        self.api = api
        self.exec_id = exec_id
        self.payload = payload
        self.closed = False

    def __iter__(self) -> Iterator[tuple[bytes | None, bytes | None]]:
        for offset in range(0, len(self.payload), 65536):
            yield self.payload[offset : offset + 65536], None

    def close(self) -> None:
        self.closed = True
        self.api.executions[self.exec_id]["Running"] = False


class InputSocket:
    def __init__(
        self,
        api: FakeApi,
        exec_id: str,
        results: list[Any] | None = None,
    ) -> None:
        self.api = api
        self.exec_id = exec_id
        self.data = bytearray()
        self.results = list(results or [])
        self.closed = False
        self.write_lengths: list[int] = []

    def write(self, data: bytes) -> Any:
        self.api.events.append("write")
        self.write_lengths.append(len(data))
        result = self.results.pop(0) if self.results else len(data)
        if isinstance(result, BaseException):
            raise result
        if isinstance(result, int) and not isinstance(result, bool) and result > 0:
            accepted = min(result, len(data))
            self.data.extend(data[:accepted])
            assert self.api.native is not None
            self.api.native.file_bytes = bytes(self.data)
        return result

    def shutdown(self, how: int) -> None:
        self.api.events.append("half-close")
        assert how == 1  # socket.SHUT_WR
        assert self.api.native is not None
        self.api.native.file_bytes = bytes(self.data)

    def close(self) -> None:
        self.api.events.append("close")
        self.closed = True
        self.api.executions[self.exec_id]["Running"] = False
        if self.api.input_close_error:
            raise OSError("stream close failed")


class FakeApi:
    def __init__(self, client: Client) -> None:
        self.client = client
        self.executions: dict[str, dict[str, Any]] = {}
        self.native: Native | None = None
        self.next_id = 0
        self.events: list[str] = []
        self.input_results: list[Any] | None = None
        self.input_sockets: list[InputSocket] = []
        self.next_write_exit_code = 0
        self.input_close_error = False

    def exec_create(self, container: str, command: list[str], **options: Any) -> dict[str, str]:
        del container
        self.next_id += 1
        exec_id = str(self.next_id)
        self.events.append("exec-create")
        self.executions[exec_id] = {
            "Running": True,
            "ExitCode": self.next_write_exit_code if command[0] == "tee" else 0,
            "command": command,
            "options": options,
        }
        if command[0] == "tee":
            self.next_write_exit_code = 0
        self.native = next(reversed(self.client.containers.created.values()))
        return {"Id": exec_id}

    def exec_start(self, exec_id: str, *, socket: bool = False, **_: Any) -> Any:
        self.events.append("exec-start")
        if socket:
            transport = InputSocket(self, exec_id, self.input_results)
            self.input_sockets.append(transport)
            self.input_results = None
            return transport
        assert self.native is not None
        command = self.executions[exec_id]["command"]
        payload = self.native.file_bytes
        if command[0] == "head":
            payload = payload[: int(command[2])]
        return ExecStream(self, exec_id, payload)

    def exec_inspect(self, exec_id: str) -> dict[str, Any]:
        self.events.append("inspect")
        return self.executions[exec_id]


def backend() -> DockerBackend03:
    instance = DockerBackend03.__new__(DockerBackend03)
    instance.run_id = "0123456789ab"
    instance.authority = instance.run_id
    instance.image = "sha256:immutable"
    instance._image_id = instance.image
    instance.network = "existing-workload-network"
    instance.sdks = {"docker": "7.2.0"}
    instance.client = Client()
    instance.threads = []
    instance._offering = instance._make_offering()
    return instance


def admitted(subject: DockerBackend03, resources: dict[str, Any] | None = None) -> dict[str, Any]:
    discovery = {
        "binding": "sandbox-provider-http/0.3",
        "endpoint_origin": "https://provider.example",
        "provider_id": subject.kind,
        "account_id": "acct",
        "server_revision": "test",
        "operations": list(validation.SCHEMA["x-operations"]),
        "limits": {
            "request_bytes": 32 * 1024 * 1024,
            "response_bytes": 64 * 1024 * 1024,
            "command_output_bytes": 65536,
            "file_bytes": 16 * 1024 * 1024,
            "page_size": 100,
            "output_frames": 100,
            "observation_ms": 5000,
            "process_buffer_bytes": 65536,
            "buffered_command_output_bytes": 16 * 1024 * 1024,
            "execution_ms": 60000,
        },
        "create_key_window_seconds": 86400,
        "process_retention_seconds": 60,
        "process_addressability": "endpoint_lifetime",
        "core_modes": ["buffered_commands_v1"],
        "offerings": subject.offerings("acct"),
    }
    probe = {
        "operation": "create",
        "request_id": "request-1",
        "account_id": "acct",
        "allocation_key": str(int(time.time())) + ":" + "a" * 32,
        "offering_id": "container",
        "declaration_id": subject._offering["declaration_id"],
        "request": {
            "resources": resources or {},
            "lifetime_seconds": 300,
            "at_end": "destroyed",
        },
        "env": {"TASK": "only-container"},
        "labels": {"run": "native-test"},
    }
    validation.validate_discovery(discovery)
    result = validation.validate_new_create_03(probe, discovery)
    result["at_end"] = "destroyed"
    return result


def test_03_create_uses_finite_native_lifetime_and_recovery_keeps_started_at() -> None:
    subject = backend()
    identity = {
        "provider_id": subject.kind,
        "account_id": "acct",
        "offering_id": "container",
        "sandbox_id": "sandbox-1",
        "incarnation": "incarnation-1",
    }
    request: dict[str, Any] = {
        "resources": {"cpu_min": 0.25, "memory_min_mib": 64},
        "gates": {},
    }
    admission = admitted(subject, request["resources"])
    assert admission["resources"]["size"] == {"cpu": 0.5, "memory_mib": 128}
    labels = {"run": "native-test"}
    created = subject.create_admitted(
        identity, request, {"TASK": "only-container"}, labels, admission
    )
    options = subject.client.containers.options
    assert options is not None
    assert options["entrypoint"] == ["sleep"]
    assert options["command"] == ["300"]
    assert options["auto_remove"] is True
    assert options["network"] == "existing-workload-network"
    assert options["environment"] == {"TASK": "only-container"}
    assert options["nano_cpus"] == 500_000_000
    assert options["mem_limit"] == "128m"
    assert options["labels"]["sps.http.public-labels"] == json.dumps(
        labels, separators=(",", ":"), sort_keys=True
    )
    assert set(created["labels"]) == {"run"}
    assert created["lifetime"] == {
        "ready_at": "2026-10-23T12:00:00Z",
        "ends_at": "2026-10-23T12:05:00Z",
    }

    # A new backend object has no clock of its own; it recovers the same native record.
    restarted = backend()
    restarted._offering = copy.deepcopy(subject._offering)
    restarted.client.containers = subject.client.containers
    observed = restarted.observe_admitted(identity)
    assert observed["lifetime"] == created["lifetime"]
    restarted.close()
    assert restarted.client.closed
    assert not subject.client.containers.created[subject.name(identity)].removed


def test_03_refuses_unsupported_lifetime_before_container_create() -> None:
    subject = backend()
    identity = {
        "provider_id": subject.kind,
        "account_id": "acct",
        "offering_id": "container",
        "sandbox_id": "sandbox-1",
        "incarnation": "incarnation-1",
    }
    admission = admitted(subject)
    admission["at_end"] = "paused"
    with pytest.raises(Failure, match="unsupported_mode"):
        subject.create_admitted(identity, {}, {}, {}, admission)
    assert subject.client.containers.options is None


@pytest.mark.parametrize("field", ["account_id", "incarnation"])
def test_03_native_lookup_rejects_wrong_account_or_incarnation(field: str) -> None:
    subject = backend()
    identity = {
        "provider_id": subject.kind,
        "account_id": "acct",
        "offering_id": "container",
        "sandbox_id": "sandbox-auth",
        "incarnation": "incarnation-auth",
    }
    subject.create_admitted(identity, {}, {}, {}, admitted(subject))
    wrong = dict(identity)
    wrong[field] = "different"
    with pytest.raises(Failure, match="forbidden"):
        subject.observe_admitted(wrong)


def test_03_default_principal_exec_transfers_full_limit_and_rejects_limit_plus_one() -> None:
    subject = backend()
    identity = {
        "provider_id": subject.kind,
        "account_id": "acct",
        "offering_id": "container",
        "sandbox_id": "sandbox-file",
        "incarnation": "incarnation-file",
    }
    admission = admitted(subject)
    subject.create_admitted(identity, {"resources": {}, "gates": {}}, {}, {}, admission)
    native = subject.client.containers.created[subject.name(identity)]
    limit = 16 * 1024 * 1024
    native.file_bytes = b"x" * limit
    request = {"sandbox": identity, "path": "/payload", "limit_bytes": limit}
    assert subject.read(request) == native.file_bytes
    native.file_bytes += b"x"
    with pytest.raises(Failure, match="limit_exceeded"):
        subject.read(request)
    write = {"sandbox": identity, "path": "/written", "byte_count": limit}
    payload = b"w" * limit
    subject.write(write, payload)
    assert native.file_bytes == payload
    read_exec = subject.client.api.executions["1"]
    write_exec = subject.client.api.executions["3"]
    assert read_exec["command"] == ["head", "-c", str(limit + 1), "--", "/payload"]
    assert read_exec["options"]["stderr"] is False
    assert read_exec["options"]["tty"] is False
    assert "user" not in read_exec["options"]
    assert write_exec["command"] == ["tee", "/written"]
    assert write_exec["options"]["stdin"] is True
    assert "user" not in write_exec["options"]
    assert subject.client.api.input_sockets[0].closed
    assert subject.client.api.events[-3:] == ["half-close", "close", "inspect"]


def test_03_write_loops_over_positive_partial_progress_then_half_closes_once() -> None:
    subject = backend()
    identity = {
        "provider_id": subject.kind,
        "account_id": "acct",
        "offering_id": "container",
        "sandbox_id": "sandbox-short-write",
        "incarnation": "incarnation-short-write",
    }
    subject.create_admitted(identity, {}, {}, {}, admitted(subject))
    api = subject.client.api
    api.input_results = [2, 2, 1]

    subject.write({"sandbox": identity, "path": "/partial", "byte_count": 5}, b"abcde")

    assert subject.client.containers.created[subject.name(identity)].file_bytes == b"abcde"
    assert api.events.count("write") == 3
    assert api.input_sockets[0].write_lengths == [5, 3, 1]
    assert api.events.count("exec-create") == 1
    assert api.events[-6:] == [
        "write",
        "write",
        "write",
        "half-close",
        "close",
        "inspect",
    ]
    assert api.executions["1"]["ExitCode"] == 0


@pytest.mark.parametrize("bad_progress", [0, None, True, -1, 4])
def test_03_write_rejects_nonprogress_or_invalid_count_as_unknown(
    bad_progress: Any,
) -> None:
    subject = backend()
    identity = {
        "provider_id": subject.kind,
        "account_id": "acct",
        "offering_id": "container",
        "sandbox_id": "sandbox-bad-write",
        "incarnation": "incarnation-bad-write",
    }
    subject.create_admitted(identity, {}, {}, {}, admitted(subject))
    api = subject.client.api
    api.input_results = [bad_progress]

    with pytest.raises(Failure, match="provider_error") as caught:
        subject.write({"sandbox": identity, "path": "/partial", "byte_count": 3}, b"abc")

    assert caught.value.outcome == "unknown"
    assert len(api.input_sockets) == 1
    assert api.input_sockets[0].closed
    assert api.events.count("exec-create") == 1
    assert subject.client.containers.created[subject.name(identity)].file_bytes in (
        b"",
        b"abc",
    )
    assert "half-close" not in api.events
    assert "inspect" not in api.events


def test_03_write_error_after_partial_mutation_is_unknown_and_not_replayed() -> None:
    subject = backend()
    identity = {
        "provider_id": subject.kind,
        "account_id": "acct",
        "offering_id": "container",
        "sandbox_id": "sandbox-write-error",
        "incarnation": "incarnation-write-error",
    }
    subject.create_admitted(identity, {}, {}, {}, admitted(subject))
    api = subject.client.api
    api.input_results = [2, OSError("stream broke")]

    with pytest.raises(Failure, match="provider_error") as caught:
        subject.write({"sandbox": identity, "path": "/partial", "byte_count": 5}, b"abcde")

    assert caught.value.outcome == "unknown"
    assert subject.client.containers.created[subject.name(identity)].file_bytes == b"ab"
    assert len(api.input_sockets) == 1
    assert api.events.count("exec-create") == 1
    assert api.input_sockets[0].closed


def test_03_write_close_error_after_payload_is_unknown() -> None:
    subject = backend()
    identity = {
        "provider_id": subject.kind,
        "account_id": "acct",
        "offering_id": "container",
        "sandbox_id": "sandbox-write-close-error",
        "incarnation": "incarnation-write-close-error",
    }
    subject.create_admitted(identity, {}, {}, {}, admitted(subject))
    api = subject.client.api
    api.input_close_error = True

    with pytest.raises(Failure, match="provider_error") as caught:
        subject.write({"sandbox": identity, "path": "/close-error", "byte_count": 3}, b"abc")

    assert caught.value.outcome == "unknown"
    assert subject.client.containers.created[subject.name(identity)].file_bytes == b"abc"
    assert api.input_sockets[0].closed
    assert "inspect" not in api.events


def test_03_nonzero_tee_exit_after_payload_is_unknown() -> None:
    subject = backend()
    identity = {
        "provider_id": subject.kind,
        "account_id": "acct",
        "offering_id": "container",
        "sandbox_id": "sandbox-tee-exit",
        "incarnation": "incarnation-tee-exit",
    }
    subject.create_admitted(identity, {}, {}, {}, admitted(subject))
    subject.client.api.next_write_exit_code = 1

    with pytest.raises(Failure, match="provider_error") as caught:
        subject.write({"sandbox": identity, "path": "/possibly-partial", "byte_count": 3}, b"abc")

    assert caught.value.outcome == "unknown"
    assert subject.client.containers.created[subject.name(identity)].file_bytes == b"abc"
    assert subject.client.api.events[-3:] == ["half-close", "close", "inspect"]


def test_03_empty_write_still_half_closes_before_inspection() -> None:
    subject = backend()
    identity = {
        "provider_id": subject.kind,
        "account_id": "acct",
        "offering_id": "container",
        "sandbox_id": "sandbox-empty-write",
        "incarnation": "incarnation-empty-write",
    }
    subject.create_admitted(identity, {}, {}, {}, admitted(subject))

    subject.write({"sandbox": identity, "path": "/empty", "byte_count": 0}, b"")

    assert subject.client.api.events[-3:] == ["half-close", "close", "inspect"]


@pytest.mark.parametrize("payload", [b"\x00\xffbinary", b""])
def test_03_pinned_read_mode_docker_socketio_delivers_native_eof(payload: bytes) -> None:
    sender, receiver = socket.socketpair()
    transport = sender.makefile("rb", buffering=0)
    assert isinstance(transport, socket.SocketIO)
    assert not transport.writable()
    receiver.settimeout(1)
    try:
        DockerBackend03._send_exec_input(transport, payload)
        assert sender.gettimeout() == 10
        if payload:
            assert receiver.recv(64) == payload
        assert receiver.recv(1) == b""
    finally:
        receiver.close()
        sender.close()


def test_03_configuration_refuses_mutable_image_and_preserves_image_default_user(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Image:
        id = "sha256:resolved"

        def __init__(self, user: str) -> None:
            self.attrs = {"Config": {"User": user}}

    class Images:
        def __init__(self, user: str) -> None:
            self.image = Image(user)

        def get(self, image: str) -> Image:
            assert image in ("repo/image@sha256:" + "a" * 64, "sha256:resolved")
            return self.image

    class Network:
        attrs = {"Name": "existing-workload-network", "Driver": "bridge", "Internal": False}

    class Networks:
        def get(self, name: str) -> Network:
            assert name == "existing-workload-network"
            return Network()

    class ConfigClient(Client):
        def __init__(self, user: str) -> None:
            super().__init__()
            self.images = Images(user)
            self.networks = Networks()

    client = ConfigClient("worker")
    monkeypatch.setenv("DOCKER_HOST", "unix:///var/run/docker.sock")
    monkeypatch.setattr(cast(Any, docker_backend).docker, "from_env", lambda **_: client)
    monkeypatch.setattr(docker_backend, "version", lambda _: "7.2.0")
    with pytest.raises(ValueError, match="immutable sha256"):
        DockerBackend03("repo/image:latest", "existing-workload-network", owner="0123456789ab")
    configured = DockerBackend03(
        "repo/image@sha256:" + "a" * 64,
        "existing-workload-network",
        owner="0123456789ab",
    )
    assert configured.client is client
    assert not client.closed
    assert not client.containers.created


def test_03_endpoint_bootstrap_independent_of_workload_file_cap(tmp_path: Path) -> None:
    subject = backend()
    endpoint = Endpoint(
        subject,
        tmp_path / "allocations.sqlite",
        {"secret": "acct"},
        settings=EndpointSettings(
            "https://provider.example",
            binding_version="0.3",
            buffered_commands=True,
            buffered_command_output_bytes=16 * 1024 * 1024,
            execution_ms=60000,
        ),
    )
    discovery = endpoint.discovery("acct")
    validation.validate_discovery(discovery)
    assert discovery["limits"]["file_bytes"] == 16 * 1024 * 1024
    assert discovery["limits"]["execution_ms"] == 60000
    request = {
        "operation": "create",
        "request_id": "create-1",
        "account_id": "acct",
        "allocation_key": str(int(time.time())) + ":" + "a" * 32,
        "offering_id": "container",
        "declaration_id": discovery["offerings"][0]["declaration_id"],
        "request": {"lifetime_seconds": 300, "at_end": "destroyed"},
        "env": {"TASK": "only-container"},
        "labels": {"run": "endpoint-test"},
    }
    raw = validation.body_bytes(request)
    created, _ = endpoint.dispatch(request, raw, validation.request_digest(raw))
    assert created["state"] == "ready"
    assert created["labels"] == request["labels"]
    get = {
        "operation": "get",
        "request_id": "get-1",
        "account_id": "acct",
        "sandbox": created["sandbox"],
    }
    get_raw = validation.body_bytes(get)
    observed, _ = endpoint.dispatch(get, get_raw, validation.request_digest(get_raw))
    assert observed["state"] == "active"
    assert observed["lifetime"] == created["lifetime"]
    endpoint.close()
