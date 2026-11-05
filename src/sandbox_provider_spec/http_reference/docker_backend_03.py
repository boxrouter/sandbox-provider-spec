# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Requestful HTTP 0.3 Docker producer with engine-owned finite lifetime.

This backend is an opt-in source implementation, not a claim of native conformance.
It uses one configured cached image and an existing operator-selected network.
"""

# Keep requestful 0.3 behavior isolated from the legacy backend.
# pylint: disable=duplicate-code

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import time
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from docker.errors import DockerException, NotFound  # type: ignore[import-untyped]
from requests.exceptions import RequestException

from sandbox_provider_spec.http_reference.docker_backend import DockerBackend
from sandbox_provider_spec.http_reference.endpoint import Failure

_OWNER = "sps.http.owner"
_IDENTITY = "sps.http.identity"
_ADMISSION = "sps.http.admission"
_PUBLIC_LABELS = "sps.http.public-labels"
_FILE_LIMIT = 16 * 1024 * 1024
_EXEC_WRITE_TIMEOUT_SECONDS = 10
_CPU_COUNT = 0.5
_MEMORY_MIB = 128
_MAX_LIFETIME_SECONDS = 3600


class DockerBackend03(DockerBackend):
    """The first requestful backend; configured image/network never come from a request."""

    kind = "docker-http-reference-03-unverified"

    def __init__(self, image: str, network: str, *, owner: str) -> None:
        if (
            "@sha256:" not in image
            or re.fullmatch(r"[a-f0-9]{64}", image.rsplit("@sha256:", 1)[-1]) is None
        ):
            raise ValueError("HTTP 0.3 requires an immutable sha256 image reference")
        if not network or network == "host":
            raise ValueError("HTTP 0.3 requires an explicitly selected existing network")
        super().__init__(image, owner=owner)
        self.network = network
        try:
            native_network = self.client.networks.get(network)
        except (DockerException, RequestException) as error:
            self.client.close()
            raise ValueError("Configured network is not available") from error
        if (
            native_network.attrs.get("Name") != network
            or native_network.attrs.get("Driver") != "bridge"
            or native_network.attrs.get("Internal") is not False
        ):
            self.client.close()
            raise ValueError("Configured network identity is ambiguous")
        self._image_id = self.image
        self._offering = self._make_offering()

    def _make_offering(self) -> dict[str, Any]:
        declaration = {
            "spec": "sandbox-provider-spec/0.1",
            "provider": self.kind,
            "class": "container",
            "verified": {"date": datetime.now(UTC).date().isoformat(), "sdks": self.sdks},
            "resources": {
                "sizes": [{"cpu": _CPU_COUNT, "memory_mib": _MEMORY_MIB}],
                "max_lifetime_seconds": _MAX_LIFETIME_SECONDS,
            },
            "lifetime_timer": {
                "enforced_by": "provider",
                "counts_paused_time": False,
                "at_end": ["destroyed"],
                "adjustable": False,
                "step_seconds": 1,
                "counts_from": "ready",
                "min_seconds": 1,
            },
            "gates": {},
            "evidence": {},
        }
        # Bind discovery identity to the configured immutable image and network.
        token = json.dumps(
            {
                "declaration": declaration,
                "binding": "sandbox-provider-http/0.3",
                "image": self._image_id,
                "network": self.network,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return {
            "offering_id": "container",
            "declaration_id": "sha256:" + hashlib.sha256(token).hexdigest(),
            "declaration": declaration,
        }

    def offerings(self, account: str) -> list[dict[str, Any]]:
        del account
        return [json.loads(json.dumps(self._offering))]

    def _box03(self, identity: dict[str, Any]) -> Any:
        native = self.client.containers.get(self.name(identity))
        labels = native.labels or {}
        if labels.get(_OWNER) != self.run_id or labels.get(_IDENTITY) != json.dumps(
            identity, sort_keys=True
        ):
            raise Failure("forbidden")
        return native

    @staticmethod
    def _started(native: Any) -> datetime | None:
        raw = (native.attrs.get("State") or {}).get("StartedAt")
        if not isinstance(raw, str) or raw.startswith("0001-"):
            return None
        try:
            value = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return None
        return value.astimezone(UTC)

    def _observation(self, native: Any, admission: dict[str, Any]) -> dict[str, Any]:
        try:
            native.reload()
        except (DockerException, RequestException) as error:
            raise Failure("provider_error", "unknown") from error
        status = native.status
        state = {"running": "active", "created": "pending"}.get(status, "unknown")
        labels = native.labels or {}
        try:
            public_labels = json.loads(labels[_PUBLIC_LABELS])
            retained = json.loads(labels[_ADMISSION])
        except (KeyError, TypeError, json.JSONDecodeError) as error:
            raise Failure("provider_error", "unknown") from error
        if retained != admission:
            raise Failure("forbidden")
        started = self._started(native)
        duration = admission["lifetime_seconds"]
        lifetime: dict[str, str | None] = {"ready_at": None, "ends_at": None}
        if started is not None:
            lifetime["ready_at"] = started.isoformat().replace("+00:00", "Z")
            if duration is not None:
                ends = started + timedelta(seconds=duration)
                lifetime["ends_at"] = ends.isoformat().replace("+00:00", "Z")
        return {"state": state, "labels": public_labels, "lifetime": lifetime}

    def create_admitted(
        self,
        identity: dict[str, Any],
        request: dict[str, Any],
        env: dict[str, str],
        labels: dict[str, Any],
        admission: dict[str, Any],
    ) -> dict[str, Any]:
        if admission["selection"]["offering"] != self._offering:
            raise Failure("conflict")
        if admission["at_end"] not in (None, "destroyed"):
            raise Failure("unsupported_mode")
        resources = request.get("resources", {})
        cpu = resources.get("cpu_min", _CPU_COUNT)
        memory = resources.get("memory_min_mib", _MEMORY_MIB)
        if cpu > _CPU_COUNT or memory > _MEMORY_MIB:
            raise Failure("unsupported_mode")
        requirements = admission["requirements"]
        if set(requirements) - {"network_lockdown"}:
            raise Failure("unsupported_mode")
        if "network_lockdown" in requirements:
            raise Failure("unsupported_mode")
        duration = admission["lifetime_seconds"]
        if (
            not isinstance(duration, int)
            or isinstance(duration, bool)
            or not 1 <= duration <= _MAX_LIFETIME_SECONDS
        ):
            raise Failure("unsupported_mode")
        # Docker's main process owns expiration, so client/Endpoint close cannot reset it.
        native = self.client.containers.create(
            self._image_id,
            command=[str(duration)],
            entrypoint=["sleep"],
            name=self.name(identity),
            environment=dict(env),
            labels={
                _OWNER: self.run_id,
                _IDENTITY: json.dumps(identity, sort_keys=True),
                _ADMISSION: json.dumps(admission, sort_keys=True, separators=(",", ":")),
                _PUBLIC_LABELS: json.dumps(labels, sort_keys=True, separators=(",", ":")),
            },
            network=self.network,
            auto_remove=True,
            mem_limit=f"{_MEMORY_MIB}m",
            memswap_limit=f"{_MEMORY_MIB}m",
            nano_cpus=500_000_000,
            pids_limit=32,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
        )
        try:
            native.start()
            native.reload()
        except (DockerException, RequestException) as error:
            raise Failure("provider_error", "unknown") from error
        return self._observation(native, admission)

    def observe_admitted(self, identity: dict[str, Any]) -> dict[str, Any]:
        try:
            native = self._box03(identity)
        except NotFound:
            return {
                "state": "absent",
                "labels": {},
                "lifetime": {"ready_at": None, "ends_at": None},
            }
        try:
            admission = json.loads(native.labels[_ADMISSION])
        except (KeyError, TypeError, json.JSONDecodeError) as error:
            raise Failure("provider_error", "unknown") from error
        return self._observation(native, admission)

    def get(self, identity: dict[str, Any]) -> str:
        return cast(str, self.observe_admitted(identity)["state"])

    def destroy(self, identity: dict[str, Any]) -> str:
        try:
            native = self._box03(identity)
        except NotFound:
            return "absent"
        try:
            native.remove(force=True, v=True)
        except NotFound:
            return "absent"
        except (DockerException, RequestException) as error:
            raise Failure("provider_error", "unknown") from error
        return "destroyed"

    def _exec_result(self, exec_id: str) -> dict[str, Any]:
        deadline = time.monotonic() + 1
        while True:
            try:
                result = self.client.api.exec_inspect(exec_id)
            except (DockerException, RequestException) as error:
                raise Failure("provider_error", "unknown") from error
            if not result.get("Running"):
                return cast(dict[str, Any], result)
            if time.monotonic() >= deadline:
                raise Failure("provider_error", "unknown")
            time.sleep(0.01)

    def read(self, request: dict[str, Any]) -> bytes:
        limit = request["limit_bytes"]
        if not isinstance(limit, int) or isinstance(limit, bool) or not 0 <= limit <= _FILE_LIMIT:
            raise Failure("limit_exceeded", "not_dispatched")
        try:
            native = self._box03(request["sandbox"])
            created = self.client.api.exec_create(
                native.id,
                ["head", "-c", str(limit + 1), "--", request["path"]],
                stdin=False,
                stdout=True,
                stderr=False,
                tty=False,
            )
            exec_id = created["Id"]
            stream = self.client.api.exec_start(exec_id, stream=True, demux=True, tty=False)
        except (DockerException, RequestException) as error:
            raise Failure("provider_error", "unknown") from error
        data = bytearray()
        overflow = False
        try:
            for pair in stream:
                if pair is None:
                    continue
                stdout, stderr = pair
                if stderr:
                    raise Failure("provider_error", "unknown")
                if stdout:
                    remaining = limit + 1 - len(data)
                    data.extend(stdout[:remaining])
                    if len(data) > limit:
                        overflow = True
                        break
        except (DockerException, RequestException) as error:
            raise Failure("provider_error", "unknown") from error
        finally:
            stream.close()
        inspected = self._exec_result(exec_id)
        if overflow:
            raise Failure("limit_exceeded", "completed")
        if inspected.get("ExitCode") != 0:
            raise Failure("provider_error", "failed")
        return bytes(data)

    @staticmethod
    def _send_exec_input(transport: Any, data: bytes) -> None:
        """Send all bytes, half-close native stdin, then close the Docker stream."""
        write_socket: socket.socket | None = None
        if isinstance(transport, socket.SocketIO):
            candidate = getattr(transport, "_sock", None)
            if isinstance(candidate, socket.socket):
                write_socket = candidate
        elif isinstance(transport, socket.socket):
            write_socket = transport
        try:
            if write_socket is not None:
                write_socket.settimeout(_EXEC_WRITE_TIMEOUT_SECONDS)
            offset = 0
            while offset < len(data):
                # Docker SDK 7.2 exposes its raw response socket as a read-mode
                # SocketIO wrapper. Write through the validated underlying socket
                # so partial progress remains observable without calling write()
                # on that read-only wrapper.
                writer = write_socket.send if write_socket is not None else None
                if writer is None:
                    writer = getattr(transport, "send", None)
                if not callable(writer):
                    writer = getattr(transport, "write", None)
                if not callable(writer):
                    raise OSError("Exec stdin transport has no byte writer")
                remaining = data[offset:]
                written = writer(remaining)
                if (
                    isinstance(written, bool)
                    or not isinstance(written, int)
                    or written <= 0
                    or written > len(remaining)
                ):
                    raise OSError("Exec stdin transport made invalid write progress")
                offset += written
            if write_socket is not None:
                write_socket.shutdown(socket.SHUT_WR)
            else:
                flush = getattr(transport, "flush", None)
                if callable(flush):
                    flush()
                shutdown = getattr(transport, "shutdown", None)
                if callable(shutdown):
                    shutdown(socket.SHUT_WR)
                else:
                    raise OSError("Exec stdin transport cannot half-close its write side")
        except Exception as error:
            raise Failure("provider_error", "unknown") from error
        finally:
            try:
                transport.close()
            except Exception as error:
                raise Failure("provider_error", "unknown") from error

    def write(self, request: dict[str, Any], data: bytes) -> None:
        if len(data) > _FILE_LIMIT or len(data) != request["byte_count"]:
            raise Failure("limit_exceeded", "not_dispatched")
        try:
            native = self._box03(request["sandbox"])
            created = self.client.api.exec_create(
                native.id,
                ["tee", request["path"]],
                stdin=True,
                stdout=False,
                stderr=False,
                tty=False,
            )
            exec_id = created["Id"]
            transport = self.client.api.exec_start(exec_id, socket=True, tty=False)
        except (DockerException, RequestException) as error:
            raise Failure("provider_error", "unknown") from error
        self._send_exec_input(transport, data)
        inspected = self._exec_result(exec_id)
        if inspected.get("ExitCode") != 0:
            # tee may have modified a prefix before reporting a write failure.
            raise Failure("provider_error", "unknown")

    def close(self) -> None:
        # Native `sleep` plus auto_remove owns lifetime; close only this local transport.
        for thread in self.threads:
            thread.join(timeout=6)
        if any(thread.is_alive() for thread in self.threads):
            raise RuntimeError("Owned native output reader did not stop")
        self.client.close()


def backend_from_environment() -> DockerBackend03:
    """Starter factory for an operator's immutable image, bridge network and stable owner."""
    image = os.environ.get("SPS_HTTP_DOCKER_IMAGE")
    network = os.environ.get("SPS_HTTP_DOCKER_NETWORK")
    owner = os.environ.get("SPS_HTTP_DOCKER_OWNER")
    if not image or not network or not owner:
        raise RuntimeError(
            "Configure SPS_HTTP_DOCKER_IMAGE, SPS_HTTP_DOCKER_NETWORK, and SPS_HTTP_DOCKER_OWNER"
        )
    return DockerBackend03(image, network, owner=owner)
