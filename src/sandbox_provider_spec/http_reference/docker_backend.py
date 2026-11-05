# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Opt-in native Docker proof backend using only owned, labelled containers.

No image pull, host bind mount, privileged container, helper or persistent command
capture file. Buffered execution uses per-stream anonymous capture files, each
bounded to 32 MiB, and reads at most L+1 bytes per stream for output-limit
decisions. The kernel releases files when the runner and inherited descriptors
close. The inline Python adaptation uses only the Python already in the cached
image; it adds no package or uploaded supervisor. Arguments execute only inside
the container. Its network is disabled; the separate proof harness establishes
HTTPS over loopback.
"""

from __future__ import annotations

import base64
import codecs
import io
import json
import os
import re
import tarfile
import time
from collections.abc import Callable
from importlib.metadata import version
from pathlib import PurePosixPath
from threading import Thread
from typing import Any, cast

import docker  # type: ignore[import-untyped]
from docker.errors import DockerException, NotFound  # type: ignore[import-untyped]
from requests.exceptions import RequestException

from sandbox_provider_spec.http_reference.buffered_runner import (
    buffered_runner_argv,
    buffered_runner_frame_limit,
    decode_buffered_runner_result,
)
from sandbox_provider_spec.http_reference.endpoint import Failure, Output


class DockerBackend:
    """Native SDK boundary; Any is limited to Docker's untyped SDK and example injection."""

    kind = "docker-reference-unverified"
    sdks: dict[str, str]

    def __init__(self, image: str, *, owner: str) -> None:
        if re.fullmatch(r"[a-f0-9]{12}", owner) is None:
            raise ValueError("A stable 12-hex-digit local owner namespace is required")
        if not os.environ.get("DOCKER_HOST", "unix:///var/run/docker.sock").startswith("unix://"):
            raise ValueError("This proof only permits a local Docker Unix socket")
        self.client: Any = docker.from_env(timeout=5)
        self.sdks = {"docker": version("docker")}
        self.image = self.client.images.get(image).id  # Cached image only; no registry access.
        self.run_id = owner
        self.authority = owner
        self.threads: list[Thread] = []

    def name(self, identity: dict[str, Any]) -> str:
        return "sps-http-" + self.run_id + "-" + cast(str, identity["sandbox_id"])

    def box(self, identity: dict[str, Any]) -> Any:
        native = self.client.containers.get(self.name(identity))
        if native.labels.get("sps.http.owner") != self.run_id or native.labels.get(
            "sps.http.identity"
        ) != json.dumps(identity, sort_keys=True):
            raise Failure("forbidden")
        return native

    def create(self, identity: dict[str, Any], env: dict[str, str]) -> None:
        native = self.client.containers.create(
            self.image,
            ["sleep", "infinity"],
            name=self.name(identity),
            environment=env,
            labels={
                "sps.http.owner": self.run_id,
                "sps.http.identity": json.dumps(identity, sort_keys=True),
            },
            network_disabled=True,
            mem_limit="128m",
            memswap_limit="128m",
            nano_cpus=500000000,
            pids_limit=32,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
        )
        native.start()
        native.reload()
        if native.status != "running":
            raise Failure("provider_error", "unknown")

    def get(self, identity: dict[str, Any]) -> str:
        try:
            native = self.box(identity)
        except NotFound:
            return "absent"
        return {"running": "active", "exited": "destroyed", "paused": "paused"}.get(
            native.status, "unknown"
        )

    def destroy(self, identity: dict[str, Any]) -> str:
        try:
            self.box(identity).remove(force=True, v=True)
        except NotFound:
            return "absent"
        return "destroyed" if self.get(identity) == "absent" else "accepted"

    def read(self, request: dict[str, Any]) -> bytes:
        chunks, stat = self.box(request["sandbox"]).get_archive(request["path"])
        if stat.get("size", 0) > request["limit_bytes"]:
            raise Failure("limit_exceeded", "completed")
        archive = bytearray()
        try:
            for chunk in chunks:
                archive.extend(chunk)
                if len(archive) > 1048576:
                    raise Failure("limit_exceeded", "completed")
        finally:
            chunks.close()
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:*") as tar:
            members = tar.getmembers()
            if len(members) != 1 or not members[0].isfile():
                raise Failure("provider_error", "failed")
            payload = tar.extractfile(members[0])
            assert payload is not None
            return payload.read(request["limit_bytes"] + 1)

    def write(self, request: dict[str, Any], data: bytes) -> None:
        destination = PurePosixPath(request["path"])
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as archive:
            member = tarfile.TarInfo(destination.name)
            member.size = len(data)
            member.mode = 0o600
            archive.addfile(member, io.BytesIO(data))
        accepted = self.box(request["sandbox"]).put_archive(
            str(destination.parent), stream.getvalue()
        )
        if not accepted:
            raise Failure("provider_error", "unknown")

    def start(
        self, request: dict[str, Any], output: Any
    ) -> tuple[str, Callable[[], tuple[str, int | None]]]:
        native = self.box(request["sandbox"])
        created = self.client.api.exec_create(
            native.id,
            request["argv"],
            environment=request["env"],
            workdir=request["cwd"],
            stdin=False,
            tty=False,
        )
        identity: str = created["Id"]
        stream = self.client.api.exec_start(identity, stream=True, demux=True, tty=False)

        def drain() -> None:
            decoders = {
                name: codecs.getincrementaldecoder("utf-8")("replace")
                for name in ("stdout", "stderr")
            }
            try:
                for pair in stream:
                    for name, data in zip(("stdout", "stderr"), pair, strict=True):
                        if data:
                            output.feed(name, decoders[name].decode(data))
                for name, decoder in decoders.items():
                    output.feed(name, decoder.decode(b"", final=True))
                output.close()
            except (DockerException, RequestException):
                output.close(lost=True)
            finally:
                stream.close()

        thread = Thread(target=drain, daemon=True)
        self.threads.append(thread)
        thread.start()

        def observe() -> tuple[str, int | None]:
            try:
                info = self.client.api.exec_inspect(identity)
            except (DockerException, RequestException):
                return "unknown", None
            if info["Running"]:
                return "running", None
            code = info.get("ExitCode")
            if isinstance(code, int) and not isinstance(code, bool):
                return "exited", code
            return "unknown", None

        return identity, observe

    def run(self, request: dict[str, Any], *, deadline: float) -> dict[str, Any]:
        output = Output(65536, 60)
        _, observe = self.start(request, output)
        cursor, size = 0, 0
        streams: dict[str, list[str]] = {"stdout": [], "stderr": []}
        while time.monotonic() < deadline:
            page = output.page(
                {
                    "cursor": cursor,
                    "max_frames": 100,
                    "limit_bytes": 65536,
                    "observation_timeout_ms": min(
                        20, max(0, int((deadline - time.monotonic()) * 1000))
                    ),
                },
                observe,
                deadline=deadline,
            )
            if page["gap"]:
                raise Failure("output_unavailable", "unknown")
            for frame in page["frames"]:
                size += len(frame["text"].encode())
                if size > 65536:
                    raise Failure(
                        "limit_exceeded",
                        "completed" if page["execution_state"] == "exited" else "unknown",
                    )
                streams[frame["stream"]].append(frame["text"])
            cursor = page["next_cursor"]
            if page["stdout_eof"] and page["stderr_eof"] and page["execution_state"] == "exited":
                return {
                    "stdout": "".join(streams["stdout"]),
                    "stderr": "".join(streams["stderr"]),
                    "exit_code": page["exit_code"],
                    "output_complete": True,
                }
            if not page["frames"]:
                time.sleep(min(0.005, max(0, deadline - time.monotonic())))
        raise Failure("timeout", "unknown")

    def run_buffered(self, request: dict[str, Any], *, execution_limit_ms: int) -> dict[str, Any]:
        """Execute argv natively with exact per-stream capture and an independent timer."""
        native = self.box(request["sandbox"])
        created = self.client.api.exec_create(
            native.id,
            buffered_runner_argv(
                request["argv"],
                execution_limit_ms=execution_limit_ms,
                output_limit_bytes=request["output_limit_bytes"],
            ),
            environment=request["env"],
            workdir=request["cwd"],
            stdin=False,
            tty=False,
        )
        identity: str = created["Id"]
        stream = self.client.api.exec_start(identity, stream=True, demux=True, tty=False)
        framed = bytearray()
        maximum = buffered_runner_frame_limit(request["output_limit_bytes"])
        try:
            for pair in stream:
                if not pair:
                    continue
                stdout_chunk, stderr_chunk = pair
                if stderr_chunk:
                    raise Failure("provider_error", "unknown")
                if stdout_chunk:
                    if len(framed) + len(stdout_chunk) > maximum:
                        raise Failure("provider_error", "unknown")
                    framed.extend(stdout_chunk)
        except (DockerException, RequestException):
            raise Failure("provider_error", "unknown") from None
        finally:
            stream.close()
        try:
            inspected = self.client.api.exec_inspect(identity)
        except (DockerException, RequestException):
            raise Failure("provider_error", "unknown") from None
        if inspected.get("Running") or inspected.get("ExitCode") != 0:
            raise Failure("provider_error", "unknown")
        try:
            result = decode_buffered_runner_result(bytes(framed))
        except ValueError:
            raise Failure("provider_error", "unknown") from None
        if result.state == "terminated":
            raise Failure("timeout", "completed", result.exit_code)
        if result.state == "unknown":
            raise Failure("provider_error", "unknown")
        limit = request["output_limit_bytes"]
        stdout, stderr = result.stdout, result.stderr
        if len(stdout) > limit or len(stderr) > limit:
            raise Failure("provider_error", "unknown")
        return {
            "mode": "buffered_commands_v1",
            "encoding": "base64",
            "stdout_base64": base64.b64encode(stdout).decode("ascii"),
            "stderr_base64": base64.b64encode(stderr).decode("ascii"),
            "stdout_bytes": len(stdout),
            "stderr_bytes": len(stderr),
            "stdout_truncated": result.stdout_truncated,
            "stderr_truncated": result.stderr_truncated,
            "exit_code": result.exit_code,
            "output_complete": True,
        }

    def close(self) -> None:
        # Exact owner labels only; never sweep other SPS/reference resources or images.
        for native in self.client.containers.list(
            all=True, filters={"label": "sps.http.owner=" + self.run_id}
        ):
            if native.labels.get("sps.http.owner") == self.run_id:
                native.remove(force=True, v=True)
        for thread in self.threads:
            thread.join(timeout=6)
        if any(thread.is_alive() for thread in self.threads):
            raise RuntimeError("Owned native output reader did not stop")
        if self.client.containers.list(
            all=True, filters={"label": "sps.http.owner=" + self.run_id}
        ):
            raise RuntimeError("Owned container cleanup was not confirmed")
        self.client.close()
