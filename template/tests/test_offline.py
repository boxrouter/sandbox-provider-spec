# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Offline tests for the template adapter.

A small in-memory Example Cloud sits behind `httpx.MockTransport` and answers
the same routes as `fake_cloud/`, so the tests need no Docker daemon.
"""

from __future__ import annotations

import asyncio
import json
import sys
import threading
import uuid
from datetime import UTC, datetime
from importlib import import_module
from importlib.resources import files
from pathlib import Path
from typing import Any

import httpx
import pytest
from sandbox_provider_spec.v1 import (
    CreateRequest,
    ProcessStartRequest,
    RunRequest,
    SpsError,
    to_json,
)

from sps_provider_example import ExampleProvider


def _drain(stream: Any) -> bytes:
    """Consume a request's async body stream from a MockTransport handler, which
    runs inside the caller's event loop and so cannot await it directly."""
    parts: list[bytes] = []

    def take() -> None:
        async def collect() -> None:
            async for part in stream:
                parts.append(part)

        asyncio.run(collect())

    worker = threading.Thread(target=take)
    worker.start()
    worker.join()
    return b"".join(parts)


class FakeCloud:
    """A recorded Example Cloud: the same routes, answered from memory."""

    def __init__(self) -> None:
        self.machines: dict[str, dict[str, Any]] = {}
        self.files: dict[tuple[str, str], bytes] = {}
        self.jobs: dict[str, dict[str, Any]] = {}
        self.posts = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        if not request.headers.get("x-api-key"):
            return self._error(401, "unauthenticated", "an X-Api-Key header is required")
        segments = [s for s in request.url.path.split("/") if s]
        if not segments or segments[0] != "machines":
            return self._error(404, "not_found", "no such route")
        if len(segments) == 1:
            return self._collection(request)
        machine = self.machines.get(segments[1])
        if machine is None:
            return self._error(404, "not_found", f"unknown machine {segments[1]}")
        rest = segments[2:]
        if not rest:
            if request.method == "GET":
                return self._json(200, self._describe(machine))
            if request.method == "DELETE":
                machine["status"] = "ended"
                machine["ended"] = self._now()
                return self._json(200, {"status": "ended"})
        if rest == ["exec"] and request.method == "POST":
            return self._exec(request)
        if rest == ["fs"]:
            return self._fs(request, machine)
        if rest == ["jobs"] and request.method == "POST":
            return self._start_job(request, machine)
        if len(rest) == 3 and rest[0] == "jobs" and rest[2] == "log":
            return self._job_log(rest[1])
        if rest == ["usage"] and request.method == "GET":
            return self._usage(machine)
        return self._error(404, "not_found", "no such route")

    # -- routes ---------------------------------------------------------------

    def _collection(self, request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            self.posts += 1
            body = json.loads(request.content)
            mid = "m-" + uuid.uuid4().hex[:8]
            machine = {
                "machine_id": mid,
                "status": "running",
                "created": self._now(),
                "expires": "2099-01-01T00:00:00Z" if body.get("ttl_seconds") else None,
                "cpu": body.get("cpu", 1),
                "memory_mb": body.get("memory_mb", 512),
                "tags": dict(body.get("tags") or {}),
                "env": dict(body.get("env") or {}),
                "ended": None,
            }
            self.machines[mid] = machine
            return self._json(201, self._describe(machine))
        if request.method == "GET":
            wanted = [tag.split(":", 1) for tag in request.url.params.get_list("tag")]
            found = [
                self._describe(m)
                for m in self.machines.values()
                if m["status"] == "running"
                and all(m["tags"].get(key) == value for key, value in wanted)
            ]
            return self._json(200, {"machines": found, "next_page_token": None})
        return self._error(405, "invalid_request", "method not allowed")

    def _exec(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        cmd = body["cmd"]
        if cmd[:2] == ["python3", "-c"] and "isdir" in cmd[2]:  # the adapter's cwd probe
            return self._json(
                200,
                {"code": 0 if cmd[3] != "/missing" else 1, "out": "", "err": "", "killed": False},
            )
        if cmd == ["echo", "hi"]:
            return self._json(200, {"code": 0, "out": "hi\n", "err": "", "killed": False})
        if cmd == ["sleep", "forever"]:
            return self._json(200, {"code": None, "out": "", "err": "", "killed": True})
        if cmd == ["shout"]:
            return self._json(200, {"code": 2, "out": "", "err": "x" * 40, "killed": False})
        return self._json(200, {"code": 0, "out": "", "err": "", "killed": False})

    def _fs(self, request: httpx.Request, machine: dict[str, Any]) -> httpx.Response:
        path = request.url.params["path"]
        if request.method == "PUT":
            data = _drain(request.stream)
            self.files[(machine["machine_id"], path)] = data
            return self._json(200, {"path": path, "size": len(data)})
        if request.method == "GET":
            key = (machine["machine_id"], path)
            if key not in self.files:
                return self._error(404, "not_found", f"no such file: {path}")
            return httpx.Response(200, content=self.files[key])
        return self._error(405, "invalid_request", "method not allowed")

    def _start_job(self, request: httpx.Request, machine: dict[str, Any]) -> httpx.Response:
        body = json.loads(request.content)
        jid = "j-" + uuid.uuid4().hex[:8]
        self.jobs[jid] = {
            "machine": machine["machine_id"],
            "done": True,
            "code": 0,
            "out": "",
            "err": "",
        }
        if body["cmd"] == ["count"]:
            self.jobs[jid].update({"out": "1\n2\n", "err": "e\n"})
        return self._json(200, {"job_id": jid})

    def _job_log(self, jid: str) -> httpx.Response:
        job = self.jobs.get(jid)
        if job is None:
            return self._error(404, "not_found", f"unknown job {jid}")
        offset = f"{len(job['out'].encode())}.{len(job['err'].encode())}"
        return self._json(
            200,
            {
                "out": job["out"],
                "err": job["err"],
                "offset": offset,
                "done": job["done"],
                "code": job["code"],
            },
        )

    def _usage(self, machine: dict[str, Any]) -> httpx.Response:
        return self._json(
            200,
            {
                "cpu": machine["cpu"],
                "memory_mb": machine["memory_mb"],
                "started": machine["created"],
                "ended": machine["ended"],
            },
        )

    # -- helpers ---------------------------------------------------------------

    def _describe(self, machine: dict[str, Any]) -> dict[str, Any]:
        return {k: machine[k] for k in ("machine_id", "status", "created", "expires")}

    def _now(self) -> str:
        return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")

    def _json(self, status: int, body: dict[str, Any]) -> httpx.Response:
        return httpx.Response(status, json=body)

    def _error(self, status: int, code: str, message: str) -> httpx.Response:
        return httpx.Response(status, json={"error": {"code": code, "message": message}})


def make_provider(cloud: FakeCloud) -> ExampleProvider:
    return ExampleProvider(
        {"api_key": "dev", "endpoint": "http://example.test"},
        transport=httpx.MockTransport(cloud.handler),
    )


def call(provider: ExampleProvider, method: str, *args: Any, **kwargs: Any) -> Any:
    return asyncio.run(getattr(provider, method)(*args, **kwargs))


def test_manifest_loaded() -> None:
    provider = make_provider(FakeCloud())
    assert provider.provider_id == "example"
    assert provider.spec_version == "1.0"
    assert provider.api_domains == ("api.example.test",)
    assert [f.name for f in provider.credential_fields] == ["api_key", "endpoint"]


def test_discovery_validates_against_the_openapi_schema() -> None:
    doc = call(make_provider(FakeCloud()), "discovery")
    data = to_json(doc)  # raises unless it fits the Discovery schema
    assert data["provider"]["id"] == "example"
    assert data["classes"][0]["prices"][0]["basis"] == "allocated"


def test_discovery_uses_identity_from_renamed_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = (
        files("sps_provider_example").joinpath("sps-provider.yaml").read_text(encoding="utf-8")
    )
    assert manifest.count("provider_id: example\n") == 1
    assert manifest.count("name: Example Cloud\n") == 1
    manifest = manifest.replace("provider_id: example\n", "provider_id: example-renamed\n", 1)
    manifest = manifest.replace("name: Example Cloud\n", "name: Renamed Example Cloud\n", 1)

    package_name = f"sps_provider_renamed_{uuid.uuid4().hex}"
    package = tmp_path / package_name
    package.mkdir()
    (package / "__init__.py").write_text(
        "from sps_provider_example import ExampleProvider as _ExampleProvider\n\n"
        "class RenamedProvider(_ExampleProvider):\n"
        "    pass\n",
        encoding="utf-8",
    )
    (package / "sps-provider.yaml").write_text(manifest, encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))

    try:
        renamed_package = import_module(package_name)
        provider = renamed_package.RenamedProvider(
            {"api_key": "dev", "endpoint": "http://example.test"},
            transport=httpx.MockTransport(FakeCloud().handler),
        )
        discovery = call(provider, "discovery")
        assert discovery.provider.id == "example-renamed"
        assert discovery.provider.name == "Renamed Example Cloud"
    finally:
        sys.modules.pop(package_name, None)


def test_create_translates_to_a_machine_and_returns_a_sandbox() -> None:
    cloud = FakeCloud()
    box = call(
        make_provider(cloud),
        "create",
        CreateRequest(lifetime_seconds=120, labels={"team": "x"}, env={"A": "1"}),
        idempotency_key="key-0001",
    )
    assert box.state == "running" and box.sandbox_class == "default"
    assert box.labels == {"team": "x"} and box.size.memory_mib == 512
    spec_tags = next(iter(cloud.machines.values()))["tags"]
    assert spec_tags["sps.idem"] == "key-0001" and spec_tags["l.team"] == "x"


def test_create_picks_the_first_size_that_meets_the_floors() -> None:
    box = call(
        make_provider(FakeCloud()),
        "create",
        CreateRequest(resources={"cpu_min": 2, "memory_min_mib": 1024}),
        idempotency_key="key-0002",
    )
    assert box.size.cpu == 2 and box.size.memory_mib == 2048


def test_idempotent_replay_returns_the_same_sandbox() -> None:
    cloud = FakeCloud()
    provider = make_provider(cloud)
    request = CreateRequest(lifetime_seconds=120)
    first = call(provider, "create", request, idempotency_key="key-0003")
    again = call(provider, "create", request, idempotency_key="key-0003")
    assert again.id == first.id and cloud.posts == 1


def test_same_key_with_a_different_body_is_a_conflict() -> None:
    provider = make_provider(FakeCloud())
    call(provider, "create", CreateRequest(), idempotency_key="key-0004")
    with pytest.raises(SpsError) as error:
        call(provider, "create", CreateRequest(lifetime_seconds=99), idempotency_key="key-0004")
    assert error.value.code == "conflict"


def test_unsupported_requests_are_refused() -> None:
    provider = make_provider(FakeCloud())
    refused = [
        CreateRequest(sandbox_class="microvm"),
        CreateRequest(at_end="paused"),
        CreateRequest(requirements={"pause_resume": {}}),
        CreateRequest(image="node-22"),
        CreateRequest(lifetime_seconds=90001),
        CreateRequest(resources={"region": "far"}),
        CreateRequest(resources={"disk_min_mib": 100}),
    ]
    for request in refused:
        with pytest.raises(SpsError) as error:
            call(provider, "create", request, idempotency_key="key-0005")
        assert error.value.code == "unsupported", request


def test_get_and_list_return_the_create_labels() -> None:
    provider = make_provider(FakeCloud())
    box = call(
        provider,
        "create",
        CreateRequest(labels={"k/slash": "v", "team": "x"}),
        idempotency_key="key-0006",
    )
    assert call(provider, "get", box.id).labels == {"k/slash": "v", "team": "x"}
    page = call(provider, "list", labels={"team": "x"})
    assert [b.id for b in page.sandboxes] == [box.id]
    assert page.sandboxes[0].labels == {"k/slash": "v", "team": "x"}
    page = call(provider, "list", labels={"k/slash": "v"})
    assert [b.id for b in page.sandboxes] == [box.id]
    assert call(provider, "list", labels={"team": "other"}).sandboxes == []


def test_run_maps_the_exec_result() -> None:
    provider = make_provider(FakeCloud())
    box = call(provider, "create", CreateRequest(), idempotency_key="key-0007")
    result = call(provider, "run", box.id, RunRequest(argv=["echo", "hi"]))
    assert result.exit_code == 0 and result.stdout == "hi\n" and not result.timed_out
    timed = call(provider, "run", box.id, RunRequest(argv=["sleep", "forever"]))
    assert timed.timed_out and timed.exit_code is None
    loud = call(provider, "run", box.id, RunRequest(argv=["shout"], output_limit_bytes=10))
    assert loud.stderr_truncated and loud.stderr == "x" * 10


def test_run_with_a_missing_cwd_is_not_found() -> None:
    provider = make_provider(FakeCloud())
    box = call(provider, "create", CreateRequest(), idempotency_key="key-0008")
    with pytest.raises(SpsError) as error:
        call(provider, "run", box.id, RunRequest(argv=["true"], cwd="/missing"))
    assert error.value.code == "not_found"


def test_files_round_trip() -> None:
    async def whole() -> None:
        provider = make_provider(FakeCloud())
        box = await provider.create(CreateRequest(), idempotency_key="key-0009")

        async def one() -> Any:
            yield b"abc"

        info = await provider.files_write(box.id, "/tmp/a.bin", one(), size=3)
        assert info.size == 3
        stream = await provider.files_read(box.id, "/tmp/a.bin")
        assert stream.size == 3
        assert b"".join([part async for part in stream.chunks]) == b"abc"
        await provider.aclose()

    asyncio.run(whole())
    provider = make_provider(FakeCloud())
    box = call(provider, "create", CreateRequest(), idempotency_key="key-0009b")
    with pytest.raises(SpsError) as error:
        call(provider, "files_read", box.id, "/tmp/none")
    assert error.value.code == "not_found"


def test_process_start_and_output() -> None:
    provider = make_provider(FakeCloud())
    box = call(provider, "create", CreateRequest(), idempotency_key="key-0010")
    proc = call(provider, "process_start", box.id, ProcessStartRequest(argv=["count"]))
    page = call(provider, "process_output", box.id, proc.id)
    assert page.state == "exited" and page.exit_code == 0
    assert [(c.stream, c.data) for c in page.chunks] == [("stdout", "1\n2\n"), ("stderr", "e\n")]
    with pytest.raises(SpsError) as error:
        call(provider, "process_output", box.id, "j-none")
    assert error.value.code == "not_found"
    with pytest.raises(SpsError) as error:
        call(provider, "process_start", box.id, ProcessStartRequest(argv=["x"], stdin=True))
    assert error.value.code == "unsupported"


def test_destroy_is_repeatable_and_cost_reaches_final() -> None:
    provider = make_provider(FakeCloud())
    box = call(provider, "create", CreateRequest(), idempotency_key="key-0011")
    result = call(provider, "destroy", box.id)
    assert result.state == "destroyed" and result.cost is None
    again = call(provider, "destroy", box.id)
    assert again.state == "destroyed"
    cost = call(provider, "cost", box.id)
    assert cost.status == "final" and cost.source == "calculated"
    assert {line.item for line in cost.lines} == {"cpu", "memory"}
    assert cost.total_usd == sum(line.amount_usd for line in cost.lines)


def test_error_mapping() -> None:
    provider = make_provider(FakeCloud())
    with pytest.raises(SpsError) as error:
        call(provider, "get", "m-none")
    assert error.value.code == "not_found"

    def html(request: httpx.Request) -> httpx.Response:
        return httpx.Response(502, text="<html>bad gateway</html>")

    provider = ExampleProvider(
        {"api_key": "dev", "endpoint": "http://example.test"},
        transport=httpx.MockTransport(html),
    )
    with pytest.raises(SpsError) as error:
        call(provider, "discovery")
    assert error.value.code == "provider_error" and error.value.outcome == "unknown"


def test_a_missing_key_is_unauthenticated() -> None:
    with pytest.raises(SpsError) as error:
        ExampleProvider({"endpoint": "http://example.test"})
    assert error.value.code == "unauthenticated"
