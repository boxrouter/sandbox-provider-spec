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
        # Entries that are not regular files: (machine, path) -> "dir", "link" or "other".
        self.special: dict[tuple[str, str], str] = {}
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
        if rest == ["fs"] and request.url.params.get("op") == "ls":
            return self._ls(request, machine["machine_id"])
        if rest == ["fs"]:
            return self._fs(request, machine)
        if rest == ["fs", "stat"]:
            return self._stat(request, machine["machine_id"])
        if rest == ["fs", "mkdir"]:
            return self._mkdir(request, machine["machine_id"])
        if rest == ["fs", "rm"]:
            return self._rm(request, machine["machine_id"])
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

    # -- directories: an in-memory tree behind the same four calls ---------------

    def _kind(self, mid: str, path: str) -> str | None:
        if (mid, path) in self.files:
            return "file"
        if path == "/" or (mid, path) not in self.special and self._children(mid, path):
            return "dir"  # a path that only has entries below it is a directory
        return self.special.get((mid, path))

    def _children(self, mid: str, path: str) -> list[str]:
        prefix = path.rstrip("/") + "/"
        paths = [p for (m, p) in [*self.files, *self.special] if m == mid]
        names = {p[len(prefix) :].split("/", 1)[0] for p in paths if p.startswith(prefix)}
        return sorted(names, key=str.encode)

    def _ls(self, request: httpx.Request, mid: str) -> httpx.Response:
        path = request.url.params["path"]
        kind = self._kind(mid, path)
        if kind is None:
            return self._error(404, "not_found", "no such directory")
        if kind != "dir":
            return self._error(400, "invalid_request", "not a directory")
        after = request.url.params.get("after")
        limit = int(request.url.params["max"])
        names = [n for n in self._children(mid, path) if after is None or n > after]
        page, rest = names[:limit], names[limit:]
        items = []
        for name in page:
            child = path.rstrip("/") + "/" + name
            kind = self._kind(mid, child) or "dir"
            size = len(self.files[(mid, child)]) if kind == "file" else 4096 if kind == "dir" else 7
            items.append({"name": name, "kind": kind, "bytes": size})
        # The token is the last name itself here; the adapter must treat it as opaque.
        return self._json(200, {"items": items, "after": page[-1] if rest else None})

    def _stat(self, request: httpx.Request, mid: str) -> httpx.Response:
        kind = self._kind(mid, request.url.params["path"])
        return self._json(200, {"found": kind is not None, "kind": kind})

    def _mkdir(self, request: httpx.Request, mid: str) -> httpx.Response:
        body = json.loads(request.content)
        parts = [p for p in body["path"].split("/") if p]
        chain = ["/" + "/".join(parts[:i]) for i in range(1, len(parts) + 1)]
        missing = []
        for item in chain:
            kind = self._kind(mid, item)
            if kind is None:
                missing.append(item)
            elif kind != "dir":
                return self._error(409, "conflict", f"not a directory: {item}")
        if len(missing) > 1 and not body["parents"]:
            return self._error(404, "not_found", "no such parent directory")
        for item in missing:
            self.special[(mid, item)] = "dir"
        return self._json(200, {})

    def _rm(self, request: httpx.Request, mid: str) -> httpx.Response:
        body = json.loads(request.content)
        path = body["path"]
        if path == "/":
            return self._error(400, "invalid_request", "cannot remove /")
        kind = self._kind(mid, path)
        if kind is None:
            return self._error(404, "not_found", "no such path")
        if kind == "dir":
            if self._children(mid, path) and not body["recursive"]:
                return self._error(409, "conflict", "directory is not empty")
            prefix = path.rstrip("/") + "/"
            for table in (self.files, self.special):
                for key in [k for k in table if k[0] == mid and k[1].startswith(prefix)]:
                    del table[key]
        self.files.pop((mid, path), None)
        self.special.pop((mid, path), None)
        return self._json(200, {})

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


def _write(provider: ExampleProvider, box_id: str, path: str, data: bytes) -> None:
    async def body() -> Any:
        yield data

    call(provider, "files_write", box_id, path, body(), size=len(data))


def test_discovery_claims_all_four_directory_operations() -> None:
    doc = call(make_provider(FakeCloud()), "discovery")
    assert tuple(doc.classes[0].operations) == (
        "files.list",
        "files.mkdir",
        "files.remove",
        "files.exists",
    )
    assert to_json(doc)["classes"][0]["operations"] == [
        "files.list",
        "files.mkdir",
        "files.remove",
        "files.exists",
    ]


def test_files_list_types_sizes_and_order() -> None:
    cloud = FakeCloud()
    provider = make_provider(cloud)
    box = call(provider, "create", CreateRequest(), idempotency_key="key-0011")
    call(provider, "files_mkdir", box.id, "/tmp/d/a", parents=True)
    _write(provider, box.id, "/tmp/d/b", b"12345")
    cloud.special[(box.id, "/tmp/d/c")] = "link"
    cloud.special[(box.id, "/tmp/d/e")] = "other"
    page = call(provider, "files_list", box.id, "/tmp/d")
    assert [(e.name, e.type) for e in page.entries] == [
        ("a", "directory"),
        ("b", "file"),
        ("c", "symlink"),
        ("e", "other"),
    ]
    assert next(e for e in page.entries if e.name == "b").size == 5
    assert page.next_cursor is None
    assert to_json(page)["entries"][1] == {"name": "b", "type": "file", "size": 5}


def test_files_list_pages_follow_name_order() -> None:
    provider = make_provider(FakeCloud())
    box = call(provider, "create", CreateRequest(), idempotency_key="key-0012")
    for index in range(7):
        _write(provider, box.id, f"/tmp/p/f{index}", b"x")
    seen: list[str] = []
    cursor: str | None = None
    pages = 0
    while True:
        page = call(provider, "files_list", box.id, "/tmp/p", cursor=cursor, limit=3)
        pages += 1
        assert len(page.entries) <= 3
        seen += [e.name for e in page.entries]
        cursor = page.next_cursor
        if cursor is None:
            break
    assert (pages, seen) == (3, [f"f{i}" for i in range(7)])
    with pytest.raises(SpsError) as error:
        call(provider, "files_list", box.id, "/tmp/p", limit=0)
    assert error.value.code == "invalid_request"


def test_files_list_errors() -> None:
    provider = make_provider(FakeCloud())
    box = call(provider, "create", CreateRequest(), idempotency_key="key-0013")
    _write(provider, box.id, "/tmp/file", b"x")
    for path, code in (("/tmp/missing", "not_found"), ("/tmp/file", "invalid_request")):
        with pytest.raises(SpsError) as error:
            call(provider, "files_list", box.id, path)
        assert error.value.code == code


def test_files_mkdir_rules() -> None:
    provider = make_provider(FakeCloud())
    box = call(provider, "create", CreateRequest(), idempotency_key="key-0014")
    with pytest.raises(SpsError) as error:
        call(provider, "files_mkdir", box.id, "/tmp/m/x/y")
    assert error.value.code == "not_found"
    call(provider, "files_mkdir", box.id, "/tmp/m/x/y", parents=True)
    call(provider, "files_mkdir", box.id, "/tmp/m/x/y", parents=True)  # a repeat succeeds
    call(provider, "files_mkdir", box.id, "/tmp/m/x/y")  # an existing directory succeeds
    assert call(provider, "files_exists", box.id, "/tmp/m/x/y").type == "directory"
    _write(provider, box.id, "/tmp/m/file", b"x")
    for path, parents in (("/tmp/m/file", False), ("/tmp/m/file/sub", True)):
        with pytest.raises(SpsError) as error:
            call(provider, "files_mkdir", box.id, path, parents=parents)
        assert error.value.code == "conflict"


def test_files_remove_rules() -> None:
    provider = make_provider(FakeCloud())
    box = call(provider, "create", CreateRequest(), idempotency_key="key-0015")
    _write(provider, box.id, "/tmp/r/file", b"x")
    _write(provider, box.id, "/tmp/r/dir/inner", b"x")
    call(provider, "files_remove", box.id, "/tmp/r/file")
    assert call(provider, "files_exists", box.id, "/tmp/r/file").exists is False
    with pytest.raises(SpsError) as error:
        call(provider, "files_remove", box.id, "/tmp/r/dir")
    assert error.value.code == "conflict"
    assert call(provider, "files_exists", box.id, "/tmp/r/dir/inner").exists is True
    call(provider, "files_remove", box.id, "/tmp/r/dir", recursive=True)
    assert call(provider, "files_exists", box.id, "/tmp/r/dir").exists is False
    for path, code in (("/tmp/r/none", "not_found"), ("/", "invalid_request")):
        with pytest.raises(SpsError) as error:
            call(provider, "files_remove", box.id, path)
        assert error.value.code == code


def test_files_exists_reports_the_type_and_a_missing_parent() -> None:
    cloud = FakeCloud()
    provider = make_provider(cloud)
    box = call(provider, "create", CreateRequest(), idempotency_key="key-0016")
    _write(provider, box.id, "/tmp/e/file", b"x")
    cloud.special[(box.id, "/tmp/e/dangling")] = "link"
    found = [
        call(provider, "files_exists", box.id, path)
        for path in ("/tmp/e/file", "/tmp/e", "/tmp/e/dangling", "/tmp/e/none", "/no/parent/x")
    ]
    assert [(f.exists, f.type) for f in found] == [
        (True, "file"),
        (True, "directory"),
        (True, "symlink"),
        (False, None),
        (False, None),
    ]
    assert to_json(found[3]) == {"exists": False, "type": None}


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
