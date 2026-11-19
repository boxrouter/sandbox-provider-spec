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
import websockets.exceptions
from sandbox_provider_spec.v1 import (
    CreateRequest,
    ProcessStartRequest,
    RunRequest,
    SnapshotRequest,
    SpsError,
    TerminalRequest,
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
        self.images: dict[str, dict[str, Any]] = {}
        self.ttys: list[dict[str, Any]] = []
        self.resizes: list[tuple[str, dict[str, Any]]] = []
        self.posts = 0
        self.image_posts: list[dict[str, Any]] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        if not request.headers.get("x-api-key"):
            return self._error(401, "unauthenticated", "an X-Api-Key header is required")
        segments = [s for s in request.url.path.split("/") if s]
        if segments and segments[0] == "images":
            return self._images(request, segments)
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
        if rest == ["tty"] and request.method == "POST":
            body = json.loads(request.content)
            tty_id = "t-" + uuid.uuid4().hex[:8]
            self.ttys.append({"id": tty_id, "machine": machine["machine_id"], "body": body})
            return self._json(201, {"tty_id": tty_id, "ws": f"{request.url.path}/{tty_id}"})
        if len(rest) == 3 and rest[0] == "tty" and rest[2] == "resize":
            self.resizes.append((rest[1], json.loads(request.content)))
            return self._json(200, {})
        if rest == ["usage"] and request.method == "GET":
            return self._usage(machine)
        if rest == ["images"] and request.method == "POST":
            return self._save(request, machine)
        return self._error(404, "not_found", "no such route")

    # -- routes ---------------------------------------------------------------

    def _save(self, request: httpx.Request, machine: dict[str, Any]) -> httpx.Response:
        if machine["status"] != "running":
            return self._error(404, "not_found", f"unknown machine {machine['machine_id']}")
        body = json.loads(request.content)
        self.image_posts.append(body)
        image = {
            "image_id": "i-" + uuid.uuid4().hex[:8],
            "machine_id": machine["machine_id"],
            "status": "ready",
            "created": self._now(),
            "cpu": machine["cpu"],
            "memory_mb": machine["memory_mb"],
            "size_bytes": 1 << 20,
            "tags": dict(body.get("tags") or {}),
            "deleted": None,
        }
        self.images[image["image_id"]] = image
        return self._json(201, self._image(image))

    def _images(self, request: httpx.Request, segments: list[str]) -> httpx.Response:
        if len(segments) == 1:
            wanted = [tag.split(":", 1) for tag in request.url.params.get_list("tag")]
            machine = request.url.params.get("machine")
            found = [
                self._image(i)
                for i in self.images.values()
                if i["deleted"] is None
                and (machine is None or i["machine_id"] == machine)
                and all(i["tags"].get(key) == value for key, value in wanted)
            ]
            return self._json(200, {"images": found, "next_page_token": None})
        image = self.images.get(segments[1])
        rest = segments[2:]
        if image is None:
            return self._error(404, "not_found", f"unknown image {segments[1]}")
        if not rest and request.method == "DELETE":
            image["deleted"] = image["deleted"] or self._now()
            return self._json(200, {"status": "deleted"})
        if image["deleted"] is not None and rest != ["usage"]:
            return self._error(404, "not_found", f"unknown image {segments[1]}")
        if not rest and request.method == "GET":
            return self._json(200, self._image(image))
        if rest == ["usage"] and request.method == "GET":
            record = {"size_bytes": image["size_bytes"], "from": image["created"]}
            record["until"] = image["deleted"]
            return self._json(
                200,
                {"machine_id": image["machine_id"], "records": [record], "as_of": self._now()},
            )
        return self._error(404, "not_found", "no such route")

    @staticmethod
    def _image(image: dict[str, Any]) -> dict[str, Any]:
        keys = ("image_id", "machine_id", "status", "created", "cpu", "memory_mb")
        return {
            **{k: image[k] for k in keys},
            "size_bytes": image["size_bytes"],
            "tags": image["tags"],
        }

    def _collection(self, request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            self.posts += 1
            body = json.loads(request.content)
            source = self.images.get(body.get("image_id", ""))
            if "image_id" in body and (source is None or source["deleted"] is not None):
                return self._error(404, "not_found", f"unknown image {body['image_id']}")
            mid = "m-" + uuid.uuid4().hex[:8]
            self.created_from = getattr(self, "created_from", []) + [body.get("image_id")]
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


def snapshot_of(
    provider: ExampleProvider, box_id: str, key: str = "snap-0001", **labels: str
) -> Any:
    return call(
        provider,
        "snapshot_create",
        box_id,
        SnapshotRequest(labels=labels),
        idempotency_key=key,
    )


def test_discovery_claims_snapshots_and_prices_them() -> None:
    doc = call(make_provider(FakeCloud()), "discovery")
    data = to_json(doc)
    klass = data["classes"][0]
    assert klass["gates"]["snapshots"] == [
        {"keeps": "files_only", "original_after": "continues", "deletable": True}
    ]
    assert {"item": "snapshot", "unit": "gib_month", "basis": "used"}.items() <= next(
        price for price in klass["prices"] if price["item"] == "snapshot"
    ).items()


def test_snapshot_create_commits_the_machine_without_pausing_it() -> None:
    cloud = FakeCloud()
    provider = make_provider(cloud)
    box = call(provider, "create", CreateRequest(), idempotency_key="key-0020")
    snap = snapshot_of(provider, box.id, team="x", **{"k/slash": "v"})
    assert (snap.state, snap.keeps, snap.sandbox_id, snap.sandbox_class) == (
        "ready",
        "files_only",
        box.id,
        "default",
    )
    assert snap.labels == {"team": "x", "k/slash": "v"}
    assert (snap.size.cpu, snap.size.memory_mib, snap.stored_bytes) == (1, 512, 1 << 20)
    assert snap.expires_at is None
    assert cloud.image_posts[0]["pause"] is False  # `continues`, as discovery declares
    assert call(provider, "snapshot_get", snap.id) == snap


def test_snapshot_create_is_idempotent_and_refuses_another_body() -> None:
    cloud = FakeCloud()
    provider = make_provider(cloud)
    box = call(provider, "create", CreateRequest(), idempotency_key="key-0021")
    first = snapshot_of(provider, box.id, a="1")
    again = snapshot_of(provider, box.id, a="1")
    assert again == first and len(cloud.images) == 1
    with pytest.raises(SpsError) as error:
        snapshot_of(provider, box.id, a="2")
    assert error.value.code == "conflict"


def test_snapshot_create_refuses_keeps_it_cannot_make_and_unknown_sandboxes() -> None:
    provider = make_provider(FakeCloud())
    box = call(provider, "create", CreateRequest(), idempotency_key="key-0022")
    with pytest.raises(SpsError) as error:
        call(
            provider,
            "snapshot_create",
            box.id,
            SnapshotRequest(keeps="files_and_memory"),
            idempotency_key="snap-0002",
        )
    assert error.value.code == "unsupported"
    with pytest.raises(SpsError) as error:
        snapshot_of(provider, "m-none", key="snap-0003")
    assert error.value.code == "not_found"


def test_snapshot_list_filters_by_label_and_sandbox() -> None:
    provider = make_provider(FakeCloud())
    one = call(provider, "create", CreateRequest(), idempotency_key="key-0023")
    two = call(provider, "create", CreateRequest(), idempotency_key="key-0024")
    first = snapshot_of(provider, one.id, key="snap-0004", team="x")
    second = snapshot_of(provider, two.id, key="snap-0005", team="y", **{"k/slash": "v"})
    assert {s.id for s in call(provider, "snapshot_list").snapshots} == {first.id, second.id}
    assert [s.id for s in call(provider, "snapshot_list", labels={"team": "x"}).snapshots] == [
        first.id
    ]
    assert [s.id for s in call(provider, "snapshot_list", sandbox_id=two.id).snapshots] == [
        second.id
    ]
    page = call(provider, "snapshot_list", labels={"k/slash": "v"})
    assert [s.id for s in page.snapshots] == [second.id] and page.next_cursor is None


def test_snapshot_delete_is_repeatable_and_a_restore_is_then_not_found() -> None:
    provider = make_provider(FakeCloud())
    box = call(provider, "create", CreateRequest(), idempotency_key="key-0025")
    snap = snapshot_of(provider, box.id)
    assert call(provider, "snapshot_delete", snap.id).state == "deleted"
    assert call(provider, "snapshot_delete", snap.id).state == "deleted"
    with pytest.raises(SpsError) as error:
        call(provider, "create", CreateRequest(snapshot=snap.id), idempotency_key="key-0026")
    assert error.value.code == "not_found"
    with pytest.raises(SpsError) as error:
        call(provider, "snapshot_get", snap.id)
    assert error.value.code == "not_found"
    with pytest.raises(SpsError) as error:
        call(provider, "snapshot_delete", "i-none")
    assert error.value.code == "not_found"
    assert call(provider, "snapshot_list").snapshots == []


def test_snapshot_restore_creates_a_machine_from_the_image_with_its_own_labels() -> None:
    cloud = FakeCloud()
    provider = make_provider(cloud)
    box = call(
        provider,
        "create",
        CreateRequest(resources={"cpu_min": 2}, labels={"which": "source"}),
        idempotency_key="key-0027",
    )
    snap = snapshot_of(provider, box.id)
    again = call(
        provider,
        "create",
        CreateRequest(snapshot=snap.id, labels={"which": "restored"}, env={"A": "b"}),
        idempotency_key="key-0028",
    )
    assert cloud.created_from[-1] == snap.id
    assert again.id != box.id and again.labels == {"which": "restored"}
    assert (again.size.cpu, again.size.memory_mib) == (2, 2048)  # the snapshot's size
    assert call(provider, "snapshot_get", snap.id) == snap  # a restore changes nothing


def test_snapshot_restore_rules() -> None:
    provider = make_provider(FakeCloud())
    box = call(provider, "create", CreateRequest(), idempotency_key="key-0029")
    snap = snapshot_of(provider, box.id)
    refused = {
        "invalid_request": CreateRequest(snapshot=snap.id, image="base"),
        "unsupported": CreateRequest(snapshot=snap.id, resources={"cpu_min": 2}),
    }
    for code, request in refused.items():
        with pytest.raises(SpsError) as error:
            call(provider, "create", request, idempotency_key="key-0030")
        assert error.value.code == code
    with pytest.raises(SpsError) as error:
        call(provider, "create", CreateRequest(snapshot="i-none"), idempotency_key="key-0031")
    assert error.value.code == "not_found"


def test_snapshot_requirements_are_met_only_by_the_claimed_variant() -> None:
    provider = make_provider(FakeCloud())
    meets = [
        {"snapshots": {"original_after": "any"}},
        {"snapshots": {"original_after": ["continues", "terminated"], "keeps": "files_only"}},
        {"snapshots": {"original_after": "continues", "deletable": True}},
    ]
    for index, requirements in enumerate(meets):
        call(
            provider,
            "create",
            CreateRequest(requirements=requirements),
            idempotency_key=f"key-004{index}",
        )
    refused = [
        {"snapshots": {"original_after": "terminated"}},
        {"snapshots": {"original_after": "any", "keeps": "files_and_memory"}},
        {"snapshots": {"original_after": "any", "deletable": False}},
        {"snapshots": {"original_after": "any", "retention_seconds": 60}},
    ]
    for requirements in refused:
        with pytest.raises(SpsError) as error:
            call(
                provider,
                "create",
                CreateRequest(requirements=requirements),
                idempotency_key="key-0050",
            )
        assert error.value.code == "unsupported", requirements


def test_snapshot_cost_lists_only_snapshot_lines_and_is_final_after_delete() -> None:
    provider = make_provider(FakeCloud())
    box = call(provider, "create", CreateRequest(), idempotency_key="key-0032")
    snap = snapshot_of(provider, box.id)
    live = call(provider, "snapshot_cost", snap.id)
    assert (live.status, live.snapshot_id, live.sandbox_id) == ("accruing", snap.id, box.id)
    assert {line.item for line in live.lines} == {"snapshot"}
    assert {line.unit for line in live.lines} == {"gib_month"}
    call(provider, "snapshot_delete", snap.id)
    done = call(provider, "snapshot_cost", snap.id)
    assert done.status == "final" and done.source == "calculated"
    assert done.total_usd == sum(line.amount_usd for line in done.lines)
    assert to_json(done)["snapshot_id"] == snap.id
    assert call(provider, "cost", box.id).snapshot_id is None  # never in the sandbox's cost


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


class FakeSocket:
    """Example Cloud's terminal WebSocket, as the adapter sees it: binary frames are the
    terminal's bytes, and a text frame says that the program is over."""

    def __init__(self, url: str, headers: Any, frames: list[bytes | str]) -> None:
        self.url, self.headers = url, dict(headers)
        self.sent: list[bytes] = []
        self.closed = False
        self._frames = frames

    async def send(self, data: bytes) -> None:
        if self.closed:
            raise websockets.exceptions.ConnectionClosedOK(None, None)
        self.sent.append(data)

    async def close(self) -> None:
        self.closed = True

    def __aiter__(self) -> Any:
        async def frames() -> Any:
            for frame in self._frames:
                yield frame

        return frames()


def terminal_provider(cloud: FakeCloud, frames: list[bytes | str]) -> tuple[Any, list[FakeSocket]]:
    sockets: list[FakeSocket] = []

    async def connect(url: str, headers: Any) -> FakeSocket:
        sockets.append(FakeSocket(url, headers, frames))
        return sockets[-1]

    provider = ExampleProvider(
        {"api_key": "dev", "endpoint": "http://example.test"},
        transport=httpx.MockTransport(cloud.handler),
        connect=connect,
    )
    return provider, sockets


def test_discovery_claims_a_terminal_that_cannot_be_reattached() -> None:
    doc = call(make_provider(FakeCloud()), "discovery")
    assert to_json(doc)["classes"][0]["gates"]["terminal"] == [{"reattach": False}]


def test_create_accepts_the_terminal_requirement_and_refuses_a_reattachable_one() -> None:
    provider = make_provider(FakeCloud())
    call(
        provider, "create", CreateRequest(requirements={"terminal": {}}), idempotency_key="key-0020"
    )
    with pytest.raises(SpsError) as error:
        call(
            provider,
            "create",
            CreateRequest(requirements={"terminal": {"reattach": True}}),
            idempotency_key="key-0021",
        )
    assert error.value.code == "unsupported"


def test_terminal_open_starts_the_program_and_connects_to_its_websocket() -> None:
    cloud = FakeCloud()
    provider, sockets = terminal_provider(cloud, [b"one", b"two", '{"exit": 7}'])

    async def main() -> None:
        box = await provider.create(CreateRequest(), idempotency_key="key-0022")
        request = TerminalRequest(
            argv=("bash", "-c", "exit 7"),
            cwd="/tmp",
            env={"A": "b"},
            columns=100,
            rows=40,
            term="vt100",
        )
        terminal = await provider.terminal_open(box.id, request)
        assert cloud.ttys[0]["body"] == {
            "cmd": ["bash", "-c", "exit 7"],
            "env": {"A": "b"},
            "cols": 100,
            "rows": 40,
            "term": "vt100",
            "dir": "/tmp",
        }
        assert sockets[0].url == f"ws://example.test/machines/{box.id}/tty/{cloud.ttys[0]['id']}"
        assert sockets[0].headers == {"X-Api-Key": "dev"}
        await terminal.write(b"input")
        await terminal.resize(120, 50)
        assert sockets[0].sent == [b"input"]
        assert cloud.resizes == [(cloud.ttys[0]["id"], {"cols": 120, "rows": 50})]
        assert [chunk async for chunk in terminal.output()] == [b"one", b"two"]
        assert terminal.exit_code == 7
        await terminal.close()
        assert sockets[0].closed
        await terminal.close()
        await provider.aclose()

    asyncio.run(main())


def test_terminal_open_without_a_program_asks_for_the_default_shell() -> None:
    cloud = FakeCloud()
    provider, _ = terminal_provider(cloud, [])

    async def main() -> None:
        box = await provider.create(CreateRequest(), idempotency_key="key-0023")
        await provider.terminal_open(box.id, TerminalRequest())
        await provider.aclose()

    asyncio.run(main())
    assert cloud.ttys[0]["body"]["cmd"] is None and "dir" not in cloud.ttys[0]["body"]


def test_a_program_that_the_sandbox_ended_has_no_exit_code() -> None:
    provider, _ = terminal_provider(FakeCloud(), [b"out", '{"exit": null}'])

    async def main() -> None:
        box = await provider.create(CreateRequest(), idempotency_key="key-0024")
        terminal = await provider.terminal_open(box.id, TerminalRequest())
        assert [chunk async for chunk in terminal.output()] == [b"out"]
        assert terminal.exit_code is None
        await provider.aclose()

    asyncio.run(main())


def test_terminal_open_in_a_missing_directory_is_not_found_and_starts_nothing() -> None:
    cloud = FakeCloud()
    provider, sockets = terminal_provider(cloud, [])
    box = call(provider, "create", CreateRequest(), idempotency_key="key-0025")
    with pytest.raises(SpsError) as error:
        call(provider, "terminal_open", box.id, TerminalRequest(cwd="/missing"))
    assert error.value.code == "not_found"
    assert cloud.ttys == [] and sockets == []


def test_terminal_open_of_an_unknown_machine_is_not_found() -> None:
    provider, _ = terminal_provider(FakeCloud(), [])
    with pytest.raises(SpsError) as error:
        call(provider, "terminal_open", "m-none", TerminalRequest())
    assert error.value.code == "not_found"
