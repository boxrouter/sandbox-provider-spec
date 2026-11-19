# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Black-box tests for Example Cloud over its HTTP API."""

from __future__ import annotations

import hashlib
import os
import subprocess
import time
import urllib.parse
from typing import Any

import pytest
from conftest import call, call_json

pytestmark = [pytest.mark.loopback, pytest.mark.integration]


def test_api_key_required(server: Any) -> None:
    status, _ = call(server.port, "POST", "/machines", key=None, body={})
    assert status == 401
    status, _ = call(server.port, "GET", "/machines", key=None)
    assert status == 401
    status, _ = call(server.port, "GET", "/healthz", key=None)
    assert status == 200


def test_create_get_list_delete(server: Any) -> None:
    status, created = call_json(
        server.port,
        "POST",
        "/machines",
        body={
            "cpu": 1,
            "memory_mb": 256,
            "ttl_seconds": 600,
            "env": {"GREETING": "hi"},
            "tags": {"suite": "c3", "color": "blue"},
        },
    )
    assert status == 201, created
    assert sorted(created) == ["created", "expires", "machine_id", "status"]
    assert created["status"] == "running"
    machine_id = created["machine_id"]

    status, got = call_json(server.port, "GET", f"/machines/{machine_id}")
    assert status == 200
    assert got == created

    status, page = call_json(
        server.port,
        "GET",
        "/machines?" + urllib.parse.urlencode({"tag": "suite:c3"}),
    )
    assert status == 200
    assert machine_id in {item["machine_id"] for item in page["machines"]}

    status, page = call_json(
        server.port,
        "GET",
        "/machines?" + urllib.parse.urlencode({"tag": "suite:other"}),
    )
    assert machine_id not in {item["machine_id"] for item in page["machines"]}

    status, deleted = call_json(server.port, "DELETE", f"/machines/{machine_id}")
    assert status == 200
    assert deleted == {"status": "ended"}

    status, got = call_json(server.port, "GET", f"/machines/{machine_id}")
    assert status == 200
    assert got["status"] == "ended"

    status, deleted = call_json(server.port, "DELETE", f"/machines/{machine_id}")
    assert status == 200
    assert deleted == {"status": "ended"}

    status, page = call_json(server.port, "GET", "/machines")
    assert machine_id not in {item["machine_id"] for item in page["machines"]}


def test_exec(server: Any, machine: str) -> None:
    status, result = call_json(
        server.port,
        "POST",
        f"/machines/{machine}/exec",
        body={"cmd": ["bash", "-c", "echo hello; echo oops >&2; exit 3"]},
    )
    assert status == 200, result
    assert result["code"] == 3
    assert result["out"] == "hello\n"
    assert result["err"] == "oops\n"
    assert result["killed"] is False

    status, result = call_json(
        server.port,
        "POST",
        f"/machines/{machine}/exec",
        body={
            "cmd": ["bash", "-c", "pwd; echo $MARK"],
            "dir": "/tmp",
            "env": {"MARK": "set"},
        },
    )
    assert result["out"] == "/tmp\nset\n"


def test_exec_timeout_kills(server: Any, machine: str) -> None:
    status, result = call_json(
        server.port,
        "POST",
        f"/machines/{machine}/exec",
        body={"cmd": ["sleep", "60"], "timeout_s": 0.5},
    )
    assert status == 200, result
    assert result["killed"] is True
    assert result["code"] is None


def test_files_roundtrip(server: Any, machine: str) -> None:
    payload = os.urandom(4 * 1024 * 1024)
    status, _ = call(server.port, "PUT", f"/machines/{machine}/fs?path=/tmp/blob", raw=payload)
    assert status == 200
    status, data = call(server.port, "GET", f"/machines/{machine}/fs?path=/tmp/blob")
    assert status == 200
    assert hashlib.sha256(data).hexdigest() == hashlib.sha256(payload).hexdigest()

    status, _ = call(server.port, "GET", f"/machines/{machine}/fs?path=/tmp/nope")
    assert status == 404


def _sh(server: Any, machine: str, script: str) -> None:
    status, result = call_json(
        server.port, "POST", f"/machines/{machine}/exec", body={"cmd": ["bash", "-c", script]}
    )
    assert status == 200 and result["code"] == 0, result


def _fs_get(server: Any, machine: str, route: str, **params: Any) -> tuple[int, Any]:
    return call_json(
        server.port, "GET", f"/machines/{machine}/fs{route}?" + urllib.parse.urlencode(params)
    )


def test_fs_ls_kinds_sizes_and_order(server: Any, machine: str) -> None:
    _sh(
        server,
        machine,
        "mkdir -p /tmp/sps-d/a && printf 12345 > /tmp/sps-d/b"
        " && ln -s /nonexistent /tmp/sps-d/c && mkfifo /tmp/sps-d/d",
    )
    status, page = _fs_get(server, machine, "", op="ls", path="/tmp/sps-d")
    assert status == 200, page
    assert [(i["name"], i["kind"]) for i in page["items"]] == [
        ("a", "dir"),
        ("b", "file"),
        ("c", "link"),
        ("d", "other"),
    ]
    assert page["items"][1]["bytes"] == 5
    assert page["after"] is None

    status, page = _fs_get(server, machine, "", op="ls", path="/tmp/sps-d", max=3)
    assert [i["name"] for i in page["items"]] == ["a", "b", "c"]
    status, rest = _fs_get(server, machine, "", op="ls", path="/tmp/sps-d", after=page["after"])
    assert [i["name"] for i in rest["items"]] == ["d"]
    assert rest["after"] is None

    assert _fs_get(server, machine, "", op="ls", path="/tmp/sps-none")[0] == 404
    assert _fs_get(server, machine, "", op="ls", path="/tmp/sps-d/b")[0] == 400


def test_fs_stat_does_not_follow_the_last_link(server: Any, machine: str) -> None:
    _sh(
        server,
        machine,
        "mkdir -p /tmp/sps-s && touch /tmp/sps-s/f && ln -s /nonexistent /tmp/sps-s/l",
    )
    got = [
        _fs_get(server, machine, "/stat", path=path)[1]
        for path in (
            "/tmp/sps-s/f",
            "/tmp/sps-s",
            "/tmp/sps-s/l",
            "/tmp/sps-s/no",
            "/tmp/sps-s/f/x",
        )
    ]
    assert got == [
        {"found": True, "kind": "file"},
        {"found": True, "kind": "dir"},
        {"found": True, "kind": "link"},
        {"found": False, "kind": None},
        {"found": False, "kind": None},
    ]


def test_fs_mkdir_and_rm_rules(server: Any, machine: str) -> None:
    def post(route: str, body: dict[str, Any]) -> int:
        return call_json(server.port, "POST", f"/machines/{machine}/fs/{route}", body=body)[0]

    assert post("mkdir", {"path": "/tmp/sps-m/x/y", "parents": False}) == 404
    assert post("mkdir", {"path": "/tmp/sps-m/x/y", "parents": True}) == 200
    assert post("mkdir", {"path": "/tmp/sps-m/x/y", "parents": True}) == 200
    assert post("mkdir", {"path": "/tmp/sps-m/x/y", "parents": False}) == 200
    _sh(server, machine, "touch /tmp/sps-m/file")
    assert post("mkdir", {"path": "/tmp/sps-m/file", "parents": False}) == 409
    assert post("mkdir", {"path": "/tmp/sps-m/file/z", "parents": True}) == 409

    _sh(server, machine, "ln -s /tmp/sps-m/x /tmp/sps-m/link")
    assert post("rm", {"path": "/tmp/sps-m/x", "recursive": False}) == 409
    assert post("rm", {"path": "/tmp/sps-m/link", "recursive": True}) == 200  # the link only
    assert _fs_get(server, machine, "/stat", path="/tmp/sps-m/x/y")[1]["found"] is True
    assert post("rm", {"path": "/tmp/sps-m/x", "recursive": True}) == 200
    assert _fs_get(server, machine, "/stat", path="/tmp/sps-m/x")[1]["found"] is False
    assert post("rm", {"path": "/tmp/sps-m/file", "recursive": False}) == 200
    assert post("rm", {"path": "/tmp/sps-m/file", "recursive": False}) == 404
    assert post("rm", {"path": "/", "recursive": True}) == 400
    assert post("mkdir", {"path": "relative", "parents": True}) == 400


def test_a_write_under_a_missing_parent_is_refused(server: Any, machine: str) -> None:
    status, _ = call(
        server.port, "PUT", f"/machines/{machine}/fs?path=/tmp/sps-np/x/y", raw=b"abcd"
    )
    assert status == 404
    assert _fs_get(server, machine, "/stat", path="/tmp/sps-np")[1]["found"] is False


def test_job_log(server: Any, machine: str) -> None:
    status, started = call_json(
        server.port,
        "POST",
        f"/machines/{machine}/jobs",
        body={
            "cmd": [
                "bash",
                "-c",
                "echo first; echo warn >&2; sleep 0.5; echo second; exit 7",
            ]
        },
    )
    assert status == 200, started
    job_id = started["job_id"]

    status, log = call_json(server.port, "GET", f"/machines/{machine}/jobs/{job_id}/log?wait=5")
    assert status == 200
    for _ in range(50):
        if log["done"]:
            break
        time.sleep(0.1)
        status, log = call_json(
            server.port,
            "GET",
            f"/machines/{machine}/jobs/{job_id}/log?offset={log['offset']}&wait=2",
        )
    assert log["done"] is True
    assert log["code"] == 7

    status, replay = call_json(server.port, "GET", f"/machines/{machine}/jobs/{job_id}/log")
    assert "first\n" in replay["out"]
    assert "second\n" in replay["out"]
    assert "warn\n" in replay["err"]


def test_usage_and_ttl(server: Any) -> None:
    status, created = call_json(
        server.port,
        "POST",
        "/machines",
        body={"cpu": 2, "memory_mb": 128, "ttl_seconds": 2},
    )
    assert status == 201, created
    machine_id = created["machine_id"]

    status, usage = call_json(server.port, "GET", f"/machines/{machine_id}/usage")
    assert status == 200
    assert usage["cpu"] == 2
    assert usage["memory_mb"] == 128
    assert usage["ended"] is None

    for _ in range(100):
        time.sleep(0.2)
        status, got = call_json(server.port, "GET", f"/machines/{machine_id}")
        if status == 200 and got["status"] == "ended":
            break
    assert got["status"] == "ended", "machine did not end at its ttl"

    status, usage = call_json(server.port, "GET", f"/machines/{machine_id}/usage")
    assert status == 200
    assert usage["ended"] is not None


def test_unknown_machine_404(server: Any) -> None:
    for method, path, body in [
        ("GET", "/machines/m-0000000000000000", None),
        ("DELETE", "/machines/m-0000000000000000", None),
        ("POST", "/machines/m-0000000000000000/exec", {"cmd": ["true"]}),
        ("GET", "/machines/m-0000000000000000/usage", None),
        ("GET", "/machines/m-0000000000000000/fs?path=/x", None),
    ]:
        status, _ = call(server.port, method, path, body=body)
        assert status == 404, (method, path)


def test_bad_requests(server: Any, machine: str) -> None:
    status, _ = call(server.port, "POST", "/machines", body={"ttl_seconds": "abc"})
    assert status == 400
    status, _ = call(server.port, "POST", f"/machines/{machine}/exec", body={"cmd": "notalist"})
    assert status == 400
    status, _ = call(server.port, "POST", "/machines", raw=b"{not json")
    assert status == 400


def _exec(port: int, machine_id: str, script: str) -> dict[str, Any]:
    status, result = call_json(
        port, "POST", f"/machines/{machine_id}/exec", body={"cmd": ["bash", "-c", script]}
    )
    assert status == 200, result
    return result  # type: ignore[no-any-return]


def _saved_images(owner: str) -> list[str]:
    # The tests may open only loopback connections, so the Docker daemon is asked by its CLI.
    found = subprocess.run(
        ["docker", "images", "--filter", f"label=example.owner={owner}", "-q"],
        capture_output=True,
        check=True,
        text=True,
    )
    return found.stdout.split()


def test_image_keeps_files_and_not_the_machines_configuration(server: Any) -> None:
    status, made = call_json(
        server.port,
        "POST",
        "/machines",
        body={
            "cpu": 1,
            "memory_mb": 256,
            "ttl_seconds": 600,
            "env": {"SOURCE": "yes"},
            "tags": {"a": "1"},
        },
    )
    assert status == 201, made
    source = made["machine_id"]
    restored = None
    try:
        _exec(server.port, source, "printf saved >/tmp/marker; mkdir /tmp/dir")
        status, image = call_json(
            server.port,
            "POST",
            f"/machines/{source}/images",
            body={"tags": {"suite": "images"}, "pause": False},
        )
        assert status == 201, image
        assert image["status"] == "ready" and image["machine_id"] == source
        assert (image["cpu"], image["memory_mb"]) == (1, 256)
        assert image["tags"] == {"suite": "images"} and image["size_bytes"] > 0

        status, again = call_json(server.port, "GET", f"/images/{image['image_id']}")
        assert (status, again) == (200, image)
        status, page = call_json(
            server.port, "GET", "/images?" + urllib.parse.urlencode({"tag": "suite:images"})
        )
        assert [item["image_id"] for item in page["images"]] == [image["image_id"]]
        status, page = call_json(server.port, "GET", f"/images?machine={source}&tag=suite:other")
        assert page["images"] == []

        status, born = call_json(
            server.port,
            "POST",
            "/machines",
            body={
                "image_id": image["image_id"],
                "ttl_seconds": 600,
                "env": {"NEW": "1"},
                "tags": {"b": "2"},
            },
        )
        assert status == 201, born
        restored = born["machine_id"]
        result = _exec(
            server.port, restored, 'cat /tmp/marker; test -d /tmp/dir; echo "$SOURCE|$NEW"'
        )
        assert result["out"] == "saved|1\n"  # the files came along; the source's env did not
        status, usage = call_json(server.port, "GET", f"/machines/{restored}/usage")
        assert (usage["cpu"], usage["memory_mb"]) == (1, 256)  # the image's size
        status, page = call_json(server.port, "GET", "/machines?tag=a:1")
        assert restored not in {item["machine_id"] for item in page["machines"]}
        status, page = call_json(server.port, "GET", "/machines?tag=b:2")
        assert restored in {item["machine_id"] for item in page["machines"]}
    finally:
        for machine_id in (source, restored):
            if machine_id:
                call(server.port, "DELETE", f"/machines/{machine_id}")
        for saved in call_json(server.port, "GET", "/images?tag=suite:images")[1]["images"]:
            call(server.port, "DELETE", f"/images/{saved['image_id']}")


def test_image_delete_is_repeatable_and_removes_the_docker_image(server: Any, machine: str) -> None:
    status, image = call_json(server.port, "POST", f"/machines/{machine}/images", body={})
    assert status == 201, image
    image_id = image["image_id"]
    assert _saved_images(server.owner)
    status, deleted = call_json(server.port, "DELETE", f"/images/{image_id}")
    assert (status, deleted) == (200, {"status": "deleted"})
    status, deleted = call_json(server.port, "DELETE", f"/images/{image_id}")
    assert (status, deleted) == (200, {"status": "deleted"})
    assert _saved_images(server.owner) == []
    assert call(server.port, "GET", f"/images/{image_id}")[0] == 404
    status, page = call_json(server.port, "GET", "/images")
    assert image_id not in {item["image_id"] for item in page["images"]}
    status, _ = call(
        server.port, "POST", "/machines", body={"image_id": image_id, "ttl_seconds": 60}
    )
    assert status == 404
    assert call(server.port, "DELETE", "/images/i-0000000000000000")[0] == 404
    assert call(server.port, "GET", "/images/i-0000000000000000/usage")[0] == 404


def test_deleting_an_image_does_not_touch_a_machine_started_from_it(
    server: Any, machine: str
) -> None:
    _exec(server.port, machine, "printf kept >/tmp/marker")
    status, image = call_json(server.port, "POST", f"/machines/{machine}/images", body={})
    status, born = call_json(
        server.port,
        "POST",
        "/machines",
        body={"image_id": image["image_id"], "ttl_seconds": 600},
    )
    assert status == 201, born
    restored = born["machine_id"]
    try:
        assert call(server.port, "DELETE", f"/images/{image['image_id']}")[0] == 200
        assert _exec(server.port, restored, "cat /tmp/marker")["out"] == "kept"
    finally:
        call(server.port, "DELETE", f"/machines/{restored}")
    for _ in range(100):  # Docker frees the files once the last machine from them has ended
        if not _saved_images(server.owner):
            break
        time.sleep(0.2)
    assert _saved_images(server.owner) == []


def test_image_usage_records_outlive_the_image(server: Any, machine: str) -> None:
    status, image = call_json(server.port, "POST", f"/machines/{machine}/images", body={})
    status, usage = call_json(server.port, "GET", f"/images/{image['image_id']}/usage")
    assert status == 200
    assert usage["machine_id"] == machine and usage["as_of"]
    assert usage["records"] == [
        {"size_bytes": image["size_bytes"], "from": image["created"], "until": None}
    ]
    call(server.port, "DELETE", f"/images/{image['image_id']}")
    status, usage = call_json(server.port, "GET", f"/images/{image['image_id']}/usage")
    assert status == 200 and usage["records"][0]["until"] is not None


def test_bad_image_requests(server: Any, machine: str) -> None:
    for body in ({"pause": "yes"}, {"tags": {"bad key": "x"}}, {"tags": ["x"]}):
        status, _ = call(server.port, "POST", f"/machines/{machine}/images", body=body)
        assert status == 400, body
    assert call(server.port, "POST", "/machines/m-0000000000000000/images", body={})[0] == 404
    assert call(server.port, "GET", "/images?tag=nocolon")[0] == 400
    assert call(server.port, "GET", "/images", key=None)[0] == 401
