# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Offline controls for the file_links.v1.* and files.stream.v1.* coverage checks."""

from __future__ import annotations

import base64
import hashlib
import http.server
import json
import re
import threading
import urllib.parse
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any, cast

import pytest

from sandbox_provider_spec import check_digests
from sandbox_provider_spec.coverage_file_transfer import (
    EXPIRY_GRACE_SECONDS,
    EXPIRY_SECONDS,
    LINK_CASES,
    MIB,
    Check,
    FileTransferRunner,
    Link,
    Reply,
    file_links,
    file_stream,
    http_send,
)
from sandbox_provider_spec.driver import Driver, Inputs, NativeFailure, NotRun, Observation
from sandbox_provider_spec.suite import read_suite, suite_path


@dataclass
class Issued:
    path: str
    operation: str
    expires: float
    user: str | None
    generation: int


@dataclass
class FakeSandbox(Driver):
    """In-memory files, links signed by the fake provider, and a fake clock."""

    flaws: set[str] = field(default_factory=set)
    files: dict[str, bytes] = field(default_factory=dict)
    owners: dict[str, str] = field(default_factory=dict)
    unreadable: dict[str, set[str]] = field(default_factory=dict)
    links: dict[str, Issued] = field(default_factory=dict)
    now: float = 0.0
    generation: int = 0
    users: set[str] = field(default_factory=lambda: {"user", "root"})
    pending: list[tuple[str, bytes]] = field(default_factory=list)

    def __post_init__(self) -> None:
        super().__init__()

    # Driver operations.

    def create(self, target: object, inputs: Inputs) -> Observation:
        del target, inputs
        return {"identity": "box"}

    def files_write(self, target: object, inputs: Inputs) -> Observation:
        del target
        self._store(str(inputs["path"]), base64.b64decode(str(inputs["data"])), "user")
        return {}

    def files_link(self, target: object, inputs: Inputs) -> Observation:
        del target
        token = f"t{len(self.links)}"
        path, operation = str(inputs["path"]), str(inputs["operation"])
        user = cast(str | None, inputs.get("user"))
        self.links[token] = Issued(
            path,
            operation,
            self.now + cast(int, inputs["lifetime_seconds"]),
            user,
            self.generation,
        )
        query = urllib.parse.urlencode({"path": path, "op": operation, "sig": token})
        if "account_key" in self.flaws:
            query += "&key=fake-account-key-value"
        link: dict[str, object] = {"url": "https://files.test/file?" + query}
        if operation == "write":
            link.update({"method": "POST", "form_field": "file"})
        return link

    def files_revoke_links(self, target: object, inputs: Inputs) -> Observation:
        del target, inputs
        if "revoke_noop" not in self.flaws:
            self.generation += 1
        return {}

    def files_write_stream(self, target: object, inputs: Inputs) -> Observation:
        del target
        data = b"".join(cast(Iterable[bytes], inputs["chunks"]))
        if "stream_short" in self.flaws:
            data = data[:-1]
        self._store(str(inputs["path"]), data, "user")
        return {"written_bytes": cast(int, inputs["size"])}

    def files_read_stream(self, target: object, inputs: Inputs) -> Observation:
        del target
        data = self.files[str(inputs["path"])]
        if "stream_short" in self.flaws:
            data = data[:-1]

        def chunks() -> Iterator[bytes]:
            for start in range(0, len(data), MIB):
                yield data[start : start + MIB]

        return {"chunks": chunks()}

    def run(self, target: object, inputs: Inputs) -> Observation:
        del target
        script = str(inputs["bash_script"])
        user = cast(str, inputs.get("run_as") or "user")
        if "SPS_FILE_OBSERVE" in script:
            environment = cast(dict[str, str], inputs["environment"])
            return {"exit_code": 0, "stdout": json.dumps(self._observe(environment, user))}
        if "shutil.disk_usage" in script:
            free = 10 if "small_disk" in self.flaws else 1 << 40
            return {"exit_code": 0, "stdout": f"/home/user {free}\n"}
        if script.startswith(("mkdir -p ", "true", "rm -f ")):
            if script.startswith("rm -f "):
                self.files.pop(script.split(" ", 2)[2].strip("'"), None)
            return {"exit_code": 0, "stdout": ""}
        if script.startswith("printf more >> "):
            path = script.split(">> ", 1)[1].strip("'")
            self.files[path] += b"more"
            return {"exit_code": 0, "stdout": ""}
        if match := re.fullmatch(r"head -c (\d+) /dev/urandom > (\S+)", script):
            self._store(match[2], bytes(int(match[1])), "user")
            return {"exit_code": 0, "stdout": ""}
        if "useradd" in script:
            if "no_root" in self.flaws:
                return {"exit_code": 77, "stdout": ""}
            named = re.search(r"useradd -M -s /bin/sh (\w+)", script)
            secret = re.search(r"printf secret > (\S+)", script)
            mine = re.search(r"printf mine > (\S+)", script)
            assert named and secret and mine
            self.users.add(named[1])
            self._store(secret[1], b"secret", "root")
            self.unreadable[secret[1]] = {named[1], "user"}
            self._store(mine[1], b"mine", named[1])
            self.unreadable[mine[1]] = {"user"}
            return {"exit_code": 0, "stdout": ""}
        raise AssertionError(f"unexpected script {script!r}")

    # The fake provider's link endpoint.

    def send(self, link: Link, body: bytes | None, send_bytes: int | None) -> Reply:
        query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(link.url).query))
        issued = self.links.get(query.get("sig", ""))
        if issued is None:
            return Reply(401, b"unknown link")
        valid = (
            ("ignores_path" in self.flaws or query["path"] == issued.path)
            and ("never_expires" in self.flaws or self.now < issued.expires)
            and issued.generation == self.generation
        )
        operation = "read" if body is None else "write"
        if "any_operation" not in self.flaws and operation != issued.operation:
            valid = False
        if not valid:
            return Reply(401, b"invalid signature")
        path, user = query["path"], issued.user or "user"
        if "ignores_user" in self.flaws:
            user = "user"
        if body is None:
            if user in self.unreadable.get(path, set()):
                return Reply(403, b"denied")
            return Reply(200, self.files[path])
        if send_bytes is not None and "late_commit" in self.flaws:
            self.pending.append((path, b"garbage"))
            return Reply(0, b"")
        if send_bytes is not None:
            self._store(path, b"garbage" if "garbage" in self.flaws else body[:send_bytes], user)
            return Reply(0, b"")
        if "write_noop" in self.flaws:
            return Reply(200, b"")
        if "drops_byte" in self.flaws and body:
            body = body[:-1]
        self._store(path, body, "root" if "root_owner" in self.flaws else user)
        return Reply(200, b"")

    def sleep(self, seconds: float) -> None:
        self.now += seconds

    def _store(self, path: str, data: bytes, owner: str) -> None:
        self.files[path] = data
        self.owners[path] = owner

    def _observe(self, environment: dict[str, str], user: str) -> dict[str, object]:
        path = environment["SPS_FILE_PATH"]
        if self.pending and self.now >= 3:  # an aborted upload committed a little later
            late, data = self.pending.pop()
            self._store(late, data, "user")
        if path not in self.files:
            return {"exists": False}
        data, owner = self.files[path], self.owners[path]
        private = owner != user and user != "root" and owner != "user"
        return {
            "exists": True,
            "size": len(data),
            "sha256": None if private else hashlib.sha256(data).hexdigest(),
            "owner": owner,
            "user": user,
            "readable": not private,
            "writable": not private,
        }


def _check(sandbox: FakeSandbox, **fixtures: object) -> Check:
    return Check(sandbox, {}, {"run_nonce": "abc123", **fixtures}, sandbox.send, sandbox.sleep)


def _run(case: str, flaws: set[str] | None = None, /, **inputs: object) -> object:
    sandbox = FakeSandbox(flaws=flaws or set())
    fixtures = {"link_lifetime_wait_seconds": 600}
    return file_links(_check(sandbox, **fixtures), {"case": case, **inputs})


OPERATION_CASES = {"credential", "one_path", "expiry", "link_lifetime", "revocable"}


@pytest.mark.parametrize("case", LINK_CASES)
def test_every_link_case_passes_against_a_conforming_provider(case: str) -> None:
    operations = ("read", "write") if case in OPERATION_CASES else (None,)
    for operation in operations:
        inputs = {"operation": operation} if operation else {}
        result = cast(dict[str, object], _run(case, **inputs))
        assert result["passed"] is True and result["case"] == case


@pytest.mark.parametrize(
    ("case", "operation", "flaw"),
    [
        ("one_path", "read", "ignores_path"),
        ("one_path", "write", "ignores_path"),
        ("one_operation", None, "any_operation"),
        ("expiry", "read", "never_expires"),
        ("expiry", "write", "never_expires"),
        ("write_exact", None, "drops_byte"),
        ("write_usable", None, "root_owner"),
        ("revocable", "read", "revoke_noop"),
        ("revocable", "write", "revoke_noop"),
        ("user_selection", None, "ignores_user"),
        ("expiry", "write", "write_noop"),
        ("link_lifetime", "write", "write_noop"),
        ("interrupted_write", None, "garbage"),
        ("interrupted_write", None, "late_commit"),
    ],
)
def test_a_provider_that_breaks_a_rule_fails_its_check(
    case: str, operation: str | None, flaw: str
) -> None:
    inputs = {"operation": operation} if operation else {}
    with pytest.raises(NativeFailure):
        _run(case, {flaw}, **inputs)


def test_expiry_waits_past_the_requested_lifetime() -> None:
    sandbox = FakeSandbox()
    file_links(_check(sandbox), {"case": "expiry", "operation": "read"})
    # The wait counts from issue on the runner's clock, so the fake clock lags it slightly.
    assert sandbox.now >= EXPIRY_SECONDS + EXPIRY_GRACE_SECONDS - 1


@pytest.mark.parametrize("operation", ["read", "write"])
def test_a_link_carrying_an_account_key_fails(
    operation: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FAKE_PROVIDER_API_KEY", "fake-account-key-value")
    with pytest.raises(NativeFailure, match="account_key"):
        _run("credential", {"account_key"}, operation=operation)


def test_link_lifetime_needs_its_fixture_and_a_bounded_wait() -> None:
    sandbox = FakeSandbox()
    with pytest.raises(NotRun, match="fixture_missing"):
        file_links(_check(sandbox), {"case": "link_lifetime", "operation": "read"})
    for wait in (4000, 10):
        with pytest.raises(NotRun, match="proof_fixture_window_invalid"):
            file_links(
                _check(sandbox, link_lifetime_wait_seconds=wait),
                {"case": "link_lifetime", "operation": "read"},
            )


def test_link_lifetime_requests_exactly_the_proven_lifetime() -> None:
    sandbox = FakeSandbox()
    file_links(
        _check(sandbox, link_lifetime_wait_seconds=600),
        {"case": "link_lifetime", "operation": "read"},
    )
    issued = [link for link in sandbox.links.values() if link.path.endswith("/lifetime")]
    assert [link.expires for link in issued] == [600]
    assert 590 <= sandbox.now < 600


def test_user_selection_without_root_is_not_run() -> None:
    with pytest.raises(NotRun):
        _run("user_selection", {"no_root"})


def test_a_path_the_link_does_not_name_is_recorded() -> None:
    result = cast(dict[str, object], _run("one_path", operation="read"))
    assert result["path_in_link"] is True


def test_link_secrets_stay_out_of_repr() -> None:
    link = Link("https://files.test/f?sig=secret", "GET", {"Authorization": "secret"})
    assert "secret" not in repr(link)


@pytest.mark.parametrize("operation", ["read", "write"])
def test_streamed_transfer_checks_exact_bytes(operation: str) -> None:
    sandbox = FakeSandbox()
    size = 64 * MIB
    result = file_stream(_check(sandbox), {"operation": operation, "size": size})
    assert result == {"operation": operation, "size": size, "passed": True}
    assert not sandbox.files  # the transferred file is removed afterwards
    with pytest.raises(NativeFailure):
        file_stream(
            _check(FakeSandbox(flaws={"stream_short"})), {"operation": operation, "size": size}
        )


def test_streams_need_guest_disk_room() -> None:
    with pytest.raises(NotRun, match="guest_disk_too_small"):
        file_stream(
            _check(FakeSandbox(flaws={"small_disk"})), {"operation": "write", "size": 64 * MIB}
        )


def test_large_streams_need_an_explicit_fixture() -> None:
    with pytest.raises(NotRun, match="fixture_missing"):
        file_stream(_check(FakeSandbox()), {"operation": "write", "size": 1024 * MIB})
    with pytest.raises(NotRun, match="file_stream_size_unknown"):
        file_stream(_check(FakeSandbox()), {"operation": "write", "size": 12345})


def test_suite_rows_reach_the_runner_and_record_not_run_without_driver_hooks() -> None:
    suite = read_suite(suite_path().parent / "coverage.yaml")
    selected = [
        test for test in suite.tests if test.id.startswith(("file_links.v1.", "files.stream.v1."))
    ]
    assert len(selected) == 23
    rules = {rule for test in selected for rule in test.rules}
    assert {"facts/file-stream-read", "facts/file-stream-write"} <= rules
    assert len({rule for rule in rules if rule.startswith("file-links/")}) == 12
    dependencies = {
        dependency for test in selected for dependency in check_digests.test_dependencies(test)
    }
    assert "coverage_file_transfer.py" in dependencies
    assert "runner.py" not in dependencies

    class Bare(Driver):
        provider = "bare"

        def create(self, target: object, inputs: Inputs) -> Observation:
            del target, inputs
            return {"identity": "box", "resource": self.own("sandbox", "box", dict)}

        def run(self, target: object, inputs: Inputs) -> Observation:
            del target, inputs
            return {"exit_code": 0, "stdout": ""}

    runner = FileTransferRunner(Bare(), {})
    results = runner.run(type(suite)(suite.digest, tuple(selected[:2]), suite.baseline_ids))
    assert [result["result"] for result in results] == ["not_run", "not_run"]


@pytest.mark.integration
@pytest.mark.loopback
def test_http_send_follows_the_link_shape_and_can_interrupt() -> None:

    seen: list[tuple[str, str, dict[str, str], bytes]] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def _record(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length else b""
            seen.append((self.command, self.path, dict(self.headers.items()), body))
            if len(body) < length:
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"served")

        do_GET = do_PUT = do_POST = _record

        def log_message(self, *args: Any) -> None:
            del args

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}/f?path=%2Ftmp%2Fx"
    try:
        assert http_send(Link(base, "GET", {"X-Token": "t"}), None, None) == Reply(200, b"served")
        assert seen[-1][0] == "GET" and seen[-1][2]["X-Token"] == "t"
        assert http_send(Link(base, "PUT"), b"raw bytes", None).status == 200
        assert seen[-1][0] == "PUT" and seen[-1][3] == b"raw bytes"
        form = Link(base, "POST", {"content-type": "text/plain", "content-length": "1"}, "file")
        assert http_send(form, b"\x00form", None).status == 200
        method, _, headers, body = seen[-1]
        boundary = headers["Content-Type"].removeprefix("multipart/form-data; boundary=")
        assert method == "POST" and boundary != headers["Content-Type"]
        head, _, rest = body.partition(b"\r\n\r\n")
        assert head.startswith(f"--{boundary}\r\n".encode())
        assert b'Content-Disposition: form-data; name="file"; filename="file"' in head
        assert rest == b"\x00form" + f"\r\n--{boundary}--\r\n".encode()
        assert http_send(Link(base, "PUT"), b"x" * 1000, 10) == Reply(0, b"")
    finally:
        server.shutdown()
        server.server_close()
