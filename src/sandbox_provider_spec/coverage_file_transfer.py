# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Checks for file links (`file_links`) and streamed transfer (`file_stream_max_bytes`).

A file link is followed by the runner exactly as the driver describes it: its URL, method,
headers and optional multipart form field, with no other credential. Every check verifies
what the sandbox holds through ordinary guest commands, never through the link itself.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import shlex
import time
import urllib.parse
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any

from sandbox_provider_spec.coverage_regular_write import RegularWriteUsabilityRunner
from sandbox_provider_spec.coverage_ssh import is_account_key
from sandbox_provider_spec.driver import Driver, NativeFailure, NotRun

LINK_CASES = (
    "credential",
    "read_exact",
    "write_exact",
    "write_parents",
    "write_usable",
    "one_path",
    "one_operation",
    "expiry",
    "link_lifetime",
    "user_selection",
    "revocable",
    "interrupted_write",
)
OPERATIONS = ("read", "write")
MIB = 1024 * 1024
#: Sizes a streamed check moves. Above 64 MiB a run opts in with `file_stream_large: true`.
STREAM_SIZES = (64 * MIB, 1024 * MIB, 5 * 1024 * MIB)
STREAM_CHUNK = MIB
#: Free guest disk a streamed check needs beyond the file itself.
STREAM_HEADROOM = 256 * MIB
#: The short lifetime the expiry check requests, and how long it waits past it.
EXPIRY_SECONDS = 5
EXPIRY_GRACE_SECONDS = 10
#: The lifetime check runs in a sandbox created for an hour, so it waits at most this long.
LIFETIME_WAIT_MAX_SECONDS = 3000
#: How long before the requested lifetime ends the lifetime check uses the link.
LIFETIME_MARGIN_SECONDS = 5
#: An interrupted write is observed every few seconds until three observations agree.
INTERRUPT_SETTLE_SECONDS = 3
INTERRUPT_SETTLE_POLLS = 10
_HTTP_TIMEOUT_SECONDS = 600
_OBSERVE = r"""
import hashlib, json, os, pwd, sys
path = os.environ["SPS_FILE_PATH"]
try:
    st = os.stat(path)
except FileNotFoundError:
    print(json.dumps({"exists": False, "parent": os.path.isdir(os.path.dirname(path))}))
    sys.exit(0)
digest = hashlib.sha256()
try:
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    sha = digest.hexdigest()
except PermissionError:
    sha = None
try:
    owner = pwd.getpwuid(st.st_uid).pw_name
except KeyError:
    owner = str(st.st_uid)
print(json.dumps({
    "exists": True, "size": st.st_size, "sha256": sha, "owner": owner,
    "user": pwd.getpwuid(os.getuid()).pw_name,
    "readable": os.access(path, os.R_OK), "writable": os.access(path, os.W_OK),
}))
"""


@dataclass(frozen=True)
class Link:
    """What a client sends to use a link. The URL and header values may carry a secret."""

    url: str
    method: str
    headers: Mapping[str, str] = field(default_factory=dict)
    form_field: str | None = None

    def __repr__(self) -> str:
        return f"Link(method={self.method!r}, form_field={self.form_field!r})"


@dataclass(frozen=True)
class Reply:
    status: int
    body: bytes


#: (link, body or None for a read, bytes to send before closing or None for all) -> reply.
Send = Callable[[Link, bytes | None, int | None], Reply]


def _multipart(form_field: str, body: bytes) -> tuple[bytes, str, int]:
    """The form body, its boundary, and where the file's bytes start in it."""
    boundary = "sps-" + os.urandom(12).hex()
    head = (
        f"--{boundary}\r\nContent-Disposition: form-data; name={json.dumps(form_field)}; "
        'filename="file"\r\nContent-Type: application/octet-stream\r\n\r\n'
    ).encode()
    return head + body + f"\r\n--{boundary}--\r\n".encode(), boundary, len(head)


def _without(headers: Mapping[str, str], *names: str) -> dict[str, str]:
    lowered = {name.lower() for name in names}
    return {name: value for name, value in headers.items() if name.lower() not in lowered}


def http_send(link: Link, body: bytes | None, send_bytes: int | None) -> Reply:
    """Send one request as the link describes, with no proxy, redirect or ambient credential.

    With `send_bytes`, the request announces the whole body but sends only that many bytes of
    the file's content and then closes the connection, as an interrupted client would.
    """
    parsed = urllib.parse.urlsplit(link.url)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname:
        raise NativeFailure("file_link_url_invalid")
    connection: http.client.HTTPConnection = (
        http.client.HTTPSConnection(parsed.hostname, parsed.port, timeout=_HTTP_TIMEOUT_SECONDS)
        if parsed.scheme == "https"
        else http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=_HTTP_TIMEOUT_SECONDS)
    )
    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query
    headers = _without(link.headers, "Content-Length")
    payload = b""
    cut = None
    if body is not None:
        payload, cut = body, send_bytes
        if link.form_field is not None:
            payload, boundary, start = _multipart(link.form_field, body)
            headers = _without(headers, "Content-Type")
            headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
            if send_bytes is not None:
                cut = start + send_bytes
        headers["Content-Length"] = str(len(payload))
    started = False
    try:
        has_host = any(name.lower() == "host" for name in headers)
        connection.putrequest(link.method, target, skip_host=has_host, skip_accept_encoding=True)
        for name, value in headers.items():
            connection.putheader(name, value)
        connection.endheaders()
        started = True
        if body is not None:
            connection.send(payload if cut is None else payload[:cut])
        if cut is not None:
            return Reply(0, b"")
        response = connection.getresponse()
        return Reply(response.status, response.read())
    except (OSError, http.client.HTTPException) as error:
        if cut is not None and started:
            return Reply(0, b"")  # the interrupted client gave up after sending its headers
        raise NativeFailure("file_link_transport") from error
    finally:
        connection.close()


def _link(value: Mapping[str, object], operation: str) -> Link:
    url, method = value.get("url"), value.get("method", "GET" if operation == "read" else "PUT")
    headers, form_field = value.get("headers", {}), value.get("form_field")
    if not isinstance(url, str) or method not in {"GET", "PUT", "POST"}:
        raise NativeFailure("file_link_invalid")
    if not isinstance(headers, Mapping) or any(
        not isinstance(k, str) or not isinstance(v, str) for k, v in headers.items()
    ):
        raise NativeFailure("file_link_invalid")
    if form_field is not None and (
        operation == "read" or not isinstance(form_field, str) or not form_field
    ):
        raise NativeFailure("file_link_invalid")
    return Link(url, str(method), dict(headers), form_field)


def _refused(reply: Reply) -> bool:
    return 400 <= reply.status <= 499


class Check:
    """One file-link or streaming check against one sandbox."""

    def __init__(
        self,
        driver: Driver,
        target: object,
        fixtures: Mapping[str, object],
        send: Send,
        sleep: Callable[[float], None],
    ) -> None:
        self.driver, self.target, self.fixtures = driver, target, fixtures
        self.send, self.sleep = send, sleep
        self.root = f"/tmp/sps-file-links-{fixtures.get('run_nonce') or 'offline'}"

    # Guest observations, through the sandbox's command interface.

    def run(self, script: str, *, user: str | None = None, as_root: bool = False) -> Any:
        if as_root:
            script = (
                'if [ "$(id -u)" = 0 ]; then /bin/sh -c '
                + shlex.quote(script)
                + "; else sudo -n true 2>/dev/null || exit 77; sudo -n /bin/sh -c "
                + shlex.quote(script)
                + "; fi"
            )
        inputs: dict[str, object] = {"bash_script": script, "timeout_ms": 600000}
        if user is not None:
            inputs["run_as"] = user
        result = self.driver.call("run", self.target, inputs)
        if as_root and result.get("exit_code") == 77:
            raise NotRun("account_guest_root_unavailable")
        if result.get("exit_code") not in {0, None}:
            raise NativeFailure("file_links_guest_command")
        return result

    def observe(self, path: str, *, user: str | None = None) -> dict[str, Any]:
        inputs: dict[str, object] = {
            "bash_script": 'python3 -c "$SPS_FILE_OBSERVE"',
            "timeout_ms": 600000,
            "environment": {"SPS_FILE_OBSERVE": _OBSERVE, "SPS_FILE_PATH": path},
        }
        if user is not None:
            inputs["run_as"] = user
        result = self.driver.call("run", self.target, inputs)
        output = result.get("stdout")
        if result.get("exit_code") != 0 or not isinstance(output, (str, bytes)):
            raise NativeFailure("file_observe_failed")
        try:
            value = json.loads(output)
        except json.JSONDecodeError as error:
            raise NativeFailure("file_observe_invalid") from error
        if not isinstance(value, dict):
            raise NativeFailure("file_observe_invalid")
        return value

    def holds(self, path: str, data: bytes) -> bool:
        seen = self.observe(path)
        return seen.get("size") == len(data) and seen.get("sha256") == _sha256(data)

    def put(self, path: str, data: bytes) -> None:
        """Prepare a file through the regular file interface (the baseline)."""
        self.driver.call(
            "files.write", self.target, {"path": path, "data": base64.b64encode(data).decode()}
        )

    # Links.

    def link(
        self, path: str, operation: str, *, lifetime: int = 300, user: str | None = None
    ) -> Link:
        inputs: dict[str, object] = {
            "path": path,
            "operation": operation,
            "lifetime_seconds": lifetime,
        }
        if user is not None:
            inputs["user"] = user
        issued = _link(self.driver.call("files.link", self.target, inputs), operation)
        if is_account_key(issued.url) or any(is_account_key(v) for v in issued.headers.values()):
            raise NativeFailure("file_link_carries_account_key")
        return issued

    def read(self, link: Link) -> Reply:
        return self.send(link, None, None)

    def write(self, link: Link, data: bytes, send_bytes: int | None = None) -> Reply:
        return self.send(link, data, send_bytes)

    def expect_read(self, link: Link, data: bytes) -> None:
        reply = self.read(link)
        if not 200 <= reply.status <= 299:
            raise NativeFailure("file_link_read_refused")
        if reply.body != data:
            raise NativeFailure("file_link_read_bytes")

    def expect_write(self, link: Link, path: str, data: bytes) -> None:
        reply = self.write(link, data)
        if not 200 <= reply.status <= 299:
            raise NativeFailure("file_link_write_refused")
        if not self.holds(path, data):
            raise NativeFailure("file_link_write_bytes")

    def expect_refused(self, reply: Reply, path: str, before: bytes | None) -> None:
        """A client error status, the file's bytes not returned, the file unchanged."""
        if not _refused(reply):
            raise NativeFailure("file_link_not_refused")
        if before is not None and before and before in reply.body:
            raise NativeFailure("file_link_not_refused")
        if before is None:
            if self.observe(path).get("exists"):
                raise NativeFailure("file_link_not_refused")
        elif not self.holds(path, before):
            raise NativeFailure("file_link_not_refused")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _operation(inputs: Mapping[str, object]) -> str:
    operation = inputs.get("operation")
    if operation not in OPERATIONS:
        raise NotRun("file_links_operation_unknown")
    return str(operation)


def _passed(case: str, **fields: object) -> dict[str, object]:
    return {"case": case, "passed": True, **fields}


def _credential(check: Check, inputs: Mapping[str, object]) -> Mapping[str, object]:
    operation = _operation(inputs)
    path = check.root + "/credential"
    data = os.urandom(4096)
    if operation == "read":
        check.put(path, data)
        check.expect_read(check.link(path, "read"), data)
    else:
        check.expect_write(check.link(path, "write"), path, data)
    return _passed("credential", account_key=False)


def _read_exact(check: Check, inputs: Mapping[str, object]) -> Mapping[str, object]:
    del inputs
    for name, data in (("empty", b""), ("binary", bytes(range(256)) * 4096 + b"\x00\xff")):
        path = f"{check.root}/read-{name}"
        check.put(path, data)
        check.expect_read(check.link(path, "read"), data)
    return _passed("read_exact")


def _write_exact(check: Check, inputs: Mapping[str, object]) -> Mapping[str, object]:
    del inputs
    for name, data in (("empty", b""), ("binary", os.urandom(MIB) + b"\x00\xff")):
        path = f"{check.root}/write-{name}"
        check.expect_write(check.link(path, "write"), path, data)
    shorter = check.root + "/write-shorter"
    check.put(shorter, b"a longer earlier content")
    check.expect_write(check.link(shorter, "write"), shorter, b"short")
    return _passed("write_exact")


def _write_parents(check: Check, inputs: Mapping[str, object]) -> Mapping[str, object]:
    del inputs
    path = check.root + "/missing/a/b/file"
    check.expect_write(check.link(path, "write"), path, b"parents")
    return _passed("write_parents")


def _write_usable(check: Check, inputs: Mapping[str, object]) -> Mapping[str, object]:
    del inputs
    path = check.root + "/usable"
    check.expect_write(check.link(path, "write"), path, b"usable")
    seen = check.observe(path)
    if not seen.get("readable") or not seen.get("writable"):
        raise NativeFailure("file_link_write_unusable")
    check.run("printf more >> " + shlex.quote(path))
    return _passed("write_usable", owner_is_default_user=seen.get("owner") == seen.get("user"))


def _substitute(link: Link, path: str, other: str) -> Link | None:
    """The same request with `other` wherever the link names `path`, or None if it never does."""
    forms = {path: other, urllib.parse.quote(path): urllib.parse.quote(other)}
    forms[urllib.parse.quote(path, safe="")] = urllib.parse.quote(other, safe="")
    forms[urllib.parse.quote_plus(path)] = urllib.parse.quote_plus(other)
    for encode in (base64.b64encode, base64.urlsafe_b64encode):
        old, new = encode(path.encode()).decode(), encode(other.encode()).decode()
        forms[old] = new
        forms[old.rstrip("=")] = new.rstrip("=")

    def swap(text: str) -> str:
        for old, new in forms.items():
            text = text.replace(old, new)
        return text

    changed = Link(
        swap(link.url),
        link.method,
        {name: swap(value) for name, value in link.headers.items()},
        link.form_field,
    )
    return None if changed == link else changed


def _one_path(check: Check, inputs: Mapping[str, object]) -> Mapping[str, object]:
    operation = _operation(inputs)
    path, other = check.root + "/scope-a", check.root + "/scope-b"
    data, other_data = b"scope a " + os.urandom(64), b"scope b " + os.urandom(64)
    check.put(path, data)
    check.put(other, other_data)
    issued = check.link(path, operation)
    moved = _substitute(issued, path, other)
    if moved is not None:
        sent = check.read(moved) if operation == "read" else check.write(moved, b"replaced")
        check.expect_refused(sent, other, other_data)
    if operation == "read":
        check.expect_read(issued, data)
    else:
        check.expect_write(issued, path, b"replaced")
        if not check.holds(other, other_data):
            raise NativeFailure("file_link_not_refused")
    return _passed("one_path", operation=operation, path_in_link=moved is not None)


def _one_operation(check: Check, inputs: Mapping[str, object]) -> Mapping[str, object]:
    del inputs
    path = check.root + "/operation"
    data = b"operation " + os.urandom(64)
    check.put(path, data)
    reader, writer = check.link(path, "read"), check.link(path, "write")
    shaped = Link(reader.url, writer.method, reader.headers, writer.form_field)
    check.expect_refused(check.write(shaped, b"changed"), path, data)
    as_read = Link(writer.url, reader.method, writer.headers, None)
    check.expect_refused(check.read(as_read), path, data)
    return _passed("one_operation")


def _expiry(check: Check, inputs: Mapping[str, object]) -> Mapping[str, object]:
    operation = _operation(inputs)
    path = check.root + "/expiry"
    data = b"expiry " + os.urandom(64)
    check.put(path, data if operation == "read" else b"old")
    issued = check.link(path, operation, lifetime=EXPIRY_SECONDS)
    started = time.monotonic()
    if operation == "read":
        check.expect_read(issued, data)
    else:
        check.expect_write(issued, path, data)
    check.sleep(max(0.0, EXPIRY_SECONDS + EXPIRY_GRACE_SECONDS - (time.monotonic() - started)))
    sent = check.read(issued) if operation == "read" else check.write(issued, b"late")
    check.expect_refused(sent, path, data)
    return _passed("expiry", operation=operation, lifetime_seconds=EXPIRY_SECONDS)


def _link_lifetime(check: Check, inputs: Mapping[str, object]) -> Mapping[str, object]:
    operation = _operation(inputs)
    wait = check.fixtures.get("link_lifetime_wait_seconds")
    if wait is None:
        raise NotRun("fixture_missing")
    if not isinstance(wait, int) or isinstance(wait, bool) or wait < 1:
        raise NotRun("proof_fixture_invalid")
    if wait > LIFETIME_WAIT_MAX_SECONDS or wait <= 2 * LIFETIME_MARGIN_SECONDS:
        raise NotRun("proof_fixture_window_invalid")
    path = check.root + "/lifetime"
    data = b"lifetime " + os.urandom(64)
    check.put(path, data if operation == "read" else b"old")
    # Request exactly the lifetime being proven, and use the link just before it ends.
    issued = check.link(path, operation, lifetime=wait)
    started = time.monotonic()
    check.sleep(max(0.0, wait - LIFETIME_MARGIN_SECONDS - (time.monotonic() - started)))
    if operation == "read":
        check.expect_read(issued, data)
    else:
        check.expect_write(issued, path, data)
    return _passed("link_lifetime", operation=operation, waited_seconds=wait)


def _user_selection(check: Check, inputs: Mapping[str, object]) -> Mapping[str, object]:
    del inputs
    user = "spsfl" + str(check.fixtures.get("run_nonce") or "offline")[:8].lower()
    if not user.isalnum():
        raise NotRun("file_links_user_name_invalid")
    root = check.root + "/users"
    secret, mine = root + "/secret", root + "/mine"
    try:
        check.run(
            f"(id -u {user} >/dev/null 2>&1 || useradd -M -s /bin/sh {user}) && "
            f"mkdir -p {root} && chmod 1777 {check.root} {root} && "
            f"printf secret > {secret} && chown 0:0 {secret} && chmod 600 {secret} && "
            f"printf mine > {mine} && chown {user} {mine} && chmod 600 {mine}",
            as_root=True,
        )
    except NativeFailure as error:
        raise NotRun("file_links_user_unprepared") from error
    path, data = root + "/owned", b"owned " + os.urandom(64)
    if not 200 <= check.write(check.link(path, "write", user=user), data).status <= 299:
        raise NativeFailure("file_link_write_refused")
    seen = check.observe(path, user=user)
    if seen.get("size") != len(data) or seen.get("sha256") != _sha256(data):
        raise NativeFailure("file_link_write_bytes")
    if seen.get("owner") != user or not seen.get("readable") or not seen.get("writable"):
        raise NativeFailure("file_link_user_not_applied")
    # Only the named user may read `mine`, and only root may read `secret`.
    check.expect_read(check.link(mine, "read", user=user), b"mine")
    reply = check.read(check.link(secret, "read", user=user))
    if not _refused(reply) or b"secret" in reply.body:
        raise NativeFailure("file_link_user_not_applied")
    return _passed("user_selection")


def _revocable(check: Check, inputs: Mapping[str, object]) -> Mapping[str, object]:
    operation = _operation(inputs)
    path = check.root + "/revoked"
    data = b"revoked " + os.urandom(64)
    check.put(path, data)
    issued = [check.link(path, operation), check.link(path, operation)]
    if operation == "read":
        check.expect_read(issued[0], data)
    check.driver.call("files.revoke_links", check.target, {})
    for link in issued:
        sent = check.read(link) if operation == "read" else check.write(link, b"after revoke")
        check.expect_refused(sent, path, data)
    check.run("true")
    if operation == "read":
        check.expect_read(check.link(path, "read"), data)
    else:
        check.expect_write(check.link(path, "write"), path, b"new link")
    return _passed("revocable", operation=operation, links=len(issued))


def _settled(check: Check, path: str) -> dict[str, Any]:
    """Observe until three observations in a row agree, so a late commit is seen."""
    seen: list[dict[str, Any]] = []
    for _ in range(INTERRUPT_SETTLE_POLLS):
        seen.append(check.observe(path))
        if len(seen) >= 3 and seen[-1] == seen[-2] == seen[-3]:
            return seen[-1]
        check.sleep(INTERRUPT_SETTLE_SECONDS)
    raise NativeFailure("file_link_interrupted_write_unsettled")


def _interrupted_write(check: Check, inputs: Mapping[str, object]) -> Mapping[str, object]:
    del inputs
    path = check.root + "/interrupted"
    before, body = b"previous content", os.urandom(MIB)
    check.put(path, before)
    check.write(check.link(path, "write"), body, MIB // 2)
    seen = _settled(check, path)
    size = seen.get("size")
    left = (
        "absent"
        if not seen.get("exists")
        else "previous"
        if seen.get("sha256") == _sha256(before) and size == len(before)
        else "prefix"
        if isinstance(size, int) and seen.get("sha256") == _sha256(body[:size])
        else "other"
    )
    if left == "other":
        raise NativeFailure("file_link_interrupted_write_foreign_bytes")
    check.expect_write(check.link(path, "write"), path, body)
    return _passed("interrupted_write", left=left)


_LINK_HANDLERS: Mapping[str, Callable[[Check, Mapping[str, object]], Mapping[str, object]]] = {
    "credential": _credential,
    "read_exact": _read_exact,
    "write_exact": _write_exact,
    "write_parents": _write_parents,
    "write_usable": _write_usable,
    "one_path": _one_path,
    "one_operation": _one_operation,
    "expiry": _expiry,
    "link_lifetime": _link_lifetime,
    "user_selection": _user_selection,
    "revocable": _revocable,
    "interrupted_write": _interrupted_write,
}


def file_links(check: Check, inputs: Mapping[str, object]) -> Mapping[str, object]:
    case = inputs.get("case")
    if case not in LINK_CASES:
        raise NotRun("file_links_case_unknown")
    check.run("mkdir -p " + check.root)
    return _LINK_HANDLERS[str(case)](check, inputs)


def _stream_size(inputs: Mapping[str, object], fixtures: Mapping[str, object]) -> int:
    size = inputs.get("size")
    if size not in STREAM_SIZES or not isinstance(size, int):
        raise NotRun("file_stream_size_unknown")
    if size > STREAM_SIZES[0] and fixtures.get("file_stream_large") is not True:
        raise NotRun("fixture_missing")
    return size


@dataclass
class _Source:
    """Random chunks of an exact size, hashed as they are produced, never held whole."""

    size: int
    digest: Any = field(default_factory=hashlib.sha256)
    produced: int = 0

    def __iter__(self) -> Iterator[bytes]:
        while self.produced < self.size:
            chunk = os.urandom(min(STREAM_CHUNK, self.size - self.produced))
            self.digest.update(chunk)
            self.produced += len(chunk)
            yield chunk


def file_stream(check: Check, inputs: Mapping[str, object]) -> Mapping[str, object]:
    operation = _operation(inputs)
    size = _stream_size(inputs, check.fixtures)
    # A disk-backed directory with room for the file, not /tmp, which may be memory.
    place = check.run(
        'python3 -c \'import os, shutil; home = os.path.expanduser("~"); '
        "print(home, shutil.disk_usage(home).free)'"
    ).get("stdout")
    try:
        home, free = str(place if isinstance(place, str) else bytes(place).decode()).split()
        room = int(free)
    except (TypeError, ValueError) as error:
        raise NativeFailure("file_stream_guest_disk_unobserved") from error
    if not home.startswith("/") or room < size + STREAM_HEADROOM:
        raise NotRun("guest_disk_too_small")
    nonce = str(check.fixtures.get("run_nonce") or "offline")
    path = f"{home}/.sps-stream-{nonce}-{operation}-{size}"
    try:
        if operation == "write":
            source = _Source(size)
            result = check.driver.call(
                "files.write_stream", check.target, {"path": path, "size": size, "chunks": source}
            )
            seen = check.observe(path)
            if (
                result.get("written_bytes") != size
                or source.produced != size
                or seen.get("size") != size
                or seen.get("sha256") != source.digest.hexdigest()
            ):
                raise NativeFailure("file_stream_write_bytes")
        else:
            check.run(f"head -c {size} /dev/urandom > {shlex.quote(path)}")
            seen = check.observe(path)
            result = check.driver.call("files.read_stream", check.target, {"path": path})
            chunks = result.get("chunks")
            if not isinstance(chunks, Iterable):
                raise NativeFailure("file_stream_read_invalid")
            digest, received = hashlib.sha256(), 0
            for chunk in chunks:
                if not isinstance(chunk, (bytes, bytearray, memoryview)):
                    raise NativeFailure("file_stream_read_invalid")
                digest.update(chunk)
                received += len(chunk)
            if (
                received != size
                or seen.get("size") != size
                or digest.hexdigest() != seen.get("sha256")
            ):
                raise NativeFailure("file_stream_read_bytes")
    finally:
        check.run("rm -f " + shlex.quote(path))
    return {"operation": operation, "size": size, "passed": True}


class FileTransferRunner(RegularWriteUsabilityRunner):
    """Adds the file-link and streamed-transfer fixture operations."""

    def __init__(
        self,
        driver: Driver,
        fixtures: Mapping[str, object] | None = None,
        *,
        send: Send = http_send,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        super().__init__(driver, fixtures)
        self.send, self.sleep = send, sleep

    def _test_operation(
        self, operation: str, target: object, inputs: Mapping[str, Any]
    ) -> Mapping[str, object]:
        if operation in {"fixture.file_links", "fixture.file_stream"}:
            check = Check(self.driver, target, self.fixtures, self.send, self.sleep)
            if operation == "fixture.file_links":
                return file_links(check, inputs)
            return file_stream(check, inputs)
        return super()._test_operation(operation, target, inputs)
