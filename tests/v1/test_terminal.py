# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Terminals over one WebSocket: the server's link and message rules, `HttpProvider` as their
client, and the tester's `terminal.*` driver operations."""

from __future__ import annotations

import asyncio
import json
import socket
import threading
import time
from collections.abc import AsyncIterator, Iterator, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar

import httpx
import pytest
import websockets.asyncio.client
import websockets.exceptions

from sandbox_provider_spec.driver import NotRun
from sandbox_provider_spec.v1 import (
    CredentialField,
    Provider,
    Sandbox,
    SpsError,
    Terminal,
    TerminalLink,
    TerminalRequest,
    from_json,
)
from sandbox_provider_spec.v1.http_client import HttpProvider
from sandbox_provider_spec.v1.server import TERMINAL_FRAME_BYTES, create_app
from sandbox_provider_spec.v1.suite_driver import ProviderDriver
from sandbox_provider_spec.v1.terminal_tickets import TERMINAL_TICKET_SECONDS

pytestmark = [pytest.mark.loopback, pytest.mark.integration]
EXAMPLES = Path(__file__).resolve().parents[2] / "spec" / "provider-api-1.0-examples"
TOKEN = "tok-terminal-0123"


def sandbox(state: str = "running") -> Sandbox:
    data = json.loads((EXAMPLES / "Sandbox.json").read_text(encoding="utf-8"))
    return from_json(Sandbox, {**data, "state": state})


class Shell(Terminal):
    """A terminal that echoes its input. `exit N` ends it with exit code N, `flood` answers with
    200000 numbered bytes, and the object records what the server did to it."""

    def __init__(self, request: TerminalRequest) -> None:
        self.request = request
        self.exit_code: int | None = None
        self.written = bytearray()
        self.sizes: list[tuple[int, int]] = [(request.columns, request.rows)]
        self.closed = False
        self._queue: asyncio.Queue[bytes | None] = asyncio.Queue()

    async def write(self, data: bytes) -> None:
        self.written += data
        if data.startswith(b"exit "):
            self.exit_code = int(data.split()[1])
            self._queue.put_nowait(None)
        elif data == b"flood":
            self._queue.put_nowait(bytes(i % 251 for i in range(200_000)))
        elif data == b"boom":
            self._queue.put_nowait(b"")  # a marker that output() turns into a failure
        else:
            self._queue.put_nowait(data)

    async def resize(self, columns: int, rows: int) -> None:
        self.sizes.append((columns, rows))

    async def output(self) -> AsyncIterator[bytes]:
        while True:
            chunk = await self._queue.get()
            if chunk is None:
                return
            if chunk == b"":
                raise SpsError("provider_error", "the terminal broke", outcome="unknown")
            yield chunk

    async def close(self) -> None:
        self.closed = True
        self._queue.put_nowait(None)


class TerminalProvider(Provider, manifest=False):
    provider_id = "shell"
    name = "Shell"
    spec_version = "1.0"
    credential_fields: ClassVar[tuple[CredentialField, ...]] = (CredentialField("token"),)
    state: ClassVar[str] = "running"
    opened: ClassVar[list[Shell]] = []

    async def discovery(self) -> Any:
        raise NotImplementedError

    async def create(self, request: Any, *, idempotency_key: str) -> Any:
        raise NotImplementedError

    async def get(self, sandbox_id: str) -> Sandbox:
        if sandbox_id == "gone":
            raise SpsError("not_found", "No such sandbox")
        return sandbox(type(self).state)

    async def list(self, **kwargs: Any) -> Any:
        raise NotImplementedError

    async def destroy(self, sandbox_id: str) -> Any:
        raise NotImplementedError

    async def run(self, sandbox_id: str, request: Any) -> Any:
        raise NotImplementedError

    async def files_read(self, sandbox_id: str, path: str) -> Any:
        raise NotImplementedError

    async def files_write(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError

    async def process_start(self, sandbox_id: str, request: Any) -> Any:
        raise NotImplementedError

    async def process_output(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError

    async def cost(self, sandbox_id: str) -> Any:
        raise NotImplementedError

    async def terminal_open(self, sandbox_id: str, request: TerminalRequest) -> Terminal:
        if request.cwd == "/missing":
            raise SpsError("not_found", "No such directory: /missing")
        shell = Shell(request)
        type(self).opened.append(shell)
        return shell


class NoTerminalProvider(TerminalProvider, manifest=False):
    """The default `terminal_open`, which refuses with `unsupported`."""

    terminal_open = Provider.terminal_open


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class Served:
    def __init__(self, port: int, clock: Clock) -> None:
        self.port = port
        self.clock = clock
        self.url = f"http://127.0.0.1:{port}"


def serve(provider_class: type[Provider]) -> Iterator[Served]:
    import uvicorn  # noqa: PLC0415 - the `http` extra

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    clock = Clock()
    server = uvicorn.Server(
        uvicorn.Config(
            create_app(provider_class, clock=clock), host="127.0.0.1", port=port, log_level="error"
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        assert time.monotonic() < deadline, "the server did not start"
        time.sleep(0.02)
    try:
        yield Served(port, clock)
    finally:
        server.should_exit = True
        thread.join(timeout=10)


@pytest.fixture()
def served() -> Iterator[Served]:
    TerminalProvider.state = "running"
    TerminalProvider.opened = []
    yield from serve(TerminalProvider)


async def collect(terminal: Terminal, until: int) -> bytes:
    """Read output until it holds `until` bytes, or the terminal ends."""
    data = bytearray()
    async for chunk in terminal.output():
        data += chunk
        if len(data) >= until:
            break
    return bytes(data)


def client(served: Served) -> HttpProvider:
    return HttpProvider(served.url, TOKEN)


def run(coroutine: Any) -> Any:
    return asyncio.run(asyncio.wait_for(coroutine, 30))


# --- the HTTP side -----------------------------------------------------------------------------


def test_terminal_open_returns_a_link_without_the_token(served: Served) -> None:
    response = httpx.post(
        f"{served.url}/v1/sandboxes/sbx-17/terminals",
        json={"columns": 100},
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    assert response.status_code == 200
    link = response.json()
    assert link["url"].startswith(f"ws://127.0.0.1:{served.port}/v1/terminal-links/")
    assert link["headers"] == {}
    assert TOKEN not in json.dumps(link)
    expires = datetime.fromisoformat(link["expires_at"])
    assert 0 < (expires - datetime.now(UTC)).total_seconds() <= TERMINAL_TICKET_SECONDS
    assert not TerminalProvider.opened  # the open started nothing: the link is not connected


@pytest.mark.parametrize(
    ("path", "body", "code", "status"),
    [
        ("/v1/sandboxes/gone/terminals", {}, "not_found", 404),
        ("/v1/sandboxes/sbx-17/terminals", {"columns": 0}, "invalid_request", 400),
        ("/v1/sandboxes/sbx-17/terminals", {"rows": 1001}, "invalid_request", 400),
        ("/v1/sandboxes/sbx-17/terminals", {"term": "bad term"}, "invalid_request", 400),
        ("/v1/sandboxes/sbx-17/terminals", {"argv": []}, "invalid_request", 400),
        ("/v1/sandboxes/sbx-17/terminals", {"cwd": "relative"}, "invalid_request", 400),
        ("/v1/sandboxes/sbx-17/terminals", {"no_such": 1}, "invalid_request", 400),
    ],
)
def test_terminal_open_checks_the_sandbox_and_the_fields(
    served: Served, path: str, body: dict[str, Any], code: str, status: int
) -> None:
    response = httpx.post(
        served.url + path, json=body, headers={"Authorization": f"Bearer {TOKEN}"}
    )
    assert (response.status_code, response.json()["error"]["code"]) == (status, code)


def test_terminal_open_of_a_sandbox_that_is_not_running_is_a_conflict(served: Served) -> None:
    TerminalProvider.state = "paused"
    response = httpx.post(
        f"{served.url}/v1/sandboxes/sbx-17/terminals",
        json={},
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    assert (response.status_code, response.json()["error"]["code"]) == (409, "conflict")


def test_an_adapter_without_a_terminal_is_unsupported() -> None:
    TerminalProvider.state = "running"
    for served in serve(NoTerminalProvider):
        response = httpx.post(
            f"{served.url}/v1/sandboxes/sbx-17/terminals",
            json={},
            headers={"Authorization": f"Bearer {TOKEN}"},
        )
        assert (response.status_code, response.json()["error"]["code"]) == (422, "unsupported")


# --- the link ----------------------------------------------------------------------------------


def test_a_link_serves_a_client_that_sends_only_the_link_and_works_once(served: Served) -> None:
    async def main() -> None:
        provider = client(served)
        try:
            link = await provider.terminal_link("sbx-17", TerminalRequest())
            assert TOKEN not in link.url
            first = await provider.terminal_connect(link)
            with pytest.raises(SpsError) as refused:
                await provider.terminal_connect(link)
            assert 400 <= refused.value.http_status <= 499
            assert refused.value.code == "not_found"
            await first.write(b"hello")
            assert await collect(first, 5) == b"hello"
            await first.close()
        finally:
            await provider.aclose()

    run(main())


def test_a_raw_websocket_without_credentials_is_served_and_the_ticket_is_spent(
    served: Served,
) -> None:
    async def main() -> None:
        async with httpx.AsyncClient(headers={"Authorization": f"Bearer {TOKEN}"}) as http:
            link = (await http.post(f"{served.url}/v1/sandboxes/sbx-17/terminals", json={})).json()
        async with websockets.asyncio.client.connect(link["url"], proxy=None) as socket_:
            await socket_.send(b"abc")
            assert await asyncio.wait_for(socket_.recv(), 10) == b"abc"
        with pytest.raises(websockets.exceptions.InvalidStatus) as refused:
            await websockets.asyncio.client.connect(link["url"], proxy=None)
        assert refused.value.response.status_code == 404
        body = json.loads(refused.value.response.body or b"")
        assert body["error"]["code"] == "not_found"

    run(main())


def test_an_expired_link_is_refused_before_the_upgrade(served: Served) -> None:
    async def main() -> None:
        provider = client(served)
        try:
            link = await provider.terminal_link("sbx-17", TerminalRequest())
            served.clock.now += TERMINAL_TICKET_SECONDS + 1
            with pytest.raises(SpsError) as refused:
                await provider.terminal_connect(link)
            assert refused.value.http_status == 404
        finally:
            await provider.aclose()

    run(main())


def test_a_made_up_link_is_refused(served: Served) -> None:
    async def main() -> None:
        provider = client(served)
        try:
            link = await provider.terminal_link("sbx-17", TerminalRequest())
            forged = type(link)(link.url[:-4] + "xxxx", link.headers, link.expires_at)
            with pytest.raises(SpsError) as refused:
                await provider.terminal_connect(forged)
            assert refused.value.http_status == 404
        finally:
            await provider.aclose()

    run(main())


# --- the messages ------------------------------------------------------------------------------


def test_input_output_resize_and_exit_follow_the_message_rules(served: Served) -> None:
    async def main() -> None:
        provider = client(served)
        try:
            request = TerminalRequest(
                argv=("bash", "-l"), cwd="/tmp", env={"A": "b"}, columns=100, rows=40, term="vt100"
            )
            terminal = await provider.terminal_open("sbx-17", request)
            shell = await shell_of(1)
            assert shell.request == request
            await terminal.write(b"one")
            await terminal.write(b"two")
            assert await collect(terminal, 6) == b"onetwo"
            await terminal.resize(120, 50)
            await terminal.write(b"exit 7")
            assert [chunk async for chunk in terminal.output()] == []
            assert terminal.exit_code == 7
            await eventually(lambda: shell.sizes == [(100, 40), (120, 50)], "no resize")
            assert bytes(shell.written) == b"onetwoexit 7"
            await terminal.close()
            await terminal.close()  # closing twice succeeds
        finally:
            await provider.aclose()

    run(main())


def test_a_long_input_and_a_long_output_travel_in_frames_of_at_most_65536_bytes(
    served: Served,
) -> None:
    async def main() -> None:
        async with httpx.AsyncClient(headers={"Authorization": f"Bearer {TOKEN}"}) as http:
            link = (await http.post(f"{served.url}/v1/sandboxes/sbx-17/terminals", json={})).json()
        async with websockets.asyncio.client.connect(link["url"], proxy=None) as socket_:
            await socket_.send(b"flood")
            received = bytearray()
            frames = []
            while len(received) < 200_000:
                frame = await asyncio.wait_for(socket_.recv(), 10)
                assert isinstance(frame, bytes)
                frames.append(len(frame))
                received += frame
            assert max(frames) <= TERMINAL_FRAME_BYTES
            assert len(frames) >= 4
            assert bytes(received) == bytes(i % 251 for i in range(200_000))

    run(main())
    provider_big = b"x" * (TERMINAL_FRAME_BYTES * 3 + 5)

    async def large_write() -> None:
        provider = client(served)
        try:
            terminal = await provider.terminal_open("sbx-17", TerminalRequest())
            await terminal.write(provider_big)
            shell = await shell_of(2)  # the first part of this test opened the first
            await eventually(lambda: len(shell.written) >= len(provider_big), "input lost")
            assert bytes(shell.written) == provider_big
            await terminal.close()
        finally:
            await provider.aclose()

    run(large_write())


async def shell_of(count: int) -> Shell:
    """The `count`th terminal that the adapter opened: it opens one after its link is connected."""
    deadline = time.monotonic() + 10
    while len(TerminalProvider.opened) < count:
        assert time.monotonic() < deadline, "the adapter never opened the terminal"
        await asyncio.sleep(0.01)
    return TerminalProvider.opened[count - 1]


async def eventually(condition: Any, what: str) -> None:
    deadline = time.monotonic() + 10
    while not condition():
        assert time.monotonic() < deadline, what
        await asyncio.sleep(0.01)


async def raw_link(served: Served) -> str:
    async with httpx.AsyncClient(headers={"Authorization": f"Bearer {TOKEN}"}) as http:
        link = (await http.post(f"{served.url}/v1/sandboxes/sbx-17/terminals", json={})).json()
    return str(link["url"])


@pytest.mark.parametrize(
    "message",
    [
        "not json",
        "[]",
        '{"type": "nope"}',
        '{"type": "resize", "columns": 80}',
        '{"type": "resize", "columns": 80, "rows": 24, "extra": 1}',
        '{"type": "resize", "columns": 0, "rows": 24}',
        '{"type": "resize", "columns": 80, "rows": "24"}',
        '{"type": "exit", "exit_code": 0}',
    ],
)
def test_a_bad_control_message_is_an_invalid_request_error_and_the_end_of_the_terminal(
    served: Served, message: str
) -> None:
    async def main() -> None:
        async with websockets.asyncio.client.connect(await raw_link(served), proxy=None) as socket_:
            await socket_.send(message)
            reply = json.loads(await asyncio.wait_for(socket_.recv(), 10))
            assert reply["type"] == "error"
            assert reply["error"]["code"] == "invalid_request"
            with pytest.raises(websockets.exceptions.ConnectionClosed) as closed:
                await asyncio.wait_for(socket_.recv(), 10)
            assert closed.value.rcvd is not None and closed.value.rcvd.code == 1011
        shell = await shell_of(1)
        await eventually(lambda: shell.closed, "the terminal was not ended")

    run(main())


def test_a_start_that_fails_is_an_error_message_and_a_close(served: Served) -> None:
    async def main() -> None:
        provider = client(served)
        try:
            terminal = await provider.terminal_open("sbx-17", TerminalRequest(cwd="/missing"))
            with pytest.raises(SpsError) as error:
                await anext(terminal.output())
            assert error.value.code == "not_found"
            await terminal.close()
        finally:
            await provider.aclose()

    run(main())


def test_a_failure_after_the_start_is_an_error_message(served: Served) -> None:
    async def main() -> None:
        provider = client(served)
        try:
            terminal = await provider.terminal_open("sbx-17", TerminalRequest())
            await terminal.write(b"boom")
            with pytest.raises(SpsError) as error:
                await anext(terminal.output())
            assert error.value.code == "provider_error"
            await terminal.close()
        finally:
            await provider.aclose()

    run(main())


def test_closing_the_connection_ends_the_terminal(served: Served) -> None:
    async def main() -> None:
        provider = client(served)
        try:
            terminal = await provider.terminal_open("sbx-17", TerminalRequest())
            shell = await shell_of(1)
            assert not shell.closed
            await terminal.close()
            await eventually(lambda: shell.closed, "the terminal outlived its connection")
        finally:
            await provider.aclose()

    run(main())


def test_the_client_never_sends_its_token_to_the_link(
    served: Served, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[Mapping[str, str]] = []

    async def main() -> None:
        provider = client(served)
        original = websockets.asyncio.client.connect

        async def spy(url: str, **kwargs: Any) -> Any:
            seen.append(dict(kwargs.get("additional_headers") or {}))
            return await original(url, **kwargs)

        try:
            link = await provider.terminal_link("sbx-17", TerminalRequest())
            monkeypatch.setattr(websockets.asyncio.client, "connect", spy)
            terminal = await provider.terminal_connect(link)
            await terminal.close()
        finally:
            monkeypatch.setattr(websockets.asyncio.client, "connect", original)
            await provider.aclose()

    run(main())
    assert seen == [{}]


def test_plain_websocket_links_are_refused_for_a_remote_host() -> None:
    async def main() -> None:
        provider = HttpProvider(
            "https://api.example.test/sps",
            TOKEN,
            transport=httpx.MockTransport(lambda request: httpx.Response(500)),
        )
        try:
            now = datetime.now(UTC)
            with pytest.raises(SpsError, match="plain WebSocket"):
                await provider.terminal_connect(TerminalLink("ws://api.example.test/x", {}, now))
            with pytest.raises(SpsError, match="not a WebSocket"):
                await provider.terminal_connect(TerminalLink("https://api.example.test/x", {}, now))
        finally:
            await provider.aclose()

    run(main())


# --- the tester's driver ---------------------------------------------------------------------


class Box:
    """A sandbox resource for a driver operation, as `ProviderDriver.create` would return it."""


def driver_box(driver: ProviderDriver) -> Any:
    from sandbox_provider_spec.v1.suite_driver import SandboxHandle  # noqa: PLC0415

    return {
        "resource": driver.own("sandbox", SandboxHandle("sbx-17"), lambda: {"result": "deleted"})
    }


def test_the_driver_runs_the_terminal_operations_over_the_http_form(served: Served) -> None:
    driver = ProviderDriver(client(served), provider_id="shell")
    try:
        box = driver_box(driver)
        tty = driver.call("terminal.open", box, {"columns": 90, "rows": 30})
        driver.call("terminal.write", tty, {"data": "aGVsbG8="})  # hello
        seen = driver.call("terminal.output", tty, {"until_contains": "hello", "timeout_ms": 10000})
        assert seen == {"terminal": b"hello"}
        driver.call("terminal.resize", tty, {"columns": 100, "rows": 40})
        deadline = time.monotonic() + 10
        while TerminalProvider.opened[-1].sizes != [(90, 30), (100, 40)]:
            assert time.monotonic() < deadline, "the resize did not arrive"
            time.sleep(0.02)
        driver.call("terminal.write", tty, {"data": "ZXhpdCA3"})  # exit 7
        assert driver.call("terminal.wait", tty, {"timeout_ms": 10000}) == {"exit_code": 7}
        driver.call("terminal.close", tty, {})
        assert driver.call("terminal.link_reuse", box, {}) == {"second_refused": True}
    finally:
        driver.close()


def test_the_driver_reports_a_refused_start_at_the_first_read(served: Served) -> None:
    from sandbox_provider_spec.driver import NativeFailure  # noqa: PLC0415

    driver = ProviderDriver(client(served), provider_id="shell")
    try:
        tty = driver.call("terminal.open", driver_box(driver), {"cwd": "/missing"})
        with pytest.raises(NativeFailure) as failure:
            driver.call("terminal.output", tty, {"first_chunk": True, "timeout_ms": 10000})
        assert failure.value.code == "not_found"
    finally:
        driver.close()


def test_the_driver_waits_for_the_wanted_text_and_returns_what_it_has_at_the_timeout(
    served: Served,
) -> None:
    driver = ProviderDriver(client(served), provider_id="shell")
    try:
        tty = driver.call("terminal.open", driver_box(driver), {})
        driver.call("terminal.write", tty, {"data": "YWJj"})  # abc
        started = time.monotonic()
        seen = driver.call("terminal.output", tty, {"until_contains": "zzz", "timeout_ms": 300})
        assert seen == {"terminal": b"abc"}
        assert 0.25 <= time.monotonic() - started < 5
        assert driver.call("terminal.output", tty, {"first_chunk": True}) == {"terminal": b"abc"}
        with pytest.raises(NotRun):
            driver.call("terminal.wait", tty, {"timeout_ms": 100})
    finally:
        driver.close()


def test_a_python_form_has_no_link_to_reuse() -> None:
    class Local(TerminalProvider, manifest=False):
        pass

    driver = ProviderDriver(Local({"token": "x"}), provider_id="shell")
    try:
        with pytest.raises(NotRun, match="the Python form has no link"):
            driver.call("terminal.link_reuse", driver_box(driver), {})
        tty = driver.call("terminal.open", driver_box(driver), {})
        driver.call("terminal.write", tty, {"data": "aGk="})
        assert driver.call("terminal.output", tty, {"until_contains": "hi"}) == {"terminal": b"hi"}
    finally:
        driver.close()


def test_terminal_operations_are_unsupported_when_discovery_does_not_claim_the_section() -> None:
    from sandbox_provider_spec.v1.tester import OPERATION_CLAIMS  # noqa: PLC0415

    assert OPERATION_CLAIMS["terminal.open"] == ("gate", "terminal")
    driver = ProviderDriver(TerminalProvider({"token": "x"}), provider_id="shell")
    try:
        assert "terminal.reattach" in driver.unsupported
        assert "terminal.disconnect" in driver.unsupported
    finally:
        driver.close()
