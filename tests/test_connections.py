# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""`v1.connections.provider_client`: idle connections outlive httpx's 5 second default."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import httpx
import pytest

from sandbox_provider_spec.v1 import connections, timing

# Longer than httpx's own keepalive_expiry (5 s), far shorter than the factory's 300 s.
IDLE_GAP_SECONDS = 5.5


class _Server:
    """A local HTTP/1.1 server that answers every request on a connection and counts connections."""

    def __init__(self) -> None:
        self.connections = 0
        self.port = 0
        self._server: asyncio.Server | None = None

    async def __aenter__(self) -> _Server:
        self._server = await asyncio.start_server(self._serve, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *_exc: object) -> None:
        assert self._server is not None
        self._server.close()
        await self._server.wait_closed()

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.connections += 1
        try:
            while await reader.readuntil(b"\r\n\r\n"):
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()


async def _connections_after_gap(client: httpx.AsyncClient, server: _Server) -> int:
    """Connections the server has seen once `client` has called twice, a gap apart."""
    url = f"http://127.0.0.1:{server.port}/x"
    before = server.connections
    async with client:
        await client.get(url)
        await asyncio.sleep(IDLE_GAP_SECONDS)
        await client.get(url)
    return server.connections - before


def test_an_idle_connection_outlives_the_httpx_default() -> None:
    async def run() -> tuple[int, int]:
        async with _Server() as plain_server, _Server() as pooled_server:
            plain, pooled = await asyncio.gather(
                _connections_after_gap(httpx.AsyncClient(), plain_server),
                _connections_after_gap(connections.provider_client(), pooled_server),
            )
        return plain, pooled

    plain, pooled = asyncio.run(run())
    # The control proves the gap is long enough to lose a connection under httpx's defaults, so
    # the pooled client's single connection is the factory's doing and not the test's gap.
    assert plain == 2
    assert pooled == 1


def test_the_pool_limits_are_the_documented_ones() -> None:
    limits = connections.provider_limits()
    assert limits.keepalive_expiry == 300.0
    assert limits.keepalive_expiry is not None and limits.keepalive_expiry < 350.0
    assert limits.max_keepalive_connections == connections.MAX_KEEPALIVE_CONNECTIONS >= 200
    assert limits.max_connections == connections.MAX_CONNECTIONS
    assert (
        limits.max_connections is not None
        and limits.max_keepalive_connections is not None
        and limits.max_connections >= limits.max_keepalive_connections
    )


def test_the_packages_own_settings_pass_through() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={})

    async def run() -> httpx.AsyncClient:
        client = connections.provider_client(
            base_url="https://api.example.test/v1",
            headers={"X-Key": "k"},
            params={"team": "t"},
            timeout=httpx.Timeout(7.0, connect=3.0),
            transport=httpx.MockTransport(handler),
        )
        async with client:
            await client.get("/sandboxes")
        return client

    client = asyncio.run(run())
    (request,) = seen
    assert str(request.url) == "https://api.example.test/v1/sandboxes?team=t"
    assert request.headers["X-Key"] == "k"
    assert client.timeout == httpx.Timeout(7.0, connect=3.0)
    assert client.follow_redirects is False
    assert client.trust_env is True


@pytest.mark.parametrize("trust_env", [True, False])
def test_redirect_and_environment_settings_are_the_callers(trust_env: bool) -> None:
    client = connections.provider_client(follow_redirects=True, trust_env=trust_env)
    assert client.follow_redirects is True
    assert client.trust_env is trust_env


class _DropsReusedConnection:
    """A server that answers the first request of a connection and, on the next one on that
    connection, reads it and closes without answering (a peer that closes as the request is
    sent). `requests` counts the requests it read, `connections` the connections it saw."""

    def __init__(self) -> None:
        self.requests = 0
        self.connections = 0
        self.port = 0
        self._server: asyncio.Server | None = None

    async def __aenter__(self) -> _DropsReusedConnection:
        self._server = await asyncio.start_server(self._serve, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *_exc: object) -> None:
        assert self._server is not None
        self._server.close()
        await self._server.wait_closed()

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.connections += 1
        served = 0
        try:
            while True:
                head = await reader.readuntil(b"\r\n\r\n")
                length = 0
                for line in head.lower().split(b"\r\n"):
                    if line.startswith(b"content-length:"):
                        length = int(line.split(b":")[1])
                if length:
                    await reader.readexactly(length)
                self.requests += 1
                served += 1
                if served > 1:
                    return
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()


def test_an_idempotent_call_on_a_connection_closed_as_it_was_sent_goes_again() -> None:
    async def run() -> tuple[int, int, int]:
        async with _DropsReusedConnection() as server:
            url = f"http://127.0.0.1:{server.port}/x"
            async with connections.provider_client() as client:
                await client.get(url)
                answer = await client.get(url)  # reuses the connection the server then drops
            return answer.status_code, server.connections, server.requests

    status, seen_connections, requests = asyncio.run(run())
    assert status == 200
    assert seen_connections == 2
    assert requests == 3  # first call, the call the dropped connection lost, its resend


def test_a_call_that_may_have_run_is_not_sent_again() -> None:
    async def run() -> tuple[str, int, int]:
        async with _DropsReusedConnection() as server:
            url = f"http://127.0.0.1:{server.port}/x"
            async with connections.provider_client() as client:
                await client.post(url, content=b"one")
                try:
                    await client.post(url, content=b"two")
                except httpx.RemoteProtocolError as error:
                    return type(error).__name__, server.connections, server.requests
            return "", server.connections, server.requests

    kind, seen_connections, requests = asyncio.run(run())
    assert kind == "RemoteProtocolError"
    assert seen_connections == 1
    assert requests == 2  # the second POST was read once and never repeated


def _flaky(error: httpx.HTTPError) -> tuple[httpx.MockTransport, list[int]]:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        if len(calls) == 1:
            raise error
        return httpx.Response(200, json={})

    return httpx.MockTransport(handler), calls


@pytest.mark.parametrize("error_type", [httpx.WriteError])
def test_a_write_that_failed_is_sent_again_for_any_method(
    error_type: type[httpx.HTTPError],
) -> None:
    async def run() -> int:
        transport, calls = _flaky(error_type("closed"))
        async with connections.provider_client(transport=transport) as client:
            response = await client.post("https://x.test/run", json={"cmd": "a"})
            assert response.status_code == 200
        return len(calls)

    assert asyncio.run(run()) == 2


def test_a_body_that_is_a_stream_is_never_sent_again() -> None:
    class Fails(httpx.AsyncBaseTransport):
        """Fails without reading the request, as a connection that broke while the body was sent."""

        def __init__(self) -> None:
            self.calls = 0

        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            self.calls += 1
            raise httpx.WriteError("closed")

    async def body() -> AsyncIterator[bytes]:
        yield b"part"

    async def run() -> int:
        transport = Fails()
        async with connections.provider_client(transport=transport) as client:
            with pytest.raises(httpx.WriteError):
                await client.post("https://x.test/upload", content=body())
        return transport.calls

    assert asyncio.run(run()) == 1


@pytest.mark.parametrize("error_type", [httpx.ConnectTimeout, httpx.ReadTimeout])
def test_other_failures_are_not_sent_again(error_type: type[httpx.HTTPError]) -> None:
    async def run() -> int:
        transport, calls = _flaky(error_type("x"))
        async with connections.provider_client(transport=transport) as client:
            with pytest.raises(error_type):
                await client.get("https://x.test/x")
        return len(calls)

    assert asyncio.run(run()) == 1


def test_a_second_failure_is_the_callers() -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        raise httpx.RemoteProtocolError("Server disconnected without sending a response.")

    async def run() -> None:
        async with connections.provider_client(transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(httpx.RemoteProtocolError):
                await client.get("https://x.test/x")

    asyncio.run(run())
    assert len(calls) == 2


class _Frame:
    """Stands for an h2 event: the class name and the integer fields are what the client reads."""

    def __init__(self, error_code: int, last_stream_id: int | None = None) -> None:
        self.error_code = error_code
        self.last_stream_id = last_stream_id


class StreamReset(_Frame):
    pass


class ConnectionTerminated(_Frame):
    pass


def _h2_failure(frame: _Frame) -> httpx.RemoteProtocolError:
    """An HTTP/2 failure as httpx raises it: httpcore's error, the event in its args, as cause."""
    error = httpx.RemoteProtocolError("closed")
    error.__cause__ = RuntimeError(frame)  # httpcore's RemoteProtocolError(event) has args[0]
    return error


def _posts(error: httpx.HTTPError, *, http2: bool) -> int:
    async def run() -> int:
        transport, calls = _flaky(error)
        async with connections.provider_client(transport=transport, http2=http2) as client:
            try:
                await client.post("https://x.test/run", json={"cmd": "a"})
            except httpx.HTTPError:
                pass
        return len(calls)

    return asyncio.run(run())


def test_http2_resends_a_refused_stream_for_any_method_and_nothing_else_that_ran() -> None:
    assert _posts(_h2_failure(StreamReset(7)), http2=True) == 2  # REFUSED_STREAM: not processed
    assert _posts(_h2_failure(StreamReset(2)), http2=True) == 1  # INTERNAL_ERROR: may have run
    assert _posts(_h2_failure(ConnectionTerminated(0, 5)), http2=True) == 1  # our stream unknown
    assert _posts(httpx.RemoteProtocolError("Server disconnected"), http2=True) == 1
    # The same reset on an HTTP/1.1 client is not an HTTP/2 fact.
    assert _posts(_h2_failure(StreamReset(7)), http2=False) == 1


def test_a_failed_write_is_not_argued_for_http2_or_for_an_unstated_length() -> None:
    assert _posts(httpx.WriteError("closed"), http2=False) == 2
    assert _posts(httpx.WriteError("closed"), http2=True) == 1

    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        raise httpx.WriteError("closed")

    async def run() -> None:
        async with connections.provider_client(transport=httpx.MockTransport(handler)) as client:
            request = client.build_request("POST", "https://x.test/run", content=b"abc")
            del request.headers["content-length"]  # a body of no stated length
            with pytest.raises(httpx.WriteError):
                await client.send(request)

    asyncio.run(run())
    assert len(calls) == 1


def test_an_idempotent_call_is_sent_again_on_http2_too() -> None:
    async def run() -> int:
        transport, calls = _flaky(httpx.RemoteProtocolError("Server disconnected"))
        async with connections.provider_client(transport=transport, http2=True) as client:
            await client.get("https://x.test/list")
        return len(calls)

    assert asyncio.run(run()) == 2


def test_an_observer_hears_every_failure_with_its_class_and_never_its_text() -> None:
    heard: list[dict[str, object]] = []
    secret = "token=abc123 https://49983-sbx9.example.test/secret"
    error = _h2_failure(StreamReset(7))
    error.args = (secret,)
    connections.observe_failures(lambda facts: heard.append(dict(facts)))
    try:
        assert _posts(error, http2=True) == 2
    finally:
        connections.observe_failures(None)
    (fact,) = heard
    assert fact | {"ms": 0} == {
        "class": "RemoteProtocolError",
        "method": "POST",
        "host": "x.test",
        "http2": True,
        "frame": "StreamReset",
        "error_code": 7,
        "last_stream_id": None,
        "resent": "yes",
        "ms": 0,
    }
    assert "abc123" not in repr(fact) and "sbx9" not in repr(fact)


def test_an_observer_that_raises_changes_nothing() -> None:
    def broken(_facts: object) -> None:
        raise RuntimeError("observer bug")

    connections.observe_failures(broken)
    try:
        assert _posts(httpx.WriteError("closed"), http2=False) == 2
    finally:
        connections.observe_failures(None)


def test_only_the_second_send_is_marked_as_a_resend() -> None:
    marks: list[bool] = []

    def handler(request: httpx.Request) -> httpx.Response:
        marks.append(timing.in_resend())
        if len(marks) == 1:
            raise httpx.WriteError("closed")
        return httpx.Response(200, json={})

    async def run() -> None:
        async with connections.provider_client(transport=httpx.MockTransport(handler)) as client:
            await client.get("https://x.test/x")
        assert timing.in_resend() is False

    asyncio.run(run())
    assert marks == [False, True]


def test_a_connect_error_from_a_supplied_transport_is_never_sent_again() -> None:
    """A transport the caller supplies (an address-checking one) raises `ConnectError` for a
    destination it refuses by policy: a second try would resolve the name again. One call, and
    the failure is reported as not resent."""

    class Refuses(httpx.AsyncBaseTransport):
        def __init__(self) -> None:
            self.calls = 0

        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            self.calls += 1
            raise httpx.ConnectError("public endpoint address refused", request=request)

    heard: list[str] = []
    connections.observe_failures(lambda facts: heard.append(str(facts["resent"])))
    transport = Refuses()
    try:

        async def run() -> None:
            async with connections.provider_client(transport=transport) as client:
                with pytest.raises(httpx.ConnectError):
                    await client.get("https://x.test/x")

        asyncio.run(run())
    finally:
        connections.observe_failures(None)
    assert transport.calls == 1
    assert heard == ["no"]


def test_a_refused_connect_on_the_libraries_own_transport_is_sent_again_once() -> None:
    heard: list[str] = []
    connections.observe_failures(lambda facts: heard.append(str(facts["resent"])))
    try:

        async def run() -> None:
            async with _Server() as server:
                port = server.port  # closed again when the block ends: nothing listens
            async with connections.provider_client() as client:
                with pytest.raises(httpx.ConnectError):
                    await client.get(f"http://127.0.0.1:{port}/x")

        asyncio.run(run())
    finally:
        connections.observe_failures(None)
    assert heard == ["yes", "second"]
