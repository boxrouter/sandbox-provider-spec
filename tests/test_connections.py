# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""`v1.connections.provider_client`: idle connections outlive httpx's 5 second default."""

from __future__ import annotations

import asyncio

import httpx
import pytest

from sandbox_provider_spec.v1 import connections

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
