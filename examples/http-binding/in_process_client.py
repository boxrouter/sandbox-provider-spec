# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Drive the installed HTTP reference through the canonical client, entirely in process.

Needs ``sandbox-provider-spec`` and ``boxrouter-http`` (which brings HTTPX and Core).
``SyncBindingClient`` and ``AsyncBindingClient`` both consume an asynchronous HTTPX
transport, so the endpoint's WSGI callable cannot be passed through
``httpx.WSGITransport`` alone. ``WsgiAsyncTransport`` below is a test adapter: it runs
that transport in a worker thread, drains and closes the synchronous response, and
returns a response whose stream the async client can read. It opens no socket, resolves
no name and starts no server. It is not a production transport.

The backend is the packaged ``TestBackend``. It executes nothing and provides no
isolation. The ``https://`` origin only has to equal the origin the endpoint advertises;
nothing here proves HTTPS, reachability or a public endpoint. The bearer values are
synthetic and authorize only these throwaway instances. Run it with
``python in_process_client.py``; it prints one line per face and exits nonzero on failure.
"""

from __future__ import annotations

import asyncio
import tempfile
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import httpx
from boxrouter_http import (
    AsyncBindingClient,
    ContractViolation,
    DiscoveryAuthenticationError,
    SyncBindingClient,
)

from sandbox_provider_spec.http_reference import Endpoint, EndpointSettings
from sandbox_provider_spec.http_reference.test_backend import TestBackend

ORIGIN = "https://reference.invalid"
ACCOUNT = "account-a"
# The operator's mapping runs from bearer token to account, never the reverse.
TOKENS = {"synthetic-token-a": ACCOUNT, "synthetic-token-b": "account-b"}


class WsgiAsyncTransport(httpx.AsyncBaseTransport):
    """Present a synchronous WSGI transport to a client that requires an async one."""

    def __init__(self, app: Callable[..., Any]) -> None:
        self._inner = httpx.WSGITransport(app=app)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        await request.aread()
        reply = await asyncio.to_thread(self._inner.handle_request, request)
        try:
            body = b"".join(reply.stream)  # type: ignore[arg-type]
        finally:
            reply.close()
        return httpx.Response(
            reply.status_code,
            headers=reply.headers.raw,
            stream=httpx.ByteStream(body),
            request=request,
        )

    async def aclose(self) -> None:
        self._inner.close()


@contextmanager
def reference_endpoint() -> Iterator[Endpoint]:
    """Own one endpoint, its state file and its backend; close them in a fixed order."""
    backend = TestBackend()
    with tempfile.TemporaryDirectory(prefix="sps-in-process-") as directory:
        database = Path(directory) / "allocations.sqlite3"
        endpoint = Endpoint(backend, database, TOKENS, settings=EndpointSettings(ORIGIN))
        try:
            yield endpoint
        finally:
            # Endpoint drains native calls in flight before any backend close or state removal.
            endpoint.close()
            # A real backend is closed here, after the endpoint and before its state is
            # removed. TestBackend holds no native resource.
    assert not database.parent.exists(), "temporary state was not removed"


def create_request(discovery: dict[str, Any]) -> dict[str, Any]:
    offering = discovery["offerings"][0]
    return {
        "operation": "create",
        "request_id": "request-create",
        "account_id": ACCOUNT,
        "allocation_key": f"{int(time.time()):010d}:{uuid.uuid4().hex}",
        "offering_id": offering["offering_id"],
        "declaration_id": offering["declaration_id"],
        "request": {},
        "env": {},
    }


def lifecycle_request(operation: str, sandbox: dict[str, Any]) -> dict[str, Any]:
    return {
        "operation": operation,
        "request_id": f"request-{operation}",
        "account_id": ACCOUNT,
        "sandbox": sandbox,
    }


def check_sync() -> str:
    with reference_endpoint() as endpoint:
        client = SyncBindingClient(
            ORIGIN, ACCOUNT, "synthetic-token-a", transport=WsgiAsyncTransport(endpoint)
        )
        try:
            discovery = dict(client.discover())
            sandbox = client.exchange("create", create_request(discovery))["sandbox"]
            states = [client.exchange("get", lifecycle_request("get", sandbox))["state"]]
            destroyed = client.exchange("destroy", lifecycle_request("destroy", sandbox))["state"]
            states += [
                destroyed,
                client.exchange("get", lifecycle_request("get", sandbox))["state"],
            ]
        finally:
            client.close()
        check_refusals(endpoint)
    assert states == ["active", "destroyed", "absent"], states
    return f"sync {discovery['binding']} {' '.join(states)}"


async def check_async() -> str:
    with reference_endpoint() as endpoint:
        client = AsyncBindingClient(
            ORIGIN, ACCOUNT, "synthetic-token-a", transport=WsgiAsyncTransport(endpoint)
        )
        try:
            discovery = dict(await client.discover())
            created = await client.exchange("create", create_request(discovery))
            sandbox = created["sandbox"]
            states = [(await client.exchange("get", lifecycle_request("get", sandbox)))["state"]]
            states.append(
                (await client.exchange("destroy", lifecycle_request("destroy", sandbox)))["state"]
            )
            states.append(
                (await client.exchange("get", lifecycle_request("get", sandbox)))["state"]
            )
        finally:
            await client.aclose()
        rejected = AsyncBindingClient(
            ORIGIN, ACCOUNT, "synthetic-token-none", transport=WsgiAsyncTransport(endpoint)
        )
        try:
            await rejected.discover()
        except DiscoveryAuthenticationError:
            pass
        else:
            raise AssertionError("an unknown token was accepted")
        finally:
            await rejected.aclose()
    assert states == ["active", "destroyed", "absent"], states
    return f"async {discovery['binding']} {' '.join(states)}"


def check_refusals(endpoint: Endpoint) -> None:
    """An unknown token and another account's token are both refused."""
    unknown = SyncBindingClient(
        ORIGIN, ACCOUNT, "synthetic-token-none", transport=WsgiAsyncTransport(endpoint)
    )
    try:
        unknown.discover()
    except DiscoveryAuthenticationError:
        pass
    else:
        raise AssertionError("an unknown token was accepted")
    finally:
        unknown.close()
    # Token b is valid, but for account-b: discovery names that account, not ACCOUNT.
    other = SyncBindingClient(
        ORIGIN, ACCOUNT, "synthetic-token-b", transport=WsgiAsyncTransport(endpoint)
    )
    try:
        other.discover()
    except ContractViolation:
        pass
    else:
        raise AssertionError("a token for another account was accepted")
    finally:
        other.close()


def main() -> None:
    print(check_sync())
    print(asyncio.run(check_async()))


if __name__ == "__main__":
    main()
