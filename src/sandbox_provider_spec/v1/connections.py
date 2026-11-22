# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The one way a provider package builds its HTTP client: `provider_client(...)`.

A package that talks to a provider over HTTP builds every `httpx.AsyncClient` here, so every
package keeps connections the same way. httpx's own defaults close an idle connection after
5 seconds and keep only 20, so a caller that returns to a provider after a short gap (the next
call on a sandbox, often on another process of a fleet) pays a TCP and TLS handshake, about two
round trips, before the exchange starts, and a package that talks to one host per sandbox loses
those connections first. `provider_client` keeps an idle connection for 5 minutes, which is under
the 350 seconds after which a typical cloud NAT drops an idle flow, and keeps hundreds of idle
connections.

The package's own `base_url`, `headers`, `params`, `auth`, `timeout`, redirect and environment
settings pass through unchanged. A `transport` (a test's mock, a caller's address-checking
transport, a Unix socket) is used as given; httpx applies the limits only to the transport it
builds itself.

This module imports `httpx` when a client is built, so the distribution's base install, without
the `http` extra, still imports it.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import httpx

__all__ = [
    "KEEPALIVE_EXPIRY_SECONDS",
    "MAX_CONNECTIONS",
    "MAX_KEEPALIVE_CONNECTIONS",
    "provider_client",
    "provider_limits",
]

# Below the 350 seconds after which an AWS NAT gateway drops an idle flow, so a connection this
# pool still holds is one the network still has. Also the value the former hosted adapters used.
KEEPALIVE_EXPIRY_SECONDS = 300.0
# One idle connection per sandbox host a process has spoken to lately; a process serves many.
MAX_KEEPALIVE_CONNECTIONS = 500
# The bound on connections open at once, idle or in use; a call waits for one beyond it.
MAX_CONNECTIONS = 1000


def provider_limits() -> httpx.Limits:
    """The pool limits `provider_client` applies."""
    import httpx  # noqa: PLC0415  # pylint: disable=import-outside-toplevel,redefined-outer-name

    return httpx.Limits(
        max_connections=MAX_CONNECTIONS,
        max_keepalive_connections=MAX_KEEPALIVE_CONNECTIONS,
        keepalive_expiry=KEEPALIVE_EXPIRY_SECONDS,
    )


def provider_client(  # pylint: disable=too-many-arguments
    *,
    base_url: str = "",
    headers: Mapping[str, str] | None = None,
    params: Mapping[str, Any] | None = None,
    auth: tuple[str, str] | None = None,
    timeout: httpx.Timeout | float | None = 5.0,
    transport: httpx.AsyncBaseTransport | None = None,
    follow_redirects: bool = False,
    trust_env: bool = True,
    http2: bool = False,
) -> httpx.AsyncClient:
    """An `httpx.AsyncClient` with the pool limits above. The other arguments are httpx's own,
    with httpx's defaults (`timeout` 5 seconds; redirects not followed; the environment's proxy
    settings read). `http2` needs httpx's `h2` extra and stays off unless a package asks."""
    import httpx  # noqa: PLC0415  # pylint: disable=import-outside-toplevel,redefined-outer-name

    return httpx.AsyncClient(
        base_url=base_url,
        headers=headers,
        params=params,
        auth=auth,
        timeout=timeout,
        transport=transport,
        limits=provider_limits(),
        follow_redirects=follow_redirects,
        trust_env=trust_env,
        http2=http2,
    )
