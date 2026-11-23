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

A connection the peer closed while the pool held it idle can still be picked for the next call: the
pool drops one whose close it has already seen, but not one that closes as the request is sent.
That call fails at once (a `WriteError`, or a `RemoteProtocolError`/`ReadError` before any byte of
an answer) although nothing is wrong with the provider. The client `provider_client` returns sends
such a call once more, on a fresh connection, only when that cannot repeat an effect, and whose body
can be read again (a stream body cannot):

- a connection that could not be made (`ConnectError`) on the library's own transport: nothing
  was sent (a transport the caller supplies may raise it for a destination it refuses, which is
  never tried again);
- a write that failed on HTTP/1.1 with a stated length: the peer closed before it took the whole
  request, and a server runs a request only once it has the whole of it;
- on HTTP/2, a stream the peer reset with REFUSED_STREAM, which RFC 9113 says was not processed;
- any other failure before the answer, for a method that is idempotent (RFC 9110).

A request that may have been written whole and run (any other method) is never sent again: it fails
as before, outcome unknown. A host that wants to know of every such failure (the class, the method,
the HTTP/2 frame kind and error code, whether it was sent again, the time to it; never any text)
registers `observe_failures`.

This module imports `httpx` when a client is built, so the distribution's base install, without
the `http` extra, still imports it.
"""

from __future__ import annotations

import functools
import time
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Any

from sandbox_provider_spec.v1 import timing

if TYPE_CHECKING:
    import httpx

#: Receives one failure's facts (see `observe_failures`).
FailureObserver = Callable[[Mapping[str, object]], None]
_OBSERVER: FailureObserver | None = None

# HTTP/2 error code REFUSED_STREAM (RFC 9113 section 7).
_H2_REFUSED_STREAM = 7

# RFC 9110 section 9.2.2: sending these twice has the effect of sending them once.
IDEMPOTENT_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE", "PUT", "DELETE"})

__all__ = [
    "IDEMPOTENT_METHODS",
    "KEEPALIVE_EXPIRY_SECONDS",
    "FailureObserver",
    "MAX_CONNECTIONS",
    "MAX_KEEPALIVE_CONNECTIONS",
    "provider_client",
    "observe_failures",
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


def observe_failures(observer: FailureObserver | None) -> None:
    """Hand `observer` the facts of every later failed exchange of the four kinds below; None
    removes it. The facts are payload-free: `class`, `method`, `host` (its last two labels),
    `http2`, `frame` (the HTTP/2 frame kind, or `-`), `error_code` and `last_stream_id` (integers
    or None), `resent` (`yes`, `no` or `second`) and `ms` (the time to the failure). The observer
    must not raise; one that does is ignored."""
    global _OBSERVER  # pylint: disable=global-statement
    _OBSERVER = observer


def _resendable(
    request: httpx.Request, error: Exception, *, http2: bool, own_transport: bool
) -> bool:
    """Whether `request`, which failed with `error` before any answer, may be sent once more on a
    fresh connection without repeating an effect."""
    import httpx  # noqa: PLC0415  # pylint: disable=import-outside-toplevel,redefined-outer-name

    # A body that is a stream is read once; one held in memory is read again.
    if not isinstance(request.stream, httpx.ByteStream):
        return False
    if isinstance(error, httpx.ConnectError):
        # Nothing was sent. Only on the library's own transport: a transport the caller supplies
        # (an address-checking one, a mock) raises `ConnectError` for what it refuses by policy,
        # and a refusal is never tried again: a second resolution of a name that just resolved
        # to a forbidden address is what a rebinding attacker wants.
        return own_transport
    if isinstance(error, httpx.WriteError):
        # HTTP/1.1 with a stated length (httpx states one for a body it holds): the peer closed
        # the connection before it took the whole request, and a server runs a request only once
        # it has the whole of it, so this one did not run. HTTP/2 is not argued here: a stream
        # may have been processed before its connection went away.
        # A request with no body states its end by having none.
        framed = "content-length" in request.headers or not any(request.stream)
        return not http2 and framed
    if http2 and _h2_fact(error)[1] == _H2_REFUSED_STREAM:
        # RFC 9113 section 8.7: a stream reset with REFUSED_STREAM was not processed, so it may
        # be sent again whatever the method. (A stream above the last stream id of a GOAWAY is the
        # other such case, and httpcore itself sends it again on a new connection.)
        return True
    if isinstance(error, (httpx.RemoteProtocolError, httpx.ReadError)):
        # The request may have been written whole and run: only a call that is the same when sent
        # twice goes again.
        return request.method.upper() in IDEMPOTENT_METHODS
    return False


def _h2_fact(error: Exception) -> tuple[str, int | None, int | None]:
    """The HTTP/2 frame behind a failure, as (kind, error code, last stream id), or ("-", None,
    None). httpcore raises `RemoteProtocolError(event)` for a stream the peer reset and for a
    connection it closed with a GOAWAY; httpx keeps that exception as `__cause__`. Integers
    and a class name only: nothing the peer sent as text."""
    cause = error.__cause__
    event = cause.args[0] if cause is not None and cause.args else None
    kind = type(event).__name__
    if kind not in ("StreamReset", "ConnectionTerminated"):
        return "-", None, None
    code = getattr(event, "error_code", None)
    last = getattr(event, "last_stream_id", None)
    return (
        kind,
        int(code) if isinstance(code, int) else None,
        int(last) if isinstance(last, int) else None,
    )


@functools.cache
def _client_class() -> type[httpx.AsyncClient]:
    import httpx  # noqa: PLC0415  # pylint: disable=import-outside-toplevel,redefined-outer-name

    # The failures that say a connection was stale. Timeouts are deliberately not here (a
    # `ReadTimeout` or `ConnectTimeout` is no `ReadError`/`ConnectError`): the peer may be running
    # the request, and waiting twice as long is no remedy. Do not add them.
    failures = (httpx.ConnectError, httpx.WriteError, httpx.RemoteProtocolError, httpx.ReadError)

    class ProviderClient(httpx.AsyncClient):
        """`httpx.AsyncClient` that logs a failed exchange's class and sends a call once more on a
        stale connection (see the module docstring)."""

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self._http2 = bool(kwargs.get("http2", False))
            self._own_transport = kwargs.get("transport") is None
            super().__init__(*args, **kwargs)

        async def send(self, request: httpx.Request, **kwargs: Any) -> httpx.Response:
            started = time.monotonic()
            try:
                return await super().send(request, **kwargs)
            except failures as error:
                resend = _resendable(
                    request, error, http2=self._http2, own_transport=self._own_transport
                )
                self._report_failure(request, error, started, resent="yes" if resend else "no")
                if not resend:
                    raise
            started = time.monotonic()
            try:
                with timing.resend():  # a host counts it, and says it is the one resend
                    return await super().send(request, **kwargs)
            except failures as error:
                self._report_failure(request, error, started, resent="second")
                raise

        def _report_failure(
            self, request: httpx.Request, error: Exception, started: float, *, resent: str
        ) -> None:
            """Tell the observer, if there is one: the failure's class, never its text (which may
            quote a URL or a header)."""
            observer = _OBSERVER
            if observer is None:
                return
            frame, code, last = _h2_fact(error)
            try:
                observer(
                    {
                        "class": type(error).__name__,
                        "method": request.method,
                        "host": ".".join((request.url.host or "-").split(".")[-2:]),
                        "http2": self._http2,
                        "frame": frame,
                        "error_code": code,
                        "last_stream_id": last,
                        "resent": resent,
                        "ms": round((time.monotonic() - started) * 1000),
                    }
                )
            except Exception:  # pylint: disable=broad-exception-caught
                pass  # an observer never changes what the caller sees

    return ProviderClient


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

    return _client_class()(
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
