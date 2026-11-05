# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the owned endpoint service and its restricted proxies."""

from __future__ import annotations

import base64
import runpy
import socket
import threading
import time
from http.server import ThreadingHTTPServer
from typing import Any

import pytest

from sandbox_provider_spec.suite import suite_path

pytestmark = [pytest.mark.integration, pytest.mark.loopback]

ENDPOINT_SERVER_PATH = suite_path().parent / "fixtures/endpoints/server.py"
ENDPOINT_SERVER = runpy.run_path(str(ENDPOINT_SERVER_PATH))
EndpointHandler = ENDPOINT_SERVER["EndpointHandler"]
EndpointState = ENDPOINT_SERVER["EndpointState"]
HTTPProxyHandler = ENDPOINT_SERVER["HTTPProxyHandler"]
ProxyServer = ENDPOINT_SERVER["ProxyServer"]
Socks5Handler = ENDPOINT_SERVER["Socks5Handler"]
ThreadedTCPServer = ENDPOINT_SERVER["ThreadedTCPServer"]
ThreadedUDPServer = ENDPOINT_SERVER["ThreadedUDPServer"]
DatagramEchoHandler = ENDPOINT_SERVER["DatagramEchoHandler"]
EchoHandler = ENDPOINT_SERVER["EchoHandler"]
TransportEchoHandler = ENDPOINT_SERVER["TransportEchoHandler"]
_allowed_target = ENDPOINT_SERVER["_allowed_target"]
_token_from_authorization = ENDPOINT_SERVER["_token_from_authorization"]


class FixtureHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], state: Any) -> None:
        self.endpoint_state = state
        super().__init__(address, EndpointHandler)


def start(server: Any) -> threading.Thread:
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    deadline = time.monotonic() + 3
    while server._BaseServer__is_shut_down.is_set():
        if time.monotonic() >= deadline:
            raise RuntimeError("test server did not start")
        time.sleep(0.001)
    return thread


def stop(server: Any, thread: threading.Thread) -> None:
    server.shutdown()
    server.server_close()
    thread.join(timeout=3)
    assert not thread.is_alive()


def port(server: Any) -> int:
    return int(server.server_address[1])


def test_main_starts_configured_production_endpoints(monkeypatch: pytest.MonkeyPatch) -> None:
    endpoint_server = runpy.run_path(str(ENDPOINT_SERVER_PATH))["main"].__globals__
    started: list[Any] = []
    start_calls: list[Any] = []

    class FakeServer:
        def __init__(self, address: tuple[str, int], *args: Any) -> None:
            self.address = address
            self.args = args
            self.shutdown_called = False
            self.server_close_called = False

        def shutdown(self) -> None:
            self.shutdown_called = True

        def server_close(self) -> None:
            self.server_close_called = True

    def make_server(address: tuple[str, int], *args: Any) -> FakeServer:
        server = FakeServer(address, *args)
        started.append(server)
        return server

    endpoint_server.update(
        {
            "EndpointHTTPServer": lambda address, state: make_server(address, state),
            "ThreadedTCPServer": lambda address, handler: make_server(address, handler),
            "ThreadedUDPServer": lambda address, handler: make_server(address, handler),
            "ProxyServer": lambda address, handler, state, allowed: make_server(
                address, handler, state, allowed
            ),
            "_start": start_calls.append,
        }
    )

    monkeypatch.setenv("SPS_BIND_HOST", "0.0.0.0")
    monkeypatch.setenv("FLY_APP_NAME", "fixture-app")
    monkeypatch.setenv("SPS_PROXY_ALLOWED_HOSTS", " Example.test,*.sps.example.test ")
    monkeypatch.setattr(endpoint_server["threading"].Event, "wait", lambda _self: None)

    endpoint_server["main"]()

    assert start_calls == started
    assert [server.address for server in started] == [
        ("0.0.0.0", 8080),
        ("0.0.0.0", 7000),
        ("fly-global-services", 7001),
        ("0.0.0.0", 8443),
        ("0.0.0.0", 1080),
        ("0.0.0.0", 3128),
    ]
    assert started[4].args[2] == ("example.test", "*.sps.example.test")
    assert started[5].args[2] == ("example.test", "*.sps.example.test")
    assert all(server.shutdown_called for server in started)
    assert all(server.server_close_called for server in started)


def test_health_and_token_records_preserve_request_details() -> None:
    state = EndpointState()
    server = FixtureHTTPServer(("127.0.0.1", 0), state)
    thread = start(server)
    try:
        with socket.create_connection(("127.0.0.1", server.server_port)) as client:
            client.sendall(
                b"POST /probe?case=one HTTP/1.1\r\n"
                b"Host: endpoint.test\r\n"
                b"x-token: t1\r\n"
                b"Content-Length: 4\r\n"
                b"Connection: close\r\n\r\nbody"
            )
            response = client.makefile("rb").read()
        assert b"200 OK" in response
        record = state.snapshot("t1")
        request = record["requests"][0]
        assert request["method"] == "POST"
        assert request["path"] == "/probe?case=one"
        assert request["body"] == "body"
        assert request["headers"]["x-token"] == "t1"
    finally:
        stop(server, thread)


def test_health_and_transport_probe_return_machine_readable_proofs() -> None:
    state = EndpointState()
    server = FixtureHTTPServer(("127.0.0.1", 0), state)
    thread = start(server)
    try:
        for path, expected in (("/health", b'{"ok":true}'), ("/probe", b"sps-transport-proof")):
            with socket.create_connection(("127.0.0.1", server.server_port), timeout=3) as client:
                request = (
                    f"GET {path} HTTP/1.1\r\nHost: endpoint.test\r\n"
                    + ("X-SPS-Probe: t3\r\n" if path == "/probe" else "")
                    + "Connection: close\r\n\r\n"
                )
                client.sendall(request.encode("ascii"))
                response = client.makefile("rb").read()
            assert b"200 OK" in response
            assert expected in response
        assert state.snapshot("t3")["requests"][0]["path"] == "/probe"
    finally:
        stop(server, thread)


def test_stream_route_uses_chunked_response_and_stops_on_disconnect() -> None:
    state = EndpointState()
    server = FixtureHTTPServer(("127.0.0.1", 0), state)
    thread = start(server)
    try:
        with socket.create_connection(("127.0.0.1", server.server_port), timeout=3) as client:
            client.sendall(
                b"GET /stream HTTP/1.1\r\nHost: endpoint.test\r\n"
                b"X-SPS-Probe: t4\r\nConnection: close\r\n\r\n"
            )
            chunks: list[bytes] = []
            while b"sps-connection-proof\n" not in b"".join(chunks):
                chunk = client.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            response = b"".join(chunks)
        assert b"200 OK" in response
        assert b"Transfer-Encoding: chunked" in response
        assert b"sps-connection-proof\n" in response
        assert state.snapshot("t4")["requests"][0]["path"] == "/stream"
    finally:
        stop(server, thread)


def test_proxy_hosts_and_ports_are_restricted() -> None:
    state = EndpointState()
    server = ProxyServer(
        ("127.0.0.1", 0), HTTPProxyHandler, state, ("endpoint.test", "*.sps.example.test")
    )
    assert _allowed_target(server, "endpoint.test", 443)
    assert _allowed_target(server, "wildcard.sps.example.test", 80)
    assert not _allowed_target(server, "other.fly.dev", 443)
    assert not _allowed_target(server, "endpoint.test", 22)
    server.server_close()


def test_http_proxy_connect_records_token_and_tunnels_bytes() -> None:
    state = EndpointState()
    echo = ThreadedTCPServer(("127.0.0.1", 0), EchoHandler)
    echo_thread = start(echo)
    proxy = ProxyServer(
        ("127.0.0.1", 0),
        HTTPProxyHandler,
        state,
        ("127.0.0.1",),
        frozenset({port(echo)}),
    )
    proxy_thread = start(proxy)
    try:
        with socket.create_connection(proxy.server_address, timeout=3) as client:
            target = f"127.0.0.1:{port(echo)}"
            client.sendall(
                f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n"
                "Proxy-Authorization: Basic dDE6c2VjcmV0\r\n\r\n".encode("ascii")
            )
            response = client.makefile("rb").readline()
            assert response.startswith(b"HTTP/1.1 200")
            client.sendall(b"ping")
            assert client.recv(4) == b"ping"
        connection = state.snapshot("t1")["connections"][0]
        assert connection["proxy"] == "http"
        assert connection["host"] == "127.0.0.1"
    finally:
        stop(proxy, proxy_thread)
        stop(echo, echo_thread)


def test_http_proxy_forwards_absolute_form_request_and_token() -> None:
    state = EndpointState()
    receiver = FixtureHTTPServer(("127.0.0.1", 0), state)
    receiver_thread = start(receiver)
    proxy = ProxyServer(
        ("127.0.0.1", 0),
        HTTPProxyHandler,
        state,
        ("127.0.0.1",),
        frozenset({receiver.server_port}),
    )
    proxy_thread = start(proxy)
    try:
        with socket.create_connection(("127.0.0.1", proxy.server_address[1]), timeout=3) as client:
            target = f"http://127.0.0.1:{receiver.server_port}/health"
            client.sendall(
                (
                    f"GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{receiver.server_port}\r\n"
                    "x-token: t2\r\nConnection: close\r\n\r\n"
                ).encode("ascii")
            )
            response = client.makefile("rb").read()
        assert b"200 OK" in response
        assert b'{"ok":true}' in response
        assert state.snapshot("t2")["requests"][0]["path"] == "/health"
        assert state.snapshot("t2")["connections"][0]["proxy"] == "http"
    finally:
        stop(proxy, proxy_thread)
        stop(receiver, receiver_thread)


def test_http_proxy_forwards_chunked_absolute_form_request_body() -> None:
    state = EndpointState()
    receiver = FixtureHTTPServer(("127.0.0.1", 0), state)
    receiver_thread = start(receiver)
    proxy = ProxyServer(
        ("127.0.0.1", 0),
        HTTPProxyHandler,
        state,
        ("127.0.0.1",),
        frozenset({receiver.server_port}),
    )
    proxy_thread = start(proxy)
    try:
        with socket.create_connection(("127.0.0.1", proxy.server_address[1]), timeout=3) as client:
            target = f"http://127.0.0.1:{receiver.server_port}/probe"
            client.sendall(
                (
                    f"POST {target} HTTP/1.1\r\nHost: 127.0.0.1:{receiver.server_port}\r\n"
                    "x-token: t-chunked\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                    "4\r\nbody\r\n0\r\n\r\n"
                ).encode("ascii")
            )
            response = client.makefile("rb").read()
        assert b"200 OK" in response
        request = state.snapshot("t-chunked")["requests"][0]
        assert request["body"] == "body"
        assert request["headers"]["Content-Length"] == "4"
        assert "Transfer-Encoding" not in request["headers"]
    finally:
        stop(proxy, proxy_thread)
        stop(receiver, receiver_thread)


def test_socks5_records_user_token_and_tunnels_bytes() -> None:
    state = EndpointState()
    echo = ThreadedTCPServer(("127.0.0.1", 0), EchoHandler)
    echo_thread = start(echo)
    proxy = ProxyServer(
        ("127.0.0.1", 0),
        Socks5Handler,
        state,
        ("127.0.0.1",),
        frozenset({port(echo)}),
    )
    proxy_thread = start(proxy)
    try:
        with socket.create_connection(proxy.server_address, timeout=3) as client:
            client.sendall(b"\x05\x01\x02")
            assert client.recv(2) == b"\x05\x02"
            username = b"t1"
            password = b"secret"
            client.sendall(
                b"\x01" + bytes((len(username),)) + username + bytes((len(password),)) + password
            )
            assert client.recv(2) == b"\x01\x00"
            echo_port = port(echo)
            client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + echo_port.to_bytes(2, "big"))
            assert client.recv(10)[:2] == b"\x05\x00"
            client.sendall(b"ping")
            assert client.recv(4) == b"ping"
        connection = state.snapshot("t1")["connections"][0]
        assert connection["proxy"] == "socks5"
        assert connection["port"] == port(echo)
    finally:
        stop(proxy, proxy_thread)
        stop(echo, echo_thread)


def test_socks5_untagged_tls_tunnel_is_correlated_by_receiver_host() -> None:
    state = EndpointState()
    state.record_connection("socks5", "app.fly.dev", 443)
    state.record_request("t1", {"path": "/health"}, "app.fly.dev")
    connections = state.snapshot("t1")["connections"]
    assert len(connections) == 1
    assert connections[0]["proxy"] == "socks5"
    assert connections[0]["host"] == "app.fly.dev"
    assert connections[0]["port"] == 443
    assert isinstance(connections[0]["recorded_at"], float)


def test_abandoned_untagged_tunnel_does_not_misattributed_later_direct_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = EndpointState()
    now = [100.0]
    monkeypatch.setattr(ENDPOINT_SERVER["time"], "time", lambda: now[0])
    state.record_connection("socks5", "app.fly.dev", 443)

    now[0] += state.PENDING_TTL_SECONDS + 1
    state.record_request("direct", {"path": "/health"}, "app.fly.dev")
    assert state.snapshot("direct")["connections"] == []

    state.record_connection("http", "app.fly.dev", 443)
    state.record_request("proxied", {"path": "/health"}, "app.fly.dev")
    connections = state.snapshot("proxied")["connections"]
    assert len(connections) == 1
    assert connections[0]["proxy"] == "http"


def test_endpoint_state_bounds_token_records_and_pending_tunnels() -> None:
    state = EndpointState()
    limit = state.MAX_RECORDS_PER_TOKEN
    for index in range(limit + 5):
        state.record_request("busy", {"index": index}, "app.fly.dev")
        state.record_connection("http", "app.fly.dev", 443, token="busy")

    records = state.snapshot("busy")
    assert len(records["requests"]) == limit
    assert records["requests"][0]["index"] == 5
    assert len(records["connections"]) == limit

    for _index in range(state.MAX_PENDING_PER_HOST + 5):
        state.record_connection("http", "app.fly.dev", 443)
    assert len(state._pending["app.fly.dev"]) == state.MAX_PENDING_PER_HOST
    pending = state._pending["app.fly.dev"]
    assert pending[0]["recorded_at"] <= pending[-1]["recorded_at"]


def test_basic_proxy_token_parser_rejects_invalid_credentials() -> None:
    value = base64.b64encode(b"test-token:secret").decode("ascii")
    assert _token_from_authorization(f"Basic {value}") == "test-token"
    assert _token_from_authorization("Bearer opaque") is None
    assert _token_from_authorization("Basic !!!") is None


def test_tcp_and_udp_echo_handlers_echo_payloads() -> None:
    tcp_server = ThreadedTCPServer(("127.0.0.1", 0), EchoHandler)
    tcp_thread = start(tcp_server)
    udp_server = ThreadedUDPServer(("127.0.0.1", 0), DatagramEchoHandler)
    udp_thread = start(udp_server)
    try:
        with socket.create_connection(("127.0.0.1", port(tcp_server)), timeout=3) as client:
            client.sendall(b"ping")
            assert client.recv(4) == b"ping"
        with socket.create_connection(("127.0.0.1", port(tcp_server)), timeout=3) as client:
            client.sendall(b"fixture-private-toke")
            assert client.recv(64) == b"fixture-private-toke"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(3)
            client.sendto(b"ping", ("127.0.0.1", port(udp_server)))
            assert client.recvfrom(16)[0] == b"ping"
    finally:
        stop(udp_server, udp_thread)
        stop(tcp_server, tcp_thread)


def test_harness_transport_proofs_and_tcp_echo_share_the_required_ports(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SPS_HARNESS_TOKEN", "fixture-private-token")
    tcp_server = ThreadedTCPServer(("127.0.0.1", 0), TransportEchoHandler)
    tcp_thread = start(tcp_server)
    udp_server = ThreadedUDPServer(("127.0.0.1", 0), DatagramEchoHandler)
    udp_thread = start(udp_server)
    try:
        with socket.create_connection(("127.0.0.1", port(tcp_server)), timeout=3) as client:
            client.sendall(b"fixture-private-token\n")
            assert client.recv(64) == b"sps-transport-proof\n"
        with socket.create_connection(("127.0.0.1", port(tcp_server)), timeout=3) as client:
            client.sendall(b"ping")
            assert client.recv(4) == b"ping"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(3)
            client.sendto(b"fixture-private-token", ("127.0.0.1", port(udp_server)))
            assert client.recvfrom(64)[0] == b"sps-transport-proof"
            client.sendto(b"ping", ("127.0.0.1", port(udp_server)))
            assert client.recvfrom(64)[0] == b"ping"
    finally:
        stop(udp_server, udp_thread)
        stop(tcp_server, tcp_thread)
