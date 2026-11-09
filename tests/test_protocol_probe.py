# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Protocol clients must exchange bytes directly and validate the WebSocket upgrade."""

from __future__ import annotations

import ast
import base64
import hashlib
import socket
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import BinaryIO, cast

import pytest

from sandbox_provider_spec.driver import NativeFailure
from sandbox_provider_spec.protocol_probe import PAYLOAD, receive, tcp, websocket
from sandbox_provider_spec.suite import suite_path

pytestmark = [pytest.mark.integration, pytest.mark.loopback]


def exchange(peer: Callable[[socket.socket], None], client: Callable[[int], object]) -> object:
    errors: list[BaseException] = []
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(5)
        port = listener.getsockname()[1]

        def serve() -> None:
            try:
                with listener.accept()[0] as connection:
                    connection.settimeout(5)
                    peer(connection)
            except BaseException as error:
                errors.append(error)

        worker = threading.Thread(target=serve)
        worker.start()
        try:
            result = client(port)
        finally:
            worker.join(timeout=6)
            assert not worker.is_alive()
            assert not errors
        return result


def test_tcp_echo_preserves_binary_and_ignores_proxy_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")

    def peer(connection: socket.socket) -> None:
        with connection.makefile("rb") as stream:
            assert receive(cast(BinaryIO, stream), len(PAYLOAD)) == PAYLOAD
        connection.sendall(PAYLOAD)

    result = exchange(
        peer, lambda port: tcp({"endpoint": {"host": "127.0.0.1", "port": port}, "tls": "none"})
    )
    assert result == {"binary_echo": True}


@pytest.mark.parametrize("valid", [True, False])
def test_websocket_validates_handshake_and_sends_a_masked_binary_frame(valid: bool) -> None:
    def peer(connection: socket.socket) -> None:
        with connection.makefile("rb") as stream:
            assert stream.readline().startswith(b"GET /probe?public=yes ")
            headers = {}
            while (line := stream.readline()) != b"\r\n":
                name, value = line.decode().split(":", 1)
                headers[name.lower()] = value.strip()
            digest = hashlib.sha1(
                (headers["sec-websocket-key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
            ).digest()
            accept = base64.b64encode(digest).decode() if valid else "wrong"
            connection.sendall(
                (
                    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                    + f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
                ).encode()
            )
            if not valid:
                return
            assert receive(cast(BinaryIO, stream), 2) == bytes([0x82, 0x80 | len(PAYLOAD)])
            mask = receive(cast(BinaryIO, stream), 4)
            masked = receive(cast(BinaryIO, stream), len(PAYLOAD))
            assert bytes(value ^ mask[index % 4] for index, value in enumerate(masked)) == PAYLOAD
            connection.sendall(bytes([0x82, len(PAYLOAD)]) + PAYLOAD)

    def client(port: int) -> object:
        return websocket({"url": f"http://127.0.0.1:{port}/probe?public=yes"})

    if valid:
        assert exchange(peer, client) == {"binary_echo": True}
    else:
        with pytest.raises(NativeFailure, match="probe_websocket_handshake_invalid"):
            exchange(peer, client)


def test_actual_websocket_fixture_uses_http11_and_echoes_binary() -> None:
    path = suite_path().parent / "fixtures/protocol_server.py"
    tree = ast.parse(path.read_text())
    definitions: list[ast.stmt] = [
        node
        for node in tree.body
        if isinstance(node, (ast.Import, ast.ImportFrom, ast.FunctionDef, ast.ClassDef))
    ]
    namespace: dict[str, object] = {}
    exec(compile(ast.Module(body=definitions, type_ignores=[]), str(path), "exec"), namespace)
    handler = cast(type[BaseHTTPRequestHandler], namespace["HTTP"])
    assert handler.protocol_version == "HTTP/1.1"
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        assert websocket({"url": f"http://127.0.0.1:{server.server_port}/probe"}) == {
            "binary_echo": True
        }
    finally:
        server.shutdown()
        server.server_close()
        worker.join()
