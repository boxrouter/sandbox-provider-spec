# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Controlled HTTP, stream, TCP, UDP, SOCKS5 and HTTP-proxy endpoints."""

from __future__ import annotations

import base64
import binascii
import json
import os
import select
import socket
import socketserver
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import unquote, urlsplit

MAX_REQUEST_BYTES = 2 * 1024 * 1024
MAX_PROXY_HEADER_BYTES = 64 * 1024
PROXY_TARGET_PORTS = frozenset({80, 443, 8443, 7000, 7001})
TRANSPORT_PROOF = b"sps-transport-proof"
STREAM_PROOF = b"sps-connection-proof\n"


class EndpointState:
    """Thread-safe request and proxy-connection records keyed by test token."""

    PENDING_TTL_SECONDS = 30
    MAX_RECORDS_PER_TOKEN = 100
    MAX_PENDING_PER_HOST = 100

    @staticmethod
    def _append_bounded(records: list[dict[str, Any]], event: dict[str, Any], limit: int) -> None:
        records.append(event)
        del records[:-limit]

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._requests: dict[str, list[dict[str, Any]]] = {}
        self._connections: dict[str, list[dict[str, Any]]] = {}
        self._pending: dict[str, list[dict[str, Any]]] = {}

    @staticmethod
    def _host_key(host: str) -> str:
        candidate = urlsplit(f"//{host}").hostname
        return (candidate or host).rstrip(".").lower()

    def record_request(self, token: str, request: dict[str, Any], host: str) -> None:
        """Record one receiver request and consume its matching proxy tunnel."""
        if not token or len(token) > 256:
            return
        key = self._host_key(host)
        with self._lock:
            self._append_bounded(
                self._requests.setdefault(token, []), request, self.MAX_RECORDS_PER_TOKEN
            )
            queued = self._pending.get(key, [])
            now = time.time()
            queued[:] = [
                event for event in queued if now - event["recorded_at"] <= self.PENDING_TTL_SECONDS
            ]
            if queued:
                event = queued.pop(0)
                self._append_bounded(
                    self._connections.setdefault(token, []), event, self.MAX_RECORDS_PER_TOKEN
                )
                if not queued:
                    self._pending.pop(key, None)

    def record_connection(
        self,
        proxy: str,
        host: str,
        port: int,
        token: str | None = None,
        method: str | None = None,
    ) -> None:
        """Record a tokened proxy request or queue a tunnel for receiver correlation."""
        event: dict[str, Any] = {
            "proxy": proxy,
            "host": self._host_key(host),
            "port": port,
            "recorded_at": time.time(),
        }
        if method:
            event["method"] = method
        with self._lock:
            if token:
                if len(token) <= 256:
                    self._append_bounded(
                        self._connections.setdefault(token, []),
                        event,
                        self.MAX_RECORDS_PER_TOKEN,
                    )
                return
            key = self._host_key(host)
            now = event["recorded_at"]
            queued = self._pending.setdefault(key, [])
            queued[:] = [
                pending
                for pending in queued
                if now - pending["recorded_at"] <= self.PENDING_TTL_SECONDS
            ]
            self._append_bounded(queued, event, self.MAX_PENDING_PER_HOST)

    def snapshot(self, token: str) -> dict[str, Any]:
        """Return a stable copy of all records for one token."""
        with self._lock:
            return {
                "token": token,
                "requests": list(self._requests.get(token, [])),
                "connections": list(self._connections.get(token, [])),
            }


class EndpointHTTPServer(ThreadingHTTPServer):
    """HTTP server carrying its shared recording state."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], state: EndpointState) -> None:
        self.endpoint_state = state
        super().__init__(address, EndpointHandler)


class EndpointHandler(BaseHTTPRequestHandler):
    """HTTP receiver with health, record and streaming routes."""

    protocol_version = "HTTP/1.1"
    server: EndpointHTTPServer

    def log_message(self, format: str, *args: object) -> None:
        del format, args

    def do_GET(self) -> None:
        self._dispatch()

    def do_HEAD(self) -> None:
        self._dispatch()

    def do_POST(self) -> None:
        self._dispatch()

    def do_PUT(self) -> None:
        self._dispatch()

    def do_PATCH(self) -> None:
        self._dispatch()

    def do_DELETE(self) -> None:
        self._dispatch()

    def _dispatch(self) -> None:
        length = self.headers.get("Content-Length", "0")
        try:
            body_length = int(length)
        except ValueError:
            self.send_error(400, "invalid content length")
            return
        if body_length < 0 or body_length > MAX_REQUEST_BYTES:
            self.send_error(413, "request body too large")
            return
        body = self.rfile.read(body_length) if body_length else b""
        token = self.headers.get("x-token") or self.headers.get("x-sps-probe", "")
        if token:
            request = {
                "method": self.command,
                "path": self.path,
                "headers": dict(self.headers.items()),
                "body": body.decode("utf-8", errors="replace"),
                "body_base64": base64.b64encode(body).decode("ascii"),
            }
            self.server.endpoint_state.record_request(token, request, self.headers.get("Host", ""))

        path = urlsplit(self.path).path
        if path == "/records/" or path.startswith("/records/"):
            requested_token = unquote(path.removeprefix("/records/"))
            self._send_json(self.server.endpoint_state.snapshot(requested_token))
            return
        if path == "/stream":
            self._stream()
            return
        if path == "/probe":
            self._send_bytes(TRANSPORT_PROOF)
            return
        if path == "/health":
            self._send_json({"ok": True})
            return
        self._send_json({"ok": True, "method": self.command, "path": self.path})

    def _send_json(self, value: dict[str, Any]) -> None:
        payload = json.dumps(value, separators=(",", ":")).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)
        self.close_connection = True

    def _send_bytes(self, payload: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)
        self.close_connection = True

    def _stream(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        try:
            while True:
                chunk = STREAM_PROOF
                self.wfile.write(f"{len(chunk):X}\r\n".encode("ascii") + chunk + b"\r\n")
                self.wfile.flush()
                time.sleep(0.5)
        except OSError:
            return


class EchoHandler(socketserver.BaseRequestHandler):
    """Echo TCP payloads until the caller closes the connection."""

    def handle(self) -> None:
        self.request.settimeout(60)
        while data := self.request.recv(65536):
            self.request.sendall(data)


class TransportEchoHandler(socketserver.BaseRequestHandler):
    """Echo general TCP payloads and answer the private transport proof probe."""

    def handle(self) -> None:
        self.request.settimeout(60)
        expected = os.environ.get("SPS_HARNESS_TOKEN", "").encode("utf-8") + b"\n"
        pending = bytearray()
        while data := self.request.recv(65536):
            pending.extend(data)
            if expected != b"\n":
                if pending == expected:
                    self.request.sendall(TRANSPORT_PROOF + b"\n")
                    pending.clear()
                    continue
                if expected.startswith(pending):
                    continue
            self.request.sendall(pending)
            pending.clear()


class DatagramEchoHandler(socketserver.BaseRequestHandler):
    """Echo one UDP datagram unchanged."""

    def handle(self) -> None:
        data, server_socket = self.request
        token = os.environ.get("SPS_HARNESS_TOKEN", "").encode("utf-8")
        response = TRANSPORT_PROOF if token and data == token else data
        server_socket.sendto(response, self.client_address)


class ThreadedTCPServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


class ThreadedUDPServer(socketserver.ThreadingUDPServer):
    daemon_threads = True
    allow_reuse_address = True


class ProxyServer(ThreadedTCPServer):
    """TCP server shared by the restricted SOCKS5 and HTTP proxies."""

    def __init__(
        self,
        address: tuple[str, int],
        handler: type[socketserver.BaseRequestHandler],
        state: EndpointState,
        allowed_hosts: tuple[str, ...],
        allowed_ports: frozenset[int] = PROXY_TARGET_PORTS,
    ) -> None:
        self.endpoint_state = state
        self.allowed_hosts = allowed_hosts
        self.allowed_ports = allowed_ports
        super().__init__(address, handler)


def _token_from_authorization(value: str) -> str | None:
    scheme, _, encoded = value.partition(" ")
    if scheme.lower() != "basic" or not encoded:
        return None
    try:
        decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return None
    username, separator, _password = decoded.partition(":")
    return username if separator and username else None


def _allowed_target(server: ProxyServer, host: str, port: int) -> bool:
    hostname = host.rstrip(".").lower()
    if port not in server.allowed_ports:
        return False
    for allowed in server.allowed_hosts:
        normalized = allowed.lower().rstrip(".")
        if normalized.startswith("*."):
            if hostname.endswith(normalized[1:]) and hostname != normalized[2:]:
                return True
        elif hostname == normalized:
            return True
    return False


def _connect_target(server: ProxyServer, host: str, port: int) -> socket.socket:
    if not _allowed_target(server, host, port):
        raise PermissionError("proxy destination is not allowed")
    return socket.create_connection((host, port), timeout=10)


def _relay(client: socket.socket, upstream: socket.socket) -> None:
    client.setblocking(False)
    upstream.setblocking(False)
    while True:
        readable, _, _ = select.select([client, upstream], [], [], 60)
        if not readable:
            return
        for source in readable:
            destination = upstream if source is client else client
            try:
                payload = source.recv(65536)
            except (ConnectionResetError, OSError):
                return
            if not payload:
                return
            try:
                destination.sendall(payload)
            except (ConnectionResetError, OSError):
                return


def _read_proxy_headers(stream: Any) -> tuple[list[bytes], dict[str, str]]:
    lines: list[bytes] = []
    headers: dict[str, str] = {}
    total = 0
    while True:
        line = stream.readline(MAX_PROXY_HEADER_BYTES + 1)
        if not line:
            raise EOFError
        total += len(line)
        if total > MAX_PROXY_HEADER_BYTES or not line.endswith(b"\n"):
            raise ValueError("proxy headers are too large")
        if line in {b"\r\n", b"\n"}:
            break
        lines.append(line)
        name, separator, value = line.decode("iso-8859-1").partition(":")
        if separator:
            headers[name.strip().lower()] = value.strip()
    return lines, headers


def _tunnel(client: socket.socket, upstream: socket.socket) -> None:
    try:
        _relay(client, upstream)
    finally:
        upstream.close()


def _read_exact(stream: Any, count: int) -> bytes:
    data = bytearray()
    while len(data) < count:
        chunk = stream.read(count - len(data))
        if not chunk:
            raise EOFError
        data.extend(chunk)
    return bytes(data)


class Socks5Handler(socketserver.BaseRequestHandler):
    """SOCKS5 CONNECT endpoint with optional username/password token."""

    server: ProxyServer

    def handle(self) -> None:
        client = self.request
        client.settimeout(15)
        stream = client.makefile("rb")
        try:
            version, count = _read_exact(stream, 2)
            methods = _read_exact(stream, count)
            method = 2 if 2 in methods else 0 if 0 in methods else 255
            client.sendall(bytes((5, method)))
            token: str | None = None
            if method == 2:
                auth_version = _read_exact(stream, 1)[0]
                username_length = _read_exact(stream, 1)[0]
                username = _read_exact(stream, username_length).decode("utf-8", errors="replace")
                password_length = _read_exact(stream, 1)[0]
                _read_exact(stream, password_length)
                if auth_version != 1 or not username:
                    client.sendall(b"\x01\x01")
                    return
                token = username
                client.sendall(b"\x01\x00")
            if version != 5 or method == 255:
                return
            version, command, _reserved, address_type = _read_exact(stream, 4)
            if address_type == 1:
                host = socket.inet_ntop(socket.AF_INET, _read_exact(stream, 4))
            elif address_type == 3:
                length = _read_exact(stream, 1)[0]
                host = _read_exact(stream, length).decode("idna")
            elif address_type == 4:
                host = socket.inet_ntop(socket.AF_INET6, _read_exact(stream, 16))
            else:
                client.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            port = int.from_bytes(_read_exact(stream, 2), "big")
            if version != 5 or command != 1:
                client.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            try:
                upstream = _connect_target(self.server, host, port)
            except (OSError, PermissionError, ValueError):
                client.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            self.server.endpoint_state.record_connection("socks5", host, port, token)
            client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            _tunnel(client, upstream)
        except (EOFError, OSError, UnicodeError, ValueError):
            return
        finally:
            stream.close()


class HTTPProxyHandler(socketserver.BaseRequestHandler):
    """HTTP CONNECT and absolute-form proxy endpoint."""

    server: ProxyServer

    def handle(self) -> None:
        client = self.request
        client.settimeout(15)
        stream = client.makefile("rb")
        try:
            request_line = stream.readline(MAX_PROXY_HEADER_BYTES + 1)
            if not request_line or len(request_line) > MAX_PROXY_HEADER_BYTES:
                return
            method, target, _version = (
                request_line.decode("iso-8859-1").rstrip("\r\n").split(" ", 2)
            )
            _header_lines, headers = _read_proxy_headers(stream)
            token = headers.get("x-token") or _token_from_authorization(
                headers.get("proxy-authorization", "")
            )
            if method.upper() == "CONNECT":
                parsed = urlsplit(f"//{target}")
                host = parsed.hostname or ""
                port = parsed.port or 443
                try:
                    upstream = _connect_target(self.server, host, port)
                except (OSError, PermissionError, ValueError):
                    client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                    return
                self.server.endpoint_state.record_connection("http", host, port, token)
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                _tunnel(client, upstream)
                return

            parsed = urlsplit(target)
            if parsed.scheme.lower() != "http" or not parsed.hostname:
                client.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                return
            host = parsed.hostname
            port = parsed.port or 80
            try:
                upstream = _connect_target(self.server, host, port)
            except (OSError, PermissionError, ValueError):
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                return
            self.server.endpoint_state.record_connection("http", host, port, token, method)
            transfer_encoding = headers.get("transfer-encoding", "").lower()
            if transfer_encoding:
                if transfer_encoding != "chunked" or "content-length" in headers:
                    upstream.close()
                    client.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                    return
                body = bytearray()
                while True:
                    size_line = stream.readline(MAX_PROXY_HEADER_BYTES + 1)
                    if not size_line or len(size_line) > MAX_PROXY_HEADER_BYTES:
                        raise ValueError("invalid chunk size")
                    try:
                        chunk_size = int(size_line.split(b";", 1)[0].strip(), 16)
                    except ValueError as exc:
                        raise ValueError("invalid chunk size") from exc
                    if chunk_size < 0 or len(body) + chunk_size > MAX_REQUEST_BYTES:
                        upstream.close()
                        client.sendall(
                            b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n"
                        )
                        return
                    if chunk_size == 0:
                        while stream.readline(MAX_PROXY_HEADER_BYTES + 1) not in {b"\r\n", b"\n"}:
                            pass
                        break
                    chunk = _read_exact(stream, chunk_size)
                    if _read_exact(stream, 2) != b"\r\n":
                        raise ValueError("invalid chunk terminator")
                    body.extend(chunk)
                body_bytes = bytes(body)
                output_body_headers = [
                    line
                    for line in _header_lines
                    if line.split(b":", 1)[0].strip().lower()
                    not in {b"transfer-encoding", b"trailer"}
                ]
                output_body_headers.append(f"Content-Length: {len(body_bytes)}\r\n".encode("ascii"))
            else:
                try:
                    body_length = int(headers.get("content-length", "0"))
                except ValueError:
                    upstream.close()
                    client.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                    return
                if body_length < 0 or body_length > MAX_REQUEST_BYTES:
                    upstream.close()
                    client.sendall(b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n")
                    return
                body_bytes = stream.read(body_length) if body_length else b""
                output_body_headers = _header_lines
            path = parsed.path or "/"
            if parsed.query:
                path = f"{path}?{parsed.query}"
            output_headers = [
                line
                for line in output_body_headers
                if line.split(b":", 1)[0].strip().lower()
                not in {b"proxy-authorization", b"proxy-connection", b"connection"}
            ]
            if "host" not in headers:
                output_headers.append(f"Host: {host}:{port}\r\n".encode("ascii"))
            output_headers.append(b"Connection: close\r\n")
            upstream.sendall(
                f"{method} {path} HTTP/1.1\r\n".encode("ascii")
                + b"".join(output_headers)
                + b"\r\n"
                + body_bytes
            )
            upstream.settimeout(30)
            while response := upstream.recv(65536):
                client.sendall(response)
            upstream.close()
        except (EOFError, OSError, UnicodeError, ValueError):
            return
        finally:
            stream.close()


def _allowed_hosts_from_environment() -> tuple[str, ...]:
    configured = os.environ.get("SPS_PROXY_ALLOWED_HOSTS", "")
    return tuple(value.strip().lower() for value in configured.split(",") if value.strip())


def _start(server: socketserver.BaseServer) -> threading.Thread:
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread


def main() -> None:
    """Start all fixture endpoints and keep the container process alive."""
    state = EndpointState()
    bind_host = os.environ.get("SPS_BIND_HOST", "0.0.0.0")
    udp_host = "fly-global-services" if os.environ.get("FLY_APP_NAME") else bind_host
    allowed_hosts = _allowed_hosts_from_environment()
    http = EndpointHTTPServer((bind_host, 8080), state)
    tcp_echo = ThreadedTCPServer((bind_host, 7000), TransportEchoHandler)
    udp_echo = ThreadedUDPServer((udp_host, 7001), DatagramEchoHandler)
    tls_echo = ThreadedTCPServer((bind_host, 8443), TransportEchoHandler)
    socks = ProxyServer((bind_host, 1080), Socks5Handler, state, allowed_hosts)
    http_proxy = ProxyServer((bind_host, 3128), HTTPProxyHandler, state, allowed_hosts)
    servers: list[socketserver.BaseServer] = [http, tcp_echo, udp_echo, tls_echo, socks, http_proxy]
    for server in servers:
        _start(server)
    try:
        threading.Event().wait()
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
