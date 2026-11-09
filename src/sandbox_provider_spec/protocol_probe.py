# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Standard protocol clients bypass proxy environment variables."""

from __future__ import annotations

import base64
import hashlib
import os
import socket
import ssl
import struct
import urllib.parse
from collections.abc import Mapping
from typing import BinaryIO, cast

from sandbox_provider_spec.driver import NativeFailure

PAYLOAD = b"sps-binary-proof\x00\xff\xfe\r\n"


def receive(stream: BinaryIO, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        chunk = stream.read(length - len(data))
        if not chunk:
            raise NativeFailure("probe_connection_closed")
        data.extend(chunk)
    return bytes(data)


def tcp(inputs: Mapping[str, object]) -> Mapping[str, object]:
    endpoint = cast(Mapping[str, object], inputs["endpoint"])
    host, port = str(endpoint["host"]), int(cast(int, endpoint["port"]))
    try:
        with socket.create_connection((host, port), timeout=10) as connection:
            if inputs["tls"] == "terminated":
                connection = ssl.create_default_context().wrap_socket(
                    connection, server_hostname=host
                )
            with connection, connection.makefile("rb") as stream:
                connection.sendall(PAYLOAD)
                return {"binary_echo": receive(stream, len(PAYLOAD)) == PAYLOAD}
    except OSError:
        raise NativeFailure("probe_connection_failed") from None


def websocket(inputs: Mapping[str, object]) -> Mapping[str, object]:
    url = urllib.parse.urlsplit(str(inputs["url"]))
    if url.scheme not in {"https", "http", "wss", "ws"} or not url.hostname:
        raise ValueError("invalid WebSocket probe URL")
    encrypted = url.scheme in {"https", "wss"}
    port = url.port or (443 if encrypted else 80)
    key = base64.b64encode(os.urandom(16)).decode()
    accept = base64.b64encode(
        hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
    ).decode()
    host = url.netloc
    path = urllib.parse.urlunsplit(("", "", url.path or "/", url.query, ""))
    try:
        with socket.create_connection((url.hostname, port), timeout=10) as connection:
            if encrypted:
                connection = ssl.create_default_context().wrap_socket(
                    connection, server_hostname=url.hostname
                )
            with connection, connection.makefile("rb") as stream:
                connection.sendall(
                    (
                        f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n"
                        f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
                        "Sec-WebSocket-Version: 13\r\n\r\n"
                    ).encode()
                )
                status = stream.readline(4096)
                headers: dict[str, str] = {}
                for _ in range(64):
                    line = stream.readline(4096)
                    if line in {b"\r\n", b"\n"}:
                        break
                    if not line or b":" not in line:
                        raise NativeFailure("probe_websocket_handshake_invalid")
                    name, value = line.decode("latin-1").split(":", 1)
                    headers[name.lower()] = value.strip()
                else:
                    raise NativeFailure("probe_websocket_handshake_invalid")
                if status.split()[1:2] != [b"101"]:
                    return {"binary_echo": False}
                if (
                    headers.get("sec-websocket-accept") != accept
                    or headers.get("upgrade", "").lower() != "websocket"
                ):
                    raise NativeFailure("probe_websocket_handshake_invalid")
                mask = os.urandom(4)
                masked = bytes(value ^ mask[index % 4] for index, value in enumerate(PAYLOAD))
                connection.sendall(bytes([0x82, 0x80 | len(PAYLOAD)]) + mask + masked)
                first, second = receive(stream, 2)
                length = second & 127
                if length == 126:
                    length = struct.unpack("!H", receive(stream, 2))[0]
                if first != 0x82 or second & 128 or length != len(PAYLOAD):
                    raise NativeFailure("probe_websocket_frame_invalid")
                return {"binary_echo": receive(stream, length) == PAYLOAD}
    except OSError:
        raise NativeFailure("probe_connection_failed") from None
