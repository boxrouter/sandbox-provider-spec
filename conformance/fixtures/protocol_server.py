# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Owned guest fixture for HTTP, WebSocket and raw TCP conformance traffic."""

import base64
import hashlib
import json
import socketserver
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

configuration = json.loads(Path("/tmp/sps-server-configuration.json").read_text())


def receive(stream, length):
    data = b""
    while len(data) < length:
        chunk = stream.read(length - len(data))
        if not chunk:
            raise EOFError
        data += chunk
    return data


class Echo(socketserver.StreamRequestHandler):
    def handle(self):
        while data := self.rfile.read(1):
            self.wfile.write(data)
            self.wfile.flush()


class HTTP(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.headers.get("Upgrade", "").lower() != "websocket":
            self.send_response(200)
            self.send_header("Content-Length", str(len(b"sps-preview-proof")))
            self.end_headers()
            self.wfile.write(b"sps-preview-proof")
            return
        key = self.headers["Sec-WebSocket-Key"]
        answer = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
        ).decode()
        self.send_response(101)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", answer)
        self.end_headers()
        try:
            first, second = receive(self.rfile, 2)
            length = second & 127
            if length == 126:
                length = struct.unpack("!H", receive(self.rfile, 2))[0]
            if length > 65536 or not second & 128 or first & 15 not in {1, 2}:
                return
            mask = receive(self.rfile, 4)
            payload = receive(self.rfile, length)
            payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
            header = (
                bytes([0x82, length]) if length < 126 else b"\x82\x7e" + struct.pack("!H", length)
            )
            self.wfile.write(header + payload)
            self.wfile.flush()
        except (EOFError, OSError):
            return


servers = []
for port in configuration["ports"]:
    if configuration["protocol"] == "tcp":
        server = socketserver.ThreadingTCPServer((configuration.get("bind", "0.0.0.0"), port), Echo)
    else:
        server = ThreadingHTTPServer((configuration.get("bind", "0.0.0.0"), port), HTTP)
    servers.append(server)
    threading.Thread(target=server.serve_forever, daemon=True).start()
Path("/tmp/sps-coverage-server-ready").write_text("ready")
threading.Event().wait()
