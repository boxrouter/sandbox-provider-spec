# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Owned receiver observes only generated test values, never supplies injection."""

import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def handler(config):
    values = config.get("values", [config["value"]])
    header = config.get("header", "X-SPS-Secret")
    has_expected_value = "expected_value" in config
    expected = config.get("expected_value", config["value"])
    counts = [0] * len(values)
    lock = threading.Lock()

    class Receiver(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            request = urllib.parse.urlsplit(self.path)
            query = urllib.parse.parse_qs(request.query)
            nonce = config["nonce"]
            body, status, echo = b"", 403, None
            observed = self.headers.get("X-SPS-Observer") == config["observer"]
            if request.path == "/health/" + nonce:
                status, body = 200, b"ready"
            elif request.path in {"/inject/" + nonce, "/echo/" + nonce}:
                value = self.headers.get(header)
                accepted = value == expected or (
                    not has_expected_value and header == "X-SPS-Secret" and value in values
                )
                if query.get("sps_run") == [nonce] and accepted:
                    with lock:
                        counts[values.index(value) if value in values else 0] += 1
                    status, body = 200, b"received"
                    if request.path.startswith("/echo/"):
                        echo = value
                        body = value.encode()
            elif request.path == "/receipt/" + nonce:
                with lock:
                    received = counts[0] > 0
                if query.get("sps_run") == [nonce] and received and observed:
                    status, body = 200, b"injected-and-not-echoed"
            elif request.path == "/observations/" + nonce and observed:
                with lock:
                    body = json.dumps({"counts": counts}).encode()
                status = 200
            self.send_response(status)
            if echo is not None:
                self.send_header("X-SPS-Echo", echo)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Receiver


if __name__ == "__main__":
    configuration = json.loads(Path("/tmp/sps-receiver-config").read_text())
    server = ThreadingHTTPServer(("0.0.0.0", 7777), handler(configuration))
    Path("/tmp/sps-receiver-ready").touch()
    threading.Timer(240, server.shutdown).start()
    server.serve_forever()
