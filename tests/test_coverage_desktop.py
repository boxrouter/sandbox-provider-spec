# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Desktop proof requires valid pixels, native events, and live browser transport."""

from __future__ import annotations

import base64
import hashlib
import json
import runpy
import struct
import threading
import zlib
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import cast

import pytest
from playwright.sync_api import sync_playwright

from sandbox_provider_spec import coverage_desktop as probe
from sandbox_provider_spec.driver import Driver, Inputs, Observation, Unsupported
from sandbox_provider_spec.suite import suite_path


def chunk(kind: bytes, value: bytes) -> bytes:
    return (
        struct.pack(">I", len(value)) + kind + value + struct.pack(">I", zlib.crc32(kind + value))
    )


def png(pixels: bytes | None = None) -> bytes:
    header = struct.pack(">IIBBBBB", 400, 200, 8, 2, 0, 0, 0)
    data = pixels if pixels is not None else (b"\x00" + b"\x11\xcb\x59" * 400) * 200
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(data))
        + chunk(b"IEND", b"")
    )


def test_screenshot_requires_decodable_image_rows_and_valid_crcs() -> None:
    image = png()
    assert probe.png_valid(image)
    assert not probe.png_valid(png(b"not image pixels"))
    assert not probe.png_valid(image[:-1] + b"!")
    assert not probe.png_valid(image + b"extra")


def test_url_credential_cannot_be_an_encoded_account_api_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SPS_TEST_API_KEY", "account-key-abcdefghijkl/+123")
    assert probe.browser(
        {"view": {"url": "https://fixture.invalid/?token=account-key-abcdefghijkl%2F%2B123"}}
    ) == {
        "desktop_visible": False,
    }


def test_audited_native_desktop_absence_is_unsupported_before_fixture_allocation() -> None:
    class Absent(Driver):
        unsupported = {"desktop.screenshot": "native_desktop_absent"}

    with pytest.raises(Unsupported, match="native_desktop_absent"):
        probe.observe(Absent(), {})


class DesktopDriver(Driver):
    def __init__(self, *, lose_keyboard: bool) -> None:
        super().__init__()
        self.lose_keyboard = lose_keyboard
        self.value = ""
        self.pointer = False
        self.committed = False

    def call(self, operation: str, target: object, inputs: Inputs) -> Observation:
        del target
        if operation in {"desktop.start", "files.write", "process.start"}:
            return {}
        if operation == "files.exists":
            return {"exists": True}
        if operation == "files.read_bytes":
            return {
                "data": json.dumps(
                    {
                        "ready": True,
                        "pointer_received": self.pointer,
                        "typed": self.value if self.committed else "",
                    }
                )
            }
        if operation == "desktop.click":
            self.pointer = True
        elif operation == "desktop.type":
            self.value = str(inputs["text"])
        elif operation == "desktop.key":
            self.committed = not self.lose_keyboard
        else:
            assert operation == "desktop.screenshot"
            return {"png": png()}
        return {}


@pytest.mark.parametrize("lose_keyboard", [False, True])
def test_keyboard_must_reach_the_same_graphical_application(
    monkeypatch: pytest.MonkeyPatch, lose_keyboard: bool
) -> None:
    clock = [0.0]
    monkeypatch.setattr("sandbox_provider_spec.coverage_desktop.time.monotonic", lambda: clock[0])
    monkeypatch.setattr(
        "sandbox_provider_spec.coverage_desktop.time.sleep",
        lambda seconds: clock.__setitem__(0, clock[0] + seconds),
    )
    assert probe.observe(DesktopDriver(lose_keyboard=lose_keyboard), {}) == {
        "screenshot_valid": True,
        "pointer_received": True,
        "keyboard_received": not lose_keyboard,
    }


def test_chromium_requires_live_websocket_frames_as_well_as_matching_canvas_pixels() -> None:
    with sync_playwright() as runner:
        if not Path(runner.chromium.executable_path).exists():
            pytest.skip("Install Chromium to run the browser integration test")
    module = runpy.run_path(str(suite_path().parent / "fixtures/desktop_browser.py"))
    visible = cast(Callable[[str], bool], module["visible"])

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.headers.get("Upgrade", "").lower() == "websocket":
                key = self.headers["Sec-WebSocket-Key"]
                accept = base64.b64encode(
                    hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
                ).decode()
                self.send_response(101)
                self.send_header("Upgrade", "websocket")
                self.send_header("Connection", "Upgrade")
                self.send_header("Sec-WebSocket-Accept", accept)
                self.end_headers()
                self.wfile.write(b"\x81\x04draw\x81\x04draw")
                self.wfile.flush()
                self.connection.settimeout(3)
                try:
                    self.connection.recv(128)
                except TimeoutError:
                    pass
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            drawing = (
                "const c=document.querySelector('canvas').getContext('2d');"
                "c.fillStyle='#11cb59';c.fillRect(0,0,400,200);"
            )
            script = (
                drawing
                if self.path == "/static"
                else "const s=new WebSocket('ws://'+location.host+'/socket');s.onmessage=()=>{"
                + drawing
                + "};"
            )
            self.wfile.write(
                ("<canvas width=400 height=200></canvas><script>" + script + "</script>").encode()
            )

        def log_message(self, *_: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}"
        assert not visible(url + "/static")
        assert visible(url + "/live")
    finally:
        server.shutdown()
        server.server_close()
        worker.join()
