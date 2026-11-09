# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Test graphical operations against a controlled ordinary GUI application."""

from __future__ import annotations

import base64
import json
import os
import re
import struct
import subprocess
import sys
import time
import urllib.parse
import zlib
from collections.abc import Mapping
from typing import cast
from uuid import uuid4

from sandbox_provider_spec.driver import Driver, NativeFailure
from sandbox_provider_spec.suite import suite_path


def png_valid(data: object) -> bool:
    if not isinstance(data, bytes) or len(data) > 16 * 1024**2 or data[:8] != b"\x89PNG\r\n\x1a\n":
        return False
    position = 8
    compressed = bytearray()
    dimensions = False
    row_bytes = height = 0
    while position + 12 <= len(data):
        length = struct.unpack(">I", data[position : position + 4])[0]
        end = position + length + 12
        if end > len(data):
            return False
        kind, payload = data[position + 4 : position + 8], data[position + 8 : end - 4]
        if zlib.crc32(kind + payload) != struct.unpack(">I", data[end - 4 : end])[0]:
            return False
        if kind == b"IHDR":
            if length != 13 or position != 8:
                return False
            width, height = struct.unpack(">II", payload[:8])
            bit_depth, color, compression, filtering, interlace = payload[8:]
            if bit_depth != 8 or color not in {2, 6} or compression or filtering or interlace:
                return False
            row_bytes = width * (3 if color == 2 else 4) + 1
            dimensions = 400 <= width <= 8192 and 200 <= height <= 8192
            if row_bytes * height > 64 * 1024**2:
                return False
        elif kind == b"IDAT":
            compressed.extend(payload)
        elif kind == b"IEND":
            if length or end != len(data) or not dimensions or not compressed:
                return False
            try:
                decoder = zlib.decompressobj()
                pixels = decoder.decompress(bytes(compressed), 64 * 1024**2)
                return (
                    len(pixels) == row_bytes * height
                    and decoder.eof
                    and not decoder.unused_data
                    and all(pixels[offset] <= 4 for offset in range(0, len(pixels), row_bytes))
                )
            except zlib.error:
                return False
        position = end
    return False


def events(driver: Driver, box: object) -> Mapping[str, object]:
    value = driver.call("files.read_bytes", box, {"path": "/tmp/sps-desktop-events.json"}).get(
        "data"
    )
    if not isinstance(value, (bytes, str)):
        raise NativeFailure("desktop_fixture_response_invalid")
    payload = json.loads(value)
    if not isinstance(payload, dict):
        raise NativeFailure("desktop_fixture_response_invalid")
    return cast(Mapping[str, object], payload)


def observe(driver: Driver, box: object) -> Mapping[str, object]:
    if "desktop.screenshot" in driver.unsupported:
        driver.call("desktop.screenshot", box, {})
    driver.call("desktop.start", box, {})
    # The application connects to the provider's native X11 desktop; it creates
    # no display server and installs no native control implementation.
    script = (suite_path().parent / "fixtures/desktop_app.py").read_bytes()
    driver.call(
        "files.write",
        box,
        {"path": "/tmp/sps-desktop-app.py", "data": base64.b64encode(script).decode()},
    )
    process = driver.call(
        "process.start",
        box,
        {"bash_script": "python3 /tmp/sps-desktop-app.py", "timeout_ms": 180000},
    )
    del process  # Its original native owner is retained in the driver's ledger.
    deadline = time.monotonic() + 30
    while not driver.call("files.exists", box, {"path": "/tmp/sps-desktop-events.json"}).get(
        "exists"
    ):
        if time.monotonic() >= deadline:
            raise NativeFailure("desktop_application_not_ready")
        time.sleep(0.2)
    if events(driver, box).get("ready") is not True:
        raise NativeFailure("desktop_application_not_ready")
    driver.call("desktop.click", box, {"x": 80, "y": 80})
    driver.call("desktop.click", box, {"x": 80, "y": 130})
    value = "sps-" + uuid4().hex
    driver.call("desktop.type", box, {"text": value})
    driver.call("desktop.key", box, {"key": "enter"})
    deadline = time.monotonic() + 5
    result = events(driver, box)
    while result.get("typed") != value and time.monotonic() < deadline:
        time.sleep(0.1)
        result = events(driver, box)
    screenshot = driver.call("desktop.screenshot", box, {}).get("png")
    return {
        "screenshot_valid": png_valid(screenshot),
        "pointer_received": result.get("pointer_received") is True,
        "keyboard_received": result.get("typed") == value,
    }


def browser(inputs: Mapping[str, object]) -> Mapping[str, object]:
    view = inputs.get("view")
    if not isinstance(view, Mapping) or not isinstance(view.get("url"), str):
        raise ValueError("native desktop URL required")
    url = view["url"]
    decoded_url = urllib.parse.unquote(url)
    # Account API keys are never a valid live-view URL credential.
    for key, value in os.environ.items():
        if (
            len(value) >= 12
            and re.search("TOKEN|KEY|SECRET|PASSWORD|AUTH", key, re.I)
            and value in decoded_url
        ):
            return {"desktop_visible": False}
    try:
        result = subprocess.run(
            [sys.executable, "-I", str(suite_path().parent / "fixtures/desktop_browser.py")],
            input=json.dumps({"url": url}).encode(),
            capture_output=True,
            timeout=50,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise NativeFailure("desktop_browser_timeout") from None
    if result.returncode != 0 or len(result.stdout) > 1024:
        raise NativeFailure("desktop_browser_failed")
    payload = json.loads(result.stdout)
    if not isinstance(payload, dict) or not isinstance(payload.get("desktop_visible"), bool):
        raise NativeFailure("desktop_browser_response_invalid")
    return cast(Mapping[str, object], payload)
