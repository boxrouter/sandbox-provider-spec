# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Confirm a live remote canvas displays the controlled application in Chromium."""

import json
import sys

from playwright.sync_api import TimeoutError as BrowserTimeout
from playwright.sync_api import sync_playwright

MARKER = """() => [...document.querySelectorAll('canvas')].some(canvas => {
  if (canvas.width < 400 || canvas.height < 200) return false;
  try {
    const context = canvas.getContext('2d');
    return [[30,30],[350,30],[30,175],[350,175]].every(([x,y]) => {
      const pixel = context.getImageData(x,y,1,1).data;
      return [17,203,89].every((value,i) => Math.abs(pixel[i]-value) < 9);
    });
  } catch (_) { return false; }
})"""


def visible(url):
    with sync_playwright() as runner:
        browser = runner.chromium.launch(headless=True, args=["--no-proxy-server"])
        try:
            context = browser.new_context()
            page = context.new_page()
            incoming = []
            page.on(
                "websocket",
                lambda socket: socket.on("framereceived", lambda _: incoming.append(True)),
            )
            page.goto(url, wait_until="domcontentloaded", timeout=20000)
            page.wait_for_function(MARKER, timeout=20000)
            return len(incoming) >= 2
        except BrowserTimeout:
            return False
        finally:
            browser.close()


if __name__ == "__main__":
    print(json.dumps({"desktop_visible": visible(json.load(sys.stdin)["url"])}))
