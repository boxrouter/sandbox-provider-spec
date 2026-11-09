# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Capture a test response privately; runner assertions never retain the value."""

import base64
import json
import os
import urllib.error
import urllib.request
from pathlib import Path

config = json.loads(Path("/tmp/sps-secret-request.json").read_text())
headers = {"Accept-Encoding": "identity"}
if config["use_placeholder"]:
    headers["X-SPS-Secret"] = os.environ.get("SPS_SECRET_PLACEHOLDER", "")
request = urllib.request.Request(config["url"], headers=headers)
opener = urllib.request.build_opener(
    urllib.request.ProxyHandler({})
    if config.get("ignore_proxy", False)
    else urllib.request.ProxyHandler()
)
try:
    response = opener.open(request, timeout=5)
except urllib.error.HTTPError as error:
    response = error
except (urllib.error.URLError, TimeoutError):
    if not config.get("ignore_proxy", False):
        raise
    print(json.dumps({"status": 0, "headers": {}, "body": ""}))
    raise SystemExit(0) from None
with response:
    print(
        json.dumps(
            {
                "status": response.code,
                "headers": dict(response.headers),
                "body": base64.b64encode(response.read(65536)).decode(),
            }
        )
    )
