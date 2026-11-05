# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""One application process makes requests before and after native rotation."""

import json
import os
import subprocess
import time
from pathlib import Path
from uuid import uuid4


def request():
    try:
        result = subprocess.run(
            ["python3", "/tmp/sps-secret-request.py"], capture_output=True, timeout=10
        )
        if result.returncode:
            return 0
        return json.loads(result.stdout)["status"]
    except subprocess.TimeoutExpired:
        return 0


def record(path, status):
    destination = Path(path)
    temporary = destination.with_suffix(".pending")
    temporary.write_text(json.dumps({"pid": pid, "instance": instance, "status": status}))
    temporary.replace(destination)


pid, instance = os.getpid(), uuid4().hex
record("/tmp/sps-secret-phase0.json", request())
while not Path("/tmp/sps-secret-continue").is_file():
    time.sleep(0.1)
deadline = time.monotonic() + 45
while time.monotonic() < deadline:
    status = request()
    record("/tmp/sps-secret-phase1.json", status)
    time.sleep(0.25)
