# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""An unattached application process records progress without an SDK connection."""

import json
import os
import time
from pathlib import Path

started = previous = time.monotonic()
count = 0
longest_gap = 0.0
path = Path("/tmp/sps-idle-activity.json")
while True:
    now = time.monotonic()
    count += 1
    longest_gap = max(longest_gap, now - previous)
    temporary = path.with_suffix(".pending")
    temporary.write_text(
        json.dumps(
            {
                "elapsed": now - started,
                "count": count,
                "longest_gap": longest_gap,
                "pid": os.getpid(),
            }
        )
    )
    temporary.replace(path)
    previous = now
    time.sleep(0.1)
