# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Observe only the controlled cancellation workload, including PID reuse."""

import json
import os
from pathlib import Path

pid = int(Path("/tmp/sps-cancel-pid").read_text())
if pid <= 0:
    raise ValueError("invalid controlled process")
expected = json.loads(os.environ.get("SPS_EXPECTED_PROCESS", "null"))
if expected is not None and (len(expected) != 2 or expected[0] != pid):
    raise ValueError("controlled process identity changed")
try:
    # The command name may contain spaces or parentheses. Fields after the final
    # parenthesis start at Linux stat field 3; starttime is field 22.
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    start_time = int(fields[19])
    if expected is not None and expected[1] != start_time:
        raise ValueError("controlled process identity changed")
    print(json.dumps({"identity": [pid, start_time], "stopped": fields[0] == "Z"}))
except FileNotFoundError:
    if expected is None:
        raise
    print(json.dumps({"identity": expected, "stopped": True}))
