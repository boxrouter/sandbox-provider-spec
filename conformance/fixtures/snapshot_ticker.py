# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Guest-only snapshot instrumentation; counters and one monotonic clock."""

import sys
import time

with open(sys.argv[1], "w", encoding="ascii") as output:
    for counter in range(3000):
        output.write(f"{counter} {time.monotonic_ns()}\n")
        output.flush()
        time.sleep(0.1)
