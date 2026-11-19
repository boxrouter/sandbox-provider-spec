# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""A controlled workload that checks a terminal delivers a long output in order."""

from __future__ import annotations

import base64
from collections.abc import Mapping

from sandbox_provider_spec.driver import Driver

LINES = 20000
"""How many lines `seq` prints: about 108 KB, more than one WebSocket frame of 65536 bytes."""


def observe(driver: Driver, target: object, inputs: Mapping[str, object]) -> Mapping[str, object]:
    """Print `seq 1 20000` on an open terminal and check that the received output holds its
    lines as one contiguous run: none reordered, dropped or repeated.

    A terminal ends each output line with a carriage return and a line feed, so the check removes
    the carriage returns. The run starts after the echo of the typed command, which is not part
    of it, and ends at the last number.
    """
    timeout_ms = inputs.get("timeout_ms", 60000)
    command = base64.b64encode(f"seq 1 {LINES}\r".encode()).decode("ascii")
    driver.call("terminal.write", target, {"data": command})
    seen = driver.call(
        "terminal.output",
        target,
        {"until_contains": f"\r\n{LINES}\r\n", "timeout_ms": timeout_ms},
    )
    data = seen["terminal"]
    if not isinstance(data, (bytes, bytearray)):
        return {"ordered": False}
    expected = "\n".join(str(number) for number in range(1, LINES + 1)).encode()
    return {"ordered": expected in bytes(data).replace(b"\r", b"")}
