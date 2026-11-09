# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The controlled guest observation rejects missing identities and PID reuse."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from sandbox_provider_spec.suite import suite_path


def test_cancellation_observes_a_live_process_then_its_termination(tmp_path: Path) -> None:
    pid_file = tmp_path / "pid"
    code = (
        (suite_path().parent / "fixtures/process_state.py")
        .read_text()
        .replace("/tmp/sps-cancel-pid", str(pid_file))
    )

    def observe(identity: object) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-c", code],
            env={**os.environ, "SPS_EXPECTED_PROCESS": json.dumps(identity)},
            text=True,
            capture_output=True,
            check=False,
        )

    process = subprocess.Popen(["sleep", "60"])
    try:
        pid_file.write_text(str(process.pid))
        first = observe(None)
        assert first.returncode == 0
        running = json.loads(first.stdout)
        assert running["stopped"] is False
        identity = running["identity"]
        # The PID alone cannot authorize observing another process that reused it.
        assert observe([identity[0], identity[1] + 1]).returncode != 0
        process.terminate()
        process.wait(timeout=5)
        stopped = observe(identity)
        assert stopped.returncode == 0
        assert json.loads(stopped.stdout)["stopped"] is True
        # An unobserved process that has already disappeared establishes nothing.
        assert observe(None).returncode != 0
        pid_file.unlink()
        assert observe(identity).returncode != 0
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
