# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The baseline distinguishes a live EOF fault from corruption after native exit."""

from __future__ import annotations

import base64
import subprocess
from pathlib import Path
from typing import Any

import pytest

from sandbox_provider_spec.driver import Driver, Inputs, Observation, resource
from sandbox_provider_spec.runner import Runner
from sandbox_provider_spec.suite import read_suite


class LocalProcessDriver(Driver):
    def __init__(self, root: Path, fault: str) -> None:
        super().__init__()
        self.root = root
        self.fault = fault
        self.witness: dict[str, object] = {}

    def local(self, text: str) -> str:
        return text.replace("/tmp/", str(self.root) + "/")

    def create(self, target: object, inputs: Inputs) -> Observation:
        del target, inputs
        return {"resource": self.own("sandbox", self.root, lambda: {"result": "deleted"})}

    def process_start(self, target: object, inputs: Inputs) -> Observation:
        del target
        native = subprocess.Popen(
            ["bash", "-c", self.local(str(inputs["bash_script"]))],
            cwd=self.root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return {"resource": self.own("process", native, lambda: self.cleanup(native))}

    @staticmethod
    def cleanup(native: subprocess.Popen[bytes]) -> Observation:
        if native.poll() is None:
            native.kill()
        native.wait(timeout=5)
        for stream in (native.stdout, native.stderr):
            if stream is not None:
                stream.close()
        return {"result": "deleted"}

    def run(self, target: object, inputs: Inputs) -> Observation:
        del target
        result = subprocess.run(
            ["bash", "-c", self.local(str(inputs["bash_script"]))],
            cwd=self.root,
            capture_output=True,
            check=False,
        )
        return {"stdout": result.stdout, "stderr": result.stderr, "exit_code": result.returncode}

    def files_write(self, target: object, inputs: Inputs) -> Observation:
        del target
        Path(self.local(str(inputs["path"]))).write_bytes(base64.b64decode(str(inputs["data"])))
        return {}

    def process_status(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        native: Any = resource(target).native
        code = native.poll()
        if self.fault == "eof_while_running" and code is None:
            self.witness = {"native_running": True, "native_exit": None, "reported_exit": 0}
            return {"state": "exited", "exit_code": 0}
        return {"state": "running" if code is None else "exited", "exit_code": code}

    def process_wait(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        native: Any = resource(target).native
        code = native.wait(timeout=5)
        if self.fault == "eof_at_native_exit":
            self.witness = {"native_running": False, "native_exit": code, "reported_exit": 0}
            return {"exit_code": 0}
        return {"exit_code": code}


@pytest.mark.parametrize(
    ("fault", "expected", "reason", "witness"),
    [
        ("none", "passed", None, {}),
        (
            "eof_while_running",
            "differs",
            "state_after_close",
            {
                "native_running": True,
                "native_exit": None,
                "reported_exit": 0,
            },
        ),
        (
            "eof_at_native_exit",
            "differs",
            "exit_code",
            {
                "native_running": False,
                "native_exit": 7,
                "reported_exit": 0,
            },
        ),
    ],
)
def test_eof_baseline_uses_live_state_and_preserves_the_later_exit(
    tmp_path: Path, fault: str, expected: str, reason: str | None, witness: dict[str, object]
) -> None:
    driver = LocalProcessDriver(tmp_path, fault)
    test = next(
        case for case in read_suite().tests if case.id == "baseline.process_eof_is_not_exit"
    )
    assert test.id in read_suite().baseline_ids
    result = Runner(driver).run_test(test)
    assert result["result"] == expected
    assert result.get("reason") == reason
    assert driver.witness == witness
    cleanup = result["cleanup"]
    assert isinstance(cleanup, list)
    assert all(item["result"] == "deleted" for item in cleanup)
