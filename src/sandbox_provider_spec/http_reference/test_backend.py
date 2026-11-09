# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Deterministic protocol test double. It executes NOTHING and provides NO isolation."""

from __future__ import annotations

import time
import uuid
from collections import Counter
from typing import Any


class TestBackend:
    """Fixed scripted observations, deliberately named and declared as test-only."""

    kind = "deterministic-test-only"
    authority = "deterministic-test-authority"
    sdks = {"reference-test-backend": "0.1"}

    def __init__(self) -> None:
        self.calls: Counter[str] = Counter()
        self.sandboxes: dict[str, dict[str, Any]] = {}
        self.processes: dict[str, dict[str, Any]] = {}
        self.fail: str | None = None

    def call(self, name: str) -> None:
        self.calls[name] += 1
        if self.fail == name:
            raise OSError("Private diagnostic must never enter the response")

    def create(self, identity: dict[str, Any], env: dict[str, str]) -> None:
        self.call("create")
        self.sandboxes[identity["sandbox_id"]] = {"env": env, "files": {}, "state": "active"}

    def get(self, identity: dict[str, Any]) -> str:
        self.call("get")
        return self.sandboxes.get(identity["sandbox_id"], {}).get("state", "absent")  # type: ignore[no-any-return]

    def destroy(self, identity: dict[str, Any]) -> str:
        self.call("destroy")
        return "destroyed" if self.sandboxes.pop(identity["sandbox_id"], None) else "absent"

    def run(self, request: dict[str, Any], *, deadline: float) -> dict[str, Any]:
        self.call("run")
        # Model argv/env/cwd round trip only, never evaluate a command.
        sandbox = self.sandboxes[request["sandbox"]["sandbox_id"]]
        return {
            "stdout": request["argv"][-1],
            "stderr": "scripted diagnostic\n",
            "exit_code": 7,
            "output_complete": time.monotonic() < deadline,
            **({} if sandbox["state"] == "active" else {"output_complete": False}),
        }

    def read(self, request: dict[str, Any]) -> bytes:
        self.call("read")
        return self.sandboxes[request["sandbox"]["sandbox_id"]]["files"][request["path"]]  # type: ignore[no-any-return]

    def write(self, request: dict[str, Any], data: bytes) -> None:
        self.call("write")
        self.sandboxes[request["sandbox"]["sandbox_id"]]["files"][request["path"]] = data

    def start(self, request: dict[str, Any], output: Any) -> tuple[str, Any]:
        self.call("start")
        sandbox_id = request["sandbox"]["sandbox_id"]
        if sandbox_id not in self.sandboxes:
            raise KeyError(sandbox_id)
        identity = uuid.uuid4().hex
        process = {"state": "running", "code": None, "output": output}
        self.processes[identity] = process
        output.feed("stdout", "ready\n")
        return identity, lambda: (process["state"], process["code"])

    def finish(self, identity: str, *, eof_only: bool = False) -> None:
        process = self.processes[identity]
        process["output"].close()
        if not eof_only:
            process.update(state="exited", code=0)
