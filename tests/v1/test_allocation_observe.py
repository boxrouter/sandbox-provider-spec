# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""`facts.sizes` on a 1.0 provider: the CPU and memory the guest sees must equal the size asked.

A provider's own record of a size can repeat what the create asked, so the step measures the guest
(the probe of `coverage.facts.sizes.delivered`) and the test compares it exactly with the request.
"""

from __future__ import annotations

import json
from typing import Any

from test_tester import LocalProvider

from sandbox_provider_spec.v1 import RunRequest, RunResult
from sandbox_provider_spec.v1.tester import TestOptions, run_tests

ROW = "facts.sizes"


class Guest(LocalProvider, manifest=False):
    """A provider whose guest shows `seen` CPUs and MiB of memory, whatever the create asked."""

    def __init__(self, cpu: float, memory_mib: int) -> None:
        super().__init__()
        self.seen = {"cpu": cpu, "memory_mib": memory_mib}

    async def run(self, sandbox_id: str, request: RunRequest) -> RunResult:
        if "sps-environment-facts" in request.argv[-1]:
            return RunResult(exit_code=0, stdout=json.dumps(self.seen), stderr="")
        return await super().run(sandbox_id, request)


def row(provider: LocalProvider, size: dict[str, Any]) -> dict[str, Any]:
    report = run_tests(provider, TestOptions(tests=(ROW,), fixtures={"test_size": size}))
    (found,) = report["tests"]
    return dict(found)


def test_a_guest_that_shows_exactly_the_size_asked_proves_that_size() -> None:
    found = row(Guest(2, 2048), {"cpu_min": 2, "memory_min_mib": 2048})
    assert found["result"] == "passed", found
    assert found["proves"] == [
        {"fact": "resources.sizes", "value": [{"cpu": 2, "memory_mib": 2048}]}
    ]


def test_a_guest_that_shows_the_default_size_instead_does_not() -> None:
    found = row(Guest(1, 128), {"cpu_min": 2, "memory_min_mib": 2048})
    assert found["result"] == "differs", found


def test_a_guest_that_shows_less_memory_than_asked_does_not() -> None:
    """A virtual machine's kernel keeps some memory, so its guest never shows the allocation
    exactly: it is not a proof of a size, though `coverage.facts.sizes.delivered` accepts it."""
    found = row(Guest(2, 2000), {"cpu_min": 2, "memory_min_mib": 2048})
    assert found["result"] == "differs", found


def test_a_size_with_a_disk_cannot_be_observed_from_the_guest() -> None:
    found = row(Guest(2, 2048), {"cpu_min": 2, "memory_min_mib": 2048, "disk_min_mib": 8192})
    assert (found["result"], found["reason"]) == (
        "not_run",
        "allocation_observed_for_cpu_and_memory_only",
    )
