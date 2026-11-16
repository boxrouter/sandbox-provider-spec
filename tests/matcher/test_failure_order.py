# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""A request's `failed` list keeps one order: the order `fit_resources` checks the facts in."""

import json
import subprocess
import sys

import pytest

_SCRIPT = """
import json
from sandbox_provider_spec.matcher.declaration import build_declaration
from sandbox_provider_spec.matcher.matching import fit_resources
from sandbox_provider_spec.matcher.registry import Registry
from sandbox_provider_spec.matcher.request import Request

needs = {fact: ["plan"] for fact in ("regions", "located_in", "paused_retention_seconds", "gpus")}
declaration = build_declaration({
    "spec": "sandbox-provider-spec/0.1",
    "provider": "fixture",
    "verified": {"sdks": {"test": "1"}},
    "resources": {"needs": needs},
    "gates": {},
})
request = Request(
    lifetime_seconds=None,
    resources={"region": "x:y", "paused_retention_seconds": 60, "gpu_count": 1},
)
_, failed = fit_resources(declaration, request, Registry(), ())
print(json.dumps([entry["resource"] for _, entry in failed]))
"""


def _failed_order(hash_seed: int) -> list[str]:
    run = subprocess.run(
        [sys.executable, "-c", _SCRIPT],
        env={"PYTHONHASHSEED": str(hash_seed), "PATH": ""},
        capture_output=True,
        text=True,
        check=True,
    )
    order: list[str] = json.loads(run.stdout)
    return order


@pytest.mark.parametrize("hash_seed", range(6))
def test_failed_resources_keep_the_check_order_under_any_hash_seed(hash_seed: int) -> None:
    assert _failed_order(hash_seed) == [
        "regions",
        "located_in",
        "gpus",
        "paused_retention_seconds",
        "paused_retention_seconds",
        "region",
        "gpu_model",
    ]
