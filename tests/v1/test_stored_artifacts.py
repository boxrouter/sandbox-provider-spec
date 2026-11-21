# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The account's stored-artifacts quota: `AccountCapacity.stored_artifacts` (a null field, a used
above limit) and the display-only `Limits.stored_artifacts_documented`."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any

import pytest
from test_tester import ContractProvider

from sandbox_provider_spec.v1 import (
    AccountCapacity,
    Discovery,
    StoredArtifacts,
    WireError,
    from_json,
    to_json,
)
from sandbox_provider_spec.v1.tester import TestOptions, run_tests

EXAMPLES = Path(__file__).resolve().parents[2] / "spec" / "provider-api-1.0-examples"


def load(name: str) -> dict[str, Any]:
    found: dict[str, Any] = json.loads((EXAMPLES / f"{name}.json").read_text("utf-8"))
    return found


@pytest.mark.rule("provider-api/stored-artifacts")
def test_stored_artifacts_is_optional_and_each_field_may_be_null() -> None:
    plain = load("AccountCapacity")
    assert "stored_artifacts" not in plain
    assert from_json(AccountCapacity, plain).stored_artifacts is None
    for stated in (
        {"used": 4, "limit": 30},
        {"used": None, "limit": None},
        {"used": 4, "limit": None},
    ):
        body = {**plain, "stored_artifacts": stated}
        parsed = from_json(AccountCapacity, body)
        assert parsed.stored_artifacts == StoredArtifacts(**stated)
        assert to_json(parsed) == body
    with pytest.raises(WireError):
        from_json(AccountCapacity, {**plain, "stored_artifacts": {"used": -1, "limit": None}})


@pytest.mark.rule("provider-api/stored-artifacts")
def test_stored_artifacts_documented_is_valid_without_a_capacity_operation() -> None:
    body = load("Discovery")
    body["limits"] = {**body["limits"], "stored_artifacts_documented": 30}
    found = from_json(Discovery, body)
    assert found.limits.stored_artifacts_documented == 30
    assert to_json(found) == body
    assert "stored_artifacts" not in body["limits"]  # the quota is not a discovery limit
    body["limits"]["stored_artifacts_documented"] = 0
    with pytest.raises(WireError):
        from_json(Discovery, body)


@pytest.mark.rule("provider-api/stored-artifacts")
def test_stored_artifacts_row_skips_without_the_field_and_refuses_a_used_above_limit() -> None:
    row = ("contract.stored_artifacts",)
    assert [
        r["result"] for r in run_tests(ContractProvider(), TestOptions(tests=row))["tests"]
    ] == ["unsupported"]

    class Reports(ContractProvider, manifest=False):
        stored = StoredArtifacts(used=0, limit=30)

        async def account_capacity(self) -> AccountCapacity:
            return dataclasses.replace(
                from_json(AccountCapacity, load("AccountCapacity")), stored_artifacts=self.stored
            )

    results = [r["result"] for r in run_tests(Reports(), TestOptions(tests=row))["tests"]]
    assert results == ["passed"]

    class Above(Reports, manifest=False):
        stored = StoredArtifacts(used=31, limit=30)

    assert [r["result"] for r in run_tests(Above(), TestOptions(tests=row))["tests"]] == ["differs"]
