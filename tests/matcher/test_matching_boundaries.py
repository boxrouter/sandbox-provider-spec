# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Public matcher boundaries retain nested diagnostics and reusable report identity."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest

from sandbox_provider_spec.matcher import match
from sandbox_provider_spec.suite import read_suite


def _report(sdks: dict[str, str]) -> dict[str, Any]:
    baseline = read_suite().baseline_ids
    return {
        "spec": "sandbox-provider-spec/0.1",
        "provider": "audit",
        "sdk_versions": sdks,
        "finished_at": "2026-10-01T00:00:00Z",
        "clean": True,
        "selected_tests": list(baseline),
        "tests": [{"id": identifier, "result": "passed"} for identifier in baseline],
    }


def _declaration(sdks: dict[str, str]) -> dict[str, Any]:
    return {
        "spec": "sandbox-provider-spec/0.1",
        "provider": "audit",
        "verified": {"sdks": sdks},
        "resources": {},
        "gates": {
            "snapshots": [{"original_after": "continues"}],
            "previews": [{"access": "public"}],
            "network_lockdown": [{"policy": "deny_all"}],
        },
    }


@pytest.mark.parametrize(
    ("gate", "body", "knob", "available"),
    [
        (
            "snapshots",
            {},
            "original_after",
            {"continues": 1, "briefly_paused": 0, "terminated": 0, "any": 1},
        ),
        (
            "network_lockdown",
            {},
            "policy",
            {"deny_all": 1, "allowlist": 0, "denylist": 0, "open": 0},
        ),
        ("previews", {"ports": [3000]}, "access", {"public": 1, "private": 0, "any": 1}),
    ],
)
def test_nested_missing_knob_reports_actual_restore_alternatives(
    gate: str, body: dict[str, Any], knob: str, available: dict[str, int]
) -> None:
    sdks = {"audit-sdk": "1.0.0"}
    request: dict[str, Any] = {
        "requirements": {"snapshots": {"original_after": "continues"}},
        "restores_need": {"requirements": {gate: body}},
    }
    original = deepcopy(request)
    result = match(request, [_declaration(sdks)], reports=[_report(sdks)])
    rejected = result["rejected"]
    assert rejected is not None
    assert rejected["path"] == f"restores_need.requirements.{gate}.{knob}"
    assert rejected["details"]["offered_by"] == available
    assert request == original
