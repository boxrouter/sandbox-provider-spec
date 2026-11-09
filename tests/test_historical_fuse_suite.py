# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Recognize the archived FUSE suite without weakening result or source validation."""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

from sandbox_provider_spec.evidence import (
    _check_cited_tests,
    _source_suite_rules,
    check_report_evidence,
)

# Archived suite.yaml SHA-256:
# 8bf9f8410a848fe6b955da9934b30ad2cb51bc421b9d4f0652b90f2da0fca0a9
# Archived coverage.yaml SHA-256:
# 6f77705a9117026a308e9315c9868c516d411dfa43ac3bd66bfb1bf15102c12a
HISTORICAL_SUITE = "sha256:8bc88facb0f056f7c0ef3dae4667f5ff1d6d7548db04023b48004ab9cbd5bf64"
HISTORICAL_CHECK = "sha256:e18c83b874c1833c7f97d618c13eec249793d90b2a3b1f0de4c19dc90509c22f"


def historical_report() -> dict[str, Any]:
    return {
        "revision": "a" * 40,
        "suite_digest": HISTORICAL_SUITE,
        "selected_tests": ["fuse_mount.lifecycle"],
        "check_digests": {"fuse_mount.lifecycle": HISTORICAL_CHECK},
        "tests": [
            {
                "id": "fuse_mount.lifecycle",
                "rules": ["fuse_mount/lifecycle"],
                "result": "passed",
                "proves": [{"gate": "fuse_mount", "value": True}],
            }
        ],
    }


def test_archived_suite_restores_exact_rule_map() -> None:
    rules, errors = _source_suite_rules(HISTORICAL_SUITE)
    assert errors == []
    assert rules is not None and len(rules) == 97
    assert rules["fuse_mount.lifecycle"] == ["fuse_mount/lifecycle"]
    digest = hashlib.sha256(json.dumps(rules, sort_keys=True, separators=(",", ":")).encode())
    assert digest.hexdigest() == "25dcf397aa503acfd1c3487021d92201cc68c815281fca125cd29b8674693964"


def test_historical_recognition_preserves_original_check_digest() -> None:
    report = historical_report()
    original = json.dumps(report, sort_keys=True)
    assert check_report_evidence(report) == []
    assert json.dumps(report, sort_keys=True) == original


def test_unknown_suite_remains_a_hard_error() -> None:
    report = historical_report()
    report["suite_digest"] = "sha256:" + "0" * 64
    assert check_report_evidence(report) == [
        "report suite digest is not recognized by this package"
    ]


def test_changed_historical_rules_remain_a_hard_error() -> None:
    report = historical_report()
    report["tests"][0]["rules"] = []
    assert check_report_evidence(report) == [
        "report test fuse_mount.lifecycle rules differ from its source suite"
    ]


@pytest.mark.parametrize("result", ["error", "differs", "not_run", "unsupported"])
def test_recognized_history_does_not_accept_failed_citations(result: str) -> None:
    report = historical_report()
    report["tests"][0]["result"] = result
    assert check_report_evidence(report) == []
    errors, proofs = _check_cited_tests(
        {"tests": ["fuse_mount.lifecycle"]},
        report=report,
        evidence_path="gates.fuse_mount.0",
        declared_value=True,
    )
    assert errors == [f"test fuse_mount.lifecycle must be passed, not {result}"]
    assert proofs == []
