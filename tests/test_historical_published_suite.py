# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""A published suite stays recognizable after unrelated coverage tests change."""

import hashlib
import json
from typing import Any

import pytest

from sandbox_provider_spec.evidence import _source_suite_rules, check_report_evidence

# The 0.3.117 wheel is identified by its artifact checksum:
# 8e768bb8a82184268da69f7dda67418aefc1419f9e91f08d5d3e1011c9ab255e.
PUBLISHED_SUITE = "sha256:588d4ce8064b70a6255afb37c6e4bce3f85e10c3562e516d54fa24d53359b030"


def _report() -> dict[str, Any]:
    return {
        "revision": "a" * 40,
        "suite_digest": PUBLISHED_SUITE,
        "selected_tests": ["baseline.run_output"],
        "tests": [
            {
                "id": "baseline.run_output",
                "rules": ["baseline/run"],
                "result": "passed",
            }
        ],
    }


def test_published_coverage_suite_keeps_its_exact_rule_map() -> None:
    rules, errors = _source_suite_rules(PUBLISHED_SUITE)
    assert not errors
    assert rules is not None and len(rules) == 98
    encoded = json.dumps(rules, sort_keys=True, separators=(",", ":")).encode()
    assert hashlib.sha256(encoded).hexdigest() == (
        "fbc5a1cdfd1ac2f063c6d11471b19772fbc9dd944bac30329c3a3ed9d727a2c3"
    )


def test_published_report_is_recognized_without_rewriting_its_identity() -> None:
    report = _report()
    original = json.dumps(report, sort_keys=True)
    assert check_report_evidence(report) == []
    assert json.dumps(report, sort_keys=True) == original


@pytest.mark.parametrize(
    ("digest", "count", "rules_sha256"),
    [
        (
            "sha256:151ae887b8785b7728a38f27489d8b7a8d49e369ee60546265cd0623f9f5ec48",
            101,
            "d107ff831d64ad651ea37746cc04639ea5f1154a8ccb2913cb0824af507cc4c2",
        ),
        (
            "sha256:d8c57d7a82454388afcedc892538b70ad1541ab229b98f89bb5ad265d0f0948e",
            152,
            "f65d28f602fb46899d3a5b1551fc72bb510bf4cfd82f369420e910bad00de8bf",
        ),
    ],
)
def test_published_0155_suites_keep_their_exact_rule_maps(
    digest: str, count: int, rules_sha256: str
) -> None:
    rules, errors = _source_suite_rules(digest)
    assert errors == []
    assert rules is not None and len(rules) == count
    encoded = json.dumps(rules, sort_keys=True, separators=(",", ":")).encode()
    assert hashlib.sha256(encoded).hexdigest() == rules_sha256
    report = _report()
    report["revision"] = "b" * 40
    report["suite_digest"] = digest
    original = json.dumps(report, sort_keys=True)
    assert check_report_evidence(report) == []
    assert json.dumps(report, sort_keys=True) == original
    report["tests"][0]["rules"] = []
    assert check_report_evidence(report) == [
        "report test baseline.run_output rules differ from its source suite"
    ]


@pytest.mark.parametrize("corruption", ["unknown-suite", "changed-rules", "unknown-check"])
def test_published_history_still_refuses_corrupt_evidence(corruption: str) -> None:
    report = _report()
    if corruption == "unknown-suite":
        report["suite_digest"] = "sha256:" + "0" * 64
    elif corruption == "changed-rules":
        report["tests"][0]["rules"] = []
    else:
        report["selected_tests"] = ["invented.check"]
        report["tests"][0]["id"] = "invented.check"
    expected = {
        "unknown-suite": "report suite digest is not recognized by this package",
        "changed-rules": "report test baseline.run_output rules differ from its source suite",
        "unknown-check": "report test invented.check is absent from its source suite",
    }
    assert check_report_evidence(report) == [expected[corruption]]
