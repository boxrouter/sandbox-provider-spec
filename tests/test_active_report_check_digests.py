# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Active hosted reports stay bound to the current SPS checks."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from sandbox_provider_spec.check_digests import check_digests, historical_rule_digest
from sandbox_provider_spec.evidence import _source_suite_rules
from sandbox_provider_spec.suite import read_suite

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = PACKAGE_ROOT.parents[1]


def _report_names(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [name for entry in value for name in _report_names(entry)]
    if isinstance(value, dict):
        return [name for entry in value.values() for name in _report_names(entry)]
    return []


def _active_reports() -> list[tuple[Path, dict[str, Any]]]:
    """Return reports named by each installed support file."""
    reports: list[tuple[Path, dict[str, Any]]] = []
    for support_path in WORKSPACE_ROOT.glob("packages/*/src/*/support*.yaml"):
        support: Any = yaml.safe_load(support_path.read_text(encoding="utf-8"))
        if not isinstance(support, dict) or not isinstance(support.get("reports"), dict):
            continue
        report_dir = support_path.parent / "reports"
        for name in _report_names(support["reports"]):
            path = report_dir / name
            reports.append((path, support))
    return sorted(
        ((path, support) for path, support in reports if path.is_file()),
        key=lambda item: str(item[0]),
    )


def _used_proof_ids(report: dict[str, Any], support: dict[str, Any]) -> set[str]:
    """Select passed checks that the support file uses to establish its declared capabilities."""
    gates = {*support.get("gates", {}), *support.get("adds", {})}
    facts = {
        *(f"resources.{name}" for name in support.get("resources", {})),
        *(f"lifetime_timer.{name}" for name in support.get("lifetime_timer", {})),
        *(f"lifetime_timer.{name}" for name in support.get("adds_lifetime_timer", {})),
    }
    return {
        str(row["id"])
        for row in report.get("tests", ())
        if isinstance(row, dict)
        and row.get("result") == "passed"
        and (
            str(row.get("id", "")).startswith("baseline.")
            or any(
                isinstance(proof, dict)
                and (proof.get("gate") in gates or proof.get("fact") in facts)
                for proof in row.get("proves", ())
            )
        )
    }


def test_active_reports_keep_current_check_digests() -> None:
    """A changed conformance/driver/runner check requires refreshed active reports."""
    if not (WORKSPACE_ROOT / "packages").is_dir():
        pytest.skip("hosted reports are only present in the canonical source workspace")

    tests = read_suite().tests
    current = check_digests(tests)
    by_id = {test.id: test for test in tests}
    mismatches: list[str] = []

    for report_path, support in _active_reports():
        report = json.loads(report_path.read_text(encoding="utf-8"))
        recorded = report.get("check_digests")
        if not isinstance(recorded, dict):
            mismatches.append(
                f"{report_path.relative_to(WORKSPACE_ROOT)}: missing or malformed check_digests"
            )
            continue
        for test_id in _used_proof_ids(report, support):
            if test_id not in current:
                continue
            if test_id not in recorded:
                mismatches.append(
                    f"{report_path.relative_to(WORKSPACE_ROOT)}: {test_id} "
                    "has no recorded check digest"
                )
                continue
            if (
                recorded[test_id] != current[test_id]
                and historical_rule_digest(by_id[test_id], report.get("suite_digest"))
                != recorded[test_id]
            ):
                mismatches.append(
                    f"{report_path.relative_to(WORKSPACE_ROOT)}: {test_id} "
                    f"recorded={recorded[test_id]} current={current[test_id]}"
                )

    assert not mismatches, (
        "Active hosted reports have stale SPS check digests; refresh or rebind them in "
        "the same change:\n" + "\n".join(mismatches)
    )


def test_active_reports_ran_a_recognized_suite() -> None:
    """A suite change records the outgoing suite in `historical-suite-rules.json`.

    Without it every active report of the old suite reads "report suite digest is not
    recognized", even for checks the change left alone (SPS 0.3.182 missed this).
    """
    if not (WORKSPACE_ROOT / "packages").is_dir():
        pytest.skip("hosted reports are only present in the canonical source workspace")
    unrecognized = sorted(
        f"{report_path.relative_to(WORKSPACE_ROOT)}: {report.get('suite_digest')}"
        for report_path, _support in _active_reports()
        if (report := json.loads(report_path.read_text(encoding="utf-8"))).get("suite_digest")
        and _source_suite_rules(report["suite_digest"])[1]
    )
    assert not unrecognized, (
        "Active hosted reports name a suite this package does not recognize; record the old "
        "suite under its digest in historical-suite-rules.json:\n" + "\n".join(unrecognized)
    )
