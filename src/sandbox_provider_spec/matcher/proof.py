# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Baseline status from an unambiguous newest full report for a declared provider."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from sandbox_provider_spec.matcher.catalog import SPEC_VERSION, Document
from sandbox_provider_spec.matcher.declaration import Declaration
from sandbox_provider_spec.matcher.json_values import same_value
from sandbox_provider_spec.suite import read_suite
from sandbox_provider_spec.timestamps import parse_aware_datetime

Report = Document


def latest_report(declaration: Declaration, reports: Sequence[Report]) -> Report | None:
    """The unique newest full report, ignoring repeated copies of the same document."""
    baseline_ids = set(read_suite().baseline_ids)
    matching: list[tuple[datetime, Report]] = []
    for report in reports:
        if (
            report.get("spec") != SPEC_VERSION
            or report.get("provider") != declaration.provider
            or report.get("class") != declaration.class_name
        ):
            continue
        selected = report.get("selected_tests")
        if not isinstance(selected, list) or any(
            not isinstance(test_id, str) for test_id in selected
        ):
            continue
        if not baseline_ids <= set(selected):
            continue
        finished_at = parse_aware_datetime(report.get("finished_at"))
        if finished_at is not None:
            matching.append((finished_at, report))
    if not matching:
        return None
    newest = max(timestamp for timestamp, _ in matching)
    tied = [report for timestamp, report in matching if timestamp == newest]
    if any(not same_value(report, tied[0]) for report in tied[1:]):
        return None
    return tied[0]


class Proof:
    """Whether the newest full report is clean and passed the provider's baseline.

    The baseline is the current suites' complete set of baseline tests: the report must have
    selected each and passed each, with the declaration's SDK set. Its own `baseline`
    summary is the conclusion of the run as it was, which may have held a candidate test since
    removed, so it is kept but not read. A newer partial report cannot displace this report.
    """

    def __init__(self, declaration: Declaration, reports: Sequence[Report]) -> None:
        self.report = latest_report(declaration, reports)
        baseline_ids = set(read_suite().baseline_ids)
        if self.report is None:
            self.baseline = False
            return
        selected = self.report.get("selected_tests", [])
        rows = {row.get("id"): row for row in self.report.get("tests", []) if isinstance(row, dict)}
        covered = (
            isinstance(selected, list)
            and all(isinstance(test_id, str) for test_id in selected)
            and baseline_ids <= set(selected)
            and all(rows.get(test_id, {}).get("result") == "passed" for test_id in baseline_ids)
        )
        sdk_match = self.report.get("sdk_versions") == declaration.sdk_versions
        self.baseline = bool(sdk_match and self.report.get("clean") is True and covered)
