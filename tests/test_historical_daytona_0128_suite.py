# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Recognize Daytona reports against their exact SPS 0.3.128 suite."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

import pytest

from sandbox_provider_spec import check_digests
from sandbox_provider_spec.check_digests import historical_check_digest
from sandbox_provider_spec.evidence import _source_suite_rules, check_report_evidence
from sandbox_provider_spec.suite import read_suite, suite_path

# These reports share one source revision and use the historical 0.3.128 suite.
SUITE = "sha256:9388f89c4361e388c048282139526f1618754a2905ebc0ddb63d2ac6fb0c778e"
REPORTS = Path(__file__).resolve().parents[1] / "providers/daytona/reports"


def _reports() -> list[tuple[Path, dict[str, Any]]]:
    return [
        (path, json.loads(path.read_text(encoding="utf-8")))
        for path in sorted(REPORTS.glob("daytona-disk-memory-sps0128-run*.json"))
    ]


def test_daytona_0128_digest_restores_complete_rule_map() -> None:
    rules, errors = _source_suite_rules(SUITE)
    assert errors == []
    assert rules is not None and len(rules) == 108
    encoded = json.dumps(rules, sort_keys=True, separators=(",", ":")).encode()
    assert hashlib.sha256(encoded).hexdigest() == (
        "d064d2583b2ae87ffa38d77bd3b6b237cc0ae7465c36f4f19d6da79472473d9b"
    )


def test_daytona_0128_reports_keep_consistent_identity_and_rule_labels() -> None:
    reports = _reports()
    assert len(reports) == 3
    rules, errors = _source_suite_rules(SUITE)
    assert errors == [] and rules is not None
    revisions = {report["revision"] for _, report in reports}
    assert len(revisions) == 1
    assert re.fullmatch(r"[0-9a-f]{40}", next(iter(revisions)))
    for path, report in reports:
        original = path.read_bytes()
        assert report["suite_digest"] == SUITE
        assert report["sdk_versions"] == {"daytona": "0.220.0"}
        assert report["driver"] == {"name": "DaytonaDriver", "version": "0.3.128"}
        assert check_report_evidence(report) == []
        assert all(row["rules"] == rules[row["id"]] for row in report["tests"])
        assert path.read_bytes() == original


def test_unknown_suite_and_wrong_labels_remain_refused() -> None:
    report = _reports()[0][1]
    report["suite_digest"] = "sha256:" + "0" * 64
    assert check_report_evidence(report) == [
        "report suite digest is not recognized by this package"
    ]

    report = _reports()[0][1]
    report["tests"][0]["rules"] = []
    assert check_report_evidence(report) == [
        f"report test {report['tests'][0]['id']} rules differ from its source suite"
    ]


def test_changed_executable_check_identity_is_not_excused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = _reports()[0][1]
    test_id = report["selected_tests"][0]
    scenario = next(
        test
        for test in read_suite(suite_path().with_name("coverage.yaml")).tests
        if test.id == test_id
    )
    recorded = report["check_digests"][test_id]
    current = check_digests.check_digests((scenario,))[test_id]
    # The #4013 probe change moved this check's identity, so the recorded run is
    # stale for it; the identity mechanism must detect that, not excuse it.
    assert current != recorded
    assert historical_check_digest(scenario, SUITE) is None
    real_digest = check_digests.file_digest

    def changed_dependency(name: str) -> str:
        digest = real_digest(name)
        return "sha256:" + "0" * 64 if name in check_digests.test_dependencies(scenario) else digest

    monkeypatch.setattr(check_digests, "file_digest", changed_dependency)
    assert check_digests.check_digests((scenario,))[test_id] not in {recorded, current}
    assert historical_check_digest(scenario, SUITE) is None
