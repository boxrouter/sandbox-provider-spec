# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Baseline eligibility rests on the current baseline tests' rows, not a report's summary."""

from __future__ import annotations

from typing import Any

import pytest

from sandbox_provider_spec.matcher import build_declaration
from sandbox_provider_spec.matcher.proof import Proof
from sandbox_provider_spec.suite import read_suite

BASELINE_IDS = read_suite().baseline_ids
DECLARATION = build_declaration(
    {
        "spec": "sandbox-provider-spec/0.1",
        "provider": "acme",
        "verified": {"date": "2026-09-30", "sdks": {"acme-sdk": "1.0.0"}},
        "resources": {},
        "gates": {},
    }
)


def report(**changes: Any) -> dict[str, Any]:
    """A clean report that passed every current baseline test, then `changes`."""
    document: dict[str, Any] = {
        "spec": "sandbox-provider-spec/0.1",
        "provider": "acme",
        "class": None,
        "sdk_versions": {"acme-sdk": "1.0.0"},
        "finished_at": "2026-09-30T00:00:00Z",
        "clean": True,
        "baseline": "passed",
        "selected_tests": list(BASELINE_IDS),
        "tests": [{"id": test_id, "result": "passed"} for test_id in BASELINE_IDS],
    }
    document.update(changes)
    return document


@pytest.mark.rule("matching/baseline-passed")
def test_a_dropped_candidate_does_not_need_a_rerun() -> None:
    # The run also held a candidate since removed from the suites, and failed it: its summary
    # says `differs`, but every test in the current baseline passed.
    dropped = "baseline.dropped_candidate"
    assert dropped not in BASELINE_IDS
    historical = report(
        baseline="differs",
        selected_tests=[*BASELINE_IDS, dropped],
        tests=[
            *({"id": test_id, "result": "passed"} for test_id in BASELINE_IDS),
            {"id": dropped, "result": "differs"},
        ],
    )
    assert Proof(DECLARATION, [historical]).baseline is True


@pytest.mark.rule("matching/baseline-passed")
def test_every_current_baseline_test_must_have_passed_in_a_clean_run() -> None:
    assert Proof(DECLARATION, [report()]).baseline is True
    assert Proof(DECLARATION, []).baseline is False

    missing = report(
        selected_tests=list(BASELINE_IDS[1:]),
        tests=[{"id": test_id, "result": "passed"} for test_id in BASELINE_IDS[1:]],
    )
    failed = report(
        tests=[
            {"id": test_id, "result": "differs" if index == 0 else "passed"}
            for index, test_id in enumerate(BASELINE_IDS)
        ]
    )
    for document in (
        missing,
        failed,
        report(clean=False),
        report(sdk_versions={"acme-sdk": "1.0.1"}),
        report(sdk_versions={"acme-sdk": "1.0.0", "extra": "1"}),
    ):
        assert Proof(DECLARATION, [document]).baseline is False

    # Only the newest report that selected the complete baseline counts.
    older = report(finished_at="2026-09-29T00:00:00Z")
    assert Proof(DECLARATION, [older, failed]).baseline is False


@pytest.mark.rule("matching/baseline-passed")
def test_newer_partial_report_does_not_displace_the_newest_full_report() -> None:
    full = report(finished_at="2026-09-30T00:00:00Z")
    partial = report(
        finished_at="2026-09-30T01:00:00Z",
        selected_tests=[BASELINE_IDS[0]],
        tests=[{"id": BASELINE_IDS[0], "result": "passed"}],
    )

    proof = Proof(DECLARATION, [full, partial])

    assert proof.report is full
    assert proof.baseline is True


@pytest.mark.rule("matching/baseline-passed")
def test_newest_full_report_uses_timezone_aware_timestamp_ordering() -> None:
    earlier = report(finished_at="2026-09-30T02:00:00+02:00")
    later = report(
        finished_at="2026-09-30T01:00:00Z",
        tests=[
            {"id": test_id, "result": "differs" if index == 0 else "passed"}
            for index, test_id in enumerate(BASELINE_IDS)
        ],
    )

    proof = Proof(DECLARATION, [earlier, later])

    assert proof.report is later
    assert proof.baseline is False


@pytest.mark.rule("matching/baseline-passed")
@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("result", ["passed", "error"])
def test_distinct_newest_reports_with_equal_timestamps_are_ambiguous(
    reverse: bool, result: str
) -> None:
    first = report(run_id="first")
    second = report(
        run_id="second",
        finished_at="2026-09-29T20:00:00-04:00",
        tests=[{"id": test_id, "result": result} for test_id in BASELINE_IDS],
    )
    tied = [second, first] if reverse else [first, second]
    older = report(finished_at="2026-09-29T00:00:00Z")
    proof = Proof(DECLARATION, [older, *tied])
    assert proof.report is None
    assert proof.baseline is False


@pytest.mark.rule("matching/baseline-passed")
def test_repeated_copies_of_one_report_do_not_make_its_timestamp_ambiguous() -> None:
    full = report()
    assert Proof(DECLARATION, [full, report()]).baseline is True


@pytest.mark.rule("matching/baseline-passed")
def test_report_identity_distinguishes_json_booleans_from_numbers() -> None:
    boolean, number = report(), report()
    boolean["tests"][0]["steps"] = [{"observed": True}]
    number["tests"][0]["steps"] = [{"observed": 1}]
    assert Proof(DECLARATION, [boolean, number]).baseline is False
