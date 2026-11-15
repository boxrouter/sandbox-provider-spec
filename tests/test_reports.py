# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Selection and result coverage determine what a report can establish."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from importlib.metadata import version
from pathlib import Path

import pytest

from sandbox_provider_spec import report as report_module
from sandbox_provider_spec.check import check_document
from sandbox_provider_spec.driver import Driver
from sandbox_provider_spec.report import report
from sandbox_provider_spec.suite import Suite, read_suite, suite_path


def fixture_suite(*, partial: bool = False) -> Suite:
    source = read_suite(suite_path().with_name("coverage.yaml"))
    baseline = tuple(test for test in source.tests if test.id in source.baseline_ids)
    return replace(source, tests=baseline[:1] if partial else baseline)


def fixture_results(suite: Suite) -> list[dict[str, object]]:
    """Synthetic observations retain the shipped suite's ids, rules and proof targets."""
    return [
        {
            "id": test.id,
            "result": "passed",
            "steps": [],
            "cleanup": [],
            "duration_ms": 0,
            "rules": list(test.rules),
            "proves": list(test.proves),
        }
        for test in suite.tests
    ]


def document(suite: Suite, results: list[Mapping[str, object]]) -> dict[str, object]:
    driver = Driver()
    driver.provider = "example"
    driver.sdk_versions = {"example-sdk": "1.0.0"}
    return report(
        driver,
        suite,
        results,
        spec_revision="a" * 40,
        started_at="2026-01-01T00:00:00+00:00",
    )


@pytest.mark.parametrize("status", ["passed", "differs", "unsupported", "not_run", "error"])
def test_complete_baseline_summary_retains_result_semantics(status: str) -> None:
    suite = fixture_suite()
    results = fixture_results(suite)
    results[1]["result"] = status
    result = document(suite, list(results))
    assert result["baseline"] == status
    assert check_document(result).errors == []
    assert result["selected_tests"] == list(suite.baseline_ids)
    assert results[0]["rules"] == ["baseline/lifecycle"]
    assert results[0]["proves"] == []


def test_partial_selection_never_establishes_the_baseline() -> None:
    suite = fixture_suite(partial=True)
    assert document(suite, list(fixture_results(suite)))["baseline"] == "not_run"


@pytest.mark.parametrize("duplicate", [True, False])
def test_missing_or_duplicate_results_cannot_form_a_report(duplicate: bool) -> None:
    suite = fixture_suite()
    results = fixture_results(suite)
    invalid = [results[0], results[0]] if duplicate else results[:1]
    with pytest.raises(ValueError, match="selected tests exactly once"):
        document(suite, list(invalid))


def test_gate_presence_proof_has_no_invented_knob() -> None:
    source = read_suite()
    scenario = next(test for test in source.tests if test.id == "terminal.interactive")
    suite = replace(source, tests=(scenario,))
    results = fixture_results(suite)
    assert results[0]["proves"] == [{"gate": "terminal", "value": True}]
    result = document(suite, list(results))
    assert check_document(result).errors == []


def test_unrecognized_report_metadata_is_rejected() -> None:
    suite = fixture_suite()
    receipt = document(suite, list(fixture_results(suite)))
    receipt["debug_metadata"] = "test-only"
    assert check_document(receipt).errors


def declared(tmp_path: Path, sdks: Mapping[str, str]) -> Path:
    path = tmp_path / "declaration.yaml"
    lines = [
        "verified:",
        "  date: '2026-01-01'",
        "  sdks:",
        *(f"    {k}: '{v}'" for k, v in sdks.items()),
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def test_a_report_records_every_installed_sdk_its_declaration_verifies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Whichever operations ran, the report states the environment: an SDK the run did not load
    is recorded at its installed version, one that is not installed is left out, and a version the
    driver recorded is never replaced."""
    path = declared(
        tmp_path, {"example-sdk": "9.9.9", "pytest": "0", "a-sdk-nobody-installed": "1"}
    )
    monkeypatch.setattr(report_module, "installed_declaration_path", lambda *_args: path)
    suite = fixture_suite()
    result = document(suite, fixture_results(suite))
    assert result["sdk_versions"] == {"example-sdk": "1.0.0", "pytest": version("pytest")}
    assert check_document(result).errors == []


def test_a_report_with_no_installed_declaration_records_only_the_drivers_versions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def missing(*_args: object) -> Path:
        raise FileNotFoundError("no installed package registers a declaration")

    monkeypatch.setattr(report_module, "installed_declaration_path", missing)
    suite = fixture_suite()
    assert document(suite, fixture_results(suite))["sdk_versions"] == {"example-sdk": "1.0.0"}
