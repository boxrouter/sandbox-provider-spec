# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Uncited baseline reports have the same semantic and source checks as citations."""

from __future__ import annotations

import json
import subprocess
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from sandbox_provider_spec import check_path, check_report, cli
from sandbox_provider_spec.suite import read_suite, suite_path


@pytest.fixture
def baseline_report() -> dict[str, Any]:
    suite = read_suite(suite_path().with_name("coverage.yaml"))
    return {
        "spec": "sandbox-provider-spec/0.1",
        "provider": "acme",
        "driver": {"name": "fixture", "version": "1"},
        "sdk_versions": {"acme-sdk": "1"},
        "started_at": "2026-09-30T00:00:00Z",
        "finished_at": "2026-09-30T00:00:01Z",
        "revision": "a" * 40,
        "suite_digest": suite.digest,
        "clean": True,
        "baseline": "passed",
        "selected_tests": list(suite.baseline_ids),
        "tests": [
            {
                "id": test.id,
                "result": "passed",
                "steps": [],
                "cleanup": [],
                "duration_ms": 0,
                "rules": list(test.rules),
                "proves": [],
            }
            for test in suite.tests
            if test.id in suite.baseline_ids
        ],
    }


def _documents(tmp_path: Path, report: dict[str, Any]) -> tuple[Path, Path, Path]:
    declaration = tmp_path / "declaration.json"
    declaration.write_text(
        json.dumps(
            {
                "spec": report["spec"],
                "provider": report["provider"],
                "verified": {"date": "2026-09-30", "sdks": report["sdk_versions"]},
                "resources": {},
                "gates": {},
                "evidence": {},
            }
        ),
        encoding="utf-8",
    )
    reports = tmp_path / "reports"
    reports.mkdir()
    path = reports / "baseline.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    request = tmp_path / "request.json"
    request.write_text("{}", encoding="utf-8")
    return declaration, path, request


@pytest.mark.rule("matching/baseline-passed")
def test_uncited_baseline_report_is_verified_before_matching(
    tmp_path: Path, baseline_report: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    declaration, report, request = _documents(tmp_path, baseline_report)
    assert check_report(baseline_report).errors == []
    assert check_path(report).errors == []
    assert check_path(declaration).errors == []
    assert cli.main(["match", str(request), str(declaration)]) == 0
    assert capsys.readouterr() == ("acme: eligible\n", "")


@pytest.mark.rule("matching/baseline-passed")
@pytest.mark.parametrize(
    ("corruption", "error"),
    [
        ("suite", "report suite digest is not recognized by this package"),
        ("missing-result", "report results do not cover exactly its selected tests"),
        ("rules", "report test baseline.create_env rules differ from its source suite"),
        ("digests", "report check digests do not cover exactly its selected tests"),
        ("duplicate-result", "report test results must have unique test ids"),
    ],
)
def test_invalid_uncited_baseline_report_cannot_establish_eligibility(
    tmp_path: Path,
    baseline_report: dict[str, Any],
    capsys: pytest.CaptureFixture[str],
    corruption: str,
    error: str,
) -> None:
    if corruption == "suite":
        baseline_report["suite_digest"] = "sha256:" + "0" * 64
    elif corruption == "missing-result":
        baseline_report["tests"].pop()
    elif corruption == "rules":
        row = next(row for row in baseline_report["tests"] if row["id"] == "baseline.create_env")
        row["rules"] = []
    elif corruption == "digests":
        baseline_report["check_digests"] = {}
    else:
        baseline_report["tests"].append(deepcopy(baseline_report["tests"][0]))
    declaration, report, request = _documents(tmp_path, baseline_report)
    assert check_report(baseline_report).errors == [error]
    assert check_path(report).errors == [error]
    assert check_path(declaration).errors == [f"full-baseline report baseline.json: {error}"]
    assert cli.main(["match", str(request), str(declaration)]) == 1
    assert capsys.readouterr() == (
        f"{declaration}: full-baseline report baseline.json: {error}\n{report}: {error}\n",
        "",
    )


@pytest.mark.rule("matching/baseline-passed")
@pytest.mark.parametrize("state", ["untracked", "staged", "unstaged"])
def test_uncited_baseline_report_must_be_committed_and_unmodified(
    tmp_path: Path,
    baseline_report: dict[str, Any],
    capsys: pytest.CaptureFixture[str],
    state: str,
) -> None:
    declaration, report, request = _documents(tmp_path, baseline_report)
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "add", str(declaration)], check=True)
    if state != "untracked":
        subprocess.run(["git", "-C", str(tmp_path), "add", str(report)], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(tmp_path),
            "-c",
            "user.name=Evidence test",
            "-c",
            "user.email=evidence-test@example.invalid",
            "commit",
            "-qm",
            "source reports",
        ],
        check=True,
    )
    if state != "untracked":
        report.write_text(report.read_text(encoding="utf-8") + "\n", encoding="utf-8")
        if state == "staged":
            subprocess.run(["git", "-C", str(tmp_path), "add", str(report)], check=True)
    error = "report is not committed" if state == "untracked" else "report has uncommitted changes"
    assert check_path(report).errors == [error]
    assert cli.main(["match", str(request), str(declaration)]) == 1
    assert "acme: eligible" not in capsys.readouterr().out


@pytest.mark.rule("matching/baseline-passed")
@pytest.mark.parametrize("failure_first", [False, True])
def test_equal_newest_baselines_refuse_independently_of_report_filenames(
    tmp_path: Path,
    baseline_report: dict[str, Any],
    capsys: pytest.CaptureFixture[str],
    failure_first: bool,
) -> None:
    declaration, report, request = _documents(tmp_path, baseline_report)
    failed = deepcopy(baseline_report)
    failed["baseline"] = "error"
    failed["tests"][0]["result"] = "error"
    name = "a-failure.json" if failure_first else "z-failure.json"
    failure = report.with_name(name)
    failure.write_text(json.dumps(failed), encoding="utf-8")
    assert check_path(declaration).errors == []
    assert check_path(failure).errors == []
    assert cli.main(["match", str(request), str(declaration)]) == 1
    assert capsys.readouterr() == (
        "acme: not eligible\n  - baseline_failed: no newest clean baseline-passing report "
        "for this provider, class and SDK set\n",
        "",
    )


@pytest.mark.rule("declaration/unknown-variant-needs-evidence")
def test_quote_only_metadata_cannot_grant_desktop(
    tmp_path: Path, baseline_report: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    declaration, _, request = _documents(tmp_path, baseline_report)
    document = json.loads(declaration.read_text(encoding="utf-8"))
    document["gates"] = {"desktop": [{"conflicts": ["resources.gpus"]}]}
    document["evidence"] = {
        "gates.desktop.0.conflicts": {
            "source": "https://example.invalid/desktop",
            "read": "2026-09-30",
            "quote": "Desktop and GPUs cannot be combined.",
        }
    }
    declaration.write_text(json.dumps(document), encoding="utf-8")
    request.write_text('{"requirements": {"desktop": {}}}', encoding="utf-8")
    error = "evidence is missing a citation for gates.desktop.0"
    assert check_path(declaration).errors == [error]
    assert cli.main(["match", str(request), str(declaration)]) == 1
    assert capsys.readouterr() == (f"{declaration}: {error}\n", "")
