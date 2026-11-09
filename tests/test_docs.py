# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Every fenced YAML or JSON example is parsed and checked for its documented format."""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path

import sandbox_provider_spec
from sandbox_provider_spec.suite import read_suite

ROOT = Path(__file__).resolve().parents[1]
FENCE = re.compile(r"```(yaml|yml|json)\s*\n(.*?)\n```", re.DOTALL | re.IGNORECASE)
SKIP = {".git", ".venv", "build", "dist", ".pytest_cache"}


def _pages() -> list[Path]:
    return sorted(
        path
        for path in ROOT.rglob("*.md")
        if not any(part in SKIP for part in path.relative_to(ROOT).parts)
    )


def _suite_ids() -> set[str]:
    conformance = ROOT / "conformance"
    return {
        test.id
        for path in (conformance / "suite.yaml", conformance / "coverage.yaml")
        for test in read_suite(path).tests
    }


def _cited_tests(declaration: Mapping[str, object]) -> set[str]:
    """Every test id an example's evidence cites, so examples cannot name retired tests."""
    evidence = declaration.get("evidence")
    entries = evidence.values() if isinstance(evidence, Mapping) else []
    cited: set[str] = set()
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        reports = entry.get("reports", [entry])
        for report in reports if isinstance(reports, list) else []:
            if isinstance(report, Mapping) and isinstance(report.get("tests"), list):
                cited.update(str(test_id) for test_id in report["tests"])
    return cited


def test_every_documented_yaml_and_json_example_passes_its_format(
    tmp_path: Path,
) -> None:
    checked: list[str] = []
    for page in _pages():
        contents = page.read_text(encoding="utf-8")
        for index, match in enumerate(FENCE.finditer(contents)):
            language, block = match.groups()
            path = tmp_path / f"example-{len(checked)}.{language.lower()}"
            path.write_text(block + "\n", encoding="utf-8")
            document = sandbox_provider_spec.load(path)
            label = f"{page.relative_to(ROOT)} example {index + 1}"
            assert isinstance(document, Mapping), label
            if "tests" in document and document.get("spec") == "sandbox-provider-spec/0.1":
                read_suite(path)
            elif "provider" in document and "verified" in document:
                assert (
                    sandbox_provider_spec.schema_errors(document, "declaration-schema.json") == []
                ), label
                assert sandbox_provider_spec.check_declaration(document).errors == [], label
                assert _cited_tests(document) <= _suite_ids(), label
            elif "driver" in document and "tests" in document:
                assert sandbox_provider_spec.check_report(document).errors == [], label
            else:
                assert sandbox_provider_spec.schema_errors(document, "request-schema.json") == [], (
                    label
                )
                assert sandbox_provider_spec.check_request(document) == [], label
            checked.append(label)
    assert checked, "the documentation contains no YAML or JSON examples"
