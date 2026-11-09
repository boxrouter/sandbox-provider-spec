# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The rule-accounting check accepts shared coverage and rejects only gaps/conflicts."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sandbox_provider_spec.rule_accounting import check_rule_accounting


def _rule_tree(
    root: Path,
    *,
    anchors: tuple[str, ...],
    coverage: str,
    waivers: str,
    vector_rules: tuple[str, ...] = (),
) -> None:
    (root / "spec").mkdir()
    (root / "conformance").mkdir()
    (root / "tests/vectors").mkdir(parents=True)
    (root / "spec/spec.md").write_text(
        "\n".join(f"<!-- rule: {rule_id} -->" for rule_id in anchors) + "\n",
        encoding="utf-8",
    )
    for name in ("vocabulary.md", "matching.md", "declarations.md"):
        (root / "spec" / name).write_text("", encoding="utf-8")
    (root / "conformance/suite.yaml").write_text(coverage, encoding="utf-8")
    (root / "spec/untested.yaml").write_text(
        "spec: sandbox-provider-spec/0.1\nuntested:\n" + waivers,
        encoding="utf-8",
    )
    (root / "tests/vectors/sample.json").write_text(
        json.dumps({"rules": vector_rules}) + "\n", encoding="utf-8"
    )


@pytest.mark.rule("declaration/evidence", "declaration/evidence-holds")
def test_shared_rule_ids_are_valid_coverage(tmp_path: Path) -> None:
    _rule_tree(
        tmp_path,
        anchors=("rule/covered", "rule/waived"),
        coverage=(
            "tests:\n"
            "  - id: first\n"
            "    rules: [rule/covered]\n"
            "  - id: second\n"
            "    rules: [rule/covered]\n"
        ),
        waivers="  rule/waived: documented\n",
        vector_rules=("rule/covered",),
    )
    nested_vectors = tmp_path / "tests/matcher/vectors"
    nested_vectors.mkdir(parents=True)
    (nested_vectors / "sample.json").write_text(
        json.dumps({"cases": [{"rules": ["rule/covered"]}]}) + "\n",
        encoding="utf-8",
    )
    (tmp_path / "tests/test_sample.py").write_text(
        "import pytest\n"
        '@pytest.mark.rule("rule/covered")\n'
        "def test_first(): pass\n"
        '@pytest.mark.rule("rule/covered")\n'
        "def test_second(): pass\n",
        encoding="utf-8",
    )

    assert check_rule_accounting(tmp_path) == []


@pytest.mark.rule("declaration/evidence-holds")
def test_rule_accounting_reports_only_uncovered_conflicting_and_unknown_ids(
    tmp_path: Path,
) -> None:
    _rule_tree(
        tmp_path,
        anchors=("rule/missing", "rule/conflict", "rule/covered"),
        coverage=(
            "tests:\n  - id: sample\n    rules: [rule/conflict, rule/covered, rule/not-in-text]\n"
        ),
        waivers="  rule/conflict: also covered\n  rule/also-not-in-text: unknown\n",
    )

    assert check_rule_accounting(tmp_path) == [
        "rule is not named by a test or waiver: rule/missing",
        "test or waiver names no anchored rule: rule/also-not-in-text",
        "test or waiver names no anchored rule: rule/not-in-text",
        "rule is both tested and waived: rule/conflict",
    ]


def test_rule_accounting_reads_coverage_tests_beside_the_suite(tmp_path: Path) -> None:
    _rule_tree(
        tmp_path,
        anchors=("rule/in-suite", "rule/in-coverage", "rule/waived"),
        coverage="tests:\n  - id: first\n    rules: [rule/in-suite]\n",
        waivers="  rule/waived: documented\n",
    )
    assert check_rule_accounting(tmp_path) == [
        "rule is not named by a test or waiver: rule/in-coverage"
    ]

    coverage = tmp_path / "conformance/coverage.yaml"
    coverage.write_text("tests:\n  - id: second\n    rules: [rule/in-coverage]\n", encoding="utf-8")
    assert check_rule_accounting(tmp_path) == []

    coverage.write_text(
        "tests:\n"
        "  - id: first\n    rules: [rule/in-coverage]\n"
        "  - id: second\n    rules: [rule/in-coverage]\n"
        "  - id: second\n    rules: [rule/in-coverage]\n",
        encoding="utf-8",
    )
    assert check_rule_accounting(tmp_path) == [
        "conformance/coverage.yaml repeats test id first from conformance/suite.yaml",
        "conformance/coverage.yaml repeats test id second from conformance/coverage.yaml",
    ]

    coverage.write_text("tests: {}\n", encoding="utf-8")
    assert check_rule_accounting(tmp_path) == [
        "conformance/coverage.yaml must contain a tests list",
        "rule is not named by a test or waiver: rule/in-coverage",
    ]


def test_rule_accounting_rejects_unanchored_normative_prose_but_skips_examples(
    tmp_path: Path,
) -> None:
    _rule_tree(
        tmp_path,
        anchors=("rule/covered",),
        coverage="tests:\n  - id: sample\n    rules: [rule/covered]\n",
        waivers="  {}\n",
    )
    (tmp_path / "spec" / "matching.md").write_text(
        "- A request is matched as follows. <!-- rule: rule/covered -->\n"
        "  The matcher **MUST** preserve the grant.\n"
        "- An allowlist **MUST** fit when each entry kind is named\n"
        "  by the variant.\n\n"
        "```markdown\n- A sample **MUST** be ignored.\n```\n\n"
        "The key words **MUST** and **SHOULD** are used as defined elsewhere.\n",
        encoding="utf-8",
    )

    assert check_rule_accounting(tmp_path) == [
        "normative statement has no rule anchor: spec/matching.md:3"
    ]


@pytest.mark.parametrize(
    ("test_fields", "expected"),
    [
        ({"rules": []}, "must name a normative rule or give a non_normative reason"),
        (
            {"rules": [], "non_normative": "  "},
            "must name a normative rule or give a non_normative reason",
        ),
        (
            {"rules": ["rule/covered"], "non_normative": "diagnostic"},
            "cannot declare both rules and non_normative",
        ),
    ],
)
def test_rule_accounting_requires_each_result_to_be_classified(
    tmp_path: Path, test_fields: dict[str, object], expected: str
) -> None:
    _rule_tree(
        tmp_path,
        anchors=("rule/covered",),
        coverage="tests:\n  - id: sample\n    rules: [rule/covered]\n",
        waivers="  {}\n",
    )
    suite = tmp_path / "conformance/suite.yaml"
    suite.write_text(
        "tests:\n  - id: sample\n"
        + "\n".join(f"    {key}: {value!r}" for key, value in test_fields.items())
        + "\n",
        encoding="utf-8",
    )
    assert any(expected in error for error in check_rule_accounting(tmp_path))


@pytest.mark.parametrize("source", ["vocabulary.md", "matching.md"])
def test_rule_accounting_requires_coverage_for_reference_rules(tmp_path: Path, source: str) -> None:
    _rule_tree(tmp_path, anchors=(), coverage="tests: []\n", waivers="  {}\n")
    (tmp_path / "spec" / source).write_text("<!-- rule: reference/required -->\n", encoding="utf-8")
    assert check_rule_accounting(tmp_path) == [
        "rule is not named by a test or waiver: reference/required"
    ]
    (tmp_path / "conformance/suite.yaml").write_text(
        "tests:\n  - id: reference\n    rules: [reference/required]\n", encoding="utf-8"
    )
    assert check_rule_accounting(tmp_path) == []
