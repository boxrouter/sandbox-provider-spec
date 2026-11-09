# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Check normative rules against conformance tests, tooling tests, and waivers."""

from __future__ import annotations

import ast
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml

from sandbox_provider_spec.load import load

_RULE_ANCHOR = re.compile(r"<!--\s*rule:\s*([a-z0-9][a-z0-9/_-]*)\s*-->")
_NORMATIVE_KEYWORD = re.compile(r"\*\*(?:MUST(?: NOT)?|SHOULD(?: NOT)?)\*\*")
_LIST_ITEM = re.compile(r"^\s*(?:[-+*]|\d+[.)])\s+")
_VECTOR_SUFFIXES = {".json", ".yaml", ".yml"}
#: The frozen suite, and the file new conformance tests go in so the suite's digest holds.
_SUITE = Path("conformance/suite.yaml")
_COVERAGE = Path("conformance/coverage.yaml")


def check_rule_accounting(root: str | Path | None = None) -> list[str]:
    """Check missing rules, test/waiver conflicts, and references to unknown rules."""
    if root is None:
        # A source checkout holds the package under src/; an installed copy is checked from
        # the checkout it is run in.
        source = Path(__file__).resolve().parents[2]
        root = source if (source / "spec/spec.md").is_file() else Path.cwd()
    repository = Path(root)
    errors: list[str] = []
    anchors = _read_anchors(repository, errors)
    coverage: dict[str, list[str]] = defaultdict(list)
    _read_suite_rules(repository, coverage, errors)
    _read_pytest_rules(repository, coverage, errors)
    _read_vector_rules(repository, coverage, errors)
    waivers = _read_waivers(repository, errors)

    rule_ids = set(anchors)
    for rule_id in sorted(rule_ids - (set(coverage) | set(waivers))):
        errors.append(f"rule is not named by a test or waiver: {rule_id}")
    for rule_id in sorted((set(coverage) | set(waivers)) - rule_ids):
        errors.append(f"test or waiver names no anchored rule: {rule_id}")
    for rule_id in sorted(set(coverage) & set(waivers)):
        errors.append(f"rule is both tested and waived: {rule_id}")
    return errors


def _read_anchors(root: Path, errors: list[str]) -> dict[str, list[str]]:
    anchors: dict[str, list[str]] = defaultdict(list)
    for relative in (
        Path("spec/spec.md"),
        Path("spec/vocabulary.md"),
        Path("spec/matching.md"),
        Path("spec/declarations.md"),
    ):
        path = root / relative
        if not path.is_file():
            errors.append(f"rule source does not exist: {relative.as_posix()}")
            continue
        lines = path.read_text(encoding="utf-8").splitlines()
        for line_number, line in enumerate(lines, 1):
            for match in _RULE_ANCHOR.finditer(line):
                anchors[match.group(1)].append(f"{relative.as_posix()}:{line_number}")
        for line_number, paragraph in _markdown_paragraphs(lines):
            text = " ".join(paragraph)
            if not _NORMATIVE_KEYWORD.search(text):
                continue
            if re.search(r"\bwords\b.*\bused as\b", text):
                continue
            normative_index = next(
                index for index, line in enumerate(paragraph) if _NORMATIVE_KEYWORD.search(line)
            )
            anchor_index = normative_index
            if normative_index and _RULE_ANCHOR.search(paragraph[normative_index - 1]):
                anchor_index -= 1
            if not _RULE_ANCHOR.search(paragraph[anchor_index]):
                errors.append(
                    f"normative statement has no rule anchor: "
                    f"{relative.as_posix()}:{line_number + anchor_index}"
                )
    return anchors


def _markdown_paragraphs(lines: list[str]) -> list[tuple[int, list[str]]]:
    """Return nonblank prose blocks, excluding fenced code and tables."""
    paragraphs: list[tuple[int, list[str]]] = []
    current: list[str] = []
    start = 0
    fence: str | None = None
    for line_number, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith(("```", "~~~")):
            if current:
                paragraphs.append((start, current))
                current = []
            fence = stripped[:3] if fence is None else None
            continue
        if fence is not None:
            continue
        if not stripped or stripped.startswith("|"):
            if current:
                paragraphs.append((start, current))
                current = []
            continue
        if current and _LIST_ITEM.match(line):
            paragraphs.append((start, current))
            current = []
        if not current:
            start = line_number
        current.append(line)
    if current:
        paragraphs.append((start, current))
    return paragraphs


def _record(coverage: dict[str, list[str]], rule_id: str, source: str) -> None:
    coverage[rule_id].append(source)


def _read_suite_rules(root: Path, coverage: dict[str, list[str]], errors: list[str]) -> None:
    """The rules the conformance tests name: the suite's, and coverage.yaml's when it exists."""
    if not (root / _SUITE).is_file():
        errors.append(f"rule source does not exist: {_SUITE.as_posix()}")
        return
    seen: dict[str, str] = {}
    for relative in (_SUITE, _COVERAGE):
        if (root / relative).is_file():
            _read_conformance_file(root, relative, seen, coverage, errors)


def _read_conformance_file(
    root: Path,
    relative: Path,
    seen: dict[str, str],
    coverage: dict[str, list[str]],
    errors: list[str],
) -> None:
    name = relative.as_posix()
    try:
        suite = load(root / relative)
    except (OSError, ValueError, TypeError, yaml.YAMLError) as error:
        errors.append(f"cannot read {name}: {error}")
        return
    tests = suite.get("tests") if isinstance(suite, dict) else None
    if not isinstance(tests, list):
        errors.append(f"{name} must contain a tests list")
        return
    for test in tests:
        if not isinstance(test, dict) or not isinstance(test.get("id"), str):
            errors.append(f"{name} has a test without a string id")
            continue
        if test["id"] in seen:
            errors.append(f"{name} repeats test id {test['id']} from {seen[test['id']]}")
            continue
        seen[test["id"]] = name
        source = f"conformance test {test['id']}"
        rules = test.get("rules")
        if not isinstance(rules, list):
            errors.append(f"{source} must declare rules as a list")
            continue
        non_normative = test.get("non_normative")
        if rules:
            if non_normative is not None:
                errors.append(f"{source} cannot declare both rules and non_normative")
        elif not isinstance(non_normative, str) or not non_normative.strip():
            errors.append(f"{source} must name a normative rule or give a non_normative reason")
        for rule_id in rules:
            if not isinstance(rule_id, str) or not rule_id:
                errors.append(f"{source} has a rule id that is not a nonempty string")
                continue
            _record(coverage, rule_id, source)


def _dotted_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent is not None else None
    return None


def _marked_rule_ids(node: ast.expr, location: str, errors: list[str]) -> list[str]:
    name = _dotted_name(node.func) if isinstance(node, ast.Call) else _dotted_name(node)
    if name != "pytest.mark.rule":
        return []
    if not isinstance(node, ast.Call):
        errors.append(f"{location} must call pytest.mark.rule with literal rule ids")
        return []
    rule_ids: list[str] = []
    for argument in node.args:
        if (
            isinstance(argument, ast.Constant)
            and isinstance(argument.value, str)
            and argument.value
        ):
            rule_ids.append(argument.value)
        else:
            errors.append(f"{location} must use nonempty string literals in pytest.mark.rule")
    if node.keywords:
        errors.append(f"{location} cannot use keyword arguments in pytest.mark.rule")
    return rule_ids


def _read_pytest_rules(root: Path, coverage: dict[str, list[str]], errors: list[str]) -> None:
    tests_root = root / "tests"
    if not tests_root.is_dir():
        errors.append("rule source directory does not exist: tests/")
        return
    for path in sorted(tests_root.rglob("test_*.py")):
        relative = path.relative_to(root).as_posix()
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
        except (OSError, SyntaxError, UnicodeDecodeError) as error:
            errors.append(f"cannot read {relative}: {error}")
            continue
        for node in ast.walk(tree):
            if not isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef)
            ) or not node.name.startswith("test_"):
                continue
            location = f"{relative}:{node.lineno}"
            for decorator in node.decorator_list:
                for rule_id in _marked_rule_ids(decorator, location, errors):
                    _record(coverage, rule_id, f"checker/matcher test {location}")


def _collect_vector_rules(
    document: Any,
    source: str,
    coverage: dict[str, list[str]],
    errors: list[str],
) -> None:
    if isinstance(document, dict):
        for key, value in document.items():
            if key == "rules":
                if not isinstance(value, list):
                    errors.append(f"{source} must declare rules as a list")
                    continue
                for rule_id in value:
                    if not isinstance(rule_id, str) or not rule_id:
                        errors.append(f"{source} has a rule id that is not a nonempty string")
                        continue
                    _record(coverage, rule_id, source)
            _collect_vector_rules(value, source, coverage, errors)
    elif isinstance(document, list):
        for child in document:
            _collect_vector_rules(child, source, coverage, errors)


def _read_vector_rules(root: Path, coverage: dict[str, list[str]], errors: list[str]) -> None:
    tests_root = root / "tests"
    if not tests_root.is_dir():
        return
    vectors_roots = sorted(path for path in tests_root.rglob("vectors") if path.is_dir())
    for vectors_root in vectors_roots:
        for path in sorted(vectors_root.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in _VECTOR_SUFFIXES:
                continue
            relative = path.relative_to(root).as_posix()
            try:
                document = load(path)
            except (OSError, ValueError, TypeError, yaml.YAMLError) as error:
                errors.append(f"cannot read {relative}: {error}")
                continue
            _collect_vector_rules(document, relative, coverage, errors)


def _read_waivers(root: Path, errors: list[str]) -> set[str]:
    path = root / "spec/untested.yaml"
    if not path.is_file():
        errors.append("rule source does not exist: spec/untested.yaml")
        return set()
    try:
        document = load(path)
    except (OSError, ValueError, TypeError, yaml.YAMLError) as error:
        errors.append(f"cannot read spec/untested.yaml: {error}")
        return set()
    if not isinstance(document, dict) or document.get("spec") != "sandbox-provider-spec/0.1":
        errors.append("spec/untested.yaml has an unknown or missing spec version")
    waivers = document.get("untested") if isinstance(document, dict) else None
    if not isinstance(waivers, dict):
        errors.append("spec/untested.yaml must contain an untested map")
        return set()
    waived: set[str] = set()
    for rule_id, _reason in waivers.items():
        if isinstance(rule_id, str) and rule_id:
            waived.add(rule_id)
    return waived
