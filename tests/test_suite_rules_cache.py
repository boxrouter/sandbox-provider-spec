# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Evidence reads the exact suite bytes once without sharing caller mutations."""

import hashlib
import json
from importlib import import_module
from pathlib import Path
from typing import Any

import pytest

from sandbox_provider_spec import evidence

loader = import_module("sandbox_provider_spec.document_cache")


@pytest.fixture(autouse=True)
def _empty_cache() -> None:
    loader._document_texts.clear()


def test_repeated_suite_evidence_parses_once(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    conformance = tmp_path / "conformance"
    conformance.mkdir()
    content = b"tests: [{id: baseline.example, rules: [original]}]\n"
    (conformance / "suite.yaml").write_bytes(content)
    monkeypatch.setattr(evidence, "_conformance_root", lambda: tmp_path)
    digest = "sha256:" + hashlib.sha256(content).hexdigest()
    calls = []
    parse = loader._parse

    def observed(suffix: str, source: bytes) -> Any:
        calls.append(source)
        return parse(suffix, source)

    monkeypatch.setattr(loader, "_parse", observed)
    first, errors = evidence._source_suite_rules(digest)
    assert errors == []
    assert first is not None
    assert first == {"baseline.example": ["original"]}
    first["baseline.example"].append("caller mutation")
    assert evidence._source_suite_rules(digest) == ({"baseline.example": ["original"]}, [])
    assert len(calls) == 1


def test_coverage_rules_and_changed_bytes_are_current(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    conformance = tmp_path / "conformance"
    conformance.mkdir()
    core = b"tests: [{id: baseline.example, rules: [original]}, {id: other, rules: []}]\n"
    coverage = b"tests: [{id: covered, rules: [first]}]\n"
    (conformance / "suite.yaml").write_bytes(core)
    path = conformance / "coverage.yaml"
    path.write_bytes(coverage)
    monkeypatch.setattr(evidence, "_conformance_root", lambda: tmp_path)

    def digest(content: bytes) -> str:
        return (
            "sha256:"
            + hashlib.sha256(
                b"suite.yaml\0" + core + b"\0coverage.yaml\0" + content + b"\0"
            ).hexdigest()
        )

    expected = {"baseline.example": ["original"], "covered": ["first"]}
    assert evidence._source_suite_rules(digest(coverage)) == (expected, [])
    changed = coverage.replace(b"first", b"other")
    path.write_bytes(changed)  # Same byte count; content, not stat metadata, invalidates it.
    assert evidence._source_suite_rules(digest(changed)) == (
        {"baseline.example": ["original"], "covered": ["other"]},
        [],
    )
    (conformance / "historical-suite-rules.json").write_text("{}")
    assert evidence._source_suite_rules(digest(coverage)) == (
        None,
        ["report suite digest is not recognized by this package"],
    )


@pytest.mark.parametrize(
    "content,expected",
    [
        (b"tests: [{id: sample, rules: [2026-10-29]}]", ({"sample": ["2026-10-29"]}, [])),
        (b"tests: [{id: sample, rules: {1: value}}]", ({"sample": {"1": "value"}}, [])),
        (
            b"tests: [{id: sample, id: again, rules: []}]",
            (None, ["package has an invalid conformance suite: duplicate key: id"]),
        ),
    ],
)
def test_suites_read_as_the_strict_loader_reads_them(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, content: bytes, expected: Any
) -> None:
    conformance = tmp_path / "conformance"
    conformance.mkdir()
    (conformance / "suite.yaml").write_bytes(content)
    monkeypatch.setattr(evidence, "_conformance_root", lambda: tmp_path)
    digest = "sha256:" + hashlib.sha256(content).hexdigest()
    assert evidence._source_suite_rules(digest) == expected
    assert evidence._source_suite_rules(digest) == expected


def test_invalid_suite_and_repaired_content_are_not_cached_as_valid(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    conformance = tmp_path / "conformance"
    conformance.mkdir()
    path = conformance / "suite.yaml"
    path.write_bytes(b"[]")
    monkeypatch.setattr(evidence, "_conformance_root", lambda: tmp_path)
    digest = "sha256:" + hashlib.sha256(b"[]").hexdigest()
    expected = (
        None,
        [
            "package has an invalid conformance suite: "
            "list indices must be integers or slices, not str"
        ],
    )
    assert evidence._source_suite_rules(digest) == expected
    assert evidence._source_suite_rules(digest) == expected
    valid = b"tests: [{id: repaired, rules: []}]"
    path.write_bytes(valid)
    digest = "sha256:" + hashlib.sha256(valid).hexdigest()
    assert evidence._source_suite_rules(digest) == ({"repaired": []}, [])


def test_historical_registry_is_read_fresh(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    conformance = tmp_path / "conformance"
    conformance.mkdir()
    (conformance / "suite.yaml").write_bytes(b"tests: []")
    monkeypatch.setattr(evidence, "_conformance_root", lambda: tmp_path)
    path = conformance / "historical-suite-rules.json"
    for rule in ["old", "new"]:
        path.write_text(json.dumps({"historical": {"sample": [rule]}}))
        assert evidence._source_suite_rules("historical") == ({"sample": [rule]}, [])
