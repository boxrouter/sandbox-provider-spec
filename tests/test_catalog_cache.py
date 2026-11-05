# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""load_catalog parses each distinct catalog once and hands every caller its own copy."""

from __future__ import annotations

from importlib import import_module
from pathlib import Path
from typing import Any

import pytest

from sandbox_provider_spec import check
from sandbox_provider_spec.load import DuplicateKeyError, load

loader = import_module("sandbox_provider_spec.document_cache")


def _catalog_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, text: str) -> Path:
    monkeypatch.setattr(check, "spec_dir", lambda: tmp_path)
    loader._document_texts.clear()
    path = tmp_path / "catalog.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def _count_loads(monkeypatch: pytest.MonkeyPatch) -> list[Path]:
    loads: list[Path] = []

    def record(path: Path) -> Any:
        loads.append(Path(path))
        return load(path)

    monkeypatch.setattr(loader, "load", record)
    return loads


def test_the_installed_catalog_reads_as_the_strict_loader_reads_it() -> None:
    loader._document_texts.clear()
    assert check.load_catalog() == load(check.spec_dir() / "catalog.yaml")
    assert check.load_catalog() == load(check.spec_dir() / "catalog.yaml")


def test_unchanged_content_is_parsed_once(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _catalog_dir(monkeypatch, tmp_path, "gates: {a: 1}\n")
    loads = _count_loads(monkeypatch)
    for _ in range(5):
        assert check.load_catalog() == {"gates": {"a": 1}}
    assert len(loads) == 1


def test_each_caller_gets_its_own_copy(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _catalog_dir(monkeypatch, tmp_path, "gates: {a: [1, 2]}\n")
    first = check.load_catalog()
    first["gates"]["a"].append(3)
    first["extra"] = True
    assert check.load_catalog() == {"gates": {"a": [1, 2]}}


def test_changed_content_is_reparsed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    path = _catalog_dir(monkeypatch, tmp_path, "n: 1\n")
    assert check.load_catalog() == {"n": 1}
    path.write_text("n: 2\n", encoding="utf-8")
    assert check.load_catalog() == {"n": 2}
    path.write_text("n: 1\n", encoding="utf-8")
    assert check.load_catalog() == {"n": 1}


def test_a_catalog_that_does_not_load_is_refused_every_time(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _catalog_dir(monkeypatch, tmp_path, "n: 1\nn: 2\n")
    for _ in range(2):
        with pytest.raises(DuplicateKeyError):
            check.load_catalog()
    assert len(loader._document_texts) == 0


def test_the_cache_is_bounded(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    path = _catalog_dir(monkeypatch, tmp_path, "n: 0\n")
    for index in range(loader._DOCUMENT_TEXTS + 3):
        path.write_text(f"n: {index}\n", encoding="utf-8")
        assert check.load_catalog() == {"n": index}
    assert len(loader._document_texts) == loader._DOCUMENT_TEXTS


def test_a_catalog_changed_during_its_parse_is_not_stored(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = _catalog_dir(monkeypatch, tmp_path, "n: 1\n")

    def parse_then_change(source: Path) -> Any:
        document = load(source)
        path.write_text("n: 2\n", encoding="utf-8")
        return document

    monkeypatch.setattr(loader, "load", parse_then_change)
    assert check.load_catalog() == {"n": 1}
    assert len(loader._document_texts) == 0
    monkeypatch.setattr(loader, "load", load)
    assert check.load_catalog() == {"n": 2}


def test_yaml_and_json_with_the_same_bytes_are_cached_apart(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _catalog_dir(monkeypatch, tmp_path, "{}\n")
    text = '{"n": 1}\n'
    for name in ("catalog.yaml", "catalog.json"):
        (tmp_path / name).write_text(text, encoding="utf-8")
        loader.cached_load(tmp_path / name)
    assert {suffix for suffix, _, _ in loader._document_texts} == {".yaml", ".json"}


def test_nothing_is_written_to_disk(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _catalog_dir(monkeypatch, tmp_path, "n: 1\n")
    monkeypatch.setattr("tempfile.TemporaryDirectory", None)
    assert check.load_catalog() == {"n": 1}
    assert sorted(path.name for path in tmp_path.iterdir()) == ["catalog.yaml"]


def test_safe_yaml_does_not_replace_strict_validation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = _catalog_dir(monkeypatch, tmp_path, "n: 1\nn: 2\n")
    assert loader.cached_load(path, yaml_content=path.read_bytes()) == {"n": 2}
    with pytest.raises(DuplicateKeyError):
        check.load_catalog()
