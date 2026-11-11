# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""cached_load parses each distinct file once, as the strict loader would, and hands every caller
its own copy."""

from __future__ import annotations

from importlib import import_module
from pathlib import Path
from typing import Any

import pytest
import yaml

from sandbox_provider_spec import check
from sandbox_provider_spec.load import DuplicateKeyError, load

loader = import_module("sandbox_provider_spec.document_cache")


def _catalog_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, text: str) -> Path:
    monkeypatch.setattr(check, "spec_dir", lambda: tmp_path)
    loader._document_texts.clear()
    path = tmp_path / "catalog.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def _count_parses(monkeypatch: pytest.MonkeyPatch) -> list[bytes]:
    parses: list[bytes] = []
    real = loader._parse

    def record(suffix: str, content: bytes) -> Any:
        parses.append(content)
        return real(suffix, content)

    monkeypatch.setattr(loader, "_parse", record)
    return parses


def test_the_installed_catalog_reads_as_the_strict_loader_reads_it() -> None:
    loader._document_texts.clear()
    assert check.load_catalog() == load(check.spec_dir() / "catalog.yaml")
    assert check.load_catalog() == load(check.spec_dir() / "catalog.yaml")


def test_unchanged_content_is_parsed_once(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _catalog_dir(monkeypatch, tmp_path, "gates: {a: 1}\n")
    parses = _count_parses(monkeypatch)
    for _ in range(5):
        assert check.load_catalog() == {"gates": {"a": 1}}
    assert len(parses) == 1


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


def test_a_catalog_changed_during_its_parse_is_stored_under_the_parsed_bytes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = _catalog_dir(monkeypatch, tmp_path, "n: 1\n")
    real = loader._parse

    def parse_then_change(suffix: str, content: bytes) -> Any:
        document = real(suffix, content)
        path.write_text("n: 2\n", encoding="utf-8")
        return document

    monkeypatch.setattr(loader, "_parse", parse_then_change)
    assert check.load_catalog() == {"n": 1}
    monkeypatch.setattr(loader, "_parse", real)
    assert check.load_catalog() == {"n": 2}
    path.write_text("n: 1\n", encoding="utf-8")
    assert check.load_catalog() == {"n": 1}


def test_yaml_and_json_with_the_same_bytes_are_cached_apart(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _catalog_dir(monkeypatch, tmp_path, "{}\n")
    text = '{"n": 1}\n'
    for name in ("catalog.yaml", "catalog.json"):
        (tmp_path / name).write_text(text, encoding="utf-8")
        loader.cached_load(tmp_path / name)
    assert {suffix for suffix, _ in loader._document_texts} == {".yaml", ".json"}


def test_nothing_is_written_to_disk(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _catalog_dir(monkeypatch, tmp_path, "n: 1\n")
    monkeypatch.setattr("tempfile.TemporaryDirectory", None)
    assert check.load_catalog() == {"n": 1}
    assert sorted(path.name for path in tmp_path.iterdir()) == ["catalog.yaml"]


def test_supplied_bytes_are_parsed_strictly(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = _catalog_dir(monkeypatch, tmp_path, "n: 1\n")
    with pytest.raises(DuplicateKeyError):
        loader.cached_load(path, content=b"n: 1\nn: 2\n")
    assert loader.cached_load(path, content=b"d: 2026-10-29\n") == {"d": "2026-10-29"}


@pytest.mark.skipif(not yaml.__with_libyaml__, reason="PyYAML is built without libyaml")
def test_the_libyaml_loader_still_refuses_duplicate_keys(tmp_path: Path) -> None:
    assert issubclass(loader._FastLoader, yaml.CSafeLoader)
    for text in ("n: 1\nn: 2\n", "a: {k: 1, k: 2}\n", "- {x: 1}\n- {y: 1, y: 2}\n"):
        with pytest.raises(DuplicateKeyError):
            yaml.load(text, Loader=loader._FastLoader)
        with pytest.raises(DuplicateKeyError):
            loader.cached_load(tmp_path / "x.yaml", content=text.encode())


def _package_yaml() -> list[Path]:
    root = Path(__file__).resolve().parents[1]
    return sorted(
        path
        for folder in ("spec", "conformance", "providers", "examples")
        for path in (root / folder).rglob("*.y*ml")
    )


def test_every_package_yaml_reads_as_the_strict_loader_reads_it() -> None:
    assert len(_package_yaml()) > 30
    for path in _package_yaml():
        assert loader.cached_load(path) == load(path), path


@pytest.mark.parametrize(
    "text",
    [
        "a: b: c\n",
        "a: [1, 2\n",
        "key: 'unterminated\n",
        "\tfoo: 1\n",
        "a: *nope\n",
        "!!python/object:os.system x\n",
        "- a\nb: c\n",
        "a: !!binary aGk=\n",
    ],
)
def test_refusals_carry_the_strict_loader_messages(tmp_path: Path, text: str) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(Exception) as direct:
        load(path)
    with pytest.raises(type(direct.value)) as cached:
        loader.cached_load(path)
    assert str(cached.value) == str(direct.value)
