# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The PP4 starter invents no optional gates and fails on invalid declarations."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

import sandbox_provider_spec
from sandbox_provider_spec import cli, starter
from sandbox_provider_spec.check import UNKNOWN_KEY, check_declaration, check_path

ROOT = Path(__file__).resolve().parents[1]
GUIDE = ROOT / "docs/how-to/provider-kit.md"
DOCUMENTED_GENERATE = "sandbox-provider-spec scaffold --output declaration.yaml"
DOCUMENTED_CHECK = "sandbox-provider-spec check declaration.yaml"


def test_generated_starter_omits_optional_gates_and_passes_check(tmp_path: Path) -> None:
    path = tmp_path / "declaration.yaml"
    assert cli.main(["scaffold", "--output", str(path)]) == 0
    result = check_path(path)
    assert result.kind == "declaration"
    assert result.errors == []
    document = sandbox_provider_spec.load(path)
    assert document["gates"] == {}
    assert document["evidence"] == {}
    assert document["resources"] == {"kernel": "unknown"}
    catalog_gates = set(sandbox_provider_spec.load_catalog()["gates"])
    assert set(document["gates"]).isdisjoint(catalog_gates)
    assert "processes" not in document["gates"]
    assert "terminal" not in document["gates"]


def test_documented_generator_and_check_commands(tmp_path: Path) -> None:
    path = tmp_path / "declaration.yaml"
    generate = subprocess.run(
        [
            shutil.which("sandbox-provider-spec") or "sandbox-provider-spec",
            "scaffold",
            "--output",
            str(path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert generate.returncode == 0, generate.stderr
    checker = shutil.which("sandbox-provider-spec")
    assert checker is not None
    checked = subprocess.run(
        [checker, "check", str(path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert checked.returncode == 0, checked.stderr + checked.stdout
    assert f"{path}: ok\n" == checked.stdout


def test_guide_documents_the_generator_and_existing_check() -> None:
    text = GUIDE.read_text(encoding="utf-8")
    assert DOCUMENTED_GENERATE in text
    assert DOCUMENTED_CHECK in text
    assert "declaration self-assessment" in text
    assert "does not admit" in text.lower() or "not admission" in text.lower()


def test_invented_optional_gate_fails_check() -> None:
    document = starter.starter_declaration()
    document["gates"] = {"processes": [{}]}
    errors = check_declaration(document).errors
    assert errors
    assert any("evidence is missing a citation for gates.processes.0" in error for error in errors)


def test_unknown_gate_fails_check() -> None:
    document = starter.starter_declaration()
    document["gates"] = {"made_up": "unsupported"}
    errors = check_declaration(document).errors
    assert any(error == f"{UNKNOWN_KEY}: gates.made_up" for error in errors)


def test_missing_required_field_fails_check() -> None:
    document = starter.starter_declaration()
    del document["spec"]
    errors = check_declaration(document).errors
    assert errors


def test_invalid_provider_is_rejected(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "declaration.yaml"
    assert cli.main(["scaffold", "--provider", "Acme Cloud", "--output", str(path)]) == 1
    assert "provider must match" in capsys.readouterr().err
    assert not path.exists()


def test_cli_check_accepts_the_generated_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "declaration.yaml"
    assert cli.main(["scaffold", "--output", str(path)]) == 0
    assert cli.main(["check", str(path)]) == 0
    assert "ok" in capsys.readouterr().out


def test_scaffold_never_overwrites_existing_declaration(tmp_path: Path) -> None:
    path = tmp_path / "declaration.yaml"
    path.write_text("existing evidence\n")
    assert cli.main(["scaffold", "--output", str(path)]) == 1
    assert path.read_text() == "existing evidence\n"
