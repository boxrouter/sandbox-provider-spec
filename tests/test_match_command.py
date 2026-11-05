# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""`sandbox-provider-spec match` checks its inputs, then prints each declaration's result."""

from __future__ import annotations

from pathlib import Path

import pytest

from sandbox_provider_spec import cli

ROOT = Path(__file__).resolve().parents[1]
DOCKER = str(ROOT / "providers/docker-engine/declaration.yaml")


def _request(tmp_path: Path, text: str) -> str:
    path = tmp_path / "request.yaml"
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_prints_every_reason_a_declaration_is_not_eligible(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    request = _request(tmp_path, "requirements: {previews: {access: public, ports: [3000]}}\n")
    assert cli.main(["match", request, DOCKER]) == 1
    assert capsys.readouterr().out.splitlines() == [
        "docker-engine: not eligible",
        "  - baseline_failed: no newest clean baseline-passing report for this provider, "
        "class and SDK set",
        "  - gate_not_listed: previews: not declared; nobody has looked",
    ]


def test_refuses_a_request_before_matching(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    request = _request(tmp_path, "requirements: {previews: {access: public}}\n")
    assert cli.main(["match", request, DOCKER]) == 1
    out = capsys.readouterr().out
    assert out.startswith(f"{request}: ")
    assert "docker-engine" not in out


def test_refuses_a_declaration_that_fails_the_checker(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    request = _request(tmp_path, "requirements: {processes: {}}\n")
    declaration = tmp_path / "declaration.yaml"
    declaration.write_text("spec: sandbox-provider-spec/0.1\nprovider: broken\n", encoding="utf-8")
    assert cli.main(["match", request, str(declaration)]) == 1
    out = capsys.readouterr().out
    assert out.startswith(f"{declaration}: ")
    assert "eligible" not in out
