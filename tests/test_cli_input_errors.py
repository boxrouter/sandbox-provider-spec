# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Input mistakes give actionable diagnostics without hiding programming errors."""

from __future__ import annotations

from pathlib import Path

import pytest

from sandbox_provider_spec import cli


@pytest.mark.parametrize(
    ("name", "contents", "diagnostic"),
    [
        ("missing.yaml", None, "error: file not found"),
        ("request.yaml", b"\xff", "error: invalid UTF-8"),
        (
            "request.yaml",
            b"requirements: [",
            "1:16: error: invalid YAML: expected the node content, but found '<stream end>'",
        ),
        ("request.json", b'{"requirements":', "1:17: error: invalid JSON: Expecting value"),
        (
            "request.yaml",
            b"requirements: {}\nrequirements: {}\n",
            "error: duplicate key: requirements",
        ),
        (
            "request.json",
            b'{"requirements": {}, "requirements": {}}',
            "error: duplicate key: requirements",
        ),
    ],
)
def test_check_reports_input_errors_and_checks_remaining_files(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    name: str,
    contents: bytes | None,
    diagnostic: str,
) -> None:
    bad = tmp_path / name
    if contents is not None:
        bad.write_bytes(contents)
    good = tmp_path / "valid.yaml"
    good.write_text("requirements: {processes: {}}\n", encoding="utf-8")
    assert cli.main(["check", str(bad), str(good)]) == 1
    output = capsys.readouterr()
    separator = ":" if diagnostic[0].isdigit() else ": "
    assert output.err == f"{bad}{separator}{diagnostic}\n"
    assert output.out == f"{good}: ok\n"


def test_match_stops_at_an_unreadable_request(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    request = tmp_path / "missing-request.yaml"
    declaration = tmp_path / "missing-declaration.yaml"
    assert cli.main(["match", str(request), str(declaration)]) == 1
    assert capsys.readouterr() == ("", f"{request}: error: file not found\n")


def test_match_reports_the_declaration_path(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    request = tmp_path / "request.yaml"
    request.write_text("requirements: {processes: {}}\n", encoding="utf-8")
    declaration = tmp_path / "missing.yaml"
    assert cli.main(["match", str(request), str(declaration)]) == 1
    assert capsys.readouterr() == ("", f"{declaration}: error: file not found\n")


def test_input_errors_do_not_hide_programming_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def broken(_path: str) -> None:
        raise RuntimeError("checker defect")

    monkeypatch.setattr(cli, "check_path", broken)
    with pytest.raises(RuntimeError, match="checker defect"):
        cli.main(["check", str(tmp_path / "request.yaml")])
