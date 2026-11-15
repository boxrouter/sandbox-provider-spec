# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The specification is distributed from its GitHub repository only, never from a package index."""

from __future__ import annotations

import re
from pathlib import Path

from sandbox_provider_spec import cli

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "git+https://github.com/boxrouter/sandbox-provider-spec"
# What a reader or a workflow of this package says. Declarations, evidence and examples quote
# third-party sites by name, so they stay out of the scan.
SCANNED = (
    "README.md",
    "CONTRIBUTING.md",
    "GOVERNANCE.md",
    "Makefile",
    "pyproject.toml",
    "docs/**/*.md",
    "template/**/*.md",
    "template/pyproject.toml",
    "src/**/*.py",
    ".github/**/*",
)
INDEX_NAME = "py" + "pi"
PUBLISH = re.compile(r"\buv publish\b|\btwine upload\b|\bnpm publish\b|gh-action-" + INDEX_NAME)
INSTALL = re.compile(r"\buvx\b|\bpip install\b[^\n]*sandbox-provider-spec")


def _files() -> list[Path]:
    found = {path for pattern in SCANNED for path in ROOT.glob(pattern) if path.is_file()}
    return sorted(found)


def test_nothing_publishes_to_or_names_a_package_index() -> None:
    named = [
        path.relative_to(ROOT).as_posix()
        for path in _files()
        if INDEX_NAME in path.read_text(encoding="utf-8").lower()
        or PUBLISH.search(path.read_text(encoding="utf-8"))
    ]
    assert not named, f"the specification is distributed from GitHub only: {named}"


def test_every_documented_install_command_uses_the_repository() -> None:
    wrong = [
        f"{path.relative_to(ROOT).as_posix()}:{number}: {line.strip()}"
        for path in _files()
        if path.suffix != ".py"
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if INSTALL.search(line) and REPOSITORY not in line
    ]
    assert not wrong, f"an install command must name {REPOSITORY}:\n" + "\n".join(wrong)


def test_the_cli_hint_installs_the_http_extra_from_the_repository() -> None:
    assert REPOSITORY in cli.HTTP_EXTRA_INSTALL
    assert "sandbox-provider-spec[http]" in cli.HTTP_EXTRA_INSTALL
