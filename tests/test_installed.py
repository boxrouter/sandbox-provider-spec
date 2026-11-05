# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Installed declaration lookup reads package metadata and never imports the package."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from sandbox_provider_spec import installed
from sandbox_provider_spec.load import load


def _register(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, files: list[str]) -> None:
    for name in files:
        path = tmp_path / "acme_sandbox" / name
        path.parent.mkdir(exist_ok=True)
        path.write_text("provider: acme\n", encoding="utf-8")
    distribution = SimpleNamespace(
        files=[Path("acme_sandbox") / name for name in files],
        locate_file=lambda relative: tmp_path / relative,
    )
    entry = SimpleNamespace(name="acme", value="acme_sandbox", dist=distribution)

    def entry_points(*, group: str) -> list[Any]:
        assert group == installed.GROUP
        return [entry]

    monkeypatch.setattr(installed, "entry_points", entry_points)
    monkeypatch.setattr(
        installed, "find_spec", lambda _: pytest.fail("metadata lookup must not import")
    )


def test_class_selects_its_declaration_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _register(monkeypatch, tmp_path, ["declaration.yaml", "declaration-vm.yaml"])
    vm = tmp_path / "acme_sandbox/declaration-vm.yaml"
    default = tmp_path / "acme_sandbox/declaration.yaml"
    assert installed.installed_declaration_path("acme", "vm") == vm
    assert installed.installed_declaration_path("acme") == default
    assert installed.installed_declaration_path("acme", "default") == default


def test_unknown_class_lists_the_shipped_ones(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _register(monkeypatch, tmp_path, ["declaration-container.yaml", "declaration-vm.yaml"])
    with pytest.raises(ValueError, match="one of: container, vm"):
        installed.installed_declaration_path("acme")


def test_unregistered_provider_says_so(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(installed, "entry_points", lambda *, group: [])
    with pytest.raises(FileNotFoundError, match="registers a declaration for acme"):
        installed.installed_declaration_path("acme")


def test_docker_reference_is_spec_owned() -> None:
    path = installed.installed_declaration_path("docker-engine")
    assert path.is_file()
    assert path.parent.name == "docker-engine"


@pytest.mark.parametrize(
    ("provider", "execution_class"),
    [
        ("e2b", None),
        ("modal", None),
        ("modal", "vm"),
        ("daytona", "container"),
        ("daytona", "vm"),
        ("daytona", "gpu"),
        ("blaxel", None),
        ("vercel", None),
    ],
)
def test_provider_declaration_is_spec_owned(provider: str, execution_class: str | None) -> None:
    path = installed.installed_declaration_path(provider, execution_class)
    assert path.is_file()
    assert path.parent.name == provider
    assert path.parents[1].name == "providers"
    declaration = load(path)
    assert declaration["verified"]["sdks"]
    assert declaration["resources"].get("default_user") != "box"
