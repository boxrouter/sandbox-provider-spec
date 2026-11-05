# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""An installed wheel verifies its evidence independently of its host project."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def wheel(tmp_path_factory: pytest.TempPathFactory) -> Path:
    output = tmp_path_factory.mktemp("wheel")
    subprocess.run(
        ["uv", "build", "--no-sources", "--wheel", "--out-dir", str(output)],
        cwd=Path(__file__).resolve().parents[1],
        check=True,
        capture_output=True,
        text=True,
    )
    [built] = output.glob("*.whl")
    return built


@pytest.fixture(scope="module")
def external_wheel(tmp_path_factory: pytest.TempPathFactory) -> Path:
    source = Path(__file__).resolve().parents[1]
    project = tmp_path_factory.mktemp("external-provider")
    shutil.copytree(source / "providers/e2b", project / "provider_evidence_fixture")
    build_system = (source / "pyproject.toml").read_text(encoding="utf-8").split("[project]", 1)[0]
    (project / "pyproject.toml").write_text(
        build_system
        + '[project]\nname = "provider-evidence-fixture"\nversion = "1.0.0"\n'
        + '[tool.hatch.build.targets.wheel]\npackages = ["provider_evidence_fixture"]\n',
        encoding="utf-8",
    )
    output = tmp_path_factory.mktemp("external-wheel")
    subprocess.run(
        ["uv", "build", "--no-sources", "--wheel", "--out-dir", str(output)],
        cwd=project,
        check=True,
        capture_output=True,
        text=True,
    )
    [built] = output.glob("*.whl")
    return built


@pytest.mark.parametrize("location", ["inside-checkout", "outside-checkout", "without-git"])
@pytest.mark.parametrize("distribution", ["bundled", "external"])
def test_installed_evidence_does_not_depend_on_venv_location(
    tmp_path: Path, wheel: Path, external_wheel: Path, location: str, distribution: str
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    if location != "outside-checkout":
        subprocess.run(["git", "init", "-q", str(project)], check=True)
    venv = project / ".venv"
    subprocess.run(
        ["uv", "venv", "--python", sys.executable, str(venv)],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        ["uv", "pip", "install", "--python", str(venv / "bin/python"), str(wheel)],
        check=True,
        capture_output=True,
        text=True,
    )
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env.pop("PYTHONHOME", None)
    if location == "without-git":
        env["PATH"] = str(venv / "bin")
    cli = str(venv / "bin/sandbox-provider-spec")
    declaration = subprocess.run(
        [cli, "installed-declaration", "e2b"],
        cwd=project,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if distribution == "external":
        subprocess.run(
            ["uv", "pip", "install", "--python", str(venv / "bin/python"), str(external_wheel)],
            check=True,
            capture_output=True,
            text=True,
        )
        declaration = subprocess.run(
            [
                str(venv / "bin/python"),
                "-c",
                "from importlib.metadata import distribution; "
                "print(distribution('provider-evidence-fixture').locate_file("
                "'provider_evidence_fixture/declaration.yaml'))",
            ],
            cwd=project,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    checked = subprocess.run(
        [cli, "check", declaration], cwd=project, env=env, capture_output=True, text=True
    )
    assert (checked.returncode, checked.stdout, checked.stderr) == (0, f"{declaration}: ok\n", "")
    request = project / "request.yaml"
    request.write_text("requirements: {processes: {}}\n", encoding="utf-8")
    matched = subprocess.run(
        [cli, "match", str(request), declaration],
        cwd=project,
        env=env,
        capture_output=True,
        text=True,
    )
    # Historical reports omit the current EOF baseline check; installation must
    # preserve that refusal in every location instead of manufacturing fresh proof.
    assert (matched.returncode, matched.stdout, matched.stderr) == (
        1,
        "e2b: not eligible\n"
        "  - baseline_failed: no newest clean baseline-passing report "
        "for this provider, class and SDK set\n",
        "",
    )
