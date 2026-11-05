# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The local publication gate checks the artifact it receives."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path


def test_public_release_verifier_checks_the_built_wheel(tmp_path: Path) -> None:
    package = Path(__file__).resolve().parents[1]
    build = tmp_path / "build"
    dist = tmp_path / "dist"
    dist.mkdir()
    subprocess.run(
        ["uv", "build", "--no-sources", "--wheel", "--out-dir", str(build)],
        cwd=package,
        check=True,
        capture_output=True,
        text=True,
    )
    [built] = build.glob("*.whl")
    wheel = dist / built.name
    shutil.copyfile(built, wheel)
    version = tomllib.loads((package / "pyproject.toml").read_text())["project"]["version"]
    command = [
        sys.executable,
        str(package / "scripts" / "verify_distribution.py"),
        "--manifest",
        str(package / "distribution-manifest.json"),
        "--artifact-directory",
        str(dist),
        "--tag",
        f"v{version}",
    ]
    assert subprocess.run(command, capture_output=True, text=True).returncode == 0

    private_tag_command = [*command]
    private_tag_command[-1] = f"dependency-acc-conform-sps-{version}-20261025"
    assert subprocess.run(private_tag_command, capture_output=True, text=True).returncode == 0

    invalid_date_command = [*private_tag_command]
    invalid_date_command[-1] = f"dependency-acc-conform-sps-{version}-20261325"
    invalid_date = subprocess.run(invalid_date_command, capture_output=True, text=True)
    assert invalid_date.returncode == 1
    assert "invalid date" in invalid_date.stderr

    with zipfile.ZipFile(wheel, "a") as archive:
        archive.writestr("unexpected.txt", "not in the distribution manifest")
    rejected = subprocess.run(command, capture_output=True, text=True)
    assert rejected.returncode == 1
    assert "wheel members absent from Hatch config and manifest" in rejected.stderr
