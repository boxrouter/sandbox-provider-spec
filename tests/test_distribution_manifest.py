# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Keep the published wheel and its public contents manifest in sync."""

from __future__ import annotations

import fnmatch
import json
import runpy
import shutil
import subprocess
import zipfile
from pathlib import Path


def test_distribution_manifest_matches_built_wheel(tmp_path: Path) -> None:
    package = Path(__file__).resolve().parents[1]
    manifest = json.loads((package / "distribution-manifest.json").read_text())
    uv = shutil.which("uv")
    assert uv is not None, "uv is required to build the distribution wheel"

    subprocess.run(
        [uv, "build", "--no-sources", "--wheel", "--out-dir", str(tmp_path)],
        cwd=package,
        check=True,
    )
    wheels = list(tmp_path.glob("sandbox_provider_spec-*.whl"))
    assert len(wheels) == 1
    with zipfile.ZipFile(wheels[0]) as archive:
        actual = {info.filename for info in archive.infolist() if not info.is_dir()}
        for guide in sorted((package / "docs").rglob("*.md")):
            member = (
                "sandbox_provider_spec/data/docs/" + guide.relative_to(package / "docs").as_posix()
            )
            assert member in actual, f"installed authoring guide is missing: {member}"
            assert archive.read(member) == guide.read_bytes()
    patterns = manifest["members"]["wheel"]
    allowed_metadata = {
        member
        for member in actual
        if any(fnmatch.fnmatchcase(member, pattern) for pattern in patterns)
    }
    verifier = runpy.run_path(str(package / "scripts" / "verify_distribution.py"))
    configured = verifier["configured_wheel_members"](package)
    assert configured | allowed_metadata == actual
    assert all(
        any(fnmatch.fnmatchcase(member, pattern) for member in actual) for pattern in patterns
    ), "manifest entries must match at least one built wheel member"
