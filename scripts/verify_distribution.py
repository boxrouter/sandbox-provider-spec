# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Verify a downloaded release wheel against the public distribution manifest."""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import subprocess
import sys
import tomllib
import zipfile
from datetime import datetime
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import Any


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def configured_wheel_members(package_root: Path) -> set[str]:
    """Derive Hatch's tracked source and force-included wheel paths."""
    config = tomllib.loads((package_root / "pyproject.toml").read_text(encoding="utf-8"))
    hatch = config["tool"]["hatch"]["build"]
    wheel = hatch.get("targets", {}).get("wheel", {})
    excludes = [*hatch.get("exclude", []), *wheel.get("exclude", [])]
    package_paths = wheel.get("packages", [])
    force_include = wheel.get("force-include", {})
    source_paths = [*package_paths, *force_include]
    tracked = subprocess.run(
        ["git", "-C", str(package_root), "ls-files", "--", *source_paths],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()
    members: set[str] = set()
    for path in tracked:
        if not path or any(fnmatch.fnmatchcase(path, pattern) for pattern in excludes):
            continue
        package_path = next(
            (source for source in package_paths if path.startswith(f"{source}/")), None
        )
        if package_path is not None:
            require(package_path.startswith("src/"), "Hatch wheel package must be under src/")
            source_path = package_root / path
            if source_path.is_symlink() and source_path.is_dir():
                continue
            members.add(Path(path).relative_to("src").as_posix())

    for source, target in force_include.items():
        for path in tracked:
            if path == source:
                members.add(target)
            elif path.startswith(f"{source}/"):
                members.add(f"{target}/{Path(path).relative_to(source).as_posix()}")
    return members


def verify(wheel: Path, manifest: dict[str, Any], tag: str) -> None:
    if tag.startswith("v") and len(tag) > 1:
        version = tag[1:]
    else:
        match = re.fullmatch(
            r"dependency-[a-z0-9]+(?:-[a-z0-9]+)*-(\d+\.\d+\.\d+)-(\d{8})",
            tag,
        )
        require(
            match is not None,
            "release tag must be vVERSION or dependency-<purpose>-VERSION-YYYYMMDD",
        )
        try:
            datetime.strptime(match.group(2), "%Y%m%d")
        except ValueError as error:
            raise ValueError("dependency release tag has an invalid date") from error
        version = match.group(1)
    distribution = manifest["distribution_name"]
    stem = distribution.replace("-", "_")
    require(manifest["version_from_tag"] is True, "manifest must bind version to tag")
    require(
        wheel.name.startswith(f"{stem}-{version}-"), "wheel filename disagrees with release tag"
    )

    with zipfile.ZipFile(wheel) as archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        members = {info.filename for info in infos if not info.is_dir()}
        require(len(names) == len(set(names)), "wheel has duplicate member names")
        require(
            all(
                name == str(PurePosixPath(name))
                and not name.startswith("/")
                and ".." not in PurePosixPath(name).parts
                for name in names
            ),
            "wheel has an unsafe member name",
        )
        patterns = manifest["members"]["wheel"]
        unmatched = [
            pattern
            for pattern in patterns
            if not any(fnmatch.fnmatchcase(name, pattern) for name in members)
        ]
        require(not unmatched, f"manifest patterns match no wheel member: {unmatched}")
        allowed_by_manifest = {
            name
            for name in members
            if any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns)
        }
        configured = configured_wheel_members(Path(__file__).resolve().parents[1])
        missing = configured - members
        require(not missing, f"configured Hatch wheel members missing: {sorted(missing)}")
        unexpected = members - configured - allowed_by_manifest
        require(
            not unexpected,
            f"wheel members absent from Hatch config and manifest: {sorted(unexpected)}",
        )

        metadata_path = f"{stem}-{version}.dist-info/METADATA"
        require(metadata_path in members, "wheel has no version-matched METADATA")
        metadata = BytesParser().parsebytes(archive.read(metadata_path), headersonly=True)
        require(
            metadata.get("Name", "").lower().replace("_", "-") == distribution,
            "wheel metadata names another distribution",
        )
        require(metadata.get("Version") == version, "wheel metadata version disagrees with tag")
        for pattern in manifest["required_license_files"]:
            require(
                any(fnmatch.fnmatchcase(name, pattern) for name in members),
                f"wheel has no required license file matching {pattern}",
            )
        for rule in manifest["public_text_disallow"]:
            for name in members:
                if not any(fnmatch.fnmatchcase(name, pattern) for pattern in rule["members"]):
                    continue
                try:
                    content = archive.read(name).decode("utf-8").casefold()
                except UnicodeDecodeError:
                    continue
                forbidden = [phrase for phrase in rule["phrases"] if phrase.casefold() in content]
                require(
                    not forbidden, f"wheel member {name} contains a forbidden phrase: {forbidden}"
                )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--artifact-directory", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    args = parser.parse_args()
    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        directory = args.artifact_directory
        files = {path.name for path in directory.iterdir() if path.is_file()}
        artifacts = manifest["artifacts"]
        require(
            len(artifacts) == 1 and artifacts[0]["kind"] == "wheel",
            "expected one wheel artifact rule",
        )
        pattern = artifacts[0]["glob"]
        wheels = sorted(directory.glob(pattern))
        require(
            artifacts[0]["min"] <= len(wheels) <= artifacts[0]["max"],
            f"expected one wheel matching {pattern}",
        )
        require(
            files == {wheel.name for wheel in wheels}, "artifact directory has unexpected files"
        )
        for wheel in wheels:
            verify(wheel, manifest, args.tag)
    except (OSError, KeyError, TypeError, ValueError, zipfile.BadZipFile) as error:
        print(f"distribution verification failed: {error}", file=sys.stderr)
        return 1
    print("distribution verification: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
