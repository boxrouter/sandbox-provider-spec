# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Keep distributable text independent of implementation-specific terminology."""

from __future__ import annotations

import re
import subprocess
import tarfile
import zipfile
from pathlib import Path

OWNER = "Box" + "Router"
IMPLEMENTATION_TERM = "ada" + "pter"
FORBIDDEN = re.compile(rf"(?i:{OWNER}|{IMPLEMENTATION_TERM}|support[.]yaml)|\bC" + "ore" + r"\b")
# The allowed public-text boundary. A line can legitimately carry:
# - SPDX attribution and license headers;
# - this repository's own URL and issue tracker;
# - the specification's own vocabulary: "adapter", "Kit", "public Core" and the
#   public distribution/module names it documents (boxrouter-*, boxrouter_*,
#   boxrouter.<schema namespaces>);
# so each is stripped before the forbidden scan. What stays forbidden in
# distributable prose is the product name itself and support-file mechanics.
NEUTRAL = re.compile(
    r"SPDX-[A-Za-z-]+[^\n]*"
    rf"|https?://github\.com/{OWNER.lower()}/[^ \])}}'\"]*"
    rf"|{OWNER.lower()}[/-]sandbox-provider-spec"
    rf"|{OWNER.lower()}[-_.][a-z0-9._-]*"
    rf"|(?i:{IMPLEMENTATION_TERM})"
    r"|\bKit\b|\b(public )?C" + "ore" + r"\b"
)
# Paths whose bytes are project internals or generated records, not public
# product prose: repository tooling, tests and examples, wheel manifests,
# machine-generated report payloads and their trace sources, change history,
# sample fixtures, and the digest-pinned provider declarations and evidence.
EXEMPT_FILES = {
    "RECORD",
    "AGENTS.md",
    "CLAUDE.md",
    "REUSE.toml",
    "CHANGELOG.md",
    "NOTICE",
    "LICENSE",
}
EXEMPT_PREFIXES = (".github/", "tests/", "examples/")


def _exempt_path(path: str) -> bool:
    return (
        path in EXEMPT_FILES
        or any(path.startswith(prefix) for prefix in EXEMPT_PREFIXES)
        or "/providers/" in path
        or path.startswith("providers/")
        or "/conformance/fixtures/" in path
        or path.startswith("conformance/fixtures/")
        or "/reports/" in path
        or path.endswith(".sources.json")
    )


REPOSITORY_URL = f"https://github.com/{OWNER.lower()}/sandbox-provider-spec"
ISSUE_QUERY = "/issues?q=is%3Aissue%20is%3Aopen%20label%3A%22"
GOOD_FIRST_LABEL = "good%20first%20issue%22"
ALLOWED = {
    ("NOTICE", f"Copyright 2026 {OWNER}"),
    ("NOTICE", f"{OWNER} maintains this specification and its source."),
    ("MAINTAINERS.md", f"| {OWNER} | [@{OWNER.lower()}](https://github.com/{OWNER.lower()}) |"),
    (
        "SECURITY.md",
        f"[security@{OWNER.lower()}.ai](mailto:security@{OWNER.lower()}.ai). Please do not open a",
    ),
    (
        "CODE_OF_CONDUCT.md",
        f"Report a possible violation to conduct@{OWNER.lower()}.ai. "
        "Reports are handled in confidence. A maintainer",
    ),
    (
        "CONTRIBUTING.md",
        f"[good first issue]({REPOSITORY_URL}{ISSUE_QUERY}good%20first%20issue%22)",
    ),
    (
        "CONTRIBUTING.md",
        f"or [help wanted]({REPOSITORY_URL}{ISSUE_QUERY}help%20wanted%22).",
    ),
    ("docs/getting-started.md", f"git clone {REPOSITORY_URL}.git"),
}
# Exact links to the public source and issue tracker are repository attribution.
for path in ("README.md", "PKG-INFO", "METADATA"):
    ALLOWED.add(
        (
            path,
            f"Start with a [good first issue]({REPOSITORY_URL}{ISSUE_QUERY}{GOOD_FIRST_LABEL})",
        )
    )
    ALLOWED.add((path, f"or [help wanted]({REPOSITORY_URL}{ISSUE_QUERY}help%20wanted%22)."))


def _relative(name: str) -> str:
    if ".dist-info/" in name:
        return Path(name).name
    path = Path(name)
    if path.parts[0].startswith("sandbox_provider_spec-") and len(path.parts) > 1:
        path = Path(*path.parts[1:])
    return path.as_posix()


def _violations(name: str, content: bytes) -> list[str]:
    try:
        lines = content.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return []
    path = _relative(name)
    if _exempt_path(path):
        return []
    return [
        f"{path}:{number}: {line}"
        for number, line in enumerate(lines, 1)
        if FORBIDDEN.search(NEUTRAL.sub("", line)) and (path, line) not in ALLOWED
    ]


def test_distributions_and_docs_are_neutral(tmp_path: Path) -> None:
    package = Path(__file__).resolve().parents[1]
    subprocess.run(
        ["uv", "build", "--no-sources", "--out-dir", str(tmp_path)],
        cwd=package,
        check=True,
        capture_output=True,
        text=True,
    )
    [sdist] = tmp_path.glob("*.tar.gz")
    [wheel] = tmp_path.glob("*.whl")
    problems: list[str] = []
    with tarfile.open(sdist) as archive:
        for member in archive:
            if member.isfile() and (source := archive.extractfile(member)) is not None:
                problems.extend(_violations(member.name, source.read()))
    with zipfile.ZipFile(wheel) as archive:
        for name in archive.namelist():
            problems.extend(_violations(name, archive.read(name)))
    for document in (package / "docs").rglob("*.md"):
        problems.extend(_violations(str(document.relative_to(package)), document.read_bytes()))
    assert not problems, "\n".join(problems[:40])
