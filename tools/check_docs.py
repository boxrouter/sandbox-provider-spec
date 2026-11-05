# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Check local documentation links, generated formats, and marked offline transcripts.

An example marker is followed by a console fence containing one command line and its
exact expected output. Examples share an empty working directory outside the checkout.
YAML file markers save requests; only request creation, `check`, and `match` are run.
No provider operation is allowed.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

from jsonschema.validators import validator_for
from markdown_it import MarkdownIt
from markdown_it.token import Token

from sandbox_provider_spec import load

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_TIMEOUT_SECONDS = 60
MATCH_EXAMPLE_TIMEOUT_SECONDS = 180
EXAMPLE = re.compile(
    r"<!-- sps:example exit=(\d+) stream=(stdout|stderr) -->\n"
    r"\n```(?:console|sh)\n(?:\$ )?((?:[^\n]*\\\n)*[^\n]+)\n(.*?)```",
    re.DOTALL,
)
FILE_EXAMPLE = re.compile(
    r"<!-- sps:example file=([\w-]+\.yaml) -->\n\n```yaml\n(.*?)```", re.DOTALL
)
SKIP = {".git", ".venv", "dist", "build", ".pytest_cache"}


class _ExplicitAnchors(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.anchors: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for name, value in attrs:
            if value is not None and (name == "id" or (tag == "a" and name == "name")):
                self.anchors.append(value)


def _walk(tokens: list[Token]) -> Iterator[Token]:
    for token in tokens:
        yield token
        yield from _walk(token.children or [])


def _slug(text: str) -> str:
    return re.sub(r"[^\w -]", "", text.lower()).replace(" ", "-")


def _anchors(tokens: list[Token]) -> tuple[set[str], list[str]]:
    headings: set[str] = set()
    html = _ExplicitAnchors()
    for index, token in enumerate(tokens):
        if token.type != "heading_open":
            continue
        children = tokens[index + 1].children or []
        text = "".join(
            child.content for child in children if child.type in {"text", "code_inline", "image"}
        )
        base = _slug(text)
        anchor, suffix = base, 0
        while anchor in headings:
            suffix += 1
            anchor = f"{base}-{suffix}"
        headings.add(anchor)
    for token in _walk(tokens):
        if token.type in {"html_inline", "html_block"}:
            html.feed(token.content)
    duplicates = sorted({anchor for anchor in html.anchors if html.anchors.count(anchor) > 1})
    return headings | set(html.anchors), duplicates


def _pages(root: Path) -> list[Path]:
    # Include new docs before commit. A source archive also works without Git metadata.
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z", "--", "*.md"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode == 0:
        return sorted({root / name for name in result.stdout.split("\0") if name})
    return sorted(
        page for page in root.rglob("*.md") if not SKIP.intersection(page.relative_to(root).parts)
    )


def check_links(root: Path) -> list[str]:
    parser = MarkdownIt("commonmark")
    documents = {
        page.resolve(): parser.parse(page.read_text(encoding="utf-8")) for page in _pages(root)
    }
    anchors: dict[Path, set[str]] = {}
    errors: list[str] = []
    for page, tokens in documents.items():
        anchors[page], duplicates = _anchors(tokens)
        errors.extend(f"{page.relative_to(root)}: duplicate anchor #{item}" for item in duplicates)
    for page, tokens in documents.items():
        for token in _walk(tokens):
            href = token.attrGet("href") if token.type == "link_open" else token.attrGet("src")
            if not isinstance(href, str):
                continue
            url = urlsplit(href)
            if url.scheme or url.netloc:
                continue
            target = (page.parent / unquote(url.path)).resolve() if url.path else page
            label = f"{page.relative_to(root)}: {href}"
            if not target.is_relative_to(root):
                errors.append(f"{label}: link escapes the repository")
            elif not target.exists():
                errors.append(f"{label}: missing local target")
            elif url.fragment:
                if target.is_dir():
                    target = target / "README.md"
                if target not in anchors and target.is_file():
                    anchors[target], _ = _anchors(parser.parse(target.read_text(encoding="utf-8")))
                if unquote(url.fragment) not in anchors.get(target, set()):
                    errors.append(f"{label}: missing heading or explicit anchor")
    return errors


def check_formats(root: Path) -> list[str]:
    for path in sorted((root / "spec").glob("*-schema.json")):
        schema = json.loads(path.read_text(encoding="utf-8"))
        validator_for(schema).check_schema(schema)
    generated = json.dumps(load(root / "spec/catalog.yaml"), indent=2) + "\n"
    if (root / "spec/catalog.json").read_text(encoding="utf-8") != generated:
        return ["spec/catalog.json: generated content differs; run make write"]
    readme = root / "README.md"
    if readme.is_file() and "<!-- sps:counts -->" in readme.read_text(encoding="utf-8"):
        catalog = load(root / "spec/catalog.yaml")
        gates = len(catalog["gates"])
        knobs = sum(len(gate["knobs"]) for gate in catalog["gates"].values())
        tests = sum(
            len(load(root / "conformance" / name)["tests"])
            for name in ("suite.yaml", "coverage.yaml")
        )
        expected = (
            f"<!-- sps:counts -->\nThe vocabulary has {gates} gates and {knobs} knobs; "
            f"the conformance suite has {tests} tests."
        )
        if expected not in readme.read_text(encoding="utf-8"):
            return [f"README.md: catalog or suite counts differ; expected {expected!r}"]
    return []


def check_examples(root: Path, cli: str) -> list[str]:
    readme = (root / "README.md").read_text(encoding="utf-8")
    examples = sorted(
        [*EXAMPLE.finditer(readme), *FILE_EXAMPLE.finditer(readme)], key=lambda item: item.start()
    )
    if len(examples) != readme.count("<!-- sps:example"):
        return ["README.md: malformed example marker or console fence"]
    commands = [example.group(3) for example in examples if example.re is EXAMPLE]
    if not any(
        command.startswith("sandbox-provider-spec check ") for command in commands
    ) or not any(command.startswith("sandbox-provider-spec match ") for command in commands):
        return ["README.md: mark at least one check and one match transcript"]
    executable = shutil.which(cli)
    if executable is None:
        return [f"README.md: CLI executable not found: {cli}"]
    errors: list[str] = []
    with tempfile.TemporaryDirectory(prefix="sps-docs-") as directory:
        work = Path(directory)
        (work / "github").mkdir()
        env = {
            "PATH": str(Path(executable).resolve().parent) + os.pathsep + os.defpath,
            "HOME": directory,
            "GH_CONFIG_DIR": str(work / "github"),
            "PYTHONUTF8": "1",
        }
        for example in examples:
            if example.re is FILE_EXAMPLE:
                name, content = example.groups()
                (work / name).write_text(content, encoding="utf-8")
                continue
            status, stream, command, expected = example.groups()
            if not command.startswith(
                ("printf ", "sed ", "sandbox-provider-spec check ", "sandbox-provider-spec match ")
            ):
                errors.append(f"README.md: example is not an offline check or match: {command}")
                continue
            result = subprocess.run(
                command,
                shell=True,
                cwd=work,
                env=env,
                capture_output=True,
                text=True,
                timeout=(
                    MATCH_EXAMPLE_TIMEOUT_SECONDS
                    if command.startswith("sandbox-provider-spec match ")
                    else EXAMPLE_TIMEOUT_SECONDS
                ),
                check=False,
            )
            stdout = expected if stream == "stdout" else ""
            stderr = expected if stream == "stderr" else ""
            if (result.returncode, result.stdout, result.stderr) != (int(status), stdout, stderr):
                errors.append(
                    f"README.md: {command}\n"
                    f"  expected {(int(status), stdout, stderr)!r}\n"
                    f"  received {(result.returncode, result.stdout, result.stderr)!r}"
                )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--links", action="store_true")
    parser.add_argument("--formats", action="store_true")
    parser.add_argument("--readme-examples", action="store_true")
    parser.add_argument("--cli", default="sandbox-provider-spec")
    args = parser.parse_args()
    root = args.root.resolve()
    all_checks = not (args.links or args.formats or args.readme_examples)
    errors = []
    if args.links or all_checks:
        errors.extend(check_links(root))
    if args.formats or all_checks:
        errors.extend(check_formats(root))
    if args.readme_examples or all_checks:
        errors.extend(check_examples(root, args.cli))
    for error in errors:
        print(error)
    if not errors:
        print("documentation: ok")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
