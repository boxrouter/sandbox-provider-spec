# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Broken links and false transcripts fail before readers encounter them."""

from __future__ import annotations

import json
import runpy
import sys
from pathlib import Path
from typing import Any

import pytest
from jsonschema.exceptions import SchemaError

TOOL = runpy.run_path(str(Path(__file__).resolve().parents[1] / "tools/check_docs.py"))


def test_links_follow_github_headings_references_and_explicit_anchors(tmp_path: Path) -> None:
    (tmp_path / "index.md").write_text(
        "# Index\n\n[One][target]\n\n[target]: <target file.md#repeated-1>\n\n"
        "[Code](target%20file.md#a-port_name)\n\n[Explicit](target%20file.md#custom)\n\n"
        "```md\n[Not a link](absent.md)\n```\n",
        encoding="utf-8",
    )
    (tmp_path / "target file.md").write_text(
        '# Repeated\n\n# Repeated\n\n# A `port_name`\n\n<a id="custom"></a>\n',
        encoding="utf-8",
    )
    assert TOOL["check_links"](tmp_path) == []


@pytest.mark.parametrize(
    ("text", "error"),
    [
        ("[Link](missing.md)", "missing.md: missing local target"),
        ("[Link](#missing)", "#missing: missing heading or explicit anchor"),
        ("[Link](../outside.md)", "../outside.md: link escapes the repository"),
        ('<a id="x"></a>\n<a name="x"></a>', "duplicate anchor #x"),
    ],
)
def test_links_report_broken_targets_and_anchors(tmp_path: Path, text: str, error: str) -> None:
    (tmp_path / "index.md").write_text(text + "\n", encoding="utf-8")
    assert TOOL["check_links"](tmp_path) == [f"index.md: {error}"]


def _transcripts(tmp_path: Path) -> Path:
    executable = tmp_path / "bin/sandbox-provider-spec"
    executable.parent.mkdir()
    executable.write_text(
        f"#!{sys.executable}\n"
        "import os, sys\nfrom pathlib import Path\n"
        "assert not any(key in os.environ for key in "
        "['GH_TOKEN', 'GITHUB_TOKEN', 'E2B_API_KEY'])\n"
        "assert list(Path(os.environ['GH_CONFIG_DIR']).iterdir()) == []\n"
        "assert Path.cwd() == Path(os.environ['HOME'])\n"
        "assert Path('request.yaml').read_text() == 'requirements: {}\\n'\n"
        "if sys.argv[1] == 'check':\n    print('request.yaml: ok')\n"
        "else:\n    print('refused', file=sys.stderr)\n    sys.exit(1)\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    (tmp_path / "README.md").write_text(
        "<!-- sps:example exit=0 stream=stdout -->\n\n```console\n"
        "$ printf 'requirements: {}\\n' > request.yaml\n```\n\n"
        "<!-- sps:example exit=0 stream=stdout -->\n\n```console\n"
        "$ sandbox-provider-spec check request.yaml\nrequest.yaml: ok\n```\n\n"
        "<!-- sps:example exit=1 stream=stderr -->\n\n```console\n"
        "$ sandbox-provider-spec match request.yaml declaration.yaml\nrefused\n```\n",
        encoding="utf-8",
    )
    return executable


def test_transcripts_run_outside_checkout_without_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = _transcripts(tmp_path)
    timeouts: list[object] = []
    run = TOOL["subprocess"].run

    def record_timeout(*args: Any, **kwargs: Any) -> Any:
        timeouts.append(kwargs.get("timeout"))
        return run(*args, **kwargs)

    monkeypatch.setattr(TOOL["subprocess"], "run", record_timeout)
    for key in ("GH_TOKEN", "GITHUB_TOKEN", "E2B_API_KEY"):
        monkeypatch.setenv(key, "test-sentinel")
    assert TOOL["check_examples"](tmp_path, str(executable)) == []
    assert timeouts == [60, 60, 180]


@pytest.mark.parametrize(
    ("before", "after"),
    [
        ("request.yaml: ok", "request.yaml: eligible"),
        ("exit=1 stream=stderr", "exit=0 stream=stderr"),
        ("exit=1 stream=stderr", "exit=1 stream=stdout"),
    ],
)
def test_transcript_drift_in_output_status_or_stream_fails(
    tmp_path: Path, before: str, after: str
) -> None:
    executable = _transcripts(tmp_path)
    readme = tmp_path / "README.md"
    readme.write_text(readme.read_text().replace(before, after), encoding="utf-8")
    errors = TOOL["check_examples"](tmp_path, str(executable))
    assert len(errors) == 1
    assert errors[0].startswith("README.md: sandbox-provider-spec ")
    assert "expected" in errors[0] and "received" in errors[0]


def test_transcripts_require_check_and_match_examples(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# No examples\n", encoding="utf-8")
    assert TOOL["check_examples"](tmp_path, "sandbox-provider-spec") == [
        "README.md: mark at least one check and one match transcript"
    ]


def test_formats_validate_schemas_and_exact_catalog_generation(tmp_path: Path) -> None:
    spec = tmp_path / "spec"
    spec.mkdir()
    (spec / "catalog.yaml").write_text("gates: {}\n", encoding="utf-8")
    catalog = spec / "catalog.json"
    catalog.write_text(json.dumps({"gates": {}}, indent=2) + "\n", encoding="utf-8")
    schema = spec / "request-schema.json"
    schema.write_text('{"type": "object"}', encoding="utf-8")
    assert TOOL["check_formats"](tmp_path) == []
    catalog.write_text('{"gates": {}}\n', encoding="utf-8")
    assert TOOL["check_formats"](tmp_path) == [
        "spec/catalog.json: generated content differs; run make write"
    ]
    schema.write_text('{"type": 7}', encoding="utf-8")
    with pytest.raises(SchemaError):
        TOOL["check_formats"](tmp_path)
