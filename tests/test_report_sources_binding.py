# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Every shipped report's sources file binds the report's exact bytes."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]


def test_sources_files_record_their_report() -> None:
    """A sources file is evidence only while `report_sha256` names the sibling report."""
    mismatches: list[str] = []
    for sources_path in sorted(PACKAGE_ROOT.glob("providers/*/reports/*.sources.json")):
        report_path = sources_path.with_suffix("").with_suffix(".json")
        if not report_path.is_file():
            mismatches.append(
                f"{sources_path.relative_to(PACKAGE_ROOT)}: no sibling report {report_path.name}"
            )
            continue
        try:
            sources = json.loads(sources_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            mismatches.append(f"{sources_path.relative_to(PACKAGE_ROOT)}: not JSON")
            continue
        recorded = sources.get("report_sha256")
        actual = hashlib.sha256(report_path.read_bytes()).hexdigest()
        if recorded != actual:
            mismatches.append(
                f"{sources_path.relative_to(PACKAGE_ROOT)}: records "
                f"{recorded}, {report_path.name} is {actual}"
            )
    assert not mismatches, (
        "Sources files must be regenerated (or removed) when their report changes:\n"
        + "\n".join(mismatches)
    )
