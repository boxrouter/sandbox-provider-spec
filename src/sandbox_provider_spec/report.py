# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Versioned run provenance and cleanup evidence, without provider secrets."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Mapping, Sequence
from importlib.metadata import version
from pathlib import Path
from typing import cast

from sandbox_provider_spec.check_digests import check_digests
from sandbox_provider_spec.driver import Driver
from sandbox_provider_spec.evidence import DEVELOPMENT_REVISION
from sandbox_provider_spec.run_id import run_id
from sandbox_provider_spec.runner import now
from sandbox_provider_spec.suite import SPEC, Suite

__all__ = ["DEVELOPMENT_REVISION", "report", "revision", "write_report"]


def revision(root: Path) -> str:
    """Refuse evidence from changed or unrelated driver code."""
    status = subprocess.run(
        ["git", "status", "--porcelain"], cwd=root, capture_output=True, text=True, check=True
    ).stdout
    if status:
        raise ValueError("live reports require a clean spec checkout")
    source = Path(__file__).resolve()
    if not source.is_relative_to(root.resolve()):
        raise ValueError("loaded runner is not from the recorded checkout")
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, check=True
    ).stdout.strip()


# Provenance fields have independent sources and are deliberately explicit.
# pylint: disable=too-many-arguments
def report(
    driver: Driver,
    suite: Suite,
    results: Sequence[Mapping[str, object]],
    *,
    spec_revision: str,
    started_at: str,
) -> dict[str, object]:
    selected = [test.id for test in suite.tests]
    actual = [str(item["id"]) for item in results]
    if len(actual) != len(set(actual)) or set(actual) != set(selected):
        raise ValueError("report results must match the selected tests exactly once")
    baseline = {str(r["id"]): r["result"] for r in results if str(r["id"]).startswith("baseline.")}
    summary = "not_run"
    if suite.baseline_ids and set(baseline) == set(suite.baseline_ids):
        summary = next(
            (
                status
                for status in ("error", "differs", "unsupported", "not_run")
                if status in baseline.values()
            ),
            "passed",
        )
    clean = all(
        c["result"] in {"deleted", "already_released", "expires"}
        for r in results
        for c in cast(list[dict[str, object]], r.get("cleanup", []))
    )
    document: dict[str, object] = {
        "spec": SPEC,
        "provider": driver.provider,
        "driver": {"name": type(driver).__name__, "version": version("sandbox-provider-spec")},
        "sdk_versions": dict(driver.sdk_versions),
        "started_at": started_at,
        "finished_at": now(),
        "revision": spec_revision,
        "suite_digest": suite.digest,
        "selected_tests": [test.id for test in suite.tests],
        "check_digests": check_digests(suite.tests),
        "run_id": run_id(),
        "clean": clean,
        "baseline": summary,
        "tests": list(results),
    }
    if driver.execution_class is not None:
        document["class"] = driver.execution_class
    return document


def write_report(path: Path, document: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
