# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The PyPI publish workflow stays switched off, token-free and limited to the verified wheel."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"


def _workflow() -> dict[str, Any]:
    loaded = yaml.safe_load((WORKFLOWS / "publish-pypi.yml").read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _jobs() -> dict[str, dict[str, Any]]:
    jobs = _workflow()["jobs"]
    assert isinstance(jobs, dict)
    return jobs


def _steps(job: str) -> list[dict[str, Any]]:
    steps = _jobs()[job]["steps"]
    assert isinstance(steps, list)
    return steps


def test_publishing_is_off_unless_both_switches_are_enabled() -> None:
    # PyYAML reads the bare key `on` as the boolean True.
    triggers = {str(key): value for key, value in _workflow().items()}["True"]
    assert set(triggers) == {"schedule", "workflow_dispatch"}
    assert triggers["workflow_dispatch"]["inputs"]["dry_run"]["default"] is True
    assert _jobs()["gate"]["if"] == "github.repository == 'boxrouter/sandbox-provider-spec'"
    [step] = _steps("gate")
    assert step["env"]["REPO_SWITCH"] == "${{ vars.PYPI_PUBLISH_SANDBOX_PROVIDER_SPEC }}"
    assert step["env"]["ORG_SWITCH"] == "${{ vars.BOXROUTER_PUBLIC_RELEASES }}"
    assert '[ "$REPO_SWITCH" = enabled ] && [ "$ORG_SWITCH" = enabled ]' in step["run"]
    assert _jobs()["resolve"]["needs"] == "gate"
    assert _jobs()["resolve"]["if"] == "needs.gate.outputs.run == 'true'"


def test_only_the_publish_job_can_mint_an_identity_token_and_no_token_is_stored() -> None:
    assert _workflow()["permissions"] == {}
    for name, job in _jobs().items():
        permissions = job.get("permissions", {})
        if name == "publish":
            assert permissions == {"id-token": "write"}
            assert job["environment"]["name"] == "pypi"
        else:
            assert "id-token" not in permissions, name
            assert "environment" not in job, name
    text = (WORKFLOWS / "publish-pypi.yml").read_text(encoding="utf-8")
    assert "secrets." not in text
    assert "password:" not in text
    assert "PYPI_API_TOKEN" not in text


def test_publish_uploads_only_the_artifact_the_candidate_job_verified() -> None:
    publish = _jobs()["publish"]
    assert publish["needs"] == ["resolve", "candidate"]
    assert "inputs.dry_run" in publish["if"]
    assert [step.get("uses", "").split("@")[0] for step in publish["steps"]] == [
        "actions/download-artifact",
        "",
        "pypa/gh-action-pypi-publish",
    ]
    assert "actions/checkout" not in {
        step.get("uses", "").split("@")[0] for step in publish["steps"]
    }
    assert "sha256sum --check --strict" in publish["steps"][1]["run"]


@pytest.mark.parametrize("job", ["gate", "resolve", "candidate", "publish", "check"])
def test_every_action_is_pinned_to_a_commit(job: str) -> None:
    for step in _steps(job):
        if "uses" in step:
            assert re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", step["uses"]), step["uses"]


def test_the_candidate_job_checks_the_release_assets_against_each_other() -> None:
    script = "\n".join(str(step.get("run", "")) for step in _steps("candidate"))
    for required in (
        "sha256sum --check --strict SHA256SUMS",
        "gh attestation verify",
        '--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/release.yml"',
        "scripts/verify_distribution.py",
        "twine check --strict",
        "uv publish --dry-run",
    ):
        assert required in script, required
    assert "uv build" not in script, "the release wheel is uploaded as built, never rebuilt"
