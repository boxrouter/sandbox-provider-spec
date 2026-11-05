# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Synthetic profile controls never substitute for a live mounted-backend report."""

import copy
import json
import shlex
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from sandbox_provider_spec.fuse_mount_identity import (
    CALIBRATION_METRIC,
    DEFAULT_PROOF_PROFILE,
    binding_digest,
    calibration_is_current,
    checkpoint_calibration_script,
    default_proof_errors,
    guest_identity_digest,
    native_plan_digest,
)


def provenance() -> dict[str, Any]:
    binding = {
        "account": "a" * 64,
        "copy": "b" * 64,
        "route": "c" * 64,
        "class": "default",
        "image_kind": "standard_source",
        "image_hash": "sha256:" + "d" * 64,
        "region": "unknown",
        "credential_kind": "byok_version",
        "credential_version": "1",
        "placement_mode": "default",
        "native_plan_digest": "sha256:" + "e" * 64,
    }
    digest = binding_digest(binding)
    guests = [guest_identity_digest(name) for name in ("fixture-writer", "fixture-successor")]
    controller = "sha256:" + "f" * 64
    return {
        "proof_profile": DEFAULT_PROOF_PROFILE,
        "execution_binding": binding,
        "controller_source_digest": controller,
        "prerequisites": [
            "fuse_mount_account",
            "placement:default",
            "image:" + binding["image_hash"],
            "native_plan:" + binding["native_plan_digest"],
            "controller:" + controller,
            "fuse_mount_egress:sha256:" + "a" * 64,
        ],
        "execution_observations": [
            {
                "guest_sha256": guest,
                "session_sha256": None,
                "binding_digest": digest,
                "physical_region": "unknown",
            }
            for guest in guests
        ],
        "calibration_observations": [
            {
                "guest_sha256": guest,
                "binding_digest": digest,
                "storage_identity_sha256": "sha256:" + "b" * 64,
                "storage_region": "aws-us-east-1",
                "metric": CALIBRATION_METRIC,
                "measured_at": "2026-01-01T00:00:00Z",
                "samples_ms": [1.0, 3.0, 2.0],
                "p50_ms": 2.0,
            }
            for guest in guests
        ],
    }


def test_exact_default_identity_keeps_physical_placement_unknown() -> None:
    assert default_proof_errors(provenance()) == []


@pytest.mark.parametrize(
    "change",
    [
        "profile",
        "route",
        "controller",
        "plan",
        "observed_region",
        "explicit_condition",
        "duplicate_guest",
        "missing_calibration",
        "wrong_guest",
        "wrong_binding",
        "metric",
        "median",
        "nonfinite",
        "negative",
        "timestamp",
        "session",
        "extra_secret",
    ],
)
def test_changed_or_malformed_default_identity_never_validates(change: str) -> None:
    document = provenance()
    binding = document["execution_binding"]
    observation = document["execution_observations"][0]
    calibration = document["calibration_observations"][0]
    if change == "profile":
        document["proof_profile"] = "observed-region"
    elif change == "route":
        binding.pop("route")
    elif change == "controller":
        document["controller_source_digest"] = "sha256:" + "0" * 64
    elif change == "plan":
        binding["native_plan_digest"] = "unknown"
    elif change == "observed_region":
        binding["region"] = "us-west-1"
    elif change == "explicit_condition":
        document["prerequisites"][1] = "region:us"
    elif change == "duplicate_guest":
        document["execution_observations"][1] = copy.deepcopy(observation)
    elif change == "missing_calibration":
        document["calibration_observations"].pop()
    elif change == "wrong_guest":
        calibration["guest_sha256"] = guest_identity_digest("other")
    elif change == "wrong_binding":
        calibration["binding_digest"] = "sha256:" + "0" * 64
    elif change == "metric":
        calibration["metric"] = "cold_read_p50_ms"
    elif change == "median":
        calibration["p50_ms"] = 1.0
    elif change == "nonfinite":
        calibration["samples_ms"][0] = float("nan")
    elif change == "negative":
        calibration["samples_ms"][0] = -1
    elif change == "timestamp":
        calibration["measured_at"] = "unknown"
    elif change == "session":
        observation["session_sha256"] = "invented"
    elif change == "extra_secret":
        calibration["token"] = "must-not-be-recorded"
    assert default_proof_errors(document)


def test_native_plan_digest_covers_actual_defaults_class_and_resources() -> None:
    values: dict[str, Any] = {
        "provider": "example",
        "execution_class": "default",
        "resources": {"kernel": "filtered"},
        "native_options": {"image": "artifact", "x": 1},
    }
    original = native_plan_digest(**values)
    assert (
        native_plan_digest(**{**values, "native_options": {"x": 1, "image": "artifact"}})
        == original
    )
    changes: tuple[dict[str, Any], ...] = (
        {"execution_class": "other"},
        {"resources": {}},
        {"native_options": {"x": 2}},
    )
    for change in changes:
        assert native_plan_digest(**{**values, **change}) != original
    for invalid in (object(), float("nan")):
        with pytest.raises(ValueError, match="finite JSON"):
            native_plan_digest(**{**values, "native_options": {"bad": invalid}})


@pytest.mark.parametrize("measured", ["2026-01-01T00:00:01Z", "2025-12-31T23:58:59Z", "bad"])
def test_unknown_future_and_expired_calibration_cannot_place(measured: str) -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    assert not calibration_is_current({"measured_at": measured}, now=now, max_age_seconds=60)
    assert calibration_is_current(
        {"measured_at": "2025-12-31T23:59:00Z"}, now=now, max_age_seconds=60
    )


def test_calibration_script_executes_three_distinct_acknowledgements(tmp_path: Path) -> None:
    # Local control checks script mechanics only; this is not mount or provider evidence.
    commands = [
        shlex.join(
            [
                sys.executable,
                "-c",
                "from pathlib import Path; import sys; Path(sys.argv[1]).write_text('ack')",
                str(tmp_path / str(i)),
            ]
        )
        for i in range(3)
    ]
    script = checkpoint_calibration_script(str(tmp_path), commands)
    result = subprocess.run(script, shell=True, check=True, capture_output=True, text=True)
    values = json.loads(result.stdout)
    assert set(values) == {"samples_ms", "p50_ms"}
    assert len(values["samples_ms"]) == 3
    assert values["p50_ms"] == sorted(values["samples_ms"])[1]
    assert all((tmp_path / str(i)).read_text() == "ack" for i in range(3))
    assert not list(tmp_path.glob(".sps-calibration-*"))
    with pytest.raises(ValueError, match="three distinct"):
        checkpoint_calibration_script(str(tmp_path), [commands[0]] * 3)
