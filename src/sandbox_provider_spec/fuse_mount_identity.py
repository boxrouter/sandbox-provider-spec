# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Identity and guest measurements for a source-bound default-placement mount proof."""

from __future__ import annotations

import hashlib
import json
import math
import re
import shlex
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from statistics import median
from typing import Any

DEFAULT_PROOF_PROFILE = "default-placement/v1"
CALIBRATION_METRIC = "write_fsync_checkpoint_ms/v1"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
BINDING_FIELDS = frozenset(
    {
        "account",
        "copy",
        "route",
        "class",
        "image_kind",
        "image_hash",
        "region",
        "credential_kind",
        "credential_version",
        "credential_fingerprint",
        "placement_mode",
        "native_plan_digest",
    }
)


def _digest(value: object) -> str:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError):
        raise ValueError("Mount proof identity requires finite JSON data") from None
    return "sha256:" + hashlib.sha256(encoded.encode()).hexdigest()


def native_plan_digest(
    *,
    provider: str,
    execution_class: str,
    resources: Mapping[str, object],
    native_options: Mapping[str, object],
) -> str:
    """Hash actual public class resources and native planner output without exposing either."""
    return _digest(
        {
            "profile": DEFAULT_PROOF_PROFILE,
            "provider": provider,
            "class": execution_class,
            "resources": dict(resources),
            "native_options": dict(native_options),
        }
    )


def binding_digest(binding: Mapping[str, str]) -> str:
    """Stable binding identity; guest/session observations remain separate."""
    return _digest(dict(binding))


def guest_identity_digest(identity: str) -> str:
    """Hash an actual public sandbox identity, never a fabricated placement value."""
    if not isinstance(identity, str) or not identity:
        raise ValueError("An actual sandbox identity is required")
    return _digest({"sandbox_id": identity})


def _utc_time(value: object) -> datetime | None:
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.utcoffset() == timedelta(0) else None


def calibration_is_current(
    observation: Mapping[str, Any], *, now: datetime, max_age_seconds: int
) -> bool:
    """An unknown, future or expired measurement cannot be reused as a current diagnostic."""
    measured = _utc_time(observation.get("measured_at"))
    return (
        measured is not None
        and now.utcoffset() == timedelta(0)
        and timedelta(0) <= now - measured <= timedelta(seconds=max_age_seconds)
    )


def _valid_digest(value: object) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


# Validate each closed profile at one boundary; no partial field acceptance.
# pylint: disable=too-many-boolean-expressions
def _calibration_errors(record: object, *, guests: set[str], binding: str) -> list[str]:
    if not isinstance(record, Mapping):
        return ["default placement calibration must be an object"]
    expected = {
        "guest_sha256",
        "binding_digest",
        "storage_identity_sha256",
        "storage_region",
        "metric",
        "measured_at",
        "samples_ms",
        "p50_ms",
    }
    if set(record) != expected:
        return ["default placement calibration fields are invalid"]
    samples = record["samples_ms"]
    if (
        not _valid_digest(record["guest_sha256"])
        or record["guest_sha256"] not in guests
        or record["binding_digest"] != binding
        or not _valid_digest(record["storage_identity_sha256"])
        or not isinstance(record["storage_region"], str)
        or not 1 <= len(record["storage_region"]) <= 64
        or record["storage_region"] in {"unknown", "default"}
        or re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", record["storage_region"]) is None
        or record["metric"] != CALIBRATION_METRIC
        or _utc_time(record["measured_at"]) is None
    ):
        return ["default placement calibration identity is invalid"]
    if (
        not isinstance(samples, list)
        or len(samples) != 3
        or any(
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not 0 < value <= 120000
            or not math.isfinite(value)
            for value in samples
        )
        or isinstance(record["p50_ms"], bool)
        or not isinstance(record["p50_ms"], (int, float))
        or not 0 < record["p50_ms"] <= 120000
        or not math.isfinite(record["p50_ms"])
        or record["p50_ms"] != median(samples)
    ):
        return ["default placement calibration samples or median are invalid"]
    return []


def default_proof_errors(provenance: Mapping[str, Any]) -> list[str]:
    """Validate the new profile without reinterpreting historical region observations."""
    fields = {
        "proof_profile",
        "execution_binding",
        "controller_source_digest",
        "prerequisites",
        "execution_observations",
        "calibration_observations",
    }
    if set(provenance) != fields or provenance.get("proof_profile") != DEFAULT_PROOF_PROFILE:
        return ["default placement proof profile is invalid"]
    binding = provenance.get("execution_binding")
    if (
        not isinstance(binding, Mapping)
        or any(
            not isinstance(key, str) or not isinstance(value, str) for key, value in binding.items()
        )
        or not set(binding) <= BINDING_FIELDS
        or binding.get("placement_mode") != "default"
        or binding.get("region") != "unknown"
        or not _valid_digest(binding.get("native_plan_digest"))
        or any(
            re.fullmatch(r"[0-9a-f]{64}", str(binding.get(key, ""))) is None
            for key in ("route", "account", "copy")
        )
        or not isinstance(binding.get("class"), str)
        or not 1 <= len(binding["class"]) <= 64
        or binding.get("image_kind") not in {"standard_source", "oci_source"}
        or not _valid_digest(binding.get("image_hash"))
        or binding.get("credential_kind") not in {"byok_version", "managed_binding"}
        or re.fullmatch(r"[1-9][0-9]*", str(binding.get("credential_version", ""))) is None
        or (
            "credential_fingerprint" in binding
            and re.fullmatch(r"[0-9a-f]{64}", str(binding["credential_fingerprint"])) is None
        )
        or (
            binding.get("credential_kind") == "managed_binding"
            and "credential_fingerprint" not in binding
        )
        or len(str(binding.get("credential_version", ""))) > 32
    ):
        return ["default placement execution binding is invalid"]
    prerequisites = provenance.get("prerequisites")
    if (
        not isinstance(prerequisites, list)
        or any(not isinstance(value, str) for value in prerequisites)
        or len(prerequisites) != 6
        or len(set(prerequisites)) != 6
        or not _valid_digest(provenance.get("controller_source_digest"))
        or "controller:" + provenance["controller_source_digest"] not in prerequisites
        or not {
            "placement:default",
            "native_plan:" + binding["native_plan_digest"],
            "image:" + binding["image_hash"],
            "fuse_mount_account",
        }
        <= set(prerequisites)
        or sum(
            bool(re.fullmatch(r"controller:sha256:[0-9a-f]{64}", value)) for value in prerequisites
        )
        != 1
        or sum(
            bool(re.fullmatch(r"fuse_mount_egress:sha256:[0-9a-f]{64}", value))
            for value in prerequisites
        )
        != 1
    ):
        return ["default placement prerequisites are invalid"]
    digest = binding_digest(binding)
    observations = provenance.get("execution_observations")
    if not isinstance(observations, list) or len(observations) != 2:
        return ["default placement requires two actual execution observations"]
    guests: set[str] = set()
    fields = {"guest_sha256", "session_sha256", "binding_digest", "physical_region"}
    for observation in observations:
        if (
            not isinstance(observation, Mapping)
            or set(observation) != fields
            or not _valid_digest(observation.get("guest_sha256"))
            or observation["binding_digest"] != digest
            or observation["physical_region"] != "unknown"
            or (
                observation["session_sha256"] is not None
                and not _valid_digest(observation["session_sha256"])
            )
        ):
            return ["default placement execution observation identity is invalid"]
        guests.add(observation["guest_sha256"])
    if len(guests) != 2:
        return ["default placement requires two distinct actual guests"]
    calibrations = provenance.get("calibration_observations")
    if not isinstance(calibrations, list) or len(calibrations) != 2:
        return ["default placement requires writer and successor calibrations"]
    errors = [
        error
        for record in calibrations
        for error in _calibration_errors(record, guests=guests, binding=digest)
    ]
    if not errors and {record["guest_sha256"] for record in calibrations} != guests:
        errors.append("default placement calibration guests do not match executions")
    return errors


# pylint: enable=too-many-boolean-expressions

_CALIBRATION_SOURCE = r"""import json,os,statistics,subprocess,sys,time,uuid
root,*checkpoints=sys.argv[1:]
path=os.path.join(root,'.sps-calibration-'+uuid.uuid4().hex)
samples=[]
try:
 for checkpoint in checkpoints:
  started=time.perf_counter_ns()
  with open(path,'wb',buffering=0) as handle:
   handle.write(os.urandom(32));os.fsync(handle.fileno())
  subprocess.run(['/bin/bash','-c',checkpoint],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)
  samples.append((time.perf_counter_ns()-started)/1000000)
finally:
 if os.path.exists(path):os.unlink(path)
print(json.dumps({'samples_ms':samples,'p50_ms':statistics.median(samples)}))
"""


def checkpoint_calibration_script(path: str, checkpoint_commands: Sequence[str]) -> str:
    """Measure guest write/fsync plus actual checkpoint acknowledgement, excluding transport."""
    if (
        not path.startswith("/")
        or isinstance(checkpoint_commands, str)
        or len(checkpoint_commands) != 3
        or any(not isinstance(command, str) or not command for command in checkpoint_commands)
        or len(set(checkpoint_commands)) != 3
    ):
        raise ValueError("A mount path and three distinct backend checkpoint commands are required")
    return shlex.join(["python3", "-c", _CALIBRATION_SOURCE, path, *checkpoint_commands])
