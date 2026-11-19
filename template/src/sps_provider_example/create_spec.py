# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Translate a 1.0 `CreateRequest` into an Example Cloud machine spec."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from sandbox_provider_spec.v1 import CreateRequest, Size, SnapshotRequest, SpsError

from sps_provider_example.facts import (
    CLASS,
    DEFAULT_SIZE,
    IMAGE,
    MAX_LIFETIME_S,
    REGION,
    SIZES,
    SNAPSHOTS,
    TAG_BODY,
    TAG_IDEM,
    TAG_LABEL,
)


def fingerprint(request: CreateRequest) -> str:
    """A stable digest of the request, stored as a tag to detect a replayed key."""
    doc = {
        "sandbox_class": request.sandbox_class,
        "resources": dict(request.resources),
        "requirements": dict(request.requirements),
        "image": request.image,
        "lifetime_seconds": request.lifetime_seconds,
        "at_end": request.at_end,
        "env": dict(request.env),
        "labels": dict(request.labels),
        "snapshot": request.snapshot,
    }
    raw = json.dumps(doc, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode()).hexdigest()


def _offers(value: object, wanted: str) -> bool:
    """Whether a requirement's value (one value or a list of them) accepts `wanted`."""
    return wanted in value if isinstance(value, list) else value == wanted


def check_requirements(requirements: Mapping[str, object]) -> None:
    """Example Cloud claims two sections: `snapshots`, with the variant of `SNAPSHOTS`, and a
    `terminal` that cannot be reattached."""
    for gate, wanted in requirements.items():
        if gate == "terminal" and isinstance(wanted, Mapping):
            if wanted.get("reattach", False) is not False or set(wanted) - {"reattach"}:
                raise SpsError("unsupported", "Example Cloud's terminal cannot be reattached")
            continue
        if gate != "snapshots" or not isinstance(wanted, Mapping):
            raise SpsError("unsupported", f"Example Cloud does not claim the section {gate!r}")
        for knob, value in wanted.items():
            if knob == "original_after":
                ok = value == "any" or _offers(value, SNAPSHOTS[knob])
            elif knob in SNAPSHOTS:
                ok = value == SNAPSHOTS[knob] or (
                    knob == "keeps" and _offers(value, SNAPSHOTS[knob])
                )
            else:
                ok = False
            if not ok:
                raise SpsError("unsupported", f"Example Cloud cannot meet snapshots.{knob}")


def snapshot_fingerprint(sandbox_id: str, request: SnapshotRequest) -> str:
    """A stable digest of a snapshot request, stored as a tag to detect a replayed key."""
    doc = {"sandbox_id": sandbox_id, "keeps": request.keeps, "labels": dict(request.labels)}
    return hashlib.sha256(json.dumps(doc, sort_keys=True).encode()).hexdigest()


def plan_create(
    request: CreateRequest, snapshot_size: Size | None = None
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Translate a `CreateRequest` into a machine spec and its meta document. A restore passes
    the size of its snapshot, which the new machine must have."""
    if request.snapshot is not None and request.image is not None:
        raise SpsError("invalid_request", "A restore names no image")
    if request.sandbox_class != CLASS:
        raise SpsError("unsupported", f"Example Cloud has no class {request.sandbox_class!r}")
    if request.at_end == "paused":
        raise SpsError("unsupported", "Example Cloud cannot pause a machine")
    check_requirements(request.requirements)
    if request.image not in (None, IMAGE):
        raise SpsError("unsupported", "Example Cloud offers only the 'base' image")
    floors: dict[str, Any] = {}
    for key, value in dict(request.resources).items():
        if value is None or (key == "root" and value == "by_default"):
            continue
        if key in ("cpu_min", "memory_min_mib"):
            floors[key] = float(value)
        elif key == "region":
            if value != REGION:
                raise SpsError("unsupported", f"Example Cloud has no region {value!r}")
        else:
            raise SpsError("unsupported", f"Example Cloud cannot meet resources.{key}")
    if snapshot_size is not None:
        # Example Cloud restores at the size of the image and cannot resize on restore, so a
        # floor that the snapshot's size does not meet is a request for another size.
        if snapshot_size.cpu < floors.get("cpu_min", 0) or snapshot_size.memory_mib < floors.get(
            "memory_min_mib", 0
        ):
            raise SpsError("unsupported", "A restore has the size of its snapshot")
        size: Size | None = snapshot_size
    elif floors:
        size = next(
            (
                s
                for s in SIZES
                if s.cpu >= floors.get("cpu_min", 0)
                and s.memory_mib >= floors.get("memory_min_mib", 0)
            ),
            None,
        )
    else:
        size = DEFAULT_SIZE
    if size is None:
        raise SpsError("unsupported", "No Example Cloud size meets the request")
    lifetime = request.lifetime_seconds
    if lifetime is not None:
        if not isinstance(lifetime, int) or lifetime < 1:
            raise SpsError("invalid_request", "lifetime_seconds must be an integer >= 1")
        if lifetime > MAX_LIFETIME_S:
            raise SpsError("unsupported", f"lifetime is capped at {MAX_LIFETIME_S}s")
    tags = {TAG_IDEM: "", TAG_BODY: ""}  # filled in by create()
    tags.update({f"{TAG_LABEL}{k}": v for k, v in request.labels.items() if "/" not in k})
    spec = {
        "cpu": size.cpu,
        "memory_mb": size.memory_mib,
        "ttl_seconds": lifetime,
        "env": dict(request.env),
        "tags": tags,
    }
    if request.snapshot is not None:
        spec["image_id"] = request.snapshot
    meta = {
        "labels": dict(request.labels),
        "size": {"cpu": size.cpu, "memory_mib": size.memory_mib},
    }
    return spec, meta
