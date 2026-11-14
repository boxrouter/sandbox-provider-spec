# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Translate a 1.0 `CreateRequest` into an Example Cloud machine spec."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from sandbox_provider_spec.v1 import CreateRequest, SpsError

from sps_provider_example.facts import (
    CLASS,
    DEFAULT_SIZE,
    IMAGE,
    MAX_LIFETIME_S,
    REGION,
    SIZES,
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
    }
    raw = json.dumps(doc, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode()).hexdigest()


def plan_create(request: CreateRequest) -> tuple[dict[str, Any], dict[str, Any]]:
    """Translate a `CreateRequest` into a machine spec and its meta document."""
    if request.sandbox_class != CLASS:
        raise SpsError("unsupported", f"Example Cloud has no class {request.sandbox_class!r}")
    if request.at_end == "paused":
        raise SpsError("unsupported", "Example Cloud cannot pause a machine")
    if request.requirements:
        raise SpsError("unsupported", "Example Cloud claims no optional sections")
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
    if floors:
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
    meta = {
        "labels": dict(request.labels),
        "size": {"cpu": size.cpu, "memory_mib": size.memory_mib},
    }
    return spec, meta
