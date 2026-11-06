# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Daytona's container class fits a request for a prepared OCI image."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sandbox_provider_spec.load import load
from sandbox_provider_spec.matcher import build_declaration, declared_fit

ROOT = Path(__file__).resolve().parents[1]
NAME = "daytona/container"
REQUEST = {
    "image": "docker.io/library/python@sha256:" + "a" * 64,
    "requirements": {"custom_images": {"prepared": True}},
    "resources": {"cpu_min": 2, "memory_min_mib": 4096, "size_is_ceiling": True},
}


def _declaration() -> Any:
    return load(ROOT / "providers" / "daytona" / "declaration-container.yaml")


def _fit(native: Any) -> Any:
    return declared_fit(REQUEST, [build_declaration(native)])["results"][NAME]


def test_prepared_oci_request_fits_the_declared_variant() -> None:
    assert _fit(_declaration())["compatible"] is True


def test_prepared_oci_request_is_refused_without_the_oci_variant() -> None:
    native = _declaration()
    gate = native["gates"]["custom_images"]
    native["gates"]["custom_images"] = [item for item in gate if item.get("source") != "oci"]
    result = _fit(native)
    assert result["compatible"] is False
    assert [failure["reason"] for failure in result["failed"]] == ["knob_mismatch"]
