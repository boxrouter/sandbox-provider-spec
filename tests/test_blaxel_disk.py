# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Blaxel's writable filesystem is in-memory, so memory covers a memory-and-disk ask."""

from __future__ import annotations

from pathlib import Path

import sandbox_provider_spec
from sandbox_provider_spec.load import load
from sandbox_provider_spec.matcher import declared_fit

ROOT = Path(__file__).resolve().parents[1]


def test_blaxel_declares_its_disk_in_memory() -> None:
    native = load(ROOT / "providers" / "blaxel" / "declaration.yaml")
    assert native["resources"]["disk_in_memory"] is True
    assert "disk_mib" not in native["resources"]
    assert sandbox_provider_spec.schema_errors(native, "declaration-schema.json") == []
    assert sandbox_provider_spec.check_declaration(native).errors == []


def test_blaxel_actions_runner_ask_fits_the_16384_size() -> None:
    """The 8,192 MiB memory + 8,192 MiB disk Actions ask folds into one memory ask."""
    native = load(ROOT / "providers" / "blaxel" / "declaration.yaml")
    request = {
        "resources": {
            "cpu_min": 4,
            "memory_min_mib": 8192,
            "disk_min_mib": 8192,
            "size_is_ceiling": True,
            "kernel": ["shared", "dedicated"],
        },
        "requirements": {"processes": {"reattach": True}},
    }
    result = declared_fit(request, [native])
    fit = result["results"]["blaxel"]
    assert fit["compatible"] is True, fit["failed"]
    assert fit["resources"]["size"] == {"cpu": 6, "memory_mib": 16384, "disk_mib": None}
