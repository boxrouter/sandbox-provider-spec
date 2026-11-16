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


def test_blaxel_actions_runner_labels_never_exceed_the_largest_declared_shape() -> None:
    """Disk-backed memory must fit in the selected shape for each runner label."""
    native = load(ROOT / "providers" / "blaxel" / "declaration.yaml")
    expected_shape = {"cpu": 6, "memory_mib": 16384, "disk_mib": None}
    cases = (
        (2, 4096, True),
        (4, 8192, True),
        (8, 8192, False),
        (16, 32768, False),
        (None, 4096, True),
    )

    for cpu, memory_mib, expected_to_fit in cases:
        request = {
            "resources": {
                **({} if cpu is None else {"cpu_min": cpu}),
                "memory_min_mib": memory_mib,
                "disk_min_mib": 8192,
                "size_is_ceiling": True,
            },
            "requirements": {"processes": {"reattach": True}},
        }
        fit = declared_fit(request, [native])["results"]["blaxel"]

        assert fit["compatible"] is expected_to_fit, (cpu, memory_mib, fit["failed"])
        if expected_to_fit:
            assert fit["resources"]["size"] == expected_shape
