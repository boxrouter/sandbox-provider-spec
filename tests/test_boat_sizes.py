# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Boat's offered sizes are the documented small and default machines."""

from __future__ import annotations

from pathlib import Path

import sandbox_provider_spec
from sandbox_provider_spec.load import load

ROOT = Path(__file__).resolve().parents[1]


def test_boat_offers_small_beside_the_documented_default() -> None:
    native = load(ROOT / "providers" / "boat" / "declaration.yaml")
    resources = native["resources"]
    assert resources["sizes"] == [
        {"cpu": 2, "memory_mib": 4096},
        {"cpu": 4, "memory_mib": 8192},
    ]
    assert resources["default_size"] == {"cpu": 4, "memory_mib": 8192}
    assert resources["size_is_ceiling"] is True
    assert native["gates"] == {}
    assert sandbox_provider_spec.schema_errors(native, "declaration-schema.json") == []
    assert sandbox_provider_spec.check_declaration(native).errors == []
