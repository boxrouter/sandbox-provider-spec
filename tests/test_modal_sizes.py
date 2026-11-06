# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Modal sizes freely: a fitting size is provisioned as asked, and it can be a ceiling."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from sandbox_provider_spec.load import load
from sandbox_provider_spec.matcher import declared_fit

PROVIDER = Path(__file__).resolve().parents[1] / "providers" / "modal"
CLASSES = {"default": "declaration.yaml", "vm": "declaration-vm.yaml"}
FITTING = [
    ("default", 2, 4096),
    ("default", 4, 8192),
    ("vm", 2, 4096),
    ("vm", 16, 32768),
]


def _fit(execution_class: str, **resources: object) -> Any:
    declaration = load(PROVIDER / CLASSES[execution_class])
    fit = declared_fit({"resources": resources}, [declaration])
    assert fit["rejected"] is None
    return fit["results"][f"modal/{execution_class}"]


@pytest.mark.parametrize(("execution_class", "cpu", "memory_mib"), FITTING)
def test_a_fitting_size_is_provisioned_as_asked(
    execution_class: str, cpu: int, memory_mib: int
) -> None:
    fit = _fit(execution_class, cpu_min=cpu, memory_min_mib=memory_mib)
    assert fit["compatible"] is True, fit["failed"]
    assert fit["resources"]["size"] == {"cpu": cpu, "memory_mib": memory_mib}


@pytest.mark.parametrize(("execution_class", "cpu", "memory_mib"), FITTING)
def test_a_fitting_size_can_be_asked_for_as_a_ceiling(
    execution_class: str, cpu: int, memory_mib: int
) -> None:
    fit = _fit(execution_class, cpu_min=cpu, memory_min_mib=memory_mib, size_is_ceiling=True)
    assert fit["compatible"] is True, fit["failed"]
    assert fit["resources"]["size"] == {"cpu": cpu, "memory_mib": memory_mib}


@pytest.mark.parametrize(
    ("execution_class", "cpu", "memory_mib"),
    [("default", 5, 8192), ("default", 4, 8193), ("vm", 17, 32768), ("vm", 16, 32769)],
)
def test_a_size_above_the_largest_created_does_not_fit(
    execution_class: str, cpu: int, memory_mib: int
) -> None:
    assert _fit(execution_class, cpu_min=cpu, memory_min_mib=memory_mib)["compatible"] is False
