# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""A size refusal says which ask is too large and what the largest size offers."""

from typing import Any

import pytest

from sandbox_provider_spec.matcher.declaration import build_declaration
from sandbox_provider_spec.matcher.matching import fit_resources
from sandbox_provider_spec.matcher.registry import Registry
from sandbox_provider_spec.matcher.request import Request


def _detail(sizes: list[dict[str, Any]], **asked: Any) -> str:
    declaration = build_declaration(
        {
            "spec": "sandbox-provider-spec/0.1",
            "provider": "fixture",
            "verified": {"sdks": {"test": "1"}},
            "resources": {"sizes": sizes, "disk_mib": 10240},
            "gates": {},
        }
    )
    _, failed = fit_resources(declaration, Request(resources=asked), Registry(), ())
    ((_, failure),) = failed
    assert failure["reason"] == "resource_mismatch"
    return failure["detail"]


SIZES = [{"cpu": 2, "memory_mib": 4096}, {"cpu": 8, "memory_mib": 16384}]
SPLIT = [{"cpu": 2, "memory_mib": 16384}, {"cpu": 8, "memory_mib": 4096}]


@pytest.mark.parametrize(
    ("sizes", "asked", "detail"),
    [
        (SIZES, {"cpu_min": 1000}, "The request needs 1,000 CPU; the largest size offers 8."),
        (
            SIZES,
            {"memory_min_mib": 99999999},
            "The request needs 99,999,999 MiB of memory; the largest size offers 16,384.",
        ),
        (
            SIZES,
            {"disk_min_mib": 99999999},
            "The request needs 99,999,999 MiB of disk; the largest size offers 10,240.",
        ),
        (
            SPLIT,
            {"cpu_min": 8, "memory_min_mib": 12000},
            "No single size holds all of: 8 CPU, 12,000 MiB of memory.",
        ),
    ],
)
def test_a_size_refusal_names_the_ask_and_the_largest_size(
    sizes: list[dict[str, Any]], asked: dict[str, int], detail: str
) -> None:
    text = _detail(sizes, **asked)
    assert text.startswith(detail)
    assert "{" not in text


def test_a_lifetime_refusal_states_the_most_a_route_allows() -> None:
    declaration = build_declaration(
        {
            "spec": "sandbox-provider-spec/0.1",
            "provider": "fixture",
            "verified": {"sdks": {"test": "1"}},
            "resources": {"max_lifetime_seconds": 3600},
            "gates": {},
        }
    )
    _, failed = fit_resources(declaration, Request(lifetime_seconds=7200), Registry(), ())
    assert [failure["detail"] for _, failure in failed] == [
        "lifetime_seconds 7,200: the most a route allows is 3,600 s"
    ]
