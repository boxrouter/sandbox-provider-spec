# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""`resources.unmet_limits`: a ceiling on one fact while one of its conditions is unmet."""

from typing import Any

import pytest

import sandbox_provider_spec
from sandbox_provider_spec.matcher.declaration import build_declaration
from sandbox_provider_spec.matcher.matching import fit_resources
from sandbox_provider_spec.matcher.registry import Registry
from sandbox_provider_spec.matcher.request import Request


def _declaration(**resources: Any) -> Any:
    return build_declaration(
        {
            "spec": "sandbox-provider-spec/0.1",
            "provider": "fixture",
            "verified": {"sdks": {"test": "1"}},
            "resources": {
                "max_lifetime_seconds": 86400,
                "disk_mib": {"at_least": 20480},
                "needs": {"max_lifetime_seconds": ["plan"], "disk_mib": ["plan", "beta"]},
                "unmet_limits": {
                    "max_lifetime_seconds": {"plan": 3600},
                    "disk_mib": {"plan": 10240, "beta": 8192},
                },
                **resources,
            },
            "gates": {},
        }
    )


def _fit(declaration: Any, *, met: tuple[str, ...] = (), **asked: Any) -> list[str]:
    lifetime = asked.pop("lifetime_seconds", None)
    request = Request(lifetime_seconds=lifetime, resources=asked)
    _, failed = fit_resources(declaration, request, Registry(), met)
    return [failure["reason"] for _, failure in failed]


def test_a_request_within_the_ceiling_is_offered_while_the_condition_is_unmet() -> None:
    assert _fit(_declaration(), lifetime_seconds=3600) == []


def test_a_request_above_the_ceiling_is_refused_until_the_condition_is_met() -> None:
    declaration = _declaration()
    assert _fit(declaration, lifetime_seconds=3601) == ["resource_mismatch"]
    assert _fit(declaration, met=("plan",), lifetime_seconds=3601) == []


def test_every_unmet_condition_of_a_fact_bounds_it_and_the_smallest_ceiling_wins() -> None:
    declaration = _declaration()
    assert _fit(declaration, disk_min_mib=8192) == []
    assert _fit(declaration, disk_min_mib=8193) == ["resource_mismatch"]
    assert _fit(declaration, met=("beta",), disk_min_mib=10240) == []
    assert _fit(declaration, met=("beta",), disk_min_mib=10241) == ["resource_mismatch"]


def test_a_condition_without_a_ceiling_leaves_the_fact_unanswered() -> None:
    no_ceiling = _declaration(unmet_limits={"disk_mib": {"plan": 10240}})
    assert _fit(no_ceiling, disk_min_mib=1024) == ["resource_unknown"]
    unknown = _declaration(unmet_limits={"max_lifetime_seconds": {"plan": "unknown"}})
    assert _fit(unknown, lifetime_seconds=60) == ["resource_unknown"]
    assert _fit(_declaration(unmet_limits={}), lifetime_seconds=60) == ["resource_unknown"]


def test_a_ceiling_never_clears_another_fact_or_an_unasked_one() -> None:
    declaration = _declaration(unmet_limits={"max_lifetime_seconds": {"plan": 3600}})
    # The lifetime ceiling does not answer the disk fact's conditions.
    assert _fit(declaration, lifetime_seconds=60, disk_min_mib=1024) == ["resource_unknown"]
    # A request that asks no disk is not blocked by the disk fact's conditions.
    assert _fit(declaration, lifetime_seconds=60) == []


def test_a_ceiling_does_not_prove_support_the_declared_fact_still_applies() -> None:
    declaration = _declaration(max_lifetime_seconds=1800)
    assert _fit(declaration, lifetime_seconds=1800) == []
    assert _fit(declaration, lifetime_seconds=2400) == ["resource_mismatch"]


@pytest.mark.parametrize(
    "unmet_limits, fragment",
    [
        ({"sizes": {"plan": 1}}, "resources.unmet_limits.sizes"),
        (
            {"max_lifetime_seconds": {"other": 60}},
            "names no condition of needs.max_lifetime_seconds",
        ),
        ({"max_lifetime_seconds": {"plan": 0}}, "resources.unmet_limits.max_lifetime_seconds.plan"),
        (
            {"max_lifetime_seconds": {"plan": True}},
            "resources.unmet_limits.max_lifetime_seconds.plan",
        ),
        (
            {"max_lifetime_seconds": {"plan": "3600"}},
            "resources.unmet_limits.max_lifetime_seconds.plan",
        ),
        ({"max_lifetime_seconds": {}}, "resources.unmet_limits.max_lifetime_seconds"),
        (["plan"], "resources.unmet_limits"),
    ],
)
def test_the_checker_refuses_a_malformed_or_unanchored_ceiling(
    unmet_limits: Any, fragment: str
) -> None:
    document = _document({"unmet_limits": unmet_limits})
    errors = sandbox_provider_spec.check_declaration(document).errors
    assert any(fragment in error for error in errors), errors


def test_a_ceiling_needs_its_own_citation_and_a_declared_fact() -> None:
    document = _document({})
    assert sandbox_provider_spec.check_declaration(document).errors == []
    del document["evidence"]["resources.unmet_limits.max_lifetime_seconds.plan"]
    errors = sandbox_provider_spec.check_declaration(document).errors
    assert any("resources.unmet_limits.max_lifetime_seconds.plan" in error for error in errors)

    without_need = _document({})
    del without_need["resources"]["needs"]
    assert any(
        "names no condition of needs.max_lifetime_seconds" in error
        for error in sandbox_provider_spec.check_declaration(without_need).errors
    )


def _document(change: dict[str, Any]) -> dict[str, Any]:
    quote = {
        "source": "https://docs.example.invalid/plans",
        "read": "2026-10-30",
        "quote": "A free account can run a sandbox for one hour; a paid account for a day.",
    }
    return {
        "spec": "sandbox-provider-spec/0.1",
        "provider": "acme",
        "verified": {"date": "2026-10-30", "sdks": {"acme": "1.0.0"}},
        "resources": {
            "max_lifetime_seconds": 86400,
            "needs": {"max_lifetime_seconds": ["plan"]},
            "unmet_limits": {"max_lifetime_seconds": {"plan": 3600}},
            **change,
        },
        "gates": {},
        "evidence": {
            "resources.max_lifetime_seconds": quote,
            "resources.needs.max_lifetime_seconds": quote,
            "resources.unmet_limits.max_lifetime_seconds.plan": quote,
        },
    }


def test_confirming_a_condition_never_raises_a_lower_declared_cap() -> None:
    """Row 4 falsifier 3: an account cap below the high-tier maximum survives confirmation."""
    declaration = _declaration(max_lifetime_seconds=1800)
    assert _fit(declaration, met=("plan",), lifetime_seconds=1800) == []
    assert _fit(declaration, met=("plan",), lifetime_seconds=1801) == ["resource_mismatch"]


def test_a_ceiling_does_not_admit_a_disk_the_declared_fact_does_not_establish() -> None:
    """Row 4 falsifier 8: an unrelated ceiling cannot make an unestablished disk ask fit."""
    declaration = _declaration(
        disk_mib={"at_least": 4096},
        needs={"disk_mib": ["plan"]},
        unmet_limits={"disk_mib": {"plan": 10240}},
    )
    assert _fit(declaration, disk_min_mib=4096) == []
    assert _fit(declaration, disk_min_mib=8192) == ["resource_unknown"]


def test_a_disk_ceiling_does_not_admit_a_size_the_class_does_not_offer() -> None:
    """Row 4 falsifier 9: ceilings never construct an allocation the sizes do not list."""
    declaration = _declaration(
        sizes=[{"cpu": 1, "memory_mib": 1024, "disk_mib": 2048}],
        needs={"disk_mib": ["plan"]},
        unmet_limits={"disk_mib": {"plan": 10240}},
    )
    assert _fit(declaration, disk_min_mib=2048) == []
    assert _fit(declaration, disk_min_mib=4096) == ["resource_mismatch"]
