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
        ({"cpu": {"plan": 1}}, "resources.unmet_limits.cpu"),
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


#: A plan sells the 8 CPU size; the accounts without it get up to 4 CPU and 8 GiB.
PLAN_SIZES: dict[str, Any] = {
    "sizes": [
        {"cpu": 2, "memory_mib": 4096},
        {"cpu": 4, "memory_mib": 8192},
        {"cpu": 8, "memory_mib": 16384},
    ],
    "default_size": {"cpu": 2, "memory_mib": 4096},
    "needs": {"sizes": ["plan"]},
    "unmet_limits": {"sizes": {"plan": {"cpu": 4, "memory_mib": 8192}}},
}


def _size(declaration: Any, *, met: tuple[str, ...] = (), **asked: Any) -> Any:
    """The size chosen, or the reason and sentence of each refusal."""
    provisioned, failed = fit_resources(declaration, Request(resources=asked), Registry(), met)
    if failed:
        return [(failure["reason"], failure["detail"]) for _, failure in failed]
    return provisioned.get("size")


def test_a_confirmed_plan_gets_the_big_size_and_others_the_sizes_under_the_ceiling() -> None:
    declaration = _declaration(**PLAN_SIZES)
    assert _size(declaration, met=("plan",), cpu_min=8) == {"cpu": 8, "memory_mib": 16384}
    assert _size(declaration, cpu_min=4) == {"cpu": 4, "memory_mib": 8192}
    assert _size(declaration, memory_min_mib=8192) == {"cpu": 4, "memory_mib": 8192}
    assert _size(declaration) is None


@pytest.mark.parametrize("asked", [{"cpu_min": 8}, {"memory_min_mib": 8193}])
def test_an_ask_above_the_size_ceiling_is_refused_with_what_the_account_allows(
    asked: dict[str, int],
) -> None:
    _, failed = fit_resources(_declaration(**PLAN_SIZES), Request(resources=asked), Registry(), ())
    ((_, failure),) = failed
    assert failure["reason"] == "resource_mismatch"
    assert failure["detail"].endswith("This account allows at most 4 CPU and 8,192 MiB of memory.")
    assert failure.get("offered") == PLAN_SIZES["sizes"][:2]


def test_a_size_ceiling_skips_a_preferred_size_above_it() -> None:
    declaration = _declaration(
        **{**PLAN_SIZES, "sizes": [{"cpu": 2, "memory_mib": 16384}, {"cpu": 4, "memory_mib": 8192}]}
    )
    assert _size(declaration, memory_min_mib=4096) == {"cpu": 4, "memory_mib": 8192}
    assert _size(declaration, met=("plan",), memory_min_mib=4096) == {
        "cpu": 2,
        "memory_mib": 16384,
    }


def test_a_range_ends_at_the_size_ceiling() -> None:
    declaration = _declaration(
        **{**PLAN_SIZES, "sizes": [{"cpu": [1, 16], "memory_mib": [1024, 65536]}]}
    )
    assert _size(declaration, cpu_min=4) == {"cpu": 4, "memory_mib": 1024}
    ((reason, _),) = _size(declaration, cpu_min=5)
    assert reason == "resource_mismatch"
    assert _size(declaration, met=("plan",), cpu_min=16) == {"cpu": 16, "memory_mib": 1024}


def test_the_smallest_size_ceiling_of_the_unmet_conditions_wins_in_each_field() -> None:
    declaration = _declaration(
        **{
            **PLAN_SIZES,
            "needs": {"sizes": ["plan", "beta"]},
            "unmet_limits": {
                "sizes": {
                    "plan": {"cpu": 4, "memory_mib": 16384},
                    "beta": {"cpu": 8, "memory_mib": 4096},
                }
            },
        }
    )
    assert _size(declaration, cpu_min=2) == {"cpu": 2, "memory_mib": 4096}
    ((reason, _),) = _size(declaration, cpu_min=4)
    assert reason == "resource_mismatch"
    assert _size(declaration, met=("beta",), cpu_min=4) == {"cpu": 4, "memory_mib": 8192}


@pytest.mark.parametrize(
    "unmet_limits",
    [
        {},
        {"sizes": {"plan": "unknown"}},
        {"sizes": {"plan": {"cpu": 4}}},
        {"sizes": {"plan": 4}},
        {"sizes": {"other": {"cpu": 4, "memory_mib": 8192}}},
    ],
)
def test_sizes_stay_unanswered_without_a_ceiling_for_the_unmet_condition(
    unmet_limits: dict[str, Any],
) -> None:
    declaration = _declaration(**{**PLAN_SIZES, "unmet_limits": unmet_limits})
    ((reason, _),) = _size(declaration, cpu_min=1)
    assert reason == "resource_unknown"


def _sizes_document(ceiling: Any, **resources: Any) -> dict[str, Any]:
    document = _document({**PLAN_SIZES, "unmet_limits": {"sizes": {"plan": ceiling}}, **resources})
    quote = document["evidence"]["resources.max_lifetime_seconds"]
    document["resources"].pop("max_lifetime_seconds")
    document["evidence"] = {
        path: quote
        for path in (
            "resources.sizes",
            "resources.default_size",
            "resources.needs.sizes",
            "resources.unmet_limits.sizes.plan",
        )
    }
    return document


def test_the_checker_accepts_a_size_ceiling_and_needs_its_citation() -> None:
    document = _sizes_document({"cpu": 4, "memory_mib": 8192})
    assert sandbox_provider_spec.check_declaration(document).errors == []
    del document["evidence"]["resources.unmet_limits.sizes.plan"]
    errors = sandbox_provider_spec.check_declaration(document).errors
    assert any("resources.unmet_limits.sizes.plan" in error for error in errors), errors


@pytest.mark.rule("declaration/size-ceiling-holds-a-size")
@pytest.mark.parametrize(
    "ceiling, fragment",
    [
        (4, "resources.unmet_limits.sizes.plan"),
        ({"cpu": 4}, "resources.unmet_limits.sizes.plan"),
        ({"cpu": 4, "memory_mib": 0}, "resources.unmet_limits.sizes.plan"),
        ({"cpu": True, "memory_mib": 8192}, "resources.unmet_limits.sizes.plan"),
        ({"cpu": 4, "memory_mib": 8192.5}, "resources.unmet_limits.sizes.plan"),
        ({"cpu": 4, "memory_mib": 8192, "disk_mib": 1}, "resources.unmet_limits.sizes.plan"),
        ({"cpu": 1, "memory_mib": 8192}, "leaves no declared size"),
        ({"cpu": 2, "memory_mib": 2048}, "leaves no declared size"),
    ],
)
def test_the_checker_refuses_a_size_ceiling_that_is_malformed_or_holds_no_size(
    ceiling: Any, fragment: str
) -> None:
    errors = sandbox_provider_spec.check_declaration(_sizes_document(ceiling)).errors
    assert any(fragment in error for error in errors), errors


@pytest.mark.rule("declaration/size-ceiling-holds-a-size")
def test_the_checker_refuses_a_size_ceiling_below_the_default_size() -> None:
    document = _sizes_document(
        {"cpu": 2, "memory_mib": 4096}, default_size={"cpu": 4, "memory_mib": 8192}
    )
    errors = sandbox_provider_spec.check_declaration(document).errors
    assert any("does not hold default_size" in error for error in errors), errors


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


def test_a_refused_ceiling_states_the_limit_and_names_no_condition() -> None:
    declaration = _declaration()
    request = Request(lifetime_seconds=7200, resources={"disk_min_mib": 20000})
    _, failed = fit_resources(declaration, request, Registry(), ())
    assert sorted(failure["detail"] for _, failure in failed) == [
        "disk_min_mib 20,000: this account allows at most 8,192 MiB of disk",
        "lifetime_seconds 7,200: this account allows at most 3,600 s",
    ]
