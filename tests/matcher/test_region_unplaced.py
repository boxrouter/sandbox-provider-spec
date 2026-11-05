# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""QA-190: an area asked of a provider whose own region lists no countries says so."""

from sandbox_provider_spec.matcher.matching import _fit_region
from sandbox_provider_spec.matcher.registry import Registry


class _Declaration:
    def __init__(self, resources: dict[str, object]) -> None:
        self.resources = resources


def _registry() -> Registry:
    return Registry(
        areas={"EU": frozenset({"DE", "FR"})},
        regions={"daytona:us": frozenset({"US"}), "daytona:eu": None},
        countries=frozenset({"DE", "FR", "US"}),
    )


def test_area_asked_of_a_region_with_no_countries_names_the_region_and_the_way_in() -> None:
    declaration = _Declaration({"regions": ["daytona:us", "daytona:eu"]})
    pinned, failed = _fit_region(declaration, "EU", _registry())  # type: ignore[arg-type]
    assert pinned == {}
    ((stage, failure),) = failed
    assert (stage, failure["reason"]) == ("resource", "resource_mismatch")
    assert "daytona:eu lists no countries" in failure["detail"]
    assert "ask region 'daytona:eu'" in failure["detail"]


def test_a_region_asked_by_its_own_identifier_still_matches() -> None:
    declaration = _Declaration({"regions": ["daytona:us", "daytona:eu"]})
    assert _fit_region(declaration, "daytona:eu", _registry())[0] == {"region": "daytona:eu"}  # type: ignore[arg-type]


def test_nothing_is_added_when_every_offered_region_lists_countries() -> None:
    declaration = _Declaration({"regions": ["daytona:us"]})
    ((_, failure),) = _fit_region(declaration, "EU", _registry())[1]  # type: ignore[arg-type]
    assert "lists no countries" not in failure["detail"]
