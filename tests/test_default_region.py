# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""`resources.default_region`: the region a create without one lands in, one of `regions`."""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any, ClassVar, cast

import pytest

import sandbox_provider_spec
from sandbox_provider_spec.v1 import CredentialField, Discovery, Provider, from_json
from sandbox_provider_spec.v1.suite_driver import ProviderDriver

EXAMPLES = Path(__file__).resolve().parents[1] / "spec" / "provider-api-1.0-examples"


def declaration(**resources: Any) -> dict[str, Any]:
    facts = {"kernel": "unknown", **resources}
    return {
        "spec": "sandbox-provider-spec/0.1",
        "provider": "acme",
        "verified": {"date": "2026-09-29", "sdks": {"acme": "1.0.0"}},
        "resources": facts,
        "gates": {},
        "evidence": {
            f"resources.{name}": {"tests": ["fixture.test"], "report": "reports/fixture.json"}
            for name in facts
            if name != "kernel"
        },
    }


def test_a_declaration_may_state_a_default_region_it_lists() -> None:
    document = declaration(regions=["us-east", "eu-west"], default_region="eu-west")
    assert sandbox_provider_spec.schema_errors(document, "declaration-schema.json") == []
    assert not any(
        "default_region" in error
        for error in sandbox_provider_spec.check_declaration(document).errors
    )


def test_a_default_region_outside_regions_or_not_text_is_refused() -> None:
    outside = declaration(regions=["us-east"], default_region="eu-west")
    errors = sandbox_provider_spec.check_declaration(outside).errors
    assert any("default_region must be one of regions" in error for error in errors)
    empty = declaration(default_region="")
    assert sandbox_provider_spec.schema_errors(empty, "declaration-schema.json")


class Regions(Provider, manifest=False):
    provider_id = "regions"
    name = "Regions"
    spec_version = "1.0"
    credential_fields: ClassVar[tuple[CredentialField, ...]] = (CredentialField("api_key"),)
    resources: ClassVar[dict[str, object]] = {}

    async def discovery(self) -> Discovery:
        found = from_json(Discovery, json.loads((EXAMPLES / "Discovery.json").read_text("utf-8")))
        item = dataclasses.replace(found.classes[0], resources=dict(self.resources))
        return dataclasses.replace(found, classes=(item, *found.classes[1:]))

    get = list = create = destroy = run = files_read = files_write = cast(Any, discovery)
    process_start = process_output = cast(Any, discovery)


@pytest.fixture(name="driver")
def driver_fixture() -> Iterator[ProviderDriver]:
    driver = ProviderDriver(Regions({"api_key": "k"}), run="run-1")
    yield driver
    driver.close()


def valid(driver: ProviderDriver, resources: dict[str, object]) -> object:
    Regions.resources = resources
    return driver.call("discovery", None, {})["valid"]


def test_the_tester_checks_that_discovery_lists_the_default_region(driver: ProviderDriver) -> None:
    both: dict[str, object] = {"regions": ["us-east", "eu-west"]}
    assert valid(driver, {**both, "default_region": "eu-west"}) is True
    assert valid(driver, {**both, "default_region": "ap-south"}) is False
    assert valid(driver, both) is True
    assert valid(driver, {"default_region": "eu-west"}) is True  # regions unknown: nothing to list
