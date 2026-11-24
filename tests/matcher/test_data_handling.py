# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Matching and checking for the data_retention and compliance facts."""

from collections.abc import Mapping
from typing import Any

import pytest

import sandbox_provider_spec
from sandbox_provider_spec.matcher.declaration import build_declaration
from sandbox_provider_spec.matcher.matching import fit_resources
from sandbox_provider_spec.matcher.registry import Registry
from sandbox_provider_spec.matcher.request import Request

QUOTE = {"source": "https://example.invalid/trust", "read": "2026-11-23", "quote": "Stated."}


def _declaration(**resources: Any) -> Any:
    return build_declaration(
        {
            "spec": "sandbox-provider-spec/0.1",
            "provider": "fixture",
            "verified": {"sdks": {"test": "1"}},
            "resources": resources,
            "gates": {},
        }
    )


def _fit(declaration: Any, *, met: tuple[str, ...] = (), **asked: Any) -> list[str]:
    _, failed = fit_resources(declaration, Request(resources=asked), Registry(), met)
    return [failure["reason"] for _, failure in failed]


@pytest.mark.parametrize(
    ("declared", "asked", "reasons"),
    [
        ("none", "none", []),
        ("none", ["none", "safety"], []),
        ("safety", ["none", "safety"], []),
        ("safety", "none", ["resource_mismatch"]),
        ("retained", ["none", "safety"], ["resource_mismatch"]),
        ("unknown", "none", ["resource_unknown"]),
        (None, "none", ["resource_unknown"]),
    ],
)
def test_a_request_lists_the_retention_it_accepts(
    declared: str | None, asked: str | list[str], reasons: list[str]
) -> None:
    resources = {} if declared is None else {"data_retention": declared}
    assert _fit(_declaration(**resources), data_retention=asked) == reasons


def test_retention_behind_a_condition_is_offered_only_when_it_is_met() -> None:
    declaration = _declaration(
        data_retention="none", needs={"data_retention": ["enterprise_agreement"]}
    )
    assert _fit(declaration, data_retention="none") != []
    assert _fit(declaration, met=("enterprise_agreement",), data_retention="none") == []


@pytest.mark.parametrize(
    ("declared", "asked", "fits"),
    [
        (["soc2", "soc2_type2"], ["soc2"], True),
        (["soc2", "soc2_type2"], ["soc2_type2"], True),
        (["soc2"], ["soc2_type2"], False),
        (["soc2", "soc2_type2", "iso27001"], ["soc2_type2", "iso27001"], True),
        (["soc2", "soc2_type2"], ["iso27001"], False),
        ([], ["soc2"], False),
        ("unknown", ["soc2"], False),
        (None, ["soc2"], False),
    ],
)
def test_a_request_needs_every_audit_it_names(
    declared: list[str] | str | None, asked: list[str], fits: bool
) -> None:
    resources = {} if declared is None else {"compliance": declared}
    assert (_fit(_declaration(**resources), compliance=asked) == []) is fits


def _checked(**resources: Any) -> list[str]:
    evidence = {f"resources.{name}": QUOTE for name in resources if name != "needs"}
    document = {
        "spec": "sandbox-provider-spec/0.1",
        "provider": "fixture",
        "verified": {"date": "2026-11-23", "sdks": {"test": "1"}},
        "resources": resources,
        "gates": {},
        "evidence": evidence,
    }
    return sandbox_provider_spec.check_declaration(document).errors


@pytest.mark.rule("facts/compliance-type-2-is-soc2")
def test_a_type_2_report_is_declared_as_soc2_too() -> None:
    assert _checked(compliance=["soc2", "soc2_type2"]) == []
    assert any("soc2_type2 without soc2" in error for error in _checked(compliance=["soc2_type2"]))


def test_declarations_use_the_catalog_values() -> None:
    assert _checked(data_retention="safety", compliance=["soc2", "iso27001"]) == []
    assert _checked(compliance=[]) == []
    assert _checked(data_retention="zero")
    assert _checked(compliance=["soc1"])
    assert _checked(compliance=["unknown"])


def test_requests_name_catalog_values() -> None:
    for request in (
        {"resources": {"data_retention": "none"}},
        {"resources": {"data_retention": ["none", "safety"]}},
        {"resources": {"compliance": ["soc2_type2", "iso27001"]}},
    ):
        assert sandbox_provider_spec.check_request(request) == [], request
    bad: Mapping[str, object]
    for bad in (
        {"resources": {"data_retention": "zero"}},
        {"resources": {"data_retention": []}},
        {"resources": {"compliance": "soc2"}},
        {"resources": {"compliance": []}},
        {"resources": {"compliance": ["soc1"]}},
    ):
        assert sandbox_provider_spec.check_request(bad), bad
