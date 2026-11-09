# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Matching and checking for the file_links gate and the file_stream_max_bytes fact."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

import sandbox_provider_spec
from sandbox_provider_spec.check import load_catalog, spec_dir
from sandbox_provider_spec.evidence import PER_OPERATION_FACTS, _declared_values, _proof_values
from sandbox_provider_spec.load import load
from sandbox_provider_spec.matcher import Registry, declared_fit

FIXTURES = Path(__file__).resolve().parent / "fixtures/providers"
REGISTRY = Registry.from_documents(
    load(spec_dir() / "registries/regions.json"), load(spec_dir() / "registries/gpu-models.json")
)


def _declaration(name: str) -> dict[str, Any]:
    document = load(FIXTURES / f"{name}.yaml")
    assert isinstance(document, dict)
    return document


def _fit(request: dict[str, Any], declaration: dict[str, Any]) -> dict[str, Any]:
    return dict(declared_fit(request, [declaration], registry=REGISTRY))


def _with(**resources: Any) -> dict[str, Any]:
    declaration = deepcopy(_declaration("alpha"))
    declaration["resources"].update(resources)
    return declaration


def _reason(result: dict[str, Any]) -> str:
    return str(result["results"]["alpha"]["failed"][0]["reason"])


def test_per_operation_facts_match_the_catalog() -> None:
    catalog = load_catalog()
    declared = {
        name
        for name, spec in catalog["declaration_resources"].items()
        if spec.get("kind") == "per_operation"
    }
    assert declared == PER_OPERATION_FACTS


@pytest.mark.parametrize(
    ("declared", "asked", "reason"),
    [
        ({"write": 2**30}, {"write": 2**30}, None),
        ({"write": {"at_least": 2**30}}, {"write": 2**26}, None),
        ({"write": {"at_least": 2**26}}, {"write": 2**30}, "resource_unknown"),
        ({"write": 2**26}, {"write": 2**30}, "resource_mismatch"),
        ({"write": 2**30}, {"read": 1}, "resource_unknown"),
        ({"read": "unknown", "write": 2**30}, {"read": 1}, "resource_unknown"),
        (None, {"write": 1}, "resource_unknown"),
        ({"read": 2**30, "write": 2**30}, {"read": 2**30, "write": 2**30}, None),
    ],
)
def test_stream_sizes_are_compared_per_direction(
    declared: dict[str, Any] | None, asked: dict[str, int], reason: str | None
) -> None:
    declaration = _with(file_stream_max_bytes=declared) if declared else _declaration("alpha")
    result = _fit({"resources": {"file_stream_bytes": asked}}, declaration)
    if reason is None:
        assert result["compatible"] == ["alpha"]
    else:
        assert result["compatible"] == []
        assert _reason(result) == reason


@pytest.mark.rule("request/refused-before-matching")
@pytest.mark.parametrize(
    "asked", [{}, {"upload": 1}, {"write": 0}, {"write": -1}, {"write": 1.5}, {"write": "big"}, 5]
)
def test_malformed_stream_asks_are_refused(asked: object) -> None:
    result = _fit({"resources": {"file_stream_bytes": asked}}, _declaration("alpha"))
    assert result["compatible"] == []
    assert sandbox_provider_spec.schema_errors(
        {"resources": {"file_stream_bytes": asked}}, "request-schema.json"
    )


@pytest.mark.parametrize(
    ("value", "valid"),
    [
        ({"read": 2**30, "write": {"at_least": 2**26}}, True),
        ({"write": "unknown"}, True),
        ({"write": "unlimited"}, False),
        ({"write": 1.5}, False),
        ({"upload": 1}, False),
        ({}, False),
        (2**30, False),
    ],
)
def test_declared_stream_sizes_are_bytes_or_floors(value: object, valid: bool) -> None:
    declaration = _with(file_stream_max_bytes=value)
    declaration["evidence"] = {}
    schema = sandbox_provider_spec.schema_errors(declaration, "declaration-schema.json")
    checked = [
        error
        for error in sandbox_provider_spec.check_declaration(declaration).errors
        if "file_stream_max_bytes" in error and not error.startswith("evidence is missing")
    ]
    assert (not schema) is valid
    assert (not checked) is valid


def test_each_stream_direction_is_cited_and_proven_on_its_own() -> None:
    declaration = _with(file_stream_max_bytes={"read": "unknown", "write": {"at_least": 2**26}})
    values = _declared_values(declaration)
    assert values["resources.file_stream_max_bytes.write"] == {"at_least": 2**26}
    assert "resources.file_stream_max_bytes.read" not in values
    assert "resources.file_stream_max_bytes" not in values
    test = {
        "proves": [
            {"fact": "resources.file_stream_max_bytes", "value": {"write": {"at_least": 2**26}}}
        ]
    }
    assert _proof_values(test, "resources.file_stream_max_bytes.write") == [{"at_least": 2**26}]
    assert _proof_values(test, "resources.file_stream_max_bytes.read") == []


def _links(**knobs: Any) -> dict[str, Any]:
    declaration = deepcopy(_declaration("alpha"))
    declaration["gates"]["file_links"] = [knobs]
    return declaration


@pytest.mark.parametrize(
    ("offered", "asked", "fits"),
    [
        ({"operations": ["read", "write"]}, {"operations": ["write"]}, True),
        ({"operations": ["write"]}, {"operations": ["read", "write"]}, False),
        ({"operations": ["write"]}, {}, True),
        ({"link_lifetime_seconds": 604800}, {"link_lifetime_seconds": 3600}, True),
        ({"link_lifetime_seconds": {"at_least": 60}}, {"link_lifetime_seconds": 3600}, False),
        ({"revocable": False}, {"revocable": True}, False),
        ({"user_selection": True}, {"user_selection": True}, True),
        ({}, {"user_selection": True}, False),
    ],
)
def test_file_links_knobs_match_like_other_gates(
    offered: dict[str, Any], asked: dict[str, Any], fits: bool
) -> None:
    request = {"requirements": {"file_links": asked}}
    assert sandbox_provider_spec.schema_errors(request, "request-schema.json") == []
    declaration = _links(**offered)
    assert sandbox_provider_spec.schema_errors(declaration, "declaration-schema.json") == []
    assert (_fit(request, declaration)["compatible"] == ["alpha"]) is fits


def test_file_links_operation_values_are_checked() -> None:
    request = {"requirements": {"file_links": {"operations": ["upload"]}}}
    assert sandbox_provider_spec.check_request(request)
    assert sandbox_provider_spec.schema_errors(request, "request-schema.json")
