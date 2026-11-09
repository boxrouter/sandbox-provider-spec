# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Keep the request and declaration schemas aligned with the catalog vocabulary."""

from __future__ import annotations

from typing import Any

import pytest

import sandbox_provider_spec
from sandbox_provider_spec.matcher import Rejected, validate_request


def _knob_values(definition: dict[str, Any], *, include_request_any: bool = False) -> list[Any]:
    kind = definition["kind"]
    if kind == "pick":
        values = list(definition["values"])
        if include_request_any and definition.get("any"):
            values.append("any")
        return values
    if kind == "yes_no":
        return [False, True]
    if kind == "all_of":
        return [[value] for value in definition["values"]]
    if kind in {"number", "integer"}:
        return [1]
    raise AssertionError(f"unhandled catalog knob kind: {kind}")


def _request(gate: str, knob: str, value: Any) -> dict[str, Any]:
    requirements: dict[str, Any] = {gate: {knob: value}}
    request: dict[str, Any] = {"requirements": requirements}

    if gate == "previews":
        requirements[gate].update({"access": "public", "ports": [3000]})
        if knob == "credential":
            requirements[gate]["access"] = "private"
        if knob == "survives_pause":
            requirements["pause_resume"] = {"keeps": "files_only"}
    elif gate == "network_lockdown":
        if knob == "policy":
            if value == "allowlist":
                requirements[gate]["allow"] = ["api.example.com"]
            elif value == "denylist":
                requirements[gate]["deny"] = ["blocked.example.com"]
            elif value == "open":
                requirements[gate].update({"switchable": True, "switches_to": ["deny_all"]})
        else:
            requirements[gate].update({"policy": "allowlist", "allow": ["api.example.com"]})
            if knob == "switchable" and value:
                requirements[gate]["switches_to"] = ["deny_all"]
    elif gate == "hidden_secrets":
        requirements[gate]["inject_into"] = ["api.example.com"]
        if knob == "header_templates" and value:
            requirements[gate]["headers"] = [{"name": "Authorization"}]
    elif gate == "volumes":
        requirements[gate].update(
            {
                "kind": "filesystem",
                "mounts": [{"provider": "example", "volume": "data", "path": "/data"}],
            }
        )
    elif gate == "snapshots":
        requirements[gate]["original_after"] = "continues"
    elif gate == "custom_images":
        # The catalog's source knob is represented by the top-level image field.
        if knob == "source":
            requirements[gate] = {}
            request["image"] = {
                "oci": "alpine:3",
                "private_oci": {"private_oci": "registry.example/image"},
                "dockerfile": {"dockerfile": "FROM alpine"},
                "provider_artifact": {"provider_artifact": "image", "provider": "example"},
            }[value]
        else:
            request["image"] = (
                {"dockerfile": "FROM alpine"} if knob == "build_context" else "alpine:3"
            )
    elif gate == "tcp_ports":
        requirements[gate]["ports"] = [3000]

    return request


def _declaration(gate: str, knob: str, value: Any) -> dict[str, Any]:
    variant = {knob: value}
    if gate == "network_lockdown" and knob == "policy" and value == "open":
        variant["switchable"] = True
    return {
        "spec": "sandbox-provider-spec/0.1",
        "provider": "example",
        "verified": {"date": "2026-01-01", "sdks": {"example-sdk": "1.0"}},
        "resources": {},
        "gates": {gate: [variant]},
        "evidence": {},
    }


def test_catalog_gates_knobs_and_values_are_accepted_by_their_schemas() -> None:
    catalog = sandbox_provider_spec.load_catalog()

    for gate, definition in catalog["gates"].items():
        knobs = definition.get("knobs", {})
        declaration_only = definition.get("declaration_only", {})

        for knob, knob_definition in knobs.items():
            request_values = _knob_values(knob_definition, include_request_any=True)
            for value in request_values:
                request = _request(gate, knob, value)
                errors = sandbox_provider_spec.schema_errors(request, "request-schema.json")
                assert errors == [], f"request catalog value {gate}.{knob}={value!r}: {errors}"

            for value in _knob_values(knob_definition):
                declaration = _declaration(gate, knob, value)
                errors = sandbox_provider_spec.schema_errors(declaration, "declaration-schema.json")
                assert errors == [], f"declaration catalog value {gate}.{knob}={value!r}: {errors}"

        for knob, knob_definition in declaration_only.items():
            for value in _knob_values(knob_definition):
                declaration = _declaration(gate, knob, value)
                errors = sandbox_provider_spec.schema_errors(declaration, "declaration-schema.json")
                assert errors == [], (
                    f"declaration-only catalog value {gate}.{knob}={value!r}: {errors}"
                )


def test_hidden_secret_header_templates_pass_the_schema_and_matcher_validator() -> None:
    request = {
        "requirements": {
            "hidden_secrets": {
                "inject_into": ["api.example.com"],
                "injection": "sets_header",
                "header_templates": True,
                "headers": [{"name": "Authorization", "prefix": "Bearer "}],
            }
        }
    }
    assert sandbox_provider_spec.schema_errors(request, "request-schema.json") == []
    validate_request(request)

    missing_templates = {
        "requirements": {
            "hidden_secrets": {
                "inject_into": ["api.example.com"],
                "injection": "sets_header",
                "headers": [{"name": "Authorization"}],
            }
        }
    }
    assert sandbox_provider_spec.schema_errors(missing_templates, "request-schema.json") == []
    with pytest.raises(Rejected, match="needs header_templates: true"):
        validate_request(missing_templates)
