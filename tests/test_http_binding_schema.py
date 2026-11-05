# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""PP1 shape/examples and generated-artifact drift, independent of live conformance."""

from __future__ import annotations

import json
import runpy
import subprocess
import sys
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from sandbox_provider_spec.check import spec_dir
from sandbox_provider_spec.http_binding_validation import (
    _buffered_result_capacity,
    validate_discovery,
)

ROOT = spec_dir().parent
SCHEMA = json.loads((spec_dir() / "http-binding.schema.json").read_text())
MESSAGES = json.loads((ROOT / "examples/http-binding/messages.json").read_text())


def validator(name: str) -> Draft202012Validator:
    documents = [SCHEMA] + [
        json.loads((spec_dir() / f"{name}-schema.json").read_text())
        for name in ["request", "declaration"]
    ]
    registry: Registry[Any] = Registry().with_resources(
        (document["$id"], Resource.from_contents(document)) for document in documents
    )
    return Draft202012Validator(
        {"$ref": SCHEMA["$id"] + "#/$defs/" + name},
        registry=registry,
        format_checker=FormatChecker(),
    )


def test_schema_is_valid_and_has_exactly_nine_baseline_operations() -> None:
    Draft202012Validator.check_schema(SCHEMA)
    assert set(SCHEMA["x-operations"]) == {
        "create",
        "get",
        "list",
        "destroy",
        "run",
        "files.read_bytes",
        "files.write",
        "process.start",
        "process.output",
    }
    assert SCHEMA["$id"].endswith(":0.2")
    assert len(SCHEMA["x-operations"]) == 9
    assert set(SCHEMA["x-binding-versions"]) == {
        "sandbox-provider-http/0.2",
        "sandbox-provider-http/0.3",
    }
    assert set(SCHEMA["x-binding-versions"]["sandbox-provider-http/0.3"]) == set(
        SCHEMA["x-operations"]
    )
    assert SCHEMA["x-binding-versions"]["sandbox-provider-http/0.3"]["create"] == {
        "request": "CreateRequest03",
        "result": "CreateResult03",
    }


@pytest.mark.parametrize("case", MESSAGES["valid"], ids=lambda case: case["type"])
def test_valid_message(case: dict[str, Any]) -> None:
    validator(case["type"]).validate(case["value"])


def test_all_discovery_examples_are_coherent() -> None:
    for discovery in SCHEMA["$defs"]["Discovery"]["examples"]:
        validate_discovery(discovery)


def test_buffered_response_capacity_uses_constant_size_envelope_arithmetic() -> None:
    large = _buffered_result_capacity(16 * 1024 * 1024)
    assert 44_739_248 < large < 44_750_000


def test_http_binding_schema_remains_distributable_neutral() -> None:
    public_text = "\n".join(
        [
            (spec_dir() / "binding-http.md").read_text(),
            json.dumps(SCHEMA),
        ]
    )
    assert "Cloud" not in public_text
    assert "Box" + "Router" not in public_text


@pytest.mark.parametrize(
    "case", MESSAGES["invalid"], ids=lambda case: case["type"] + case["reason"]
)
def test_invalid_message(case: dict[str, Any]) -> None:
    assert list(validator(case["type"]).iter_errors(case["value"]))
    if "rejection" in case:
        validator("Error").validate(case["rejection"])
        assert case["rejection"]["error"]["outcome"] == "not_dispatched"


def test_generated_artifacts_match_canonical_binding_schema() -> None:
    subprocess.run(
        [sys.executable, str(ROOT / "tooling/http_binding/generate.py"), "--check"], check=True
    )
    namespace = runpy.run_path(str(ROOT / "src/sandbox_provider_spec/http_binding_types.py"))
    for operation in SCHEMA["x-operations"].values():
        assert operation["request"] in namespace
        assert operation["result"] in namespace
    generated = (spec_dir().parent / "src/sandbox_provider_spec/http_binding_types.py").read_text()
    assert "mode: NotRequired[str]" in generated
    assert "execution_limit_ms: NotRequired[int]" in generated
    assert "buffered_command_output_bytes: NotRequired[int]" in generated
    assert "stdout: NotRequired[str]" in generated
    document = json.loads((spec_dir() / "http-binding.openapi.json").read_text())
    assert len(document["paths"]) == 10  # Nine operations plus authenticated discovery.
    assert document["info"]["version"] == "0.3"
    create_schema = document["paths"]["/sps/v1/create"]["post"]["requestBody"]["content"][
        "application/json"
    ]["schema"]
    assert create_schema["oneOf"] == [
        {"$ref": "#/components/schemas/CreateRequest"},
        {"$ref": "#/components/schemas/CreateRequest03"},
    ]
    assert document["components"]["schemas"]["SPSRequest"]["$id"].endswith("request-schema")


@pytest.mark.parametrize("case", MESSAGES["valid"], ids=lambda case: case["type"])
def test_openapi_bundled_schemas_resolve_and_accept_examples(case: dict[str, Any]) -> None:
    document = json.loads((spec_dir() / "http-binding.openapi.json").read_text())
    schemas = document["components"]["schemas"]
    documents = [schemas["SPSRequest"], schemas["SPSDeclaration"]]
    registry: Registry[Any] = Registry().with_resources(
        (item["$id"], Resource.from_contents(item)) for item in documents
    )
    root = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": "#/components/schemas/" + case["type"],
        "components": document["components"],
    }
    Draft202012Validator(root, registry=registry, format_checker=FormatChecker()).validate(
        case["value"]
    )
