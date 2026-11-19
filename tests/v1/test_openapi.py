# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The 1.0 provider API OpenAPI file: operations, examples, request strictness, errors."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

from sandbox_provider_spec import schema_errors

SPEC = Path(__file__).resolve().parents[2] / "spec"
OPENAPI = SPEC / "provider-api-1.0.openapi.yaml"
EXAMPLES = SPEC / "provider-api-1.0-examples"
BASE = "https://spec.invalid/"
HTTP_METHODS = {"get", "put", "post", "delete", "patch", "head", "options"}

OPERATION_IDS = [
    "cost",
    "create",
    "destroy",
    "discovery",
    "files_exists",
    "files_link",
    "files_list",
    "files_mkdir",
    "files_read",
    "files_remove",
    "files_write",
    "get",
    "lifetime_extend",
    "list",
    "pause",
    "preview_link",
    "process_cancel",
    "process_close_stdin",
    "process_output",
    "process_start",
    "process_write_stdin",
    "resume",
    "run",
    "snapshot_cost",
    "snapshot_create",
    "snapshot_delete",
    "snapshot_get",
    "snapshot_list",
    "tcp_link",
]
ERROR_CODES = {
    "invalid_request": (400, "caller"),
    "unauthenticated": (401, "caller"),
    "forbidden": (403, "caller"),
    "not_found": (404, "caller"),
    "conflict": (409, "caller"),
    "too_large": (413, "caller"),
    "unsupported": (422, "caller"),
    "quota_exceeded": (402, "caller"),
    "rate_limited": (429, "caller"),
    "unavailable": (503, "provider"),
    "timeout": (504, "provider"),
    "provider_error": (500, "provider"),
}


def snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def load_document() -> dict[str, Any]:
    document = yaml.safe_load(OPENAPI.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


DOCUMENT = load_document()
SCHEMAS: dict[str, Any] = DOCUMENT["components"]["schemas"]


def registry() -> Registry[Any]:
    """The OpenAPI document and the two SPS schemas it references, by relative file name."""
    found: Registry[Any] = Registry().with_resource(
        BASE + OPENAPI.name, Resource.from_contents(DOCUMENT, default_specification=DRAFT202012)
    )
    for name in ("request-schema.json", "declaration-schema.json"):
        contents = json.loads((SPEC / name).read_text(encoding="utf-8"))
        resource = Resource.from_contents(contents, default_specification=DRAFT202012)
        found = found.with_resource(BASE + name, resource).with_resource(contents["$id"], resource)
    return found


def validator(name: str) -> Draft202012Validator:
    ref = f"{BASE}{OPENAPI.name}#/components/schemas/{name}"
    return Draft202012Validator({"$ref": ref}, registry=registry(), format_checker=FormatChecker())


def operations() -> list[tuple[str, str, dict[str, Any]]]:
    return [
        (path, method, item)
        for path, methods in DOCUMENT["paths"].items()
        for method, item in methods.items()
        if method in HTTP_METHODS
    ]


def refs(value: Any) -> list[str]:
    if isinstance(value, dict):
        found = [value["$ref"]] if isinstance(value.get("$ref"), str) else []
        return found + [ref for item in value.values() for ref in refs(item)]
    if isinstance(value, list):
        return [ref for item in value for ref in refs(item)]
    return []


def test_header_and_servers() -> None:
    assert DOCUMENT["openapi"].startswith("3.1")
    assert DOCUMENT["info"]["version"] == "1.0.0"
    assert [server["url"] for server in DOCUMENT["servers"]] == ["{base_url}"]
    assert DOCUMENT["security"] == [{"bearerAuth": []}]
    assert DOCUMENT["components"]["securitySchemes"]["bearerAuth"] == {
        "type": "http",
        "scheme": "bearer",
        "description": DOCUMENT["components"]["securitySchemes"]["bearerAuth"]["description"],
    }
    for _, _, item in operations():
        assert "security" not in item, "every operation uses the global bearer scheme"


def test_operation_ids() -> None:
    ids = [item["operationId"] for _, _, item in operations()]
    assert sorted(ids) == OPERATION_IDS
    assert len(ids) == len(set(ids))


def test_paths_carry_the_version_and_no_binding_prefix() -> None:
    for path in DOCUMENT["paths"]:
        assert path.startswith("/v1/")
        assert "/sps/" not in path


def test_create_takes_the_idempotency_key() -> None:
    create = DOCUMENT["paths"]["/v1/sandboxes"]["post"]
    assert "201" in create["responses"]
    assert "200" not in create["responses"]
    ref = next(p["$ref"] for p in create["parameters"] if "$ref" in p)
    parameter = DOCUMENT["components"]["parameters"][ref.rsplit("/", 1)[1]]
    assert parameter["name"] == "Idempotency-Key"
    assert parameter["in"] == "header" and parameter["required"] is True
    assert parameter["schema"]["pattern"] == "^[a-z0-9][a-z0-9-]{7,62}$"


@pytest.mark.parametrize("ref", sorted(set(refs(DOCUMENT))))
def test_every_reference_resolves(ref: str) -> None:
    resolver = registry().resolver(BASE + OPENAPI.name)
    resolver.lookup(ref)


def test_every_path_parameter_is_declared() -> None:
    for path, methods in DOCUMENT["paths"].items():
        declared = {
            DOCUMENT["components"]["parameters"][p["$ref"].rsplit("/", 1)[1]]["name"]
            for p in methods.get("parameters", [])
            if "$ref" in p
        }
        for name in {part[1:-1] for part in path.split("/") if part.startswith("{")}:
            assert name in declared, f"{path} does not declare {name}"


def test_every_operation_lists_only_known_error_statuses() -> None:
    statuses = {str(status) for status, _ in ERROR_CODES.values()}
    for _, _, item in operations():
        for status in item["responses"]:
            assert status in statuses | {"200", "201"}


def test_error_codes_and_faults() -> None:
    components = DOCUMENT["components"]
    assert set(SCHEMAS["Error"]["properties"]["code"]["enum"]) == set(ERROR_CODES)
    assert len(SCHEMAS["Error"]["properties"]["code"]["enum"]) == 12
    table = components["x-sps-errors"]
    assert {code: (row["status"], row["x-sps-fault"]) for code, row in table.items()} == ERROR_CODES
    # Every error response in the file has the status that its code has.
    for name, response in components["responses"].items():
        assert response["content"]["application/json"]["schema"] == {
            "$ref": "#/components/schemas/ErrorResponse"
        }, name
    for _, _, item in operations():
        for status, response in item["responses"].items():
            if status in {"200", "201"}:
                continue
            name = response["$ref"].rsplit("/", 1)[1]
            assert name in components["responses"]
            assert ERROR_CODES[snake(name)][0] == int(status), f"{name} is listed under {status}"


def test_every_component_schema_has_an_example() -> None:
    files = {path.stem for path in EXAMPLES.glob("*.json")}
    assert files == set(SCHEMAS)


@pytest.mark.parametrize("name", sorted(SCHEMAS))
def test_example_validates(name: str) -> None:
    example = json.loads((EXAMPLES / f"{name}.json").read_text(encoding="utf-8"))
    errors = sorted(validator(name).iter_errors(example), key=lambda error: list(error.path))
    assert [f"{list(error.path)}: {error.message}" for error in errors] == []


def test_discovery_example_is_the_one_in_the_design() -> None:
    example = json.loads((EXAMPLES / "Discovery.json").read_text(encoding="utf-8"))
    assert example["spec_version"] == "1.0"
    assert example["classes"][0]["prices"][0] == {
        "item": "cpu",
        "price_usd": "0.000014",
        "unit": "vcpu_second",
        "basis": "allocated",
    }
    assert example["limits"]["file_bytes"] == 5368709120


REQUEST_SCHEMAS = sorted(
    name for name in SCHEMAS if name.endswith("Request") or name == "EmptyObject"
)


def test_request_schemas_are_found() -> None:
    assert REQUEST_SCHEMAS == [
        "CreateRequest",
        "EmptyObject",
        "FileLinkRequest",
        "LifetimeExtendRequest",
        "MkdirRequest",
        "PreviewRequest",
        "ProcessStartRequest",
        "RunRequest",
        "SnapshotRequest",
        "TcpLinkRequest",
    ]
    bodies = {
        item["requestBody"]["content"]["application/json"]["schema"]["$ref"].rsplit("/", 1)[1]
        for _, _, item in operations()
        if "requestBody" in item and "application/json" in item["requestBody"]["content"]
    }
    assert bodies == set(REQUEST_SCHEMAS)


@pytest.mark.parametrize("name", REQUEST_SCHEMAS)
def test_request_schema_refuses_unknown_fields(name: str) -> None:
    assert SCHEMAS[name]["additionalProperties"] is False
    example = json.loads((EXAMPLES / f"{name}.json").read_text(encoding="utf-8"))
    assert validator(name).is_valid({**example, "no_such_field": 1}) is False


def test_create_request_is_an_sps_request_plus_three_fields() -> None:
    example = json.loads((EXAMPLES / "CreateRequest.json").read_text(encoding="utf-8"))
    sps = {k: v for k, v in example.items() if k not in {"sandbox_class", "env", "labels"}}
    assert schema_errors(sps, "request-schema.json") == []
    assert set(SCHEMAS["CreateRequest"]["properties"]) == {
        "sandbox_class",
        "resources",
        "requirements",
        "image",
        "lifetime_seconds",
        "at_end",
        "env",
        "labels",
        "snapshot",
    }


def price(**fields: Any) -> dict[str, Any]:
    return {"item": "cpu", "price_usd": "1", "unit": "vcpu_hour", "basis": "allocated", **fields}


def test_price_requires_exactly_four_fields() -> None:
    assert sorted(SCHEMAS["Price"]["required"]) == ["basis", "item", "price_usd", "unit"]
    assert validator("Price").is_valid(price())
    for missing in ("item", "price_usd", "unit", "basis"):
        assert not validator("Price").is_valid({k: v for k, v in price().items() if k != missing})


@pytest.mark.parametrize("zero", ["0", "0.0", "0.000"])
def test_zero_price_needs_included(zero: str) -> None:
    assert not validator("Price").is_valid(price(price_usd=zero))
    assert not validator("Price").is_valid(price(price_usd=zero, included=False))
    assert validator("Price").is_valid(price(price_usd=zero, included=True))


def test_included_needs_a_zero_price() -> None:
    assert not validator("Price").is_valid(price(price_usd="0.5", included=True))


def test_price_amounts_are_strings() -> None:
    assert not validator("Price").is_valid(price(price_usd=0.5))
    assert not validator("Price").is_valid(price(unit="parsec"))


def test_discovery_needs_exactly_one_default_image() -> None:
    example = json.loads((EXAMPLES / "Discovery.json").read_text(encoding="utf-8"))
    images = example["classes"][0]["images"]
    for value in (False, True):
        broken = json.loads(json.dumps(example))
        for image in images:
            image["default"] = value
        broken["classes"][0]["images"] = images
        assert not validator("Discovery").is_valid(broken)


def test_discovery_limits_are_at_least_the_floors() -> None:
    example = json.loads((EXAMPLES / "Discovery.json").read_text(encoding="utf-8"))
    example["limits"]["file_bytes"] = 1024
    assert not validator("Discovery").is_valid(example)


def test_idempotency_key_pattern() -> None:
    pattern = DOCUMENT["components"]["parameters"]["IdempotencyKey"]["schema"]["pattern"]
    assert re.fullmatch(pattern, "3f2b8c1e-0a5d-4e7b-9c1d-2a6b7c8d9e0f")
    assert not re.fullmatch(pattern, "short")
    assert not re.fullmatch(pattern, "-leading-dash-key")
    assert not re.fullmatch(pattern, "UPPERCASE-KEY-1234")
