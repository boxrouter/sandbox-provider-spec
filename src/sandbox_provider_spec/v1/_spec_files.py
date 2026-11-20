# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The spec files that the 1.0 package validates against, found in the repository or the wheel."""

from __future__ import annotations

from functools import cache
from importlib.resources import as_file, files
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

from sandbox_provider_spec.load import load

BASE = "https://spec.invalid/"
OPENAPI_NAME = "provider-api-1.0.openapi.yaml"


@cache
def document(name: str) -> Any:
    """One file from spec/ (the wheel keeps the same files under `data/`). Do not change it."""
    with as_file(files("sandbox_provider_spec").joinpath("data", name)) as path:
        return load(path)


@cache
def registry() -> Registry[Any]:
    """The OpenAPI document and the SPS schemas that it references, by relative file name."""
    found: Registry[Any] = Registry().with_resource(
        BASE + OPENAPI_NAME,
        Resource.from_contents(document(OPENAPI_NAME), default_specification=DRAFT202012),
    )
    for name in ("request-schema.json", "declaration-schema.json"):
        contents = document(name)
        resource = Resource.from_contents(contents, default_specification=DRAFT202012)
        found = found.with_resource(BASE + name, resource)
        if isinstance(contents, dict) and isinstance(contents.get("$id"), str):
            found = found.with_resource(contents["$id"], resource)
    return found


def schema_ref(name: str) -> dict[str, str]:
    """A schema that points at one component of the OpenAPI file."""
    return {"$ref": f"{BASE}{OPENAPI_NAME}#/components/schemas/{name}"}


@cache
def validator(schema: str) -> Draft202012Validator:
    """The cached validator of one component schema of the OpenAPI file."""
    return Draft202012Validator(
        schema_ref(schema), registry=registry(), format_checker=FormatChecker()
    )
