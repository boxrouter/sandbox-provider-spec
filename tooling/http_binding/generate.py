# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Render only HTTP binding artifacts; existing SPS schemas remain authoritative.

Run from any directory: python tooling/http_binding/generate.py [--check].
The canonical source is spec/http-binding.schema.json, including its example messages.
"""

from __future__ import annotations

import argparse
import json
import runpy
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "spec/http-binding.schema.json"


def type_name(schema: dict[str, Any]) -> str:
    if "$ref" in schema:
        reference: str = schema["$ref"]
        return reference.rsplit("/", 1)[-1] if reference.startswith("#/") else "dict[str, object]"
    if "const" in schema:
        value = schema["const"]
        if isinstance(value, list):
            return "list[str]"
        return f"Literal[{value!r}]"
    if "enum" in schema:
        return "Literal[" + ", ".join(repr(value) for value in schema["enum"]) + "]"
    if "anyOf" in schema:
        return " | ".join(type_name(item) for item in schema["anyOf"])
    kind = schema["type"]
    if kind == "array":
        return f"list[{type_name(schema['items'])}]"
    if kind == "object":
        if "additionalProperties" not in schema:
            return "dict[str, object]"
        return f"dict[str, {type_name(schema['additionalProperties'])}]"
    return {
        "string": "str",
        "integer": "int",
        "number": "float",
        "boolean": "bool",
        "null": "None",
    }[kind]


def python_types(source: dict[str, Any]) -> str:
    lines = Path(__file__).read_text().splitlines()[:2] + [
        "",
        '"""Generated HTTP binding wire shapes; validate values before trusting them.',
        "",
        "Do not edit: tooling/http_binding/generate.py. These types are not an HTTP client.",
        '"""',
        "",
        "from __future__ import annotations",
        "",
        "from typing import Literal, NotRequired, TypedDict",
        "",
    ]
    for name, definition in source["$defs"].items():
        if "properties" not in definition:
            lines.extend([f"{name} = {type_name(definition)}", ""])
            continue
        lines.extend(["", f"class {name}(TypedDict):"])
        required = set(definition.get("required", []))
        for field, value in definition["properties"].items():
            annotation = type_name(value)
            if field not in required:
                annotation = f"NotRequired[{annotation}]"
            lines.append(f"    {field}: {annotation}")
        lines.append("")
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "ruff",
            "format",
            "--stdin-filename",
            str(ROOT / "src/sandbox_provider_spec/http_binding_types.py"),
            "-",
        ],
        input="\n".join(lines),
        text=True,
        capture_output=True,
        check=True,
    ).stdout


def openapi(source: dict[str, Any]) -> dict[str, Any]:
    paths: dict[str, Any] = {}
    for operation, entry in source["x-operations"].items():
        versions = [
            binding[operation]
            for binding in source.get("x-binding-versions", {}).values()
            if operation in binding
        ]
        request_names = list(dict.fromkeys(item["request"] for item in versions)) or [
            entry["request"]
        ]
        result_names = list(dict.fromkeys(item["result"] for item in versions)) or [entry["result"]]
        request_schema: dict[str, Any] = (
            {"$ref": "#/components/schemas/" + request_names[0]}
            if len(request_names) == 1
            else {"oneOf": [{"$ref": "#/components/schemas/" + name} for name in request_names]}
        )
        result_schema: dict[str, Any] = (
            {"$ref": "#/components/schemas/" + result_names[0]}
            if len(result_names) == 1
            else {"oneOf": [{"$ref": "#/components/schemas/" + name} for name in result_names]}
        )
        schemas = {"200": result_schema} | {
            status: {"$ref": "#/components/schemas/Error"}
            for status in ["401", "403", "409", "410", "413", "422", "502", "504"]
        }
        definition: dict[str, Any] = {
            "operationId": operation.replace(".", "_"),
            "x-sps-rules": entry["rules"],
            "requestBody": {
                "required": True,
                "content": {"application/json": {"schema": request_schema}},
            },
            "responses": {
                status: {
                    "description": "Observed result"
                    if status == "200"
                    else "Binding error; inspect outcome",
                    "content": {"application/json": {"schema": schema}},
                }
                for status, schema in schemas.items()
            },
        }
        if operation == "create":
            definition["parameters"] = [
                {
                    "name": "SPS-Request-Digest",
                    "in": "header",
                    "required": True,
                    "description": (
                        "SHA-256 of exact UTF-8 request body bytes; retries reuse those bytes."
                    ),
                    "schema": {"$ref": "#/components/schemas/Digest"},
                }
            ]
        paths[entry["path"]] = {"post": definition}
    paths["/.well-known/sandbox-provider-spec.json"] = {
        "get": {
            "operationId": "discovery",
            "responses": {
                "200": {
                    "description": "Account-scoped discovery",
                    "content": {
                        "application/json": {"schema": {"$ref": "#/components/schemas/Discovery"}}
                    },
                },
                "401": {"description": "Unauthenticated; empty body"},
                "403": {"description": "Forbidden; empty body"},
            },
        }
    }

    # Bundle the two existing schemas without maintaining a second vocabulary/model.
    def component_refs(value: Any) -> Any:
        if isinstance(value, list):
            return [component_refs(item) for item in value]
        if isinstance(value, dict):
            return {
                key: (
                    item.replace("#/$defs/", "#/components/schemas/")
                    if key == "$ref" and isinstance(item, str) and item.startswith("#/$defs/")
                    else component_refs(item)
                )
                for key, item in value.items()
            }
        return value

    components = component_refs(source["$defs"])
    for name, file in [
        ("SPSRequest", "request-schema.json"),
        ("SPSDeclaration", "declaration-schema.json"),
    ]:
        existing = json.loads((ROOT / "spec" / file).read_text())
        components[name] = existing
    for value in components.values():
        value.pop("examples", None)
    document = {
        "openapi": "3.1.0",
        "info": {"title": source["title"], "version": "0.3"},
        "security": [{"accountBearer": []}],
        "paths": paths,
        "components": {
            "securitySchemes": {"accountBearer": {"type": "http", "scheme": "bearer"}},
            "schemas": components,
        },
    }
    # Existing schemas keep their own $id and local references. External URNs resolve
    # to the embedded resources; binding references use OpenAPI component locations.
    return document


def fixtures(source: dict[str, Any]) -> dict[str, Any]:
    valid = [
        {"type": name, "value": value}
        for name, definition in source["$defs"].items()
        for value in definition.get("examples", [])
    ]
    invalid = []
    for operation, entry in source["x-operations"].items():
        for name in [entry["request"], entry["result"]]:
            example = source["$defs"][name]["examples"][0]
            for reason in ["missing_account", "wrong_account_type", "unknown_required_field"]:
                value = json.loads(json.dumps(example))
                if reason == "missing_account":
                    del value["account_id"]
                elif reason == "wrong_account_type":
                    value["account_id"] = 7
                else:
                    value["future_required_semantics"] = True
                invalid.append({"type": name, "reason": reason, "value": value})
        request = source["$defs"][entry["request"]]["examples"][0]
        value = {**request, "required_mode": "undefined-mode"}
        invalid.append(
            {
                "type": entry["request"],
                "reason": "unsupported_mode",
                "value": value,
                "rejection": {
                    "operation": operation,
                    "request_id": request["request_id"],
                    "account_id": request["account_id"],
                    "error": {
                        "code": "unsupported_mode",
                        "outcome": "not_dispatched",
                        "message": "Mode is not bound",
                        "exit_code": None,
                    },
                },
            }
        )
    return {"valid": valid, "invalid": invalid}


def outputs(source: dict[str, Any]) -> dict[Path, str]:
    semantic_cases = runpy.run_path(str(ROOT / "tooling/http_binding/semantic_cases.py"))["cases"]
    return {
        ROOT / "examples/http-binding/semantics.json": json.dumps(semantic_cases(source), indent=2)
        + "\n",
        ROOT / "spec/http-binding.openapi.json": json.dumps(openapi(source), indent=2) + "\n",
        ROOT / "src/sandbox_provider_spec/http_binding_types.py": python_types(source),
        ROOT / "examples/http-binding/messages.json": json.dumps(fixtures(source), indent=2) + "\n",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    source = json.loads(SOURCE.read_text())
    for path, text in outputs(source).items():
        if args.check:
            if not path.exists() or path.read_text() != text:
                raise SystemExit(f"Binding artifact drift: {path.relative_to(ROOT)}")
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)


if __name__ == "__main__":
    main()
