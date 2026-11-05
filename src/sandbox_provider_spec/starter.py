# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Generate a structurally valid starter declaration with optional capabilities omitted."""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Mapping
from datetime import date
from pathlib import Path
from typing import Any

import yaml

from sandbox_provider_spec.check import check_declaration

SPEC = "sandbox-provider-spec/0.1"
PROVIDER_NAME = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
SDK_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
DEFAULT_PROVIDER = "example"
DEFAULT_SDK = "example-sdk"
DEFAULT_SDK_VERSION = "0.0.0"

_HEADER = (
    "# Generated starter. Optional gates are omitted (unknown), not claimed.\n"
    "# Replace provider, verified.date, and verified.sdks after a real run.\n"
)


def starter_declaration(
    *,
    provider: str = DEFAULT_PROVIDER,
    sdk: str = DEFAULT_SDK,
    sdk_version: str = DEFAULT_SDK_VERSION,
    verified_date: str | None = None,
) -> dict[str, Any]:
    """Return a structurally valid declaration that invents no optional gates."""
    if not PROVIDER_NAME.fullmatch(provider):
        raise ValueError(f"provider must match {PROVIDER_NAME.pattern}: {provider}")
    if not SDK_NAME.fullmatch(sdk):
        raise ValueError(f"sdk must match {SDK_NAME.pattern}: {sdk}")
    if not sdk_version or "\n" in sdk_version or ":" in sdk_version:
        raise ValueError(f"sdk version must be a single-line string: {sdk_version}")
    return {
        "spec": SPEC,
        "provider": provider,
        "verified": {
            "date": verified_date or date.today().isoformat(),
            "sdks": {sdk: sdk_version},
        },
        "resources": {"kernel": "unknown"},
        "gates": {},
        "evidence": {},
    }


def render_starter(declaration: Mapping[str, Any]) -> str:
    """Serialize a starter declaration as YAML with an honesty header."""
    body = yaml.safe_dump(
        dict(declaration),
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
    )
    return _HEADER + body


def arguments(parser: argparse.ArgumentParser) -> None:
    """Attach the one native scaffold command's arguments."""
    parser.add_argument("--provider", default=DEFAULT_PROVIDER, help="provider registry id")
    parser.add_argument("--sdk", default=DEFAULT_SDK, help="client or SDK package name")
    parser.add_argument("--sdk-version", default=DEFAULT_SDK_VERSION)
    parser.add_argument("--output", type=Path, required=True, help="new declaration YAML")


def run(args: argparse.Namespace) -> int:
    """Validate before creating a declaration; never replace an existing identity."""
    try:
        document = starter_declaration(
            provider=args.provider,
            sdk=args.sdk,
            sdk_version=args.sdk_version,
        )
        if errors := check_declaration(document).errors:
            raise ValueError("; ".join(str(error) for error in errors))
        with args.output.open("x", encoding="utf-8") as stream:
            stream.write(render_starter(document))
    except (ValueError, OSError) as error:
        print(f"scaffold: {error}", file=sys.stderr)
        return 1
    return 0
