# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Generate vocabulary resource meanings from catalog.yaml's canonical description map."""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "spec/catalog.yaml"
VOCABULARY = ROOT / "spec/vocabulary.md"
CODE = re.compile(r"`([a-z][a-z0-9_]*)`")
PROVIDERS = ROOT / "providers"
#: Vendors that are not declared providers but must not appear in neutral descriptions.
OTHER_VENDOR_NAMES = ("aws", "cloudflare")
PROVIDER_NAMES = (
    *OTHER_VENDOR_NAMES,
    *sorted(path.name for path in PROVIDERS.iterdir() if path.is_dir()),
)


def descriptions(catalog: dict[str, Any] | None = None) -> dict[str, str]:
    """Require the canonical map to describe exactly every declaration resource."""
    value = catalog or yaml.safe_load(CATALOG.read_text(encoding="utf-8"))
    expected = set(value["declaration_resources"])
    result = value.get("resource_descriptions")
    if not isinstance(result, dict):
        raise ValueError("catalog.resource_descriptions must be an object")
    actual = set(result)
    if actual != expected:
        raise ValueError(
            "resource_descriptions keys must equal declaration_resources; "
            f"missing={sorted(expected - actual)}, unknown={sorted(actual - expected)}"
        )
    for name, description in result.items():
        if not isinstance(description, str) or not description.strip():
            raise ValueError(f"resource description for {name} must be non-empty text")
        lowered = description.casefold()
        if any(re.search(rf"\b{re.escape(name)}\b", lowered) for name in PROVIDER_NAMES):
            raise ValueError(f"resource description for {name} must be provider-neutral")
    for section in ("resources", "declaration_resources"):
        for name, entry in value[section].items():
            if (
                isinstance(entry, dict)
                and "description" in entry
                and not (section == "resources" and name == "region")
            ):
                raise ValueError(f"{section}.{name} duplicates the canonical resource description")
    return result


def generated(source: str, summaries: dict[str, str], informative: set[str] | None = None) -> str:
    """Render the vocabulary table's resource meanings from the canonical map."""
    informative_names = informative or set()
    start = source.index("| Fact | Meaning |")
    end = source.index("\n\n", start)
    lines = source[start:end].splitlines()
    output = lines[:2]
    seen: set[str] = set()
    for line in lines[2:]:
        columns = [column.strip() for column in line.strip("|").split("|")]
        if len(columns) != 4:
            raise ValueError(f"malformed resource vocabulary row: {line}")
        names = set(CODE.findall(columns[0])) & summaries.keys()
        if names:
            seen.update(names)
            meanings = {summaries[name] for name in names}
            if len(meanings) != 1:
                raise ValueError(f"resource row {columns[0]} has multiple meanings")
            columns[1] = meanings.pop()
        output.append("| " + " | ".join(columns) + " |")
    for name in sorted(set(summaries) - seen):
        request_field = "" if name in informative_names else f"`{name}`"
        comparison = (
            "not compared"
            if name in informative_names
            else "the declaration establishes the requested value"
        )
        output.append(f"| `{name}` | {summaries[name]} | {request_field} | {comparison} |")
    return source[:start] + "\n".join(output) + source[end:]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    catalog = yaml.safe_load(CATALOG.read_text(encoding="utf-8"))
    summaries = descriptions(catalog)
    informative = set(catalog["declaration_resources"]) - set(catalog["resources"])
    source = VOCABULARY.read_text(encoding="utf-8")
    expected = generated(source, summaries, informative)
    if args.check:
        if source != expected:
            print("spec/vocabulary.md: resource meanings differ; run make write")
            return 1
        return 0
    VOCABULARY.write_text(expected, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
