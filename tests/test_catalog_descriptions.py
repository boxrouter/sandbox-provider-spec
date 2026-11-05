# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml

import sandbox_provider_spec

ROOT = Path(__file__).resolve().parents[1]


def test_catalog_descriptions_match_vocabulary_source() -> None:
    result = subprocess.run(
        [sys.executable, "tools/sync_catalog_descriptions.py", "--check"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_resource_descriptions_have_exact_declaration_keys() -> None:
    catalog = yaml.safe_load((ROOT / "spec/catalog.yaml").read_text(encoding="utf-8"))
    descriptions = catalog["resource_descriptions"]
    assert set(descriptions) == set(catalog["declaration_resources"])
    assert all(isinstance(value, str) and value.strip() for value in descriptions.values())
    assert all("description" not in item for item in catalog["declaration_resources"].values())


def test_guest_reserved_ports_is_informative_port_list_with_unknown_omission() -> None:
    catalog = sandbox_provider_spec.load_catalog()
    resource = catalog["declaration_resources"]["guest_reserved_tcp_ports"]
    assert resource["kind"] == "list"
    assert resource["item"] == {"kind": "integer", "minimum": 1, "maximum": 65535}
    assert resource["nonempty"] is True
    assert resource["left_out"] == "unknown"
    assert "guest_reserved_tcp_ports" not in catalog["resources"]
    assert sandbox_provider_spec.check_request({"resources": {"guest_reserved_tcp_ports": [8080]}})

    declaration: dict[str, Any] = {
        "spec": "sandbox-provider-spec/0.1",
        "provider": "acme",
        "verified": {"date": "2026-10-27", "sdks": {"acme": "1.0"}},
        "resources": {"guest_reserved_tcp_ports": [8080]},
        "gates": {},
        "evidence": {},
    }
    assert sandbox_provider_spec.schema_errors(declaration, "declaration-schema.json") == []
    declaration["resources"]["guest_reserved_tcp_ports"] = []
    assert sandbox_provider_spec.schema_errors(declaration, "declaration-schema.json")


def test_new_informative_resource_description_generates_a_vocabulary_row() -> None:
    generator = ROOT / "tools/sync_catalog_descriptions.py"
    namespace = __import__("runpy").run_path(str(generator))
    catalog = yaml.safe_load((ROOT / "spec/catalog.yaml").read_text(encoding="utf-8"))
    summaries = namespace["descriptions"](catalog)
    vocabulary = (ROOT / "spec/vocabulary.md").read_text(encoding="utf-8")
    rendered = namespace["generated"](
        vocabulary,
        summaries,
        set(catalog["declaration_resources"]) - set(catalog["resources"]),
    )
    assert "| `guest_reserved_tcp_ports` |" in rendered
    assert rendered.count("| `guest_reserved_tcp_ports` |") == 1
    assert rendered == vocabulary


@pytest.mark.parametrize(
    "mutate",
    [
        lambda descriptions, name: descriptions.pop(name),
        lambda descriptions, _name: descriptions.update({"unknown_resource": "Unknown fact."}),
        lambda descriptions, name: descriptions.update({name: ""}),
    ],
)
def test_catalog_schema_rejects_missing_unknown_or_empty_resource_descriptions(
    mutate: Callable[[dict[str, str], str], object],
) -> None:
    catalog = yaml.safe_load((ROOT / "spec/catalog.yaml").read_text(encoding="utf-8"))
    name = next(iter(catalog["resource_descriptions"]))
    mutate(catalog["resource_descriptions"], name)
    assert sandbox_provider_spec.schema_errors(catalog, "catalog-schema.json")


def test_description_generator_rejects_non_neutral_wording() -> None:
    generator = ROOT / "tools/sync_catalog_descriptions.py"
    namespace = __import__("runpy").run_path(str(generator))
    catalog = yaml.safe_load((ROOT / "spec/catalog.yaml").read_text(encoding="utf-8"))
    catalog["resource_descriptions"]["kernel"] = "Daytona uses this kernel."
    with pytest.raises(ValueError, match="provider-neutral"):
        namespace["descriptions"](catalog)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda descriptions, name: descriptions.pop(name),
        lambda descriptions, _name: descriptions.update({"unknown_resource": "Unknown fact."}),
    ],
)
def test_description_generator_rejects_missing_or_unknown_keys(
    mutate: Callable[[dict[str, str], str], object],
) -> None:
    generator = ROOT / "tools/sync_catalog_descriptions.py"
    namespace = __import__("runpy").run_path(str(generator))
    catalog = yaml.safe_load((ROOT / "spec/catalog.yaml").read_text(encoding="utf-8"))
    name = next(iter(catalog["resource_descriptions"]))
    mutate(catalog["resource_descriptions"], name)
    with pytest.raises(ValueError, match="keys must equal declaration_resources"):
        namespace["descriptions"](catalog)
