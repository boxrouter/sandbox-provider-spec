# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The reference matcher consumes exactly the vocabulary in the catalog."""

from __future__ import annotations

from pathlib import Path

import pytest

from sandbox_provider_spec import load_catalog
from sandbox_provider_spec.matcher.catalog import (
    ALL_OF,
    ALL_OF_RESOURCES,
    DECLARATION_RESOURCES,
    FLAG,
    GATES,
    NUMBER,
    PICK,
    PICK_RESOURCES,
    RESOURCE_ASKS,
    ROOT_WAYS,
    SECONDS_RESOURCES,
    WHOLE_NUMBERS,
    YES_RESOURCES,
)
from sandbox_provider_spec.matcher.declaration import build_declaration, parse_conflict


def test_matcher_words_and_order_equal_the_catalog() -> None:
    catalog = load_catalog()
    assert list(GATES) == catalog["gate_order"]
    for gate, definition in GATES.items():
        published = catalog["gates"][gate]
        assert list(definition.knobs) == list(published["knobs"])
        assert list(definition.settings) == list(published["settings"])
        assert list(definition.limits) == published["limits"]
        for knob, spec in definition.knobs.items():
            vocabulary = published["knobs"][knob]
            kind = {PICK: "pick", ALL_OF: "all_of", FLAG: "yes_no", NUMBER: "number"}[spec.kind]
            assert vocabulary["kind"] == kind
            assert tuple(vocabulary.get("values", [])) == spec.values
            assert vocabulary.get("must_be_named", False) is spec.must_be_named
            assert vocabulary.get("exactly_one", False) is spec.one_value
            if spec.only_when is not None:
                other, required = spec.only_when
                condition = vocabulary["only_when"]
                assert condition["knob"] == other
                if isinstance(required, tuple):
                    assert condition["in"] == list(required)
                else:
                    expected_key = "equals" if spec.only_when_exact else "includes"
                    assert condition[expected_key] == required
            elif spec.only_when_any is not None:
                conditions = vocabulary["only_when"]["any_of"]
                assert conditions == [
                    {"knob": other, "equals": required} for other, required in spec.only_when_any
                ]
            else:
                assert "only_when" not in vocabulary, (gate, knob)
        assert set(definition.variant_keys) == set(published.get("declaration_only", {}))
    resources = catalog["resources"]
    assert set(RESOURCE_ASKS) == set(resources)
    assert {key: list(values) for key, values in PICK_RESOURCES.items()} == {
        key: spec["values"]
        for key, spec in resources.items()
        if spec.get("kind") == "pick" and "values" in spec
    }
    assert {key: list(values) for key, values in ALL_OF_RESOURCES.items()} == {
        key: spec["values"] for key, spec in resources.items() if spec.get("kind") == "all_of"
    }
    assert YES_RESOURCES == {key for key, spec in resources.items() if spec["kind"] == "yes_no"}
    assert WHOLE_NUMBERS == {key for key, spec in resources.items() if spec["kind"] == "integer"}
    assert set(SECONDS_RESOURCES.values()) <= set(catalog["declaration_resources"])
    assert DECLARATION_RESOURCES == set(catalog["declaration_resources"])
    assert list(ROOT_WAYS) == catalog["declaration_resources"]["root"]["values"]


def test_declaration_conflict_rule_names_each_catalog_resource() -> None:
    catalog = load_catalog()
    source = (Path(__file__).resolve().parents[2] / "spec/declarations.md").read_text()
    start = source.index("<!-- rule: declaration/conflicts-name-real-things -->")
    end = source.index("\n- **`needs`**", start)
    rule = source[start:end]
    expected = {
        f"`resources.{resource}`" for resource in catalog["conflicts_may_name"]["resources"]
    }
    assert {token for token in expected if token in rule} == expected


def test_hidden_secret_selected_header_catalog_shape() -> None:
    hidden = load_catalog()["gates"]["hidden_secrets"]
    assert hidden["knobs"]["header_templates"] == {
        "description": (
            "Whether the provider can use request-supplied header templates for the secret."
        ),
        "kind": "yes_no",
        "must_be_named": False,
    }
    assert hidden["settings"]["headers"] == {
        "kind": "list",
        "required": False,
        "item": {
            "kind": "object",
            "required": ["name"],
            "properties": {
                "name": {"kind": "nonempty_string"},
                "prefix": {"kind": "string"},
                "suffix": {"kind": "string"},
            },
            "additional_properties": False,
        },
    }


def test_catalog_describes_each_gate_and_knob() -> None:
    catalog = load_catalog()
    for gate_name, gate in catalog["gates"].items():
        assert gate["description"].strip(), gate_name
        for knob_name, knob in gate["knobs"].items():
            assert knob["description"].strip(), f"{gate_name}.{knob_name}"
    assert catalog["resources"]["region"]["description"].strip()


def test_conflicts_recognise_positive_number_values_and_only_real_extensions() -> None:
    conflict = parse_conflict("previews.link_lifetime_seconds=300")
    assert conflict is not None
    assert conflict.value == 300
    resource_conflict = parse_conflict("resources.kernel_features")
    assert resource_conflict is not None
    assert resource_conflict.resource == "kernel_features"

    declaration = build_declaration(
        {
            "spec": "sandbox-provider-spec/0.1",
            "provider": "acme",
            "verified": {"sdks": {"acme": "1"}},
            "resources": {},
            "gates": {
                "pause_resume": [{"keeps": "files_only", "conflicts": ["x-acme.not_declared"]}]
            },
            "x-acme": {"declared": True},
        }
    )
    assert declaration.gates["pause_resume"].variants[0].unusable is not None


def test_reserved_ports_are_a_limit_and_runs_entrypoint_a_knob() -> None:
    def gates(previews: dict[str, object], images: dict[str, object]) -> dict[str, object]:
        return {
            "spec": "sandbox-provider-spec/0.1",
            "provider": "acme",
            "verified": {"sdks": {"acme": "1"}},
            "resources": {},
            "gates": {"previews": [previews], "custom_images": [images]},
        }

    declaration = build_declaration(
        gates(
            {"access": "public", "max_ports": 2, "reserved_ports": [22, 8080]},
            {"source": "oci", "runs_entrypoint": True},
        )
    )
    previews = declaration.gates["previews"].variants[0]
    assert previews.reserved_ports == {22, 8080}
    assert previews.limits == {"max_ports": 2}
    images = declaration.gates["custom_images"].variants[0]
    assert images.unusable is None
    assert images.knobs["runs_entrypoint"] == frozenset({True})

    for reserved in (["22"], [22, 22], [0], 22, "unknown"):
        declaration = build_declaration(gates({"reserved_ports": reserved}, {"source": "oci"}))
        assert declaration.gates["previews"].variants[0].unusable is not None, reserved
    retired = gates({"access": "public"}, {"source": "oci", "image_must_have": ["bash"]})
    assert build_declaration(retired).gates["custom_images"].variants[0].unusable is not None


@pytest.mark.parametrize("value", [["shared"], ["shared", "filtered"], [], ["unknown"], True])
def test_declared_kernel_does_not_accept_selectable_boundaries(value: object) -> None:
    declaration = build_declaration(
        {
            "spec": "sandbox-provider-spec/0.1",
            "provider": "acme",
            "verified": {"sdks": {"acme": "1"}},
            "resources": {"kernel": value},
            "gates": {},
        }
    )
    assert declaration.unusable == "kernel must be a single boundary"
