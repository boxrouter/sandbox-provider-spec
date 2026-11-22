# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""A create that the tester sends must be a valid `CreateRequest` on the wire.

The tester builds the request in Python, and an in-process provider never encodes it, so a field
that the request schema does not allow went unseen until a package was tested over HTTP (the
prober's route): `HttpProvider` encodes with `to_json`, which raised `WireError` for the knob
`custom_images.source` that a test names for what it proves."""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from typing import Any, cast

import pytest

from sandbox_provider_spec.check import spec_dir
from sandbox_provider_spec.v1 import CreateRequest, to_json
from sandbox_provider_spec.v1.suite_driver import (
    PROOF_ONLY_REQUIREMENTS,
    _request_requirements,
)
from sandbox_provider_spec.v1.tester import shared_suite


def _allowed() -> Mapping[str, Mapping[str, Any]]:
    schema = json.loads((spec_dir() / "request-schema.json").read_text("utf-8"))
    return cast(Mapping[str, Mapping[str, Any]], schema["$defs"]["requirements"]["properties"])


def _create_requirements() -> Iterator[tuple[str, Mapping[str, Any]]]:
    for test in shared_suite().tests:
        for step in test.steps:
            given = step.get("in")
            if step.get("op") == "create" and isinstance(given, Mapping):
                requirements = given.get("requirements")
                if isinstance(requirements, Mapping):
                    yield test.id, requirements


def test_no_create_of_the_shared_suite_names_a_requirement_the_request_schema_lacks() -> None:
    allowed = _allowed()
    seen = 0
    for test_id, requirements in _create_requirements():
        seen += 1
        sent = _request_requirements(requirements)
        for section, value in sent.items():
            assert section in allowed, (test_id, section)
            properties = allowed[section].get("properties")
            if isinstance(value, Mapping) and properties is not None:
                assert set(value) <= set(properties), (test_id, section, sorted(value))
    assert seen > 20


def test_the_proof_only_knobs_are_the_ones_the_suite_names_and_the_schema_lacks() -> None:
    allowed = _allowed()
    missing = {
        (section, key)
        for _, requirements in _create_requirements()
        for section, value in requirements.items()
        if isinstance(value, Mapping) and allowed.get(section, {}).get("properties") is not None
        for key in value
        if key not in allowed[section]["properties"]
    }
    assert missing == {
        (section, key) for section, keys in PROOF_ONLY_REQUIREMENTS.items() for key in keys
    }


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        ({"custom_images": {"source": "oci"}}, {"custom_images": {}}),
        (
            {"custom_images": {"source": "oci", "prepared": True}},
            {"custom_images": {"prepared": True}},
        ),
        (
            {"network_lockdown": {"cuts_open_connections": True, "policy": "deny_all"}},
            {"network_lockdown": {"policy": "deny_all"}},
        ),
        ({"custom_images": {"prepared": True}}, {"custom_images": {"prepared": True}}),
    ],
)
def test_only_the_proof_knobs_are_left_out_and_the_request_encodes(
    given: dict[str, Any], expected: dict[str, Any]
) -> None:
    sent = _request_requirements(given)
    assert sent == expected
    to_json(CreateRequest(requirements=sent))
