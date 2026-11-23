# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Every suite row's create request can be sent: it encodes on the wire.

A row whose create asked `keeps: any` (not a wire value) passed 3,239 unit tests and failed with a
`WireError` on every package's first live prober run. This builds each `create` step's
`CreateRequest` as the driver does and encodes it with the wire schema, so a row that cannot be
sent fails here. A value the runner fills in at run time (`$runner.<name>`) is left out of the
request; everything else a step names must encode.
"""

from collections.abc import Mapping
from typing import Any

import pytest

from sandbox_provider_spec.v1 import CreateRequest
from sandbox_provider_spec.v1.suite_driver import (
    CREATE_INPUTS,
    _request_requirements,  # pylint: disable=protected-access
)
from sandbox_provider_spec.v1.tester import shared_suite
from sandbox_provider_spec.v1.wire import WireError, to_json


def _has_runner_value(value: Any) -> bool:
    """Whether a part of `value` is filled in at run time, by the runner (`$runner.x`) or from an
    earlier step (`$receiver.x`): such a step cannot be judged offline, so it is left out."""
    if isinstance(value, str):
        return value.startswith("$")
    if isinstance(value, Mapping):
        return any(_has_runner_value(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_has_runner_value(item) for item in value)
    return False


def _create_steps() -> list[tuple[str, int, dict[str, Any]]]:
    found: list[tuple[str, int, dict[str, Any]]] = []
    for test in shared_suite().tests:
        for index, step in enumerate(test.steps):
            if step.get("op") != "create":
                continue
            inputs = step.get("in") or {}
            if _has_runner_value(inputs):
                continue
            if set(inputs) - CREATE_INPUTS or inputs.get("at_end", "destroyed") not in (
                "destroyed",
                "paused",
            ):
                continue  # a create SPS 1.0 cannot name: the driver answers `unsupported`
            assert isinstance(inputs, Mapping), (test.id, index, inputs)
            found.append((test.id, index, dict(inputs)))
    return found


def test_the_suite_has_create_steps_to_check() -> None:
    assert len(_create_steps()) > 50


@pytest.mark.parametrize(("test_id", "index", "inputs"), _create_steps())
def test_a_create_step_of_the_suite_encodes_on_the_wire(
    test_id: str, index: int, inputs: dict[str, Any]
) -> None:
    clean = inputs
    request = CreateRequest(
        sandbox_class="default",
        resources=clean.get("resources", {}),
        requirements=_request_requirements(clean.get("requirements", {})),
        image=None,
        at_end=clean.get("at_end", "destroyed"),
        env={},
        secrets=(),
        labels={"run": "suite-encode-check"},
        lifetime_seconds=clean.get("lifetime_seconds", 300),
        snapshot=None,
    )
    try:
        to_json(request)
    except WireError as error:
        pytest.fail(f"{test_id} step {index}: its create request cannot be sent: {error}")
