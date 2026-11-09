# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Every example request is valid, so the README can point readers at them."""

from __future__ import annotations

from pathlib import Path

import pytest

import sandbox_provider_spec

EXAMPLES = sorted((Path(__file__).resolve().parents[1] / "examples").rglob("*.yaml"))


def test_there_are_examples() -> None:
    assert EXAMPLES


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda path: path.name)
def test_example_request_passes_the_checker(path: Path) -> None:
    request = sandbox_provider_spec.load(path)
    assert sandbox_provider_spec.schema_errors(request, "request-schema.json") == []
    assert sandbox_provider_spec.check_request(request) == []
