# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Sandbox-wide private ingress is a contract difference, not a missing SDK API."""

import pytest
from e2b import Sandbox

from sandbox_provider_spec.drivers.e2b import E2BDriver
from sandbox_provider_spec.runner import Runner
from sandbox_provider_spec.suite import Test as Scenario


@pytest.mark.parametrize(
    "step",
    [
        {"op": "create", "in": {"requirements": {"previews": {"access": "private"}}}},
        {"op": "preview.link", "in": {"port": 3000, "access": "private"}},
    ],
)
def test_private_ingress_scope_is_reported_as_differs(
    monkeypatch: pytest.MonkeyPatch, step: dict[str, object]
) -> None:
    def unexpected_allocation(**_options: object) -> None:
        pytest.fail("A known scope difference must not allocate a sandbox")

    monkeypatch.setattr(Sandbox, "create", unexpected_allocation)
    proof = {"gate": "previews", "knob": "access", "value": "private"}
    rules = ("previews/private-credential-is-its-own",)
    driver = E2BDriver()
    result = Runner(driver).run_test(
        Scenario("private_preview", "Private credential scope", (step,), (proof,), rules)
    )
    assert result["result"] == "differs"
    assert result["rules"] == list(rules)
    assert result["proves"] == [proof]
    assert result["cleanup"] == []
    assert driver.resources == []
    steps = result["steps"]
    assert isinstance(steps, list)
    assert steps[0]["operation"] == step["op"]
    assert steps[0]["result"] == "differs"
    assert "sandbox" in str(result["reason"])
