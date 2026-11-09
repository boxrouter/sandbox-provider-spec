# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Shared snapshot and idle selectors respect the normative mode constraints."""

from __future__ import annotations

from collections.abc import Mapping

from sandbox_provider_spec.check import check_document
from sandbox_provider_spec.suite import read_suite, suite_path


def test_literal_snapshot_and_idle_selectors_are_valid_requests() -> None:
    for test in read_suite().tests:
        for step in test.steps:
            inputs = step.get("in", {})
            if not isinstance(inputs, Mapping):
                continue
            requirements = inputs.get("requirements", {})
            if not isinstance(requirements, Mapping):
                continue
            for gate in ("snapshots", "idle_shutdown"):
                settings = requirements.get(gate)
                if not isinstance(settings, Mapping):
                    continue
                result = check_document({"requirements": {gate: dict(settings)}})
                assert result.errors == [], (test.id, gate, result.errors)


def test_stopped_and_destroyed_idle_cases_request_the_reference_timer_explicitly() -> None:
    tests = {test.id: test for test in read_suite().tests}
    for state in ("stopped", "destroyed"):
        test = tests[f"idle_shutdown.on_idle.{state}"]
        create = next(step for step in test.steps if step.get("op") == "create")
        inputs = create["in"]
        requirements = inputs["requirements"]
        assert requirements["idle_shutdown"] == {
            "custom_idle_time": True,
            "idle_seconds": 60,
            "on_idle": state,
        }
        waits = [step["wait_ms"] for step in test.steps if "wait_ms" in step]
        assert waits == ["$runner.idle_before_wait_ms", "$runner.idle_after_wait_ms"]
        states = [
            step["expect"]["equals"]["state"] for step in test.steps if step.get("op") == "get"
        ]
        assert states == ["active", state]


def test_open_network_lockdown_case_names_and_exercises_switchability() -> None:
    coverage_suite = read_suite(suite_path().with_name("coverage.yaml"))
    test = next(
        test for test in coverage_suite.tests if test.id == "coverage.network_lockdown.open"
    )
    create = next(step for step in test.steps if step.get("op") == "create")
    requirements = create["in"]["requirements"]
    result = check_document({"requirements": requirements})
    assert result.errors == []
    assert any(
        proof.get("knob") == "switchable" and proof.get("value") is True for proof in test.proves
    )
    assert any(step.get("op") == "fixture.coverage_policy_change" for step in test.steps)


def test_network_lockdown_runner_probes_use_recorder_aware_fixtures() -> None:
    for test in read_suite().tests:
        if not test.id.startswith("network_lockdown."):
            continue
        for step in test.steps:
            inputs = step.get("in", {})
            if step.get("op") == "probe.http" and isinstance(inputs, Mapping):
                url = inputs.get("url")
                assert not (isinstance(url, str) and url.startswith("$runner.")), test.id

    coverage_suite = read_suite(suite_path().with_name("coverage.yaml"))
    for test in coverage_suite.tests:
        if not test.id.startswith("coverage.network_lockdown."):
            continue
        for step in test.steps:
            inputs = step.get("in", {})
            if step.get("op") == "probe.http" and isinstance(inputs, Mapping):
                url = inputs.get("url")
                assert not (isinstance(url, str) and url.startswith("$runner.")), test.id


def test_deny_all_allows_a_refused_request_to_reach_its_receiver() -> None:
    test = next(test for test in read_suite().tests if test.id == "network_lockdown.deny_all")
    step = next(step for step in test.steps if step.get("op") == "fixture.coverage_network_checks")
    request = step["in"]["requests"][0]
    assert request == {
        "url": "$runner.denied_url",
        "reachable": False,
        "recorder": "required",
    }
    assert "returns no destination data" in test.title
