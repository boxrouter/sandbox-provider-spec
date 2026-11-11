# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""A coverage step that creates a sandbox names its lifetime only when its test proves a lifetime
fact.

Any other create or restore takes the lifetime the run gives its fixtures. A literal there proves
nothing, and it keeps the test from running on a provider that never ends a sandbox: such a provider
admits no lifetime at all, so the create is refused before the check starts.
"""

from __future__ import annotations

import re

from sandbox_provider_spec.suite import Test, read_suite, suite_path

#: A test proves a lifetime fact when its id or a fact, gate or knob it proves is about the
#: sandbox's lifetime, idle time or another duration in seconds.
LIFETIME_SUBJECT = re.compile(r"lifetime|idle|_seconds$")

#: Steps that create a sandbox from a whole create request.
CREATES = {"create", "snapshot.restore"}

#: Tests whose own work outlasts the run's default lifetime, so they name a longer one.
LONGER_THAN_DEFAULT = {
    # A 5 GiB stream took up to 492 s in committed reports.
    "files.stream.v1.write.5gib",
    "files.stream.v1.read.5gib",
}


def coverage_tests() -> dict[str, Test]:
    """The coverage suite's tests by id."""
    return {test.id: test for test in read_suite(suite_path().with_name("coverage.yaml")).tests}


def proves_lifetime(test: Test) -> bool:
    names = [test.id] + [
        str(proof[key]) for proof in test.proves for key in ("fact", "gate", "knob") if key in proof
    ]
    return any(LIFETIME_SUBJECT.search(name) for name in names)


def literal_lifetimes(test: Test) -> list[object]:
    """The literal `lifetime_seconds` each creating step names; `$runner.` values are the run's."""
    return [
        step["in"]["lifetime_seconds"]
        for step in test.steps
        if step.get("op") in CREATES
        and isinstance(step.get("in"), dict)
        and "lifetime_seconds" in step["in"]
        and not str(step["in"]["lifetime_seconds"]).startswith("$")
    ]


def test_only_lifetime_tests_name_a_create_lifetime() -> None:
    named = {
        test.id: lifetimes
        for test in coverage_tests().values()
        if (lifetimes := literal_lifetimes(test))
        and not proves_lifetime(test)
        and test.id not in LONGER_THAN_DEFAULT
    }
    assert named == {}


def test_longer_than_default_tests_still_name_a_lifetime() -> None:
    by_id = coverage_tests()
    assert {
        test: bool(literal_lifetimes(by_id[test])) for test in LONGER_THAN_DEFAULT
    } == dict.fromkeys(LONGER_THAN_DEFAULT, True)


def test_the_predicate_tells_lifetime_tests_apart() -> None:
    def test(identifier: str, *proves: dict[str, str]) -> Test:
        return Test(identifier, identifier, (), proves)

    assert proves_lifetime(test("facts.max_lifetime", {"fact": "resources.max_lifetime_seconds"}))
    assert proves_lifetime(test("facts.max_run", {"fact": "resources.max_run_seconds"}))
    assert proves_lifetime(test("x", {"gate": "idle_shutdown", "knob": "on_idle"}))
    assert proves_lifetime(test("edge.lifetime.granularity"))
    assert not proves_lifetime(test("coverage.facts.arch.amd64", {"fact": "resources.arch"}))
    assert not proves_lifetime(test("y", {"gate": "network_lockdown", "knob": "policy"}))
