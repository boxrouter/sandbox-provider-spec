# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Check groups a run leaves out unless it names them, and the one test selection every runner uses.

This module is deliberately not one of `check_digests.SHARED_MODULES`: choosing which tests a run
executes does not change what any check does, so editing it moves no committed report's digests.
"""

from __future__ import annotations

from collections.abc import Collection, Mapping

from sandbox_provider_spec.suite import Suite

#: Each key is an option a run passes (`--opt-in streamed_transfer`); each value holds the
#: test-id prefixes it switches on. The tests stay in the suite, so their definitions, digests
#: and committed reports remain valid.
OPT_IN_CHECKS: Mapping[str, tuple[str, ...]] = {
    "streamed_transfer": ("file_links.v1.", "files.stream.v1."),
}


def opt_in_group(test_id: str) -> str | None:
    """The opt-in group a test belongs to, or None when every run selects it."""
    for group, prefixes in OPT_IN_CHECKS.items():
        if test_id.startswith(prefixes):
            return group
    return None


def without_opt_in(suite: Suite, opted_in: Collection[str] = ()) -> Suite:
    """The suite without the opt-in checks no run option named; identity and baseline are kept."""
    unknown = sorted(set(opted_in) - set(OPT_IN_CHECKS))
    if unknown:
        raise ValueError(f"unknown opt-in checks: {', '.join(unknown)}")
    tests = tuple(
        test
        for test in suite.tests
        if (group := opt_in_group(test.id)) is None or group in opted_in
    )
    return Suite(suite.digest, tests, suite.baseline_ids)


def select_tests(
    suite: Suite, prefixes: Collection[str] = (), opted_in: Collection[str] = ()
) -> Suite:
    """What a run executes: the opt-in checks only when named, then the tests with a prefix.

    No prefix keeps every test left. A prefix that names only opt-in checks no run option
    switched on says so, instead of reporting that nothing matches.
    """
    chosen = without_opt_in(suite, opted_in)
    if not prefixes:
        return chosen
    wanted = tuple(prefixes)
    tests = tuple(test for test in chosen.tests if test.id.startswith(wanted))
    if not tests:
        if any(opt_in_group(test.id) and test.id.startswith(wanted) for test in suite.tests):
            raise ValueError("the selected tests are opt-in checks; pass --opt-in to run them")
        raise ValueError("no shared tests match selection")
    return Suite(suite.digest, tests, suite.baseline_ids)
