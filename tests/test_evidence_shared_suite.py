# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""A report that the tester wrote under the shared suite's digest may hold any shared test."""

from __future__ import annotations

from sandbox_provider_spec.evidence import _source_suite_rules
from sandbox_provider_spec.suite import read_suite, suite_path


def test_the_shared_suite_digest_covers_core_coverage_and_baseline_tests() -> None:
    digest = read_suite(suite_path().with_name("coverage.yaml")).digest
    rules, errors = _source_suite_rules(digest)
    assert errors == [] and rules is not None
    assert "baseline.get" in rules  # a baseline row
    assert any(name.startswith("coverage.") for name in rules)  # a coverage row
    assert "run.user" in rules and "directories.list" in rules  # core rows that are not baseline


def test_the_core_suite_digest_still_covers_only_the_core_tests() -> None:
    rules, errors = _source_suite_rules(read_suite().digest)
    assert errors == [] and rules is not None
    assert "run.user" in rules and not any(name.startswith("coverage.") for name in rules)
