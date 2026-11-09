# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""A mixed-entry proof must actually exercise both declared entry kinds."""

import pytest

from sandbox_provider_spec.driver import NotRun
from sandbox_provider_spec.proofs import proof_fixtures
from sandbox_provider_spec.suite import read_suite, suite_path


@pytest.mark.parametrize("entries", [["blocked.example"], ["192.0.2.1"]])
def test_mixed_denylist_cannot_prove_an_unexercised_entry_kind(entries: list[str]) -> None:
    scenario = next(
        test
        for test in read_suite(suite_path().with_name("coverage.yaml")).tests
        if test.id == "coverage.network_lockdown.denylist.mixed"
    )
    with pytest.raises(NotRun, match="^proof_fixture_invalid$"):
        proof_fixtures(
            scenario,
            {
                "denylist_mixed_entries": entries,
                "denylist_mixed_urls": [
                    [f"http://{entry}/", f"https://{entry}/"] for entry in entries
                ],
            },
        )
