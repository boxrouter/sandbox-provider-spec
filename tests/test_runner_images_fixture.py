# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The shared image fixture file and the endpoint inventory agree with the fixtures the tester
accepts."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from sandbox_provider_spec.driver import NotRun
from sandbox_provider_spec.fixtures import DERIVED, FIXTURES, RESERVED, read_fixtures
from sandbox_provider_spec.runner import resolve
from sandbox_provider_spec.suite import read_suite

CONFORMANCE = Path(__file__).resolve().parents[1] / "conformance"
IMAGES = CONFORMANCE / "fixtures" / "runner-images.yaml"
INVENTORY = CONFORMANCE / "fixtures" / "endpoints" / "inventory.md"


def test_the_shared_image_is_digest_pinned_ubuntu_and_the_tester_accepts_it() -> None:
    given = read_fixtures([], [str(IMAGES)])
    assert set(given) == {"oci_image", "image_marker"}
    assert re.fullmatch(r"docker\.io/library/ubuntu@sha256:[0-9a-f]{64}", given["oci_image"])
    assert given["image_marker"] == "Ubuntu"


def test_the_endpoint_inventory_lists_only_names_the_tester_knows() -> None:
    names = set(re.findall(r"^\| `([a-z_0-9]+)` \|", INVENTORY.read_text("utf-8"), re.M))
    assert names <= set(FIXTURES) | set(DERIVED) | set(RESERVED)


def test_lifetime_ends_asks_for_60_seconds_unless_the_run_names_another() -> None:
    assert resolve("$runner.lifetime_ends_seconds", {}, {}) == 60
    assert resolve("$runner.lifetime_ends_wait_ms", {}, {}) == 60_000
    given = {"lifetime_ends_seconds": 330}
    assert resolve("$runner.lifetime_ends_seconds", {}, given) == 330
    assert resolve("$runner.lifetime_ends_wait_ms", {}, given) == 330_000


def test_the_oci_custom_image_test_runs_its_commands_with_sh_where_a_driver_can() -> None:
    tests = {test.id: test for test in read_suite(CONFORMANCE / "suite.yaml").tests}
    runs = [step for step in tests["custom_images.oci"].steps if step.get("op") == "run"]
    assert len(runs) == 2
    for step in runs:
        assert step["in"]["sh_script"] == step["in"]["bash_script"]


def test_a_prepared_image_is_compared_with_the_larger_size_in_its_own_names() -> None:
    given = {"larger_size": {"cpu_min": 2, "memory_min_mib": 4096}}
    assert resolve("$runner.larger_size_value", {}, given) == {"cpu": 2, "memory_mib": 4096}
    assert resolve({"one_of": [None, "$runner.larger_size_value"]}, {}, given) == {
        "one_of": [None, {"cpu": 2, "memory_mib": 4096}]
    }
    with pytest.raises(NotRun, match="fixture_missing"):
        resolve("$runner.larger_size_value", {}, {})
    with pytest.raises(NotRun, match="proof_fixture_invalid"):
        resolve("$runner.larger_size_value", {}, {"larger_size": {"gpu": 1}})
