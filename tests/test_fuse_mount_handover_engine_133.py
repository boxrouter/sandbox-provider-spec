# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Engine identities have their own fact schema and never impersonate Core bindings."""

from __future__ import annotations

import copy
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
from test_fuse_mount_handover_130 import _facts
from test_fuse_mount_handover_env_132 import binding, prerequisites

from sandbox_provider_spec.driver import Driver
from sandbox_provider_spec.fuse_mount import controller_digest
from sandbox_provider_spec.fuse_mount_handover_130 import handover_fact_errors
from sandbox_provider_spec.fuse_mount_handover_engine_133 import (
    ENGINE_IDENTITY_BASIS,
    ENGINE_WRITE_CHECK,
    ENGINE_WRITE_OPERATION,
    EngineNativeHandoverRunner,
    engine_identity_digest,
    engine_native_identity_digest,
    engine_write_fact_errors,
)
from sandbox_provider_spec.suite import Test as SuiteTest
from sandbox_provider_spec.suite import read_suite, suite_path


def _identity(sandbox: str) -> dict[str, str]:
    return {
        "sandbox_id": sandbox,
        "workspace_id": "workspace",
        "route_id": "route",
        "provider": "e2b",
        "account_id": "account",
        "native_id": "native-" + sandbox,
    }


def _engine_facts() -> dict[str, Any]:
    facts = _facts()
    for name, sandbox in (("terminal_receipt", "old"), ("successor", "new")):
        item = facts[name]
        item.pop("public_core_binding_sha256")
        item.pop("binding_basis")
        item["engine_identity_sha256"] = engine_identity_digest(_identity(sandbox))
        item["native_identity_sha256"] = engine_native_identity_digest(_identity(sandbox))
        item["identity_basis"] = list(ENGINE_IDENTITY_BASIS)
    return facts


def test_engine_facts_use_a_distinct_identity_and_keep_existing_safety_checks() -> None:
    facts = _engine_facts()
    assert engine_write_fact_errors(facts, access_mode="write") == []
    for change in (
        "same_identity",
        "same_native",
        "bad_basis",
        "missing_cleanup",
        "forced_mount",
        "legacy_field",
    ):
        changed = copy.deepcopy(facts)
        if change == "same_identity":
            changed["successor"]["engine_identity_sha256"] = changed["terminal_receipt"][
                "engine_identity_sha256"
            ]
        elif change == "same_native":
            changed["successor"]["native_identity_sha256"] = changed["terminal_receipt"][
                "native_identity_sha256"
            ]
        elif change == "bad_basis":
            changed["terminal_receipt"]["identity_basis"] = ["native_id"]
        elif change == "missing_cleanup":
            changed["cleanup"]["owned_resources"] = "unknown"
        elif change == "forced_mount":
            changed["successor"]["force"] = True
        else:
            changed["terminal_receipt"]["public_core_binding_sha256"] = "sha256:" + "1" * 64
        assert engine_write_fact_errors(changed, access_mode="write")
    assert engine_write_fact_errors(facts, access_mode="branch")


def test_engine_identity_requires_every_actual_field_and_separates_accounts() -> None:
    identity = _identity("old")
    digest = engine_identity_digest(identity)
    assert digest != engine_identity_digest({**identity, "account_id": "other"})
    assert digest != engine_identity_digest({**identity, "native_id": "other"})
    assert engine_native_identity_digest(identity) == engine_native_identity_digest(
        {**identity, "sandbox_id": "another"}
    )
    for change in ({"native_id": ""}, {"account_id": ""}):
        with pytest.raises(ValueError):
            engine_identity_digest({**identity, **change})
    with pytest.raises(ValueError):
        engine_identity_digest({**identity, "incarnation": "invented"})


def test_owner_client_delegation_requires_a_successful_revoke() -> None:
    facts = _engine_facts()
    item = facts["delegations"][0]
    item["is_orphaned"] = False
    item["revoke_basis"] = "owner_client"
    assert engine_write_fact_errors(facts, access_mode="write") == []
    item["revoke"]["outcome"] = "not_attempted"
    assert engine_write_fact_errors(facts, access_mode="write")


def test_engine_runner_accepts_new_facts_and_legacy_checker_rejects_them() -> None:
    class Controller:
        source_files = (Path(__file__),)
        execution_binding = binding()

        def observe_provider_terminal_handover(
            self, _driver: Driver, _create: Mapping[str, object], *, access_mode: str
        ) -> dict[str, Any]:
            assert access_mode == "write"
            return _engine_facts()

        def cleanup(self, _driver: Driver) -> None:
            return None

    controller = Controller()
    scoped = [item for item in prerequisites(binding()) if not item.startswith("controller:")]
    fixtures = {
        "fuse_mount_handover_controller": controller,
        "fuse_mount_handover_controller_digest": controller_digest(controller.source_files),
    }
    test = SuiteTest(
        id=ENGINE_WRITE_CHECK,
        title="Engine-native write handover",
        steps=(
            {
                "op": ENGINE_WRITE_OPERATION,
                "in": {"create": {}, "prerequisites": scoped},
                "expect": {"record": ["fuse_mount_handover"]},
            },
        ),
        proves=(),
    )
    assert handover_fact_errors(_engine_facts(), access_mode="write")
    assert EngineNativeHandoverRunner(Driver(), fixtures).run_test(test)["result"] == "passed"


def test_engine_check_is_separate_from_the_historical_suite_case() -> None:
    suite = read_suite(suite_path().with_name("coverage.yaml"))
    checks = {test.id: test for test in suite.tests}
    assert ENGINE_WRITE_CHECK in checks
    assert checks[ENGINE_WRITE_CHECK].steps[0]["op"] == ENGINE_WRITE_OPERATION
    assert checks["fuse_mount.provider_terminal_handover_env_132"].steps[0]["op"] == (
        "fixture.fuse_mount_provider_terminal_handover_env_132"
    )
