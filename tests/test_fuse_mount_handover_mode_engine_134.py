# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The new mode facts never reinterpret a retired Core binding as an engine identity."""

from collections.abc import Callable, Mapping
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from test_fuse_mount_handover_130 import _facts as old_mode_facts
from test_fuse_mount_handover_branch_131 import _facts as old_branch_facts
from test_fuse_mount_handover_env_132 import binding, prerequisites

from sandbox_provider_spec.driver import Driver
from sandbox_provider_spec.fuse_mount import controller_digest
from sandbox_provider_spec.fuse_mount_handover_engine_133 import (
    ENGINE_IDENTITY_BASIS,
    engine_identity_digest,
    engine_native_identity_digest,
)
from sandbox_provider_spec.fuse_mount_handover_mode_engine_134 import (
    HANDOVER_IDENTITIES_134,
    EngineNativeModeHandoverRunner,
    branch_fact_errors,
    read_fact_errors,
    shared_fact_errors,
)
from sandbox_provider_spec.suite import Test as SuiteTest


def facts(mode: str) -> dict[str, Any]:
    result = deepcopy(old_branch_facts() if mode == "branch" else old_mode_facts(mode))
    for delegation in result["delegations"]:
        delegation["revoke_basis"] = "orphaned"
    for field, suffix in (("terminal_receipt", "old"), ("successor", "new")):
        row = result[field]
        del row["public_core_binding_sha256"]
        del row["binding_basis"]
        identity = dict(
            zip(
                ENGINE_IDENTITY_BASIS,
                (suffix, "workspace", "route", "e2b", "account", suffix),
                strict=True,
            )
        )
        row["engine_identity_sha256"] = engine_identity_digest(identity)
        row["native_identity_sha256"] = engine_native_identity_digest(identity)
        row["identity_basis"] = list(ENGINE_IDENTITY_BASIS)
    return result


@pytest.mark.parametrize(
    "mode,validate",
    [("read", read_fact_errors), ("shared", shared_fact_errors), ("branch", branch_fact_errors)],
)
def test_mode_requires_distinct_actual_engine_and_native_identities(
    mode: str, validate: Callable[[object, object], list[str]]
) -> None:
    original = facts(mode)
    assert validate(original, mode) == []
    for field in ("sandbox_id_sha256", "engine_identity_sha256", "native_identity_sha256"):
        invalid = deepcopy(original)
        invalid["successor"][field] = invalid["terminal_receipt"][field]
        assert validate(invalid, mode), field
    for field in ("engine_identity_sha256", "native_identity_sha256", "identity_basis"):
        invalid = deepcopy(original)
        del invalid["terminal_receipt"][field]
        assert validate(invalid, mode), field
    invalid = deepcopy(original)
    invalid["terminal_receipt"]["identity_basis"] = ["native_id"]
    assert validate(invalid, mode)
    assert validate(original, "write")


def test_mode_specific_guarantees_remain_mandatory() -> None:
    read = facts("read")
    read["file_evidence"]["denial_errno"] = "EACCES"
    assert read_fact_errors(read)
    shared = facts("shared")
    shared["file_evidence"]["sync_acknowledged"] = False
    assert shared_fact_errors(shared)
    branch = facts("branch")
    branch["branch_evidence"]["private_marker_absent_from_parent"] = False
    assert branch_fact_errors(branch)


def test_owner_client_revoke_requires_the_observed_basis_and_success() -> None:
    value = facts("shared")
    delegation = value["delegations"][0]
    delegation["is_orphaned"] = False
    delegation["revoke_basis"] = "owner_client"
    assert shared_fact_errors(value) == []
    delegation["revoke"]["attempted"] = False
    assert shared_fact_errors(value)
    delegation["revoke"]["attempted"] = True
    delegation["revoke_basis"] = "orphaned"
    assert shared_fact_errors(value)


@pytest.mark.parametrize("mode", ["read", "shared", "branch"])
def test_engine_mode_runner_checks_mode_facts_and_scope(mode: str) -> None:
    class Controller:
        source_files = (Path(__file__),)
        execution_binding = {**binding(), "access_mode": mode}

        def observe_provider_terminal_handover(
            self, _driver: Driver, _create: Mapping[str, object], *, access_mode: str
        ) -> dict[str, Any]:
            assert access_mode == mode
            return facts(mode)

        def cleanup(self, _driver: Driver) -> None:
            return None

    controller = Controller()
    scoped = [
        item
        for item in prerequisites(controller.execution_binding)
        if not item.startswith("controller:")
    ]
    entry = next(row for row in HANDOVER_IDENTITIES_134.values() if row[0] == mode)
    test = SuiteTest(
        id="fixture",
        title="Engine mode",
        steps=(
            {
                "op": entry[2],
                "in": {"create": {}, "prerequisites": scoped, "access_mode": mode},
                "expect": {"record": ["fuse_mount_handover"]},
            },
        ),
        proves=(),
    )
    fixtures = {
        "fuse_mount_handover_controller": controller,
        "fuse_mount_handover_controller_digest": controller_digest(controller.source_files),
    }
    assert EngineNativeModeHandoverRunner(Driver(), fixtures).run_test(test)["result"] == "passed"
