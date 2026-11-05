# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Strict read/shared handover contracts and their source-bound fixture operations."""

from __future__ import annotations

import copy
import hashlib
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

from sandbox_provider_spec.check_digests import check_digests
from sandbox_provider_spec.driver import Driver, Inputs, Observation
from sandbox_provider_spec.fuse_mount import controller_digest
from sandbox_provider_spec.fuse_mount_handover import handover_scope_errors
from sandbox_provider_spec.fuse_mount_handover_read import (
    OPERATION as READ_OPERATION,
)
from sandbox_provider_spec.fuse_mount_handover_read import (
    ProviderTerminalHandoverReadRunner,
)
from sandbox_provider_spec.fuse_mount_handover_read import (
    handover_fact_errors as read_fact_errors,
)
from sandbox_provider_spec.fuse_mount_handover_shared import (
    OPERATION as SHARED_OPERATION,
)
from sandbox_provider_spec.fuse_mount_handover_shared import (
    ProviderTerminalHandoverSharedRunner,
)
from sandbox_provider_spec.fuse_mount_handover_shared import (
    handover_fact_errors as shared_fact_errors,
)
from sandbox_provider_spec.runner import Runner
from sandbox_provider_spec.suite import Test as Scenario
from sandbox_provider_spec.suite import read_suite, suite_path

_TIME = "2026-10-26T16:00:00Z"
_IMAGE = "sha256:" + "a" * 64
_EGRESS = "sha256:" + "b" * 64


def facts(mode: str) -> dict[str, object]:
    common: dict[str, object] = {
        "terminal_receipt": {
            "sandbox_id_sha256": "sha256:" + "1" * 64,
            "incarnation_sha256": "sha256:" + "2" * 64,
            "provider_state": "terminated",
            "observed_at": _TIME,
        },
        "issuance": {
            "claim_sha256": "sha256:" + "3" * 64,
            "credential_sha256": "sha256:" + "4" * 64,
            "resolution": "current",
        },
        "delegations": [
            {
                "delegation_sha256": "sha256:" + "5" * 64,
                "client_sha256": "sha256:" + "6" * 64,
                "is_orphaned": True,
                "revoke": {"attempted": True, "outcome": "revoked"},
            },
            {
                "delegation_sha256": "sha256:" + "c" * 64,
                "client_sha256": "sha256:" + "d" * 64,
                "is_orphaned": False,
                "revoke": {"attempted": False, "outcome": "not_attempted"},
            },
        ],
        "delegations_cleared": True,
        "no_force": True,
        "successor": {
            "sandbox_id_sha256": "sha256:" + "7" * 64,
            "incarnation_sha256": "sha256:" + "8" * 64,
            "access_mode": mode,
            "force": False,
            "mounted": True,
        },
        "cleanup": {"owned_resources": "deleted"},
    }
    if mode == "read":
        common.update(
            {
                "connected_reader": {
                    "connected": True,
                    "outcome": "busy",
                    "revoke_attempted": False,
                    "successor_dispatched": False,
                    "read_after_refusal": True,
                },
                "file_evidence": {
                    "write_attempted": True,
                    "write_denied": True,
                    "denial_errno": "EROFS",
                    "expected_readback_sha256": "sha256:" + "a" * 64,
                    "readback_sha256": "sha256:" + "a" * 64,
                },
            }
        )
    else:
        common.update(
            {
                "connected_writer": {
                    "connected": True,
                    "outcome": "busy",
                    "revoke_attempted": False,
                    "successor_dispatched": False,
                    "write_after_refusal": True,
                },
                "file_evidence": {
                    "default_user_write": True,
                    "fsync_acknowledged": True,
                    "sync_acknowledged": True,
                    "checkpoint_sha256": "sha256:" + "9" * 64,
                    "expected_readback_sha256": "sha256:" + "a" * 64,
                    "readback_sha256": "sha256:" + "a" * 64,
                },
            }
        )
    return common


def source_prerequisites(mode: str) -> list[str]:
    return [
        "image:" + _IMAGE,
        "fuse_mount_account",
        "fuse_mount_egress:" + _EGRESS,
        "access_mode:" + mode,
        "region:us-east-1",
    ]


def binding(mode: str) -> dict[str, str]:
    return {
        "account": "a" * 64,
        "copy": "b" * 64,
        "class": "modal-default",
        "credential_kind": "byok_version",
        "credential_version": "1",
        "image_kind": "standard_source",
        "image_hash": _IMAGE,
        "region": "us-east-1",
        "access_mode": mode,
    }


def scenario(test_id: str) -> Scenario:
    return next(
        test
        for test in read_suite(suite_path().with_name("coverage.yaml")).tests
        if test.id == test_id
    )


class MockHandoverController:
    """Mock callback facts; these fixtures do not execute provider or native effects."""

    def __init__(self, mode: str) -> None:
        self.source_files = (Path(__file__),)
        self.execution_binding = binding(mode)
        self.observations = facts(mode)
        self.observe_calls = 0
        self.cleanup_calls = 0

    def observe_provider_terminal_handover(
        self, driver: Driver, create: dict[str, object], *, access_mode: str
    ) -> dict[str, object]:
        del driver, create
        self.observe_calls += 1
        return self.observations

    def cleanup(self) -> Observation:
        self.cleanup_calls += 1
        return {"result": "deleted"}


class EmptyDriver(Driver):
    def call(self, operation: str, target: object, inputs: Inputs) -> Observation:
        del operation, target, inputs
        raise AssertionError("the host callback owns the fixture")


@pytest.mark.parametrize(
    ("mode", "runner", "test_id", "operation", "validator"),
    [
        (
            "read",
            ProviderTerminalHandoverReadRunner,
            "fuse_mount.provider_terminal_handover_read",
            READ_OPERATION,
            read_fact_errors,
        ),
        (
            "shared",
            ProviderTerminalHandoverSharedRunner,
            "fuse_mount.provider_terminal_handover_shared",
            SHARED_OPERATION,
            shared_fact_errors,
        ),
    ],
)
def test_mode_contract_accepts_only_its_complete_mocked_facts_and_emits_envelope(
    mode: str,
    runner: type[Runner],
    test_id: str,
    operation: str,
    validator: Callable[[object, object], list[str]],
) -> None:
    """Explicitly mocked positives verify source shape, never consumer or live proof."""
    assert validator(facts(mode), mode) == []
    controller = MockHandoverController(mode)
    inputs = {
        "fuse_mount_create": {"requirements": {}},
        "fuse_mount_prerequisites": source_prerequisites(mode),
        "fuse_mount_access_mode": mode,
        "fuse_mount_handover_controller": controller,
        "fuse_mount_handover_controller_digest": controller_digest((Path(__file__).resolve(),)),
    }
    result = runner(EmptyDriver(), inputs).run_test(scenario(test_id))
    assert result["result"] == "passed"
    assert controller.observe_calls == 1
    assert controller.cleanup_calls == 1
    steps = result["steps"]
    assert isinstance(steps, list) and isinstance(steps[0], dict)
    assert steps[0]["operation"] == operation
    observation = steps[0]["observations"]["fuse_mount_handover"]
    assert observation["requested_access_mode"] == mode
    assert observation["observed_access_mode"] == mode
    assert observation["execution_binding"]["access_mode"] == mode
    if mode == "read":
        assert "connected_reader" in observation
        assert "connected_writer" not in observation
    else:
        assert "connected_writer" in observation
        assert "connected_reader" not in observation


@pytest.mark.parametrize(
    ("mode", "validator", "mutations"),
    [
        (
            "read",
            read_fact_errors,
            [
                lambda item: item["connected_reader"].__setitem__("connected", 1),
                lambda item: item["connected_reader"].__setitem__("read_after_refusal", False),
                lambda item: item["connected_reader"].__setitem__("revoke_attempted", True),
                lambda item: item["connected_reader"].__setitem__("successor_dispatched", True),
                lambda item: item["file_evidence"].__setitem__("write_attempted", False),
                lambda item: item["file_evidence"].__setitem__("write_denied", 1),
                lambda item: item["file_evidence"].__setitem__("denial_errno", "EIO"),
                lambda item: item["file_evidence"].__setitem__(
                    "readback_sha256", "sha256:" + "f" * 64
                ),
                lambda item: item["file_evidence"].__setitem__("save_acknowledged", True),
            ],
        ),
        (
            "shared",
            shared_fact_errors,
            [
                lambda item: item["connected_writer"].__setitem__("connected", 1),
                lambda item: item["connected_writer"].__setitem__("write_after_refusal", False),
                lambda item: item["connected_writer"].__setitem__("revoke_attempted", True),
                lambda item: item["connected_writer"].__setitem__("successor_dispatched", True),
                lambda item: item["file_evidence"].__setitem__("default_user_write", 1),
                lambda item: item["file_evidence"].__setitem__("fsync_acknowledged", False),
                lambda item: item["file_evidence"].__setitem__("sync_acknowledged", 1),
                lambda item: item["file_evidence"].__setitem__("checkpoint_sha256", "bad"),
                lambda item: item["file_evidence"].__setitem__(
                    "readback_sha256", "sha256:" + "f" * 64
                ),
                lambda item: item["file_evidence"].__setitem__("write_denied", True),
            ],
        ),
    ],
)
def test_mode_specific_causal_negatives_are_rejected(
    mode: str,
    validator: Callable[[object, object], list[str]],
    mutations: list[Callable[[Any], None]],
) -> None:
    for mutate in mutations:
        candidate = copy.deepcopy(facts(mode))
        mutate(candidate)
        assert validator(candidate, mode), mutate


@pytest.mark.parametrize("mode", ["read", "shared"])
def test_common_handover_guards_reject_bad_terminal_orphan_force_successor_and_cleanup(
    mode: str,
) -> None:
    validator = read_fact_errors if mode == "read" else shared_fact_errors
    mutations: list[Callable[[Any], None]] = [
        lambda item: item["terminal_receipt"].__setitem__("provider_state", "stopped"),
        lambda item: item["issuance"].__setitem__("resolution", "stale"),
        lambda item: item["delegations"][1]["revoke"].__setitem__("attempted", True),
        lambda item: item.__setitem__("delegations_cleared", False),
        lambda item: item.__setitem__("no_force", False),
        lambda item: item["successor"].__setitem__("access_mode", "write"),
        lambda item: item["successor"].__setitem__("force", True),
        lambda item: item["successor"].__setitem__(
            "incarnation_sha256", item["terminal_receipt"]["incarnation_sha256"]
        ),
        lambda item: item["cleanup"].__setitem__("owned_resources", "pending"),
        lambda item: item.__setitem__("extra", True),
    ]
    for mutate in mutations:
        candidate = copy.deepcopy(facts(mode))
        mutate(candidate)
        assert validator(candidate, mode), mutate


@pytest.mark.parametrize(
    ("mode", "validator"), [("read", read_fact_errors), ("shared", shared_fact_errors)]
)
def test_mode_identity_and_scope_must_match_exactly(
    mode: str, validator: Callable[[object, object], list[str]]
) -> None:
    assert validator(facts(mode), "write")
    observed = copy.deepcopy(facts(mode))
    cast(dict[str, object], observed["successor"])["access_mode"] = "write"
    assert validator(observed, mode)
    assert handover_scope_errors(
        controller_source_digest="sha256:" + "e" * 64,
        execution_binding=binding("write"),
        prerequisites=source_prerequisites(mode),
        requested_access_mode=mode,
        observed_access_mode=mode,
    )


@pytest.mark.parametrize(
    ("mode", "runner", "test_id"),
    [
        ("read", ProviderTerminalHandoverReadRunner, "fuse_mount.provider_terminal_handover_read"),
        (
            "shared",
            ProviderTerminalHandoverSharedRunner,
            "fuse_mount.provider_terminal_handover_shared",
        ),
    ],
)
def test_runner_refuses_wrong_mode_before_callback_or_cleanup(
    mode: str, runner: type[Runner], test_id: str
) -> None:
    controller = MockHandoverController(mode)
    selected = scenario(test_id)
    step = dict(selected.steps[0])
    step["in"] = {
        "create": {},
        "prerequisites": source_prerequisites(mode),
        "access_mode": "shared" if mode == "read" else "read",
    }
    selected = replace(selected, steps=(step,))
    values = {
        "fuse_mount_create": {"requirements": {}},
        "fuse_mount_prerequisites": source_prerequisites(mode),
        "fuse_mount_handover_controller": controller,
        "fuse_mount_handover_controller_digest": controller_digest((Path(__file__).resolve(),)),
    }
    result = runner(EmptyDriver(), values).run_test(selected)
    assert result["result"] == "not_run"
    assert controller.observe_calls == 0
    assert controller.cleanup_calls == 0


@pytest.mark.parametrize(
    "mutation",
    [
        lambda values: values.remove("fuse_mount_account"),
        lambda values: values.__setitem__(values.index("access_mode:read"), "access_mode:shared"),
        lambda values: values.append("fuse_mount_egress:sha256:bad"),
        lambda values: values.append("unexpected:scope"),
        lambda values: values.append("region:us--east-1"),
    ],
)
def test_invalid_prerequisites_refuse_before_callback_or_cleanup(
    mutation: Callable[[list[str]], None],
) -> None:
    controller = MockHandoverController("read")
    prerequisites = source_prerequisites("read")
    mutation(prerequisites)
    values = {
        "fuse_mount_handover_controller": controller,
        "fuse_mount_handover_controller_digest": controller_digest((Path(__file__).resolve(),)),
    }
    selected = scenario("fuse_mount.provider_terminal_handover_read")
    step = dict(selected.steps[0])
    step["in"] = {"create": {}, "prerequisites": prerequisites, "access_mode": "read"}
    result = ProviderTerminalHandoverReadRunner(EmptyDriver(), values).run_test(
        replace(selected, steps=(step,))
    )
    assert result["result"] == "not_run"
    assert controller.observe_calls == 0
    assert controller.cleanup_calls == 0


def test_source_digest_mismatch_refuses_before_callback_or_cleanup() -> None:
    controller = MockHandoverController("shared")
    values = {
        "fuse_mount_handover_controller": controller,
        "fuse_mount_handover_controller_digest": "sha256:" + "0" * 64,
    }
    result = ProviderTerminalHandoverSharedRunner(EmptyDriver(), values).run_test(
        scenario("fuse_mount.provider_terminal_handover_shared")
    )
    assert result["result"] == "not_run"
    assert controller.observe_calls == 0
    assert controller.cleanup_calls == 0


def test_sps123_source_and_check_digest_are_unchanged() -> None:
    source = (
        Path(__file__).resolve().parents[1] / "src/sandbox_provider_spec/fuse_mount_handover.py"
    )
    # The two SPDX header lines the public guardrails require are not part of the frozen body.
    body = source.read_bytes().removeprefix(
        b"# SPDX-FileCopyrightText: BoxRouter, Inc.\n# SPDX-License-Identifier: Apache-2.0\n"
    )
    assert hashlib.sha256(body).hexdigest() == (
        "6744080b44d0d8757fec62ecc30af6e12914823f8a986a9bce14eb5f548fe368"
    )
    tests = {test.id: test for test in read_suite(suite_path().with_name("coverage.yaml")).tests}
    assert check_digests((tests["fuse_mount.provider_terminal_handover"],)) == {
        "fuse_mount.provider_terminal_handover": (
            "sha256:bad431fde9cac10cfd9cdff1ddee2f72d990d720eb73a8b953ac03467de93df5"
        )
    }


def test_mode_rows_have_locked_id_rule_operation_and_distinct_new_check_digests() -> None:
    suite = read_suite(suite_path().with_name("coverage.yaml"))
    tests = {test.id: test for test in suite.tests}
    expected = {
        "fuse_mount.provider_terminal_handover_read": (
            "fuse_mount/provider-terminal-handover-read",
            READ_OPERATION,
            "read",
        ),
        "fuse_mount.provider_terminal_handover_shared": (
            "fuse_mount/provider-terminal-handover-shared",
            SHARED_OPERATION,
            "shared",
        ),
    }
    digests = check_digests(tuple(tests[test_id] for test_id in expected))
    assert len(set(digests.values())) == 2
    for test_id, (rule, operation, mode) in expected.items():
        test = tests[test_id]
        assert test.rules == (rule,)
        assert test.steps[0]["op"] == operation
        assert test.steps[0]["in"]["access_mode"] == mode


def test_ordinary_runner_cannot_emit_either_mode_handover() -> None:
    for test_id in (
        "fuse_mount.provider_terminal_handover_read",
        "fuse_mount.provider_terminal_handover_shared",
    ):
        assert Runner(EmptyDriver()).run_test(scenario(test_id))["result"] != "passed"
