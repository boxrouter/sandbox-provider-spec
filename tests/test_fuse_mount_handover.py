# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Mode and identity bounds for the separate provider-terminal handover proof."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

from sandbox_provider_spec.driver import Driver, Inputs, Observation
from sandbox_provider_spec.evidence import _source_suite_rules
from sandbox_provider_spec.fuse_mount import controller_digest
from sandbox_provider_spec.fuse_mount_handover import (
    ProviderTerminalHandoverRunner,
    handover_fact_errors,
    handover_scope_errors,
)
from sandbox_provider_spec.runner import Runner
from sandbox_provider_spec.suite import Test as Scenario
from sandbox_provider_spec.suite import read_suite, suite_path

_CONTROLLER = "sha256:" + "c" * 64
_IMAGE = "sha256:" + "a" * 64
_EGRESS = "sha256:" + "b" * 64
_NATIVE_PLAN = "sha256:" + "d" * 64
_TIME = "2026-10-26T16:00:00Z"


def observed_binding(mode: str) -> dict[str, str]:
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


def observed_prerequisites(mode: str) -> list[str]:
    return [
        "image:" + _IMAGE,
        "fuse_mount_account",
        "fuse_mount_egress:" + _EGRESS,
        "controller:" + _CONTROLLER,
        "access_mode:" + mode,
        "region:us-east-1",
    ]


def runner_prerequisites(mode: str) -> list[str]:
    return [value for value in observed_prerequisites(mode) if not value.startswith("controller:")]


def scope_errors(
    *,
    binding: object,
    prerequisites: object,
    requested: object = "write",
    observed: object = "write",
    controller: object = _CONTROLLER,
) -> list[str]:
    return handover_scope_errors(
        controller_source_digest=controller,
        execution_binding=binding,
        prerequisites=prerequisites,
        requested_access_mode=requested,
        observed_access_mode=observed,
    )


def handover_facts(mode: str = "write") -> dict[str, object]:
    return {
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
            }
        ],
        "delegations_cleared": True,
        "connected_writer": {
            "connected": True,
            "outcome": "busy",
            "revoke_attempted": False,
            "successor_dispatched": False,
            "write_after_refusal": True,
        },
        "no_force": True,
        "successor": {
            "sandbox_id_sha256": "sha256:" + "7" * 64,
            "incarnation_sha256": "sha256:" + "8" * 64,
            "access_mode": mode,
            "force": False,
            "mounted": True,
        },
        "file_evidence": {
            "default_user_write": True,
            "save_acknowledged": True,
            "checkpoint_sha256": "sha256:" + "9" * 64,
            "expected_readback_sha256": "sha256:" + "a" * 64,
            "readback_sha256": "sha256:" + "a" * 64,
        },
        "cleanup": {"owned_resources": "deleted"},
    }


@pytest.mark.parametrize("mode", ["write", "read", "shared", "branch"])
def test_observed_scope_binds_only_the_mode_actually_exercised(mode: str) -> None:
    binding = observed_binding(mode)
    assert (
        scope_errors(
            binding=binding,
            prerequisites=observed_prerequisites(mode),
            requested=mode,
            observed=mode,
        )
        == []
    )


@pytest.mark.parametrize("mode", ["write", "read", "shared", "branch"])
def test_default_scope_binds_only_the_mode_actually_exercised(mode: str) -> None:
    binding = {
        **observed_binding(mode),
        "region": "unknown",
        "route": "e" * 64,
        "placement_mode": "default",
        "native_plan_digest": _NATIVE_PLAN,
    }
    prerequisites = [
        "image:" + _IMAGE,
        "fuse_mount_account",
        "fuse_mount_egress:" + _EGRESS,
        "controller:" + _CONTROLLER,
        "access_mode:" + mode,
        "placement:default",
        "native_plan:" + _NATIVE_PLAN,
    ]
    assert (
        scope_errors(
            binding=binding,
            prerequisites=prerequisites,
            requested=mode,
            observed=mode,
        )
        == []
    )


@pytest.mark.parametrize(
    ("requested", "observed", "binding_mode", "token"),
    [
        ("write", "read", "write", "write"),
        ("write", "write", "read", "write"),
        ("write", "write", "write", "read"),
        ("future", "future", "future", "future"),
        (True, True, "write", "write"),
    ],
)
def test_mode_mismatch_or_unknown_value_refuses(
    requested: object, observed: object, binding_mode: str, token: str
) -> None:
    binding = observed_binding(binding_mode)
    prerequisites = observed_prerequisites(token)
    assert scope_errors(
        binding=binding,
        prerequisites=prerequisites,
        requested=requested,
        observed=observed,
    )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda values: values.remove("fuse_mount_account"),
        lambda values: values.append("region:us-west-2"),
        lambda values: values.append("access_mode:shared"),
        lambda values: values.append("controller:sha256:" + "0" * 64),
        lambda values: values.__setitem__(
            values.index("fuse_mount_egress:" + _EGRESS), "fuse_mount_egress:unknown"
        ),
    ],
)
def test_observed_scope_requires_exact_unique_prerequisites(
    mutation: Callable[[list[str]], None],
) -> None:
    prerequisites = observed_prerequisites("write")
    mutation(prerequisites)
    assert scope_errors(binding=observed_binding("write"), prerequisites=prerequisites)


def test_default_and_observed_prerequisite_families_cannot_mix() -> None:
    binding = {
        **observed_binding("write"),
        "region": "unknown",
        "route": "e" * 64,
        "placement_mode": "default",
        "native_plan_digest": _NATIVE_PLAN,
    }
    prerequisites = observed_prerequisites("write") + [
        "placement:default",
        "native_plan:" + _NATIVE_PLAN,
    ]
    assert scope_errors(binding=binding, prerequisites=prerequisites)


@pytest.mark.parametrize(
    ("controller", "binding_digest"),
    [("sha256:" + "0" * 64, _CONTROLLER), ("bad", _CONTROLLER)],
)
def test_controller_source_digest_must_match_exact_token(
    controller: str, binding_digest: str
) -> None:
    prerequisites = observed_prerequisites("write")
    prerequisites[3] = "controller:" + binding_digest
    assert scope_errors(
        binding=observed_binding("write"),
        prerequisites=prerequisites,
        controller=controller,
    )


@pytest.mark.parametrize("mode", ["write", "branch"])
def test_typed_handover_facts_accept_only_the_locked_positive_modes(mode: str) -> None:
    assert handover_fact_errors(handover_facts(mode), access_mode=mode) == []


def test_handover_successor_mode_must_match_requested_mode() -> None:
    assert handover_fact_errors(handover_facts("branch"), access_mode="write")


@pytest.mark.parametrize("mode", ["read", "shared", "future", True])
def test_unimplemented_or_malformed_fact_modes_do_not_pass(mode: object) -> None:
    assert handover_fact_errors(handover_facts(), access_mode=mode)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("terminal_receipt", "provider_state"), "requested"),
        (("terminal_receipt", "incarnation_sha256"), "not-a-digest"),
        (("terminal_receipt", "observed_at"), "unknown"),
        (("issuance", "resolution"), "latest"),
        (("delegations", 0, "is_orphaned"), 1),
        (("delegations", 0, "is_orphaned"), "true"),
        (("delegations", 0, "revoke", "attempted"), 1),
        (("delegations", 0, "revoke", "outcome"), "not_attempted"),
        (("connected_writer", "connected"), 1),
        (("connected_writer", "outcome"), "clear"),
        (("connected_writer", "revoke_attempted"), True),
        (("connected_writer", "successor_dispatched"), True),
        (("connected_writer", "successor_dispatched"), 0),
        (("connected_writer", "write_after_refusal"), False),
        (("no_force",), 1),
        (("successor", "force"), True),
        (("successor", "mounted"), False),
        (("successor", "access_mode"), "read"),
        (("file_evidence", "default_user_write"), 1),
        (("file_evidence", "save_acknowledged"), False),
        (("file_evidence", "readback_sha256"), "sha256:" + "f" * 64),
        (("cleanup", "owned_resources"), "unknown"),
    ],
)
def test_malformed_or_unsafe_fact_values_are_rejected(
    path: tuple[str | int, ...], value: object
) -> None:
    facts = handover_facts()
    target: object = facts
    for component in path[:-1]:
        target = target[component]  # type: ignore[index]
    target[path[-1]] = value  # type: ignore[index]
    assert handover_fact_errors(facts, access_mode="write")


@pytest.mark.parametrize(
    "delegations",
    [
        [],
        [
            {
                "delegation_sha256": "sha256:" + "5" * 64,
                "client_sha256": "sha256:" + "6" * 64,
                "is_orphaned": True,
                "revoke": {"attempted": True, "outcome": "revoked"},
            },
            {
                "delegation_sha256": "sha256:" + "c" * 64,
                "client_sha256": "sha256:" + "d" * 64,
                "is_orphaned": True,
                "revoke": {"attempted": True, "outcome": "revoked"},
            },
        ],
        [
            {
                "delegation_sha256": "sha256:" + "5" * 64,
                "client_sha256": "sha256:" + "6" * 64,
                "is_orphaned": False,
                "revoke": {"attempted": False, "outcome": "not_attempted"},
            }
        ],
    ],
)
def test_empty_multiple_and_nonorphan_delegations_are_reported_safely(
    delegations: list[dict[str, object]],
) -> None:
    facts = handover_facts()
    facts["delegations"] = delegations
    assert handover_fact_errors(facts, access_mode="write") == []


def test_fact_groups_are_closed_and_cleanup_is_required() -> None:
    facts = handover_facts()
    del facts["cleanup"]
    assert handover_fact_errors(facts, access_mode="write")
    facts = handover_facts()
    facts["verified"] = True
    assert handover_fact_errors(facts, access_mode="write")


def test_nonorphan_delegation_must_never_be_revoked() -> None:
    facts = handover_facts()
    delegation = cast(list[dict[str, object]], facts["delegations"])[0]
    delegation["is_orphaned"] = False
    assert handover_fact_errors(facts, access_mode="write")


class FakeHandoverController:
    def __init__(self, source: Path, mode: str = "write") -> None:
        self.source_files = (Path(__file__), source)
        self.execution_binding = observed_binding(mode)
        self.facts = handover_facts(mode)
        self.observe_calls = 0
        self.cleanup_calls = 0

    def observe_provider_terminal_handover(
        self, driver: Driver, create: dict[str, object], *, access_mode: str
    ) -> dict[str, object]:
        del driver, create
        self.observe_calls += 1
        self.execution_binding["access_mode"] = access_mode
        return self.facts

    def cleanup(self) -> Observation:
        self.cleanup_calls += 1
        return {"result": "deleted"}


class EmptyDriver(Driver):
    def call(self, operation: str, target: object, inputs: Inputs) -> Observation:
        del operation, target, inputs
        raise AssertionError("the host handover controller owns the callback")


def handover_scenario() -> Scenario:
    return next(
        test
        for test in read_suite(suite_path().with_name("coverage.yaml")).tests
        if test.id == "fuse_mount.provider_terminal_handover"
    )


def test_handover_and_legacy_rules_keep_their_roles() -> None:
    suite = read_suite(suite_path().with_name("coverage.yaml"))
    tests = {test.id: test for test in suite.tests}
    assert tests["fuse_mount.provider_terminal_handover"].rules == (
        "fuse_mount/provider-terminal-handover",
    )
    assert tests["fuse_mount.provider_terminal_handover"].proves == (
        {"gate": "fuse_mount", "value": True},
    )
    assert tests["fuse_mount.lifecycle"].rules == ("fuse_mount/lifecycle",)
    assert tests["fuse_mount.default_placement"].rules == (
        "fuse_mount/lifecycle",
        "fuse_mount/default-placement",
    )
    assert tests["fuse_mount.default_placement"].proves == ()


def test_exact_prechange_suite_rules_remain_historical() -> None:
    rules, errors = _source_suite_rules(
        "sha256:c7c3162c196dfa17f12772d26d61d6707489e0b43f15abaa61605e781e4081ff"
    )
    assert errors == []
    assert rules is not None
    assert rules["fuse_mount.lifecycle"] == ["fuse_mount/lifecycle"]
    assert rules["fuse_mount.default_placement"] == [
        "fuse_mount/lifecycle",
        "fuse_mount/default-placement",
    ]
    assert "fuse_mount.provider_terminal_handover" not in rules


@pytest.mark.parametrize("mode", ["write", "branch"])
def test_opt_in_runner_emits_only_the_structured_typed_envelope(tmp_path: Path, mode: str) -> None:
    source = tmp_path / "controller.py"
    source.write_text("# test controller source\n")
    controller = FakeHandoverController(source, mode)
    prerequisites = runner_prerequisites(mode)
    test_driver = EmptyDriver()
    result = ProviderTerminalHandoverRunner(
        test_driver,
        {
            "fuse_mount_create": {"requirements": {}},
            "fuse_mount_prerequisites": prerequisites,
            "fuse_mount_access_mode": mode,
            "fuse_mount_handover_controller": controller,
            "fuse_mount_handover_controller_digest": controller_digest((Path(__file__), source)),
        },
    ).run_test(handover_scenario())
    assert result["result"] == "passed"
    assert controller.observe_calls == 1
    assert controller.cleanup_calls == 1
    steps = result["steps"]
    assert isinstance(steps, list)
    step = steps[0]
    assert isinstance(step, dict)
    observations = step["observations"]
    assert isinstance(observations, dict)
    observation = observations["fuse_mount_handover"]
    assert isinstance(observation, dict)
    assert set(observation) == {
        "controller_source_digest",
        "prerequisites",
        "execution_binding",
        "requested_access_mode",
        "observed_access_mode",
        "terminal_receipt",
        "issuance",
        "delegations",
        "delegations_cleared",
        "connected_writer",
        "no_force",
        "successor",
        "file_evidence",
        "cleanup",
    }
    assert observation["requested_access_mode"] == mode
    assert observation["observed_access_mode"] == mode
    assert observation["execution_binding"]["access_mode"] == mode
    assert "verified" not in observation
    digest = controller_digest((Path(__file__), source))
    assert observation["controller_source_digest"] == digest
    assert "controller:" + digest in observation["prerequisites"]
    assert "access_mode:" + mode in observation["prerequisites"]


def test_ordinary_runner_cannot_attest_the_opt_in_handover_fixture() -> None:
    result = Runner(EmptyDriver()).run_test(handover_scenario())
    assert result["result"] != "passed"


@pytest.mark.parametrize("mode", ["read", "shared", "unknown"])
def test_unimplemented_modes_refuse_before_callback_or_cleanup_allocation(
    tmp_path: Path, mode: str
) -> None:
    source = tmp_path / "controller.py"
    source.write_text("# test controller source\n")
    controller = FakeHandoverController(source)
    result = ProviderTerminalHandoverRunner(
        EmptyDriver(),
        {
            "fuse_mount_create": {"requirements": {}},
            "fuse_mount_prerequisites": runner_prerequisites("write"),
            "fuse_mount_access_mode": mode,
            "fuse_mount_handover_controller": controller,
            "fuse_mount_handover_controller_digest": controller_digest((Path(__file__), source)),
        },
    ).run_test(handover_scenario())
    assert result["result"] == "not_run"
    assert controller.observe_calls == 0
    assert controller.cleanup_calls == 0


def test_wrong_controller_digest_refuses_before_callback_or_cleanup(tmp_path: Path) -> None:
    source = tmp_path / "controller.py"
    source.write_text("# test controller source\n")
    controller = FakeHandoverController(source)
    result = ProviderTerminalHandoverRunner(
        EmptyDriver(),
        {
            "fuse_mount_create": {"requirements": {}},
            "fuse_mount_prerequisites": runner_prerequisites("write"),
            "fuse_mount_access_mode": "write",
            "fuse_mount_handover_controller": controller,
            "fuse_mount_handover_controller_digest": "sha256:" + "0" * 64,
        },
    ).run_test(handover_scenario())
    assert result["result"] == "not_run"
    assert controller.observe_calls == 0
    assert controller.cleanup_calls == 0


@pytest.mark.parametrize(
    "mutation",
    [
        lambda values: values.remove("access_mode:write"),
        lambda values: values.append("access_mode:branch"),
        lambda values: values.append("region:us-west-2"),
        lambda values: values.append("unexpected:scope"),
        lambda values: values.append("controller:" + _CONTROLLER),
    ],
)
def test_invalid_input_scope_refuses_before_callback_or_cleanup(
    tmp_path: Path, mutation: Callable[[list[str]], None]
) -> None:
    source = tmp_path / "controller.py"
    source.write_text("# test controller source\n")
    controller = FakeHandoverController(source)
    prerequisites = runner_prerequisites("write")
    mutation(prerequisites)
    result = ProviderTerminalHandoverRunner(
        EmptyDriver(),
        {
            "fuse_mount_create": {"requirements": {}},
            "fuse_mount_prerequisites": prerequisites,
            "fuse_mount_access_mode": "write",
            "fuse_mount_handover_controller": controller,
            "fuse_mount_handover_controller_digest": controller_digest((Path(__file__), source)),
        },
    ).run_test(handover_scenario())
    assert result["result"] == "not_run"
    assert controller.observe_calls == 0
    assert controller.cleanup_calls == 0


def test_malformed_controller_facts_cannot_emit_a_positive_observation(
    tmp_path: Path,
) -> None:
    source = tmp_path / "controller.py"
    source.write_text("# test controller source\n")
    controller = FakeHandoverController(source)
    controller.facts["no_force"] = False
    result = ProviderTerminalHandoverRunner(
        EmptyDriver(),
        {
            "fuse_mount_create": {"requirements": {}},
            "fuse_mount_prerequisites": runner_prerequisites("write"),
            "fuse_mount_access_mode": "write",
            "fuse_mount_handover_controller": controller,
            "fuse_mount_handover_controller_digest": controller_digest((Path(__file__), source)),
        },
    ).run_test(handover_scenario())
    assert result["result"] == "differs", result
    assert controller.observe_calls == 1
    assert controller.cleanup_calls == 1
    steps = result["steps"]
    assert isinstance(steps, list)
    step = steps[0]
    assert isinstance(step, dict)
    assert "observations" not in step
