# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Strict ENV/prepared-handle handover profile controls."""

from __future__ import annotations

from test_fuse_mount_handover_130 import _facts

from sandbox_provider_spec.fuse_mount_handover_env_132 import (
    HANDOVER_IDENTITIES_132,
    environment_account_digest,
    environment_route_scope_digest,
    handover_scope_errors_132,
    handover_write_fact_errors_132,
)
from sandbox_provider_spec.suite import read_suite, suite_path


def binding() -> dict[str, str]:
    fingerprint = "a" * 24
    provider = "e2b"
    account = environment_account_digest(provider, fingerprint)
    return {
        "account": account,
        "account_fingerprint": fingerprint,
        "source_account": "9" * 64,
        "copy": "b" * 64,
        "route": environment_route_scope_digest(provider, account),
        "source_route": "c" * 64,
        "provider": provider,
        "class": "vm",
        "credential_kind": "environment",
        "image_kind": "prepared_handle",
        "prepared_image_key": "d" * 64,
        "region": "unknown",
        "access_mode": "write",
        "placement_mode": "default",
        "native_plan_digest": "sha256:" + "e" * 64,
    }


def prerequisites(value: dict[str, str]) -> list[str]:
    return [
        "prepared_image:sha256:" + value["prepared_image_key"],
        "fuse_mount_account",
        "access_mode:" + value["access_mode"],
        "controller:sha256:" + "f" * 64,
        "fuse_mount_egress:sha256:" + "1" * 64,
        "placement:default",
        "native_plan:" + value["native_plan_digest"],
    ]


def errors(value: object, binding_value: object | None = None) -> list[str]:
    return handover_scope_errors_132(
        controller_source_digest="sha256:" + "f" * 64,
        execution_binding=binding() if binding_value is None else binding_value,
        prerequisites=prerequisites(binding()) if value is None else value,
        requested_access_mode="write",
        observed_access_mode="write",
    )


def test_current_env_handle_binding_accepts_absent_credential_version() -> None:
    current = binding()
    assert (
        handover_scope_errors_132(
            controller_source_digest="sha256:" + "f" * 64,
            execution_binding=current,
            prerequisites=prerequisites(current),
            requested_access_mode="write",
            observed_access_mode="write",
        )
        == []
    )


def test_environment_route_scope_is_portable_only_for_same_provider_account() -> None:
    current = binding()
    second_workspace = binding()
    second_workspace["source_route"] = "2" * 64
    second_workspace["source_account"] = "3" * 64
    assert (
        handover_scope_errors_132(
            controller_source_digest="sha256:" + "f" * 64,
            execution_binding=second_workspace,
            prerequisites=prerequisites(current),
            requested_access_mode="write",
            observed_access_mode="write",
        )
        == []
    )
    for field, changed in (("provider", "modal"), ("account_fingerprint", "b" * 24)):
        changed_identity = binding()
        changed_identity[field] = changed
        assert handover_scope_errors_132(
            controller_source_digest="sha256:" + "f" * 64,
            execution_binding=changed_identity,
            prerequisites=prerequisites(changed_identity),
            requested_access_mode="write",
            observed_access_mode="write",
        ) == ["environment handover binding values are invalid"]


def test_environment_binding_rejects_any_credential_version_or_fingerprint() -> None:
    for field in ("credential_version", "credential_fingerprint"):
        current = binding()
        current[field] = "1"
        assert errors(None, current) == [
            "environment handover binding fields are incomplete or unknown"
        ]


def test_prepared_handle_key_must_match_exact_prerequisite() -> None:
    current = binding()
    tokens = prerequisites(current)
    tokens[0] = "prepared_image:sha256:" + "2" * 64
    assert handover_scope_errors_132(
        controller_source_digest="sha256:" + "f" * 64,
        execution_binding=current,
        prerequisites=tokens,
        requested_access_mode="write",
        observed_access_mode="write",
    ) == ["environment handover prerequisites do not match the binding"]


def test_image_digest_kind_cannot_be_reinterpreted_as_prepared_handle() -> None:
    current = binding()
    current["image_kind"] = "standard_source"
    assert errors(None, current) == ["environment handover binding values are invalid"]


def test_unknown_binding_or_prerequisite_fields_are_refused() -> None:
    current = binding()
    current["future_identity"] = "x"
    assert errors(None, current) == [
        "environment handover binding fields are incomplete or unknown"
    ]
    current = binding()
    tokens = prerequisites(current) + ["future_scope"]
    assert handover_scope_errors_132(
        controller_source_digest="sha256:" + "f" * 64,
        execution_binding=current,
        prerequisites=tokens,
        requested_access_mode="write",
        observed_access_mode="write",
    ) == ["environment handover prerequisites do not match the binding"]


def test_default_profile_rejects_missing_plan_and_unknown_compute_region() -> None:
    current = binding()
    del current["native_plan_digest"]
    assert errors(None, current) == ["environment handover default plan identity is invalid"]
    current = binding()
    current["region"] = "us-east-1"
    assert errors(None, current) == ["environment handover default plan identity is invalid"]


def test_default_path_observation_is_optional_but_exactly_valued() -> None:
    current = binding()
    base = prerequisites(current)
    for value in ("free", "occupied"):
        assert errors(base + ["default_path:" + value]) == [], (
            "a captured default path observation must pass unchanged"
        )
    assert errors(base) == []
    assert errors(base + ["default_path:unknown"]) == [
        "environment handover default path observation is invalid"
    ]
    assert errors(base + ["default_path:free", "default_path:occupied"]) == [
        "environment handover default path observation is invalid"
    ]
    assert errors(base + ["default_path_free"]) == [
        "environment handover prerequisites do not match the binding"
    ]


def test_new_suite_identities_are_distinct_from_frozen_130_and_131() -> None:
    suite = read_suite(suite_path().with_name("coverage.yaml"))
    ids = {item.id for item in suite.tests}
    assert set(HANDOVER_IDENTITIES_132) <= ids
    assert not set(HANDOVER_IDENTITIES_132) & {
        "fuse_mount.provider_terminal_handover_130",
        "fuse_mount.provider_terminal_branch_fork",
    }


def _write_errors(delegation: dict[str, object]) -> list[str]:
    fact = _facts("write")
    fact["delegations"] = [delegation]
    return handover_write_fact_errors_132(fact, "write")


def _delegation(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "delegation_sha256": "sha256:" + "5" * 64,
        "client_sha256": "sha256:" + "6" * 64,
        "is_orphaned": False,
        "revoke_basis": "owner_client",
        "revoke": {"attempted": True, "outcome": "revoked"},
    }
    return value | changes


def test_write_accepts_orphan_and_owner_client_revokes_and_legacy_orphan() -> None:
    assert _write_errors(_delegation()) == []
    assert _write_errors(_delegation(is_orphaned=True, revoke_basis="orphaned")) == []
    legacy = _delegation(is_orphaned=True)
    del legacy["revoke_basis"]
    assert _write_errors(legacy) == []


def test_write_refuses_unbased_or_contradictory_non_orphan_revokes() -> None:
    legacy = _delegation()
    del legacy["revoke_basis"]
    assert _write_errors(legacy) == ["non-orphaned handover delegation was targeted"]
    assert _write_errors(_delegation(revoke_basis="orphaned")) != []
    assert _write_errors(_delegation(is_orphaned=True)) != []
    assert _write_errors(_delegation(revoke_basis="other")) != []
    assert _write_errors(_delegation(extra=1)) != []
    unrevoked = {"attempted": False, "outcome": "not_attempted"}
    assert _write_errors(_delegation(revoke=unrevoked)) != []
