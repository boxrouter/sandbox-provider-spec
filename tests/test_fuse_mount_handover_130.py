# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""SPS 0.3.130 handover identity controls, isolated from frozen historical checks."""

from __future__ import annotations

from typing import Any

import pytest

from sandbox_provider_spec.check_digests import check_digests
from sandbox_provider_spec.fuse_mount_handover_130 import handover_fact_errors
from sandbox_provider_spec.fuse_mount_handover_read_130 import handover_fact_errors as read_errors
from sandbox_provider_spec.fuse_mount_handover_shared_130 import (
    handover_fact_errors as shared_errors,
)
from sandbox_provider_spec.fuse_mount_public_core_binding import (
    public_core_binding_digest,
    public_core_binding_identity_matches,
    public_core_binding_identity_valid,
)
from sandbox_provider_spec.suite import read_suite, suite_path

_TIME = "2026-10-26T16:00:00Z"


def _binding(native_id: str, **updates: object) -> dict[str, object]:
    return {
        "native_id": native_id,
        "incarnation": None,
        "created_at_ms": None,
        "session_id": None,
        **updates,
    }


def _identity(native_id: str) -> dict[str, object]:
    digest, basis = public_core_binding_digest(_binding(native_id))
    return {"public_core_binding_sha256": digest, "binding_basis": basis}


def _facts(mode: str = "write") -> dict[str, Any]:
    facts: dict[str, Any] = {
        "terminal_receipt": {
            "sandbox_id_sha256": "sha256:" + "1" * 64,
            **_identity("terminal"),
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
        "no_force": True,
        "successor": {
            "sandbox_id_sha256": "sha256:" + "7" * 64,
            **_identity("successor"),
            "access_mode": mode,
            "force": False,
            "mounted": True,
        },
        "cleanup": {"owned_resources": "deleted"},
    }
    if mode == "read":
        facts["connected_reader"] = {
            "connected": True,
            "outcome": "busy",
            "revoke_attempted": False,
            "successor_dispatched": False,
            "read_after_refusal": True,
        }
        facts["file_evidence"] = {
            "write_attempted": True,
            "write_denied": True,
            "denial_errno": "EROFS",
            "expected_readback_sha256": "sha256:" + "a" * 64,
            "readback_sha256": "sha256:" + "a" * 64,
        }
    elif mode == "shared":
        facts["connected_writer"] = {
            "connected": True,
            "outcome": "busy",
            "revoke_attempted": False,
            "successor_dispatched": False,
            "write_after_refusal": True,
        }
        facts["file_evidence"] = {
            "default_user_write": True,
            "fsync_acknowledged": True,
            "sync_acknowledged": True,
            "checkpoint_sha256": "sha256:" + "a" * 64,
            "expected_readback_sha256": "sha256:" + "b" * 64,
            "readback_sha256": "sha256:" + "b" * 64,
        }
    else:
        facts["connected_writer"] = {
            "connected": True,
            "outcome": "busy",
            "revoke_attempted": False,
            "successor_dispatched": False,
            "write_after_refusal": True,
        }
        facts["file_evidence"] = {
            "default_user_write": True,
            "save_acknowledged": True,
            "checkpoint_sha256": "sha256:" + "a" * 64,
            "expected_readback_sha256": "sha256:" + "b" * 64,
            "readback_sha256": "sha256:" + "b" * 64,
        }
    return facts


def test_public_binding_digest_is_exact_and_preserves_actual_basis() -> None:
    id_only = _binding("native-1")
    digest, basis = public_core_binding_digest(id_only)
    assert basis == ["native_id"]
    assert public_core_binding_identity_matches(id_only, digest, basis)
    assert not public_core_binding_identity_matches(id_only, digest, ["native_id", "incarnation"])
    assert not public_core_binding_identity_matches(id_only, "sha256:" + "0" * 64, basis)

    for field, actual in (
        ("incarnation", "inc-1"),
        ("created_at_ms", 123),
        ("session_id", "session-1"),
    ):
        changed = {**id_only, field: actual}
        changed_digest, changed_basis = public_core_binding_digest(changed)
        assert field in changed_basis
        assert changed_digest != digest
        assert public_core_binding_identity_matches(changed, changed_digest, changed_basis)
        assert not public_core_binding_identity_matches(changed, digest, changed_basis)


@pytest.mark.parametrize(
    "binding",
    [
        {"native_id": "native-1", "incarnation": None, "created_at_ms": None},
        {**_binding("native-1"), "unknown": "value"},
        _binding("native-1", created_at_ms=True),
        _binding("native-1", created_at_ms=1.5),
        _binding("native-1", incarnation=3),
        _binding("native-1", session_id=""),
    ],
)
def test_public_binding_digest_rejects_unknown_or_malformed_fields(
    binding: dict[str, object],
) -> None:
    with pytest.raises(ValueError):
        public_core_binding_digest(binding)


@pytest.mark.parametrize(
    "basis",
    [
        [],
        ["incarnation"],
        ["native_id", "unknown"],
        ["native_id", "native_id"],
        ["native_id", 1],
        ("native_id",),
    ],
)
def test_public_binding_report_rejects_invalid_basis(basis: object) -> None:
    assert not public_core_binding_identity_valid("sha256:" + "a" * 64, basis)


@pytest.mark.parametrize(
    ("mode", "validator"),
    [("write", handover_fact_errors), ("read", read_errors), ("shared", shared_errors)],
)
def test_sps130_handover_accepts_captured_id_only_core_binding(mode: str, validator: Any) -> None:
    if mode == "write":
        assert validator(_facts(mode), access_mode=mode) == []
    else:
        assert validator(_facts(mode), mode) == []


def test_sps130_handover_rejects_unknown_or_mismatched_binding_basis() -> None:
    facts = _facts()
    facts["terminal_receipt"]["binding_basis"] = ["native_id", "unknown"]
    assert handover_fact_errors(facts, access_mode="write")


def test_sps130_rows_and_digests_are_distinct_from_frozen_rows() -> None:
    tests = {test.id: test for test in read_suite(suite_path().with_name("coverage.yaml")).tests}
    legacy = tests["fuse_mount.provider_terminal_handover"]
    current = tests["fuse_mount.provider_terminal_handover_130"]
    assert legacy.steps[0]["op"] == "fixture.fuse_mount_provider_terminal_handover"
    assert current.steps[0]["op"] == "fixture.fuse_mount_provider_terminal_handover_130"
    assert current.rules == ("fuse_mount/provider-terminal-handover-130",)
    digests = check_digests((legacy, current))
    assert digests[legacy.id] != digests[current.id]
