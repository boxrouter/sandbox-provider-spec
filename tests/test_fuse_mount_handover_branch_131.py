# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Offline SPS 0.3.131 branch-fork fixture and check membership tests."""

from __future__ import annotations

from typing import Any

from sandbox_provider_spec.check_digests import check_digests
from sandbox_provider_spec.fuse_mount_handover_branch_131 import (
    ACCESS_MODE,
    OPERATION,
    ProviderTerminalBranchForkRunner,
    handover_fact_errors,
)
from sandbox_provider_spec.suite import read_suite, suite_path


def _facts() -> dict[str, Any]:
    def digest(char: str) -> str:
        return "sha256:" + char * 64

    return {
        "terminal_receipt": {
            "sandbox_id_sha256": digest("1"),
            "public_core_binding_sha256": digest("2"),
            "binding_basis": ["native_id"],
            "provider_state": "terminated",
            "observed_at": "2026-10-26T16:00:00Z",
        },
        "issuance": {
            "claim_sha256": digest("3"),
            "credential_sha256": digest("4"),
            "resolution": "current",
        },
        "delegations": [
            {
                "delegation_sha256": digest("5"),
                "client_sha256": digest("6"),
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
            "sandbox_id_sha256": digest("7"),
            "public_core_binding_sha256": digest("8"),
            "binding_basis": ["native_id"],
            "access_mode": "branch",
            "force": False,
            "mounted": True,
        },
        "branch_evidence": {
            "source_checkpoint_sha256": digest("9"),
            "branch_identity_sha256": digest("a"),
            "successor_branch_identity_sha256": digest("b"),
            "default_user_write": True,
            "fsync_acknowledged": True,
            "sync_acknowledged": True,
            "expected_branch_sha256": digest("c"),
            "branch_readback_sha256": digest("c"),
            "expected_source_sha256": digest("d"),
            "successor_source_readback_sha256": digest("d"),
            "parent_readback_sha256": digest("d"),
            "private_marker_absent_from_successor": True,
            "private_marker_absent_from_parent": True,
            "source_head_unchanged": True,
        },
        "cleanup": {"owned_resources": "deleted"},
    }


def test_branch_fork_accepts_closed_fresh_fork_evidence() -> None:
    assert ACCESS_MODE == "branch"
    assert handover_fact_errors(_facts()) == []


def test_branch_fork_requires_strict_true_and_exact_evidence_fields() -> None:
    for field in (
        "default_user_write",
        "fsync_acknowledged",
        "sync_acknowledged",
        "private_marker_absent_from_successor",
        "private_marker_absent_from_parent",
        "source_head_unchanged",
    ):
        facts = _facts()
        facts["branch_evidence"][field] = 1
        assert handover_fact_errors(facts)

    unknown = _facts()
    unknown["branch_evidence"]["save_acknowledged"] = True
    assert handover_fact_errors(unknown)


def test_branch_fork_rejects_wrong_checkpoint_identity_and_reused_branch() -> None:
    facts = _facts()
    facts["branch_evidence"]["source_checkpoint_sha256"] = "not-a-digest"
    assert handover_fact_errors(facts)

    facts = _facts()
    facts["branch_evidence"]["successor_branch_identity_sha256"] = facts["branch_evidence"][
        "branch_identity_sha256"
    ]
    assert handover_fact_errors(facts)


def test_branch_fork_rejects_mismatched_readbacks_and_non_branch_mode() -> None:
    facts = _facts()
    facts["branch_evidence"]["parent_readback_sha256"] = "sha256:" + "e" * 64
    assert handover_fact_errors(facts)
    assert handover_fact_errors(_facts(), access_mode="shared")


def test_branch_fork_has_a_distinct_coverage_row_and_check_digest() -> None:
    tests = {test.id: test for test in read_suite(suite_path().with_name("coverage.yaml")).tests}
    selected = tests["fuse_mount.provider_terminal_branch_fork"]
    assert selected.steps[0]["op"] == OPERATION
    assert selected.steps[0]["in"]["access_mode"] == "branch"
    assert selected.rules == ("fuse_mount/provider-terminal-branch-fork",)
    assert ProviderTerminalBranchForkRunner.operation == OPERATION
    assert ProviderTerminalBranchForkRunner.access_mode == "branch"
    assert check_digests((selected,))[selected.id]
