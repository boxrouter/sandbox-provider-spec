# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Fresh private-fork branch evidence for the SPS 0.3.131 handover check."""

# pylint: disable=duplicate-code

from __future__ import annotations

from collections.abc import Mapping

from sandbox_provider_spec.fuse_mount_handover_mode_130 import (
    ModeHandoverRunner,
    _common_fact_errors,
    _digest,
)

OPERATION = "fixture.fuse_mount_provider_terminal_branch_fork"
ACCESS_MODE = "branch"


def handover_fact_errors(value: object, access_mode: object = ACCESS_MODE) -> list[str]:
    """Validate common provider-terminal facts and the closed fresh-fork evidence.

    ``source_checkpoint_sha256`` identifies the acknowledged checkpoint selected by both
    forks; ``source_head_unchanged`` is a separate post-release head comparison.
    """
    if access_mode != ACCESS_MODE:
        return ["branch-fork handover access mode is not supported by this fixture"]
    errors = _common_fact_errors(
        value,
        access_mode=ACCESS_MODE,
        mode_keys={"connected_writer", "branch_evidence"},
    )
    if errors:
        return errors
    assert isinstance(value, Mapping)
    writer = value["connected_writer"]
    if not isinstance(writer, Mapping) or set(writer) != {
        "connected",
        "outcome",
        "revoke_attempted",
        "successor_dispatched",
        "write_after_refusal",
    }:
        return ["connected-writer control fields are invalid"]
    if (
        writer["connected"] is not True
        or writer["outcome"] != "busy"
        or writer["revoke_attempted"] is not False
        or writer["successor_dispatched"] is not False
        or writer["write_after_refusal"] is not True
    ):
        return ["connected-writer Cloud refusal dispatched a successor or changed the writer"]

    evidence = value["branch_evidence"]
    expected_fields = {
        "source_checkpoint_sha256",
        "branch_identity_sha256",
        "successor_branch_identity_sha256",
        "default_user_write",
        "fsync_acknowledged",
        "sync_acknowledged",
        "expected_branch_sha256",
        "branch_readback_sha256",
        "expected_source_sha256",
        "successor_source_readback_sha256",
        "parent_readback_sha256",
        "private_marker_absent_from_successor",
        "private_marker_absent_from_parent",
        "source_head_unchanged",
    }
    if not isinstance(evidence, Mapping) or set(evidence) != expected_fields:
        return ["branch-fork evidence fields are incomplete or unknown"]
    boolean_fields = (
        "default_user_write",
        "fsync_acknowledged",
        "sync_acknowledged",
        "private_marker_absent_from_successor",
        "private_marker_absent_from_parent",
        "source_head_unchanged",
    )
    if any(evidence[field] is not True for field in boolean_fields):
        return ["branch-fork acknowledgments, absence or source-head evidence are invalid"]
    digest_fields = expected_fields - set(boolean_fields)
    if any(not _digest(evidence[field]) for field in digest_fields):
        return ["branch-fork identity or content digest is invalid"]
    if (
        evidence["branch_identity_sha256"] == evidence["successor_branch_identity_sha256"]
        or evidence["expected_branch_sha256"] != evidence["branch_readback_sha256"]
        or evidence["expected_source_sha256"] != evidence["successor_source_readback_sha256"]
        or evidence["expected_source_sha256"] != evidence["parent_readback_sha256"]
    ):
        return ["branch-fork identities or source/marker readbacks do not match"]
    return []


class ProviderTerminalBranchForkRunner(ModeHandoverRunner):
    """Run only the selected, source-bound branch-fork fixture operation."""

    operation = OPERATION
    access_mode = ACCESS_MODE
    fact_errors = staticmethod(handover_fact_errors)
