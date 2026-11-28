# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Draft mode handover facts using observed engine and native identities."""

# pylint: disable=duplicate-code

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

from sandbox_provider_spec.driver import NotRun
from sandbox_provider_spec.fuse_mount_handover_engine_133 import (
    EngineNativeHandoverRunner,
    engine_identity_valid,
)
from sandbox_provider_spec.fuse_mount_handover_env_132 import _observe
from sandbox_provider_spec.fuse_mount_handover_mode_130 import _digest, _timestamp
from sandbox_provider_spec.runner import resolve


def _engine_mode_common_errors(  # pylint: disable=too-many-boolean-expressions
    value: object, *, access_mode: object, mode_keys: set[str]
) -> list[str]:
    if not isinstance(value, Mapping):
        return ["handover facts are not an object"]
    fact_keys = {
        "terminal_receipt",
        "issuance",
        "delegations",
        "delegations_cleared",
        "no_force",
        "successor",
        "cleanup",
        *mode_keys,
    }
    if set(value) != fact_keys:
        return ["handover fact fields are incomplete or unknown"]
    terminal = value["terminal_receipt"]
    if not isinstance(terminal, Mapping) or set(terminal) != {
        "sandbox_id_sha256",
        "engine_identity_sha256",
        "native_identity_sha256",
        "identity_basis",
        "provider_state",
        "observed_at",
    }:
        return ["handover terminal receipt fields are invalid"]
    if (
        not _digest(terminal["sandbox_id_sha256"])
        or not _digest(terminal["native_identity_sha256"])
        or not engine_identity_valid(terminal["engine_identity_sha256"], terminal["identity_basis"])
        or terminal["provider_state"] != "terminated"
        or not _timestamp(terminal["observed_at"])
    ):
        return ["handover terminal receipt is not provider-confirmed"]
    issuance = value["issuance"]
    if not isinstance(issuance, Mapping) or set(issuance) != {
        "claim_sha256",
        "credential_sha256",
        "resolution",
    }:
        return ["handover issuance fields are invalid"]
    if (
        not _digest(issuance["claim_sha256"])
        or not _digest(issuance["credential_sha256"])
        or issuance["resolution"] != "current"
    ):
        return ["handover issuance is not current"]
    delegations = value["delegations"]
    if not isinstance(delegations, list):
        return ["handover delegations are not a list"]
    seen: set[str] = set()
    for delegation in delegations:
        if not isinstance(delegation, Mapping) or set(delegation) != {
            "delegation_sha256",
            "client_sha256",
            "is_orphaned",
            "revoke_basis",
            "revoke",
        }:
            return ["handover delegation fields are invalid"]
        identifier = delegation["delegation_sha256"]
        if (
            not _digest(identifier)
            or identifier in seen
            or not _digest(delegation["client_sha256"])
            or not isinstance(delegation["is_orphaned"], bool)
        ):
            return ["handover delegation identity or orphan state is invalid"]
        seen.add(cast(str, identifier))
        revoke = delegation["revoke"]
        if not isinstance(revoke, Mapping) or set(revoke) != {"attempted", "outcome"}:
            return ["handover delegation revoke fields are invalid"]
        basis = delegation["revoke_basis"]
        if (basis, delegation["is_orphaned"]) not in {
            ("orphaned", True),
            ("owner_client", False),
        }:
            return ["handover delegation revoke basis contradicts the orphan flag"]
        if revoke["attempted"] is not True or revoke["outcome"] != "revoked":
            return ["owned or orphaned handover delegation was not revoked"]
    if value["delegations_cleared"] is not True:
        return ["handover delegations were not freshly confirmed clear"]
    if value["no_force"] is not True:
        return ["handover did not use the normal no-force path"]
    successor = value["successor"]
    if not isinstance(successor, Mapping) or set(successor) != {
        "sandbox_id_sha256",
        "engine_identity_sha256",
        "native_identity_sha256",
        "identity_basis",
        "access_mode",
        "force",
        "mounted",
    }:
        return ["handover successor fields are invalid"]
    if (
        not _digest(successor["sandbox_id_sha256"])
        or not _digest(successor["native_identity_sha256"])
        or not engine_identity_valid(
            successor["engine_identity_sha256"], successor["identity_basis"]
        )
        or successor["sandbox_id_sha256"] == terminal["sandbox_id_sha256"]
        or successor["engine_identity_sha256"] == terminal["engine_identity_sha256"]
        or successor["native_identity_sha256"] == terminal["native_identity_sha256"]
        or successor["access_mode"] != access_mode
        or successor["force"] is not False
        or successor["mounted"] is not True
    ):
        return ["handover successor identity, mode or mount result is invalid"]
    cleanup = value["cleanup"]
    if not isinstance(cleanup, Mapping) or set(cleanup) != {"owned_resources"}:
        return ["handover cleanup fields are invalid"]
    if cleanup["owned_resources"] != "deleted":
        return ["handover owned-resource cleanup is incomplete"]
    return []


def read_fact_errors(value: object, access_mode: object = "read") -> list[str]:
    """Validate the exact read-mode facts; a read-only client never claims a successful write."""
    if access_mode != "read":
        return ["read handover access mode is not supported by this fixture"]
    errors = _engine_mode_common_errors(
        value,
        access_mode="read",
        mode_keys={"connected_reader", "file_evidence"},
    )
    if errors:
        return errors
    assert isinstance(value, Mapping)
    reader = value["connected_reader"]
    if not isinstance(reader, Mapping) or set(reader) != {
        "connected",
        "outcome",
        "revoke_attempted",
        "successor_dispatched",
        "read_after_refusal",
    }:
        return ["connected-reader control fields are invalid"]
    if (
        reader["connected"] is not True
        or reader["outcome"] != "busy"
        or reader["revoke_attempted"] is not False
        or reader["successor_dispatched"] is not False
        or reader["read_after_refusal"] is not True
    ):
        return ["connected-reader refusal dispatched a successor or changed the reader"]
    evidence = value["file_evidence"]
    if not isinstance(evidence, Mapping) or set(evidence) != {
        "write_attempted",
        "write_denied",
        "denial_errno",
        "expected_readback_sha256",
        "readback_sha256",
    }:
        return ["read-mode file evidence fields are invalid"]
    if (  # pylint: disable=too-many-boolean-expressions
        evidence["write_attempted"] is not True
        or evidence["write_denied"] is not True
        or evidence["denial_errno"] != "EROFS"
        or not _digest(evidence["expected_readback_sha256"])
        or not _digest(evidence["readback_sha256"])
        or evidence["expected_readback_sha256"] != evidence["readback_sha256"]
    ):
        return ["read-mode denial or readback evidence is invalid"]
    return []


def shared_fact_errors(value: object, access_mode: object = "shared") -> list[str]:
    """Validate shared-writer refusal and the acknowledged write/fsync/sync/readback chain."""
    if access_mode != "shared":
        return ["shared handover access mode is not supported by this fixture"]
    errors = _engine_mode_common_errors(
        value,
        access_mode="shared",
        mode_keys={"connected_writer", "file_evidence"},
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
    evidence = value["file_evidence"]
    if not isinstance(evidence, Mapping) or set(evidence) != {
        "default_user_write",
        "fsync_acknowledged",
        "sync_acknowledged",
        "checkpoint_sha256",
        "expected_readback_sha256",
        "readback_sha256",
    }:
        return ["shared-mode file evidence fields are invalid"]
    if (  # pylint: disable=too-many-boolean-expressions
        evidence["default_user_write"] is not True
        or evidence["fsync_acknowledged"] is not True
        or evidence["sync_acknowledged"] is not True
        or not _digest(evidence["checkpoint_sha256"])
        or not _digest(evidence["expected_readback_sha256"])
        or not _digest(evidence["readback_sha256"])
        or evidence["expected_readback_sha256"] != evidence["readback_sha256"]
    ):
        return ["shared-mode write, acknowledgments or readback evidence is invalid"]
    return []


def branch_fact_errors(value: object, access_mode: object = "branch") -> list[str]:
    """Validate common provider-terminal facts and the closed fresh-fork evidence.

    ``source_checkpoint_sha256`` identifies the acknowledged checkpoint selected by both
    forks; ``source_head_unchanged`` is a separate post-release head comparison.
    """
    if access_mode != "branch":
        return ["branch-fork handover access mode is not supported by this fixture"]
    errors = _engine_mode_common_errors(
        value,
        access_mode="branch",
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


HANDOVER_IDENTITIES_134 = {
    "fuse_mount.provider_terminal_handover_read_engine_134": (
        "read",
        "fuse_mount/provider-terminal-handover-read-engine-134",
        "fixture.fuse_mount_provider_terminal_handover_read_engine_134",
        read_fact_errors,
    ),
    "fuse_mount.provider_terminal_handover_shared_engine_134": (
        "shared",
        "fuse_mount/provider-terminal-handover-shared-engine-134",
        "fixture.fuse_mount_provider_terminal_handover_shared_engine_134",
        shared_fact_errors,
    ),
    "fuse_mount.provider_terminal_branch_fork_engine_134": (
        "branch",
        "fuse_mount/provider-terminal-branch-fork-engine-134",
        "fixture.fuse_mount_provider_terminal_branch_fork_engine_134",
        branch_fact_errors,
    ),
}


class EngineNativeModeHandoverRunner(EngineNativeHandoverRunner):
    """Run the separate engine-native read, shared, and branch checks."""

    def _step(self, step: dict[str, Any], bindings: dict[str, object]) -> dict[str, object]:
        entry = next(
            (entry for entry in HANDOVER_IDENTITIES_134.values() if entry[2] == step.get("op")),
            None,
        )
        if entry is None:
            return super()._step(step, bindings)
        mode, _, operation, validator = entry
        expected = resolve(step.get("expect", {}), bindings, self.fixtures)
        if not isinstance(expected, Mapping) or expected != {"record": ["fuse_mount_handover"]}:
            raise NotRun("fixture_handover_record_invalid")
        inputs = resolve(step.get("in", {}), bindings, self.fixtures)
        if not isinstance(inputs, Mapping):
            raise NotRun("fixture_missing")
        observation = _observe(self.driver, inputs, self.fixtures, mode=mode, fact_errors=validator)
        if name := step.get("as"):
            bindings[name] = observation
        return {
            "operation": operation,
            "result": "passed",
            "observations": {"fuse_mount_handover": observation},
        }
