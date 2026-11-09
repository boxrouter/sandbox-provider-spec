# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Read-only-client provider-terminal handover contract and fixture runner."""

from __future__ import annotations

from collections.abc import Mapping

from sandbox_provider_spec.fuse_mount_handover_mode import (
    ModeHandoverRunner,
    _common_fact_errors,
    _digest,
)

OPERATION = "fixture.fuse_mount_provider_terminal_handover_read"
ACCESS_MODE = "read"


def handover_fact_errors(value: object, access_mode: object = ACCESS_MODE) -> list[str]:
    """Validate the exact read-mode facts; a read-only client never claims a successful write."""
    if access_mode != ACCESS_MODE:
        return ["read handover access mode is not supported by this fixture"]
    errors = _common_fact_errors(
        value,
        access_mode=ACCESS_MODE,
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


class ProviderTerminalHandoverReadRunner(ModeHandoverRunner):
    """Run only the selected, source-bound read handover fixture operation."""

    operation = OPERATION
    access_mode = ACCESS_MODE
    fact_errors = staticmethod(handover_fact_errors)
