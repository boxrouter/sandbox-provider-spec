# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Writable-client provider-terminal handover contract for shared access."""

# The shared writer control is intentionally identical to the frozen SPS123 fact shape.
# pylint: disable=duplicate-code

from __future__ import annotations

from collections.abc import Mapping

from sandbox_provider_spec.fuse_mount_handover_mode_130 import (
    ModeHandoverRunner,
    _common_fact_errors,
    _digest,
)

OPERATION = "fixture.fuse_mount_provider_terminal_handover_shared_130"
ACCESS_MODE = "shared"


def handover_fact_errors(value: object, access_mode: object = ACCESS_MODE) -> list[str]:
    """Validate shared-writer refusal and the acknowledged write/fsync/sync/readback chain."""
    if access_mode != ACCESS_MODE:
        return ["shared handover access mode is not supported by this fixture"]
    errors = _common_fact_errors(
        value,
        access_mode=ACCESS_MODE,
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


class ProviderTerminalHandoverSharedRunner(ModeHandoverRunner):
    """Run only the selected, source-bound shared handover fixture operation."""

    operation = OPERATION
    access_mode = ACCESS_MODE
    fact_errors = staticmethod(handover_fact_errors)
