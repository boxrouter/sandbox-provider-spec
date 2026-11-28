# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Draft engine-native FUSE handover facts, distinct from historical Core bindings.

The digest is derived from actual route/account/native identities; it makes no claim
that the provider returned an incarnation, creation time, or session identifier.
"""

# Keep the historical lifecycle checks independent so published proof digests stay fixed.
# pylint: disable=duplicate-code

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any

from sandbox_provider_spec.driver import NotRun
from sandbox_provider_spec.fuse_mount_handover_130 import (
    _exact_mapping,
    _valid_digest,
    _valid_utc_timestamp,
)
from sandbox_provider_spec.fuse_mount_handover_env_132 import EnvironmentHandoverRunner, _observe
from sandbox_provider_spec.runner import resolve

ENGINE_IDENTITY_BASIS = (
    "sandbox_id",
    "workspace_id",
    "route_id",
    "provider",
    "account_id",
    "native_id",
)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


def engine_identity_digest(identity: Mapping[str, str]) -> str:
    """Hash only the actual observed fields, with a separate domain from Core bindings."""
    if (
        not isinstance(identity, Mapping)
        or set(identity) != set(ENGINE_IDENTITY_BASIS)
        or any(
            not isinstance(identity[key], str) or not identity[key] for key in ENGINE_IDENTITY_BASIS
        )
    ):
        raise ValueError("Engine identity fields are incomplete")
    canonical = json.dumps(dict(identity), sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(("sps-engine-identity-v1\0" + canonical).encode()).hexdigest()


def engine_identity_valid(digest: object, basis: object) -> bool:
    return (
        isinstance(digest, str)
        and _DIGEST.fullmatch(digest) is not None
        and basis == list(ENGINE_IDENTITY_BASIS)
    )


def engine_native_identity_digest(identity: Mapping[str, str]) -> str:
    """Hash provider/account/native identity independently of the Cloud sandbox ID."""
    engine_identity_digest(identity)  # Require the complete observed identity first.
    native = {key: identity[key] for key in ("provider", "account_id", "native_id")}
    canonical = json.dumps(native, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(("sps-native-identity-v1\0" + canonical).encode()).hexdigest()


def _engine_fact_errors(  # pylint: disable=too-many-boolean-expressions
    value: object, *, access_mode: object
) -> list[str]:
    """Validate the engine-native fact schema and its mode-specific success conditions."""
    if access_mode != "write":
        return ["handover access mode is not supported by this fixture"]
    if not isinstance(value, Mapping):
        return ["handover facts are not an object"]
    fact_keys = {
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
    if set(value) != fact_keys:
        return ["handover fact fields are incomplete or unknown"]

    terminal = value["terminal_receipt"]
    if not _exact_mapping(
        terminal,
        {
            "sandbox_id_sha256",
            "engine_identity_sha256",
            "native_identity_sha256",
            "identity_basis",
            "provider_state",
            "observed_at",
        },
    ):
        return ["handover terminal receipt fields are invalid"]
    if (
        not _valid_digest(terminal["sandbox_id_sha256"])
        or not _valid_digest(terminal["native_identity_sha256"])
        or not engine_identity_valid(terminal["engine_identity_sha256"], terminal["identity_basis"])
        or terminal["provider_state"] != "terminated"
        or not _valid_utc_timestamp(terminal["observed_at"])
    ):
        return ["handover terminal receipt is not provider-confirmed"]

    issuance = value["issuance"]
    if not _exact_mapping(issuance, {"claim_sha256", "credential_sha256", "resolution"}):
        return ["handover issuance fields are invalid"]
    if (
        not _valid_digest(issuance["claim_sha256"])
        or not _valid_digest(issuance["credential_sha256"])
        or issuance["resolution"] != "current"
    ):
        return ["handover issuance is not current"]

    delegations = value["delegations"]
    if not isinstance(delegations, list):
        return ["handover delegations are not a list"]
    delegation_ids: set[str] = set()
    for delegation in delegations:
        if not _exact_mapping(
            delegation, {"delegation_sha256", "client_sha256", "is_orphaned", "revoke"}
        ):
            return ["handover delegation fields are invalid"]
        identifier = delegation["delegation_sha256"]
        if (
            not _valid_digest(identifier)
            or identifier in delegation_ids
            or not _valid_digest(delegation["client_sha256"])
            or not isinstance(delegation["is_orphaned"], bool)
        ):
            return ["handover delegation identity or orphan state is invalid"]
        delegation_ids.add(identifier)
        revoke = delegation["revoke"]
        if not _exact_mapping(revoke, {"attempted", "outcome"}):
            return ["handover delegation revoke fields are invalid"]
        if delegation["is_orphaned"] is True:
            if revoke["attempted"] is not True or revoke["outcome"] != "revoked":
                return ["orphaned handover delegation was not revoked"]
        elif revoke["attempted"] is not False or revoke["outcome"] != "not_attempted":
            return ["non-orphaned handover delegation was targeted"]
    if value["delegations_cleared"] is not True:
        return ["handover delegations were not freshly confirmed clear"]

    connected = value["connected_writer"]
    if not _exact_mapping(
        connected,
        {
            "connected",
            "outcome",
            "revoke_attempted",
            "successor_dispatched",
            "write_after_refusal",
        },
    ):
        return ["handover connected-writer control fields are invalid"]
    if (
        connected["connected"] is not True
        or connected["outcome"] != "busy"
        or connected["revoke_attempted"] is not False
        or connected["successor_dispatched"] is not False
        or connected["write_after_refusal"] is not True
    ):
        return ["connected-writer Cloud refusal dispatched a successor or changed the writer"]
    if value["no_force"] is not True:
        return ["handover did not use the normal no-force path"]

    successor = value["successor"]
    if not _exact_mapping(
        successor,
        {
            "sandbox_id_sha256",
            "engine_identity_sha256",
            "native_identity_sha256",
            "identity_basis",
            "access_mode",
            "force",
            "mounted",
        },
    ):
        return ["handover successor fields are invalid"]
    if (
        not _valid_digest(successor["sandbox_id_sha256"])
        or not _valid_digest(successor["native_identity_sha256"])
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

    file_evidence = value["file_evidence"]
    if not _exact_mapping(
        file_evidence,
        {
            "default_user_write",
            "save_acknowledged",
            "checkpoint_sha256",
            "expected_readback_sha256",
            "readback_sha256",
        },
    ):
        return ["handover file evidence fields are invalid"]
    if (
        file_evidence["default_user_write"] is not True
        or file_evidence["save_acknowledged"] is not True
        or not _valid_digest(file_evidence["checkpoint_sha256"])
        or not _valid_digest(file_evidence["expected_readback_sha256"])
        or not _valid_digest(file_evidence["readback_sha256"])
        or file_evidence["expected_readback_sha256"] != file_evidence["readback_sha256"]
    ):
        return ["handover save, checkpoint or readback evidence is invalid"]

    cleanup = value["cleanup"]
    if not _exact_mapping(cleanup, {"owned_resources"}) or cleanup["owned_resources"] != "deleted":
        return ["handover owned-resource cleanup is incomplete"]
    return []


_LEGACY_DELEGATION_KEYS = {"delegation_sha256", "client_sha256", "is_orphaned", "revoke"}


def engine_write_fact_errors(value: object, *, access_mode: object) -> list[str]:
    """Check owner-client and orphan revocations without changing the identity fields."""
    if not isinstance(value, Mapping) or not isinstance(value.get("delegations"), list):
        return _engine_fact_errors(value, access_mode=access_mode)
    normalised: list[object] = []
    for delegation in value["delegations"]:
        if not isinstance(delegation, Mapping) or "revoke_basis" not in delegation:
            normalised.append(delegation)
            continue
        if set(delegation) != _LEGACY_DELEGATION_KEYS | {"revoke_basis"}:
            return ["handover delegation fields are invalid"]
        basis, orphaned, revoke = (
            delegation["revoke_basis"],
            delegation["is_orphaned"],
            delegation["revoke"],
        )
        if (basis, orphaned) not in {("orphaned", True), ("owner_client", False)}:
            return ["handover delegation revoke basis contradicts the orphan flag"]
        plain = {key: item for key, item in delegation.items() if key != "revoke_basis"}
        if basis == "owner_client":
            if (
                not isinstance(revoke, Mapping)
                or revoke.get("attempted") is not True
                or revoke.get("outcome") != "revoked"
            ):
                return ["owner-client handover delegation was not revoked"]
            plain["revoke"] = {"attempted": False, "outcome": "not_attempted"}
        normalised.append(plain)
    return _engine_fact_errors({**value, "delegations": normalised}, access_mode=access_mode)


ENGINE_WRITE_CHECK = "fuse_mount.provider_terminal_handover_engine_133"
ENGINE_WRITE_OPERATION = "fixture.fuse_mount_provider_terminal_handover_engine_133"


def _validate_engine_write(value: object, mode: object) -> list[str]:
    return engine_write_fact_errors(value, access_mode=mode)


HANDOVER_IDENTITIES_133 = {
    ENGINE_WRITE_CHECK: (
        "write",
        "fuse_mount/provider-terminal-handover-engine-133",
        ENGINE_WRITE_OPERATION,
        _validate_engine_write,
    )
}


class EngineNativeHandoverRunner(EnvironmentHandoverRunner):
    """Run the write-only draft with engine-native, rather than retired Core, identity."""

    def _step(self, step: dict[str, Any], bindings: dict[str, object]) -> dict[str, object]:
        if step.get("op") != ENGINE_WRITE_OPERATION:
            return super()._step(step, bindings)
        expected = resolve(step.get("expect", {}), bindings, self.fixtures)
        if not isinstance(expected, Mapping) or expected != {"record": ["fuse_mount_handover"]}:
            raise NotRun("fixture_handover_record_invalid")
        inputs = resolve(step.get("in", {}), bindings, self.fixtures)
        if not isinstance(inputs, Mapping):
            raise NotRun("fixture_missing")
        observation = _observe(
            self.driver,
            inputs,
            self.fixtures,
            mode="write",
            fact_errors=_validate_engine_write,
        )
        if name := step.get("as"):
            bindings[name] = observation
        return {
            "operation": ENGINE_WRITE_OPERATION,
            "result": "passed",
            "observations": {"fuse_mount_handover": observation},
        }
