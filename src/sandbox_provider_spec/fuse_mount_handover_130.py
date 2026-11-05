# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Source-bound, mode-specific provider-terminal FUSE handover proof."""

# This version preserves SPS123 lifecycle semantics while using a new binding identity.
# pylint: disable=duplicate-code

from __future__ import annotations

import inspect
import re
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, Protocol, TypedDict, cast

from sandbox_provider_spec.driver import Differs, Driver, NotRun
from sandbox_provider_spec.fuse_mount import controller_digest
from sandbox_provider_spec.fuse_mount_identity import BINDING_FIELDS
from sandbox_provider_spec.fuse_mount_public_core_binding import public_core_binding_identity_valid
from sandbox_provider_spec.runner import Runner, resolve

AccessMode = Literal["write", "read", "shared", "branch"]
ACCESS_MODES = frozenset({"write", "read", "shared", "branch"})
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
_BARE_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_UTC_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|\+00:00)\Z"
)


class TerminalReceipt(TypedDict):
    sandbox_id_sha256: str
    public_core_binding_sha256: str
    binding_basis: list[str]
    provider_state: Literal["terminated"]
    observed_at: str


class Issuance(TypedDict):
    claim_sha256: str
    credential_sha256: str
    resolution: Literal["current"]


class Revoke(TypedDict):
    attempted: bool
    outcome: Literal["revoked", "not_attempted"]


class DelegationOutcome(TypedDict):
    delegation_sha256: str
    client_sha256: str
    is_orphaned: bool
    revoke: Revoke


class ConnectedWriter(TypedDict):
    connected: bool
    outcome: Literal["busy", "clear"]
    revoke_attempted: bool
    successor_dispatched: bool
    write_after_refusal: bool


class Successor(TypedDict):
    sandbox_id_sha256: str
    public_core_binding_sha256: str
    binding_basis: list[str]
    access_mode: AccessMode
    force: bool
    mounted: bool


class FileEvidence(TypedDict):
    default_user_write: bool
    save_acknowledged: bool
    checkpoint_sha256: str
    expected_readback_sha256: str
    readback_sha256: str


class Cleanup(TypedDict):
    owned_resources: Literal["deleted"]


class HandoverFacts(TypedDict):
    terminal_receipt: TerminalReceipt
    issuance: Issuance
    delegations: list[DelegationOutcome]
    delegations_cleared: bool
    connected_writer: ConnectedWriter
    no_force: bool
    successor: Successor
    file_evidence: FileEvidence
    cleanup: Cleanup


class HandoverProvenance(HandoverFacts):
    controller_source_digest: str
    prerequisites: list[str]
    execution_binding: dict[str, str]
    requested_access_mode: AccessMode
    observed_access_mode: AccessMode


class ProviderTerminalHandoverController(Protocol):
    """Host-owned implementation of one provider-terminal handover observation."""

    source_files: tuple[Path, ...]
    execution_binding: Mapping[str, str] | None

    def observe_provider_terminal_handover(
        self, driver: Driver, create: Mapping[str, object], *, access_mode: AccessMode
    ) -> HandoverFacts: ...

    def cleanup(self) -> Mapping[str, object]: ...


def handover_scope_errors(  # pylint: disable=too-many-boolean-expressions
    *,
    controller_source_digest: object,
    execution_binding: object,
    prerequisites: object,
    requested_access_mode: object,
    observed_access_mode: object,
) -> list[str]:
    """Validate exact source, execution, placement and access-mode scope."""
    if (
        not isinstance(controller_source_digest, str)
        or _SHA256.fullmatch(controller_source_digest) is None
    ):
        return ["handover controller source identity is invalid"]
    if (
        not isinstance(requested_access_mode, str)
        or requested_access_mode not in ACCESS_MODES
        or not isinstance(observed_access_mode, str)
        or observed_access_mode not in ACCESS_MODES
        or requested_access_mode != observed_access_mode
    ):
        return ["handover access mode is invalid or mismatched"]
    if not isinstance(execution_binding, Mapping) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in execution_binding.items()
    ):
        return ["handover execution binding is invalid"]
    binding = dict(execution_binding)
    allowed = BINDING_FIELDS | {"access_mode"}
    common = {
        "account",
        "copy",
        "class",
        "credential_kind",
        "credential_version",
        "image_kind",
        "image_hash",
        "region",
        "access_mode",
    }
    if not common <= set(binding) or not set(binding) <= allowed:
        return ["handover execution binding fields are incomplete or unknown"]
    if (
        binding["access_mode"] != requested_access_mode
        or any(_BARE_SHA256.fullmatch(binding[key]) is None for key in ("account", "copy"))
        or not binding["class"]
        or len(binding["class"]) > 64
        or binding["image_kind"] not in {"standard_source", "oci_source"}
        or _SHA256.fullmatch(binding["image_hash"]) is None
        or binding["credential_kind"] not in {"byok_version", "managed_binding"}
        or re.fullmatch(r"[1-9][0-9]{0,31}", binding["credential_version"]) is None
        or (
            "credential_fingerprint" in binding
            and _BARE_SHA256.fullmatch(binding["credential_fingerprint"]) is None
        )
        or (
            binding["credential_kind"] == "managed_binding"
            and "credential_fingerprint" not in binding
        )
    ):
        return ["handover execution binding value is invalid"]

    if not isinstance(prerequisites, list) or any(
        not isinstance(value, str) for value in prerequisites
    ):
        return ["handover prerequisites are invalid"]
    if len(prerequisites) != len(set(prerequisites)):
        return ["handover prerequisites are duplicated"]
    required = {
        "image:" + binding["image_hash"],
        "fuse_mount_account",
        "access_mode:" + requested_access_mode,
        "controller:" + controller_source_digest,
    }
    egress = [
        value
        for value in prerequisites
        if re.fullmatch(r"fuse_mount_egress:sha256:[0-9a-f]{64}", value)
    ]
    if len(egress) != 1:
        return ["handover requires one exact egress prerequisite"]
    required.add(egress[0])

    default = binding.get("placement_mode") == "default"
    if default:
        native_plan = binding.get("native_plan_digest")
        route = binding.get("route")
        if (
            binding["region"] != "unknown"
            or not isinstance(native_plan, str)
            or _SHA256.fullmatch(native_plan) is None
            or not isinstance(route, str)
            or _BARE_SHA256.fullmatch(route) is None
        ):
            return ["handover default-placement binding is invalid"]
        required.update({"placement:default", "native_plan:" + native_plan})
        if any(value.startswith("region:") for value in prerequisites):
            return ["default handover cannot claim an observed region"]
    else:
        region = binding["region"]
        if (
            region in {"", "unknown", "default"}
            or re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", region) is None
            or any(key in binding for key in ("placement_mode", "native_plan_digest", "route"))
        ):
            return ["handover observed-region binding is invalid"]
        required.add("region:" + region)
        if any(value.startswith(("placement:", "native_plan:")) for value in prerequisites):
            return ["observed handover cannot claim a default native plan"]

    if set(prerequisites) != required:
        return ["handover prerequisites do not exactly match the execution binding"]
    return []


def handover_fact_errors(  # pylint: disable=too-many-boolean-expressions
    value: object, *, access_mode: object
) -> list[str]:
    """Validate the closed D8 fact schema and its mode-specific success conditions."""
    if not isinstance(access_mode, str) or access_mode not in {"write", "branch"}:
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
            "public_core_binding_sha256",
            "binding_basis",
            "provider_state",
            "observed_at",
        },
    ):
        return ["handover terminal receipt fields are invalid"]
    if (
        not _valid_digest(terminal["sandbox_id_sha256"])
        or not public_core_binding_identity_valid(
            terminal["public_core_binding_sha256"], terminal["binding_basis"]
        )
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
            "public_core_binding_sha256",
            "binding_basis",
            "access_mode",
            "force",
            "mounted",
        },
    ):
        return ["handover successor fields are invalid"]
    if (
        not _valid_digest(successor["sandbox_id_sha256"])
        or not public_core_binding_identity_valid(
            successor["public_core_binding_sha256"], successor["binding_basis"]
        )
        or successor["sandbox_id_sha256"] == terminal["sandbox_id_sha256"]
        or successor["public_core_binding_sha256"] == terminal["public_core_binding_sha256"]
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


def _exact_mapping(value: object, keys: set[str]) -> bool:
    return isinstance(value, Mapping) and set(value) == keys


def _valid_digest(value: object) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _valid_utc_timestamp(value: object) -> bool:
    if not isinstance(value, str) or _UTC_TIMESTAMP.fullmatch(value) is None:
        return False
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    offset = timestamp.utcoffset()
    return offset is not None and offset.total_seconds() == 0


def _input_prerequisite_errors(  # pylint: disable=too-many-boolean-expressions
    prerequisites: object, *, access_mode: AccessMode
) -> list[str]:
    """Validate caller prerequisites before the controller can allocate resources."""
    if not isinstance(prerequisites, list) or any(
        not isinstance(value, str) for value in prerequisites
    ):
        return ["handover prerequisites are invalid"]
    if len(prerequisites) != len(set(prerequisites)):
        return ["handover prerequisites are duplicated"]
    if any(value.startswith("controller:") for value in prerequisites):
        return ["controller prerequisite must come from the frozen source manifest"]
    common = {
        "fuse_mount_account",
        "access_mode:" + access_mode,
    }
    image = [value for value in prerequisites if _is_token(value, "image:")]
    egress = [value for value in prerequisites if _is_token(value, "fuse_mount_egress:")]
    if len(image) != 1 or len(egress) != 1 or not common <= set(prerequisites):
        return ["handover prerequisites are incomplete"]
    if not _valid_digest(image[0].removeprefix("image:")):
        return ["handover image prerequisite is invalid"]
    if not _valid_digest(egress[0].removeprefix("fuse_mount_egress:")):
        return ["handover egress prerequisite is invalid"]
    regions = [value for value in prerequisites if value.startswith("region:")]
    placement = [value for value in prerequisites if value.startswith("placement:")]
    native_plans = [value for value in prerequisites if value.startswith("native_plan:")]
    if regions:
        if (
            len(regions) != 1
            or placement
            or native_plans
            or regions[0] == "region:"
            or regions[0] in {"region:unknown", "region:default"}
            or re.fullmatch(r"region:[a-z0-9]+(?:-[a-z0-9]+)*", regions[0]) is None
        ):
            return ["handover observed-region prerequisites are invalid"]
    else:
        if (
            placement != ["placement:default"]
            or len(native_plans) != 1
            or not _valid_digest(native_plans[0].removeprefix("native_plan:"))
        ):
            return ["handover default-placement prerequisites are invalid"]
    allowed = common | set(image) | set(egress) | set(regions or placement) | set(native_plans)
    if set(prerequisites) != allowed:
        return ["handover prerequisites contain unknown scope tokens"]
    return []


def observe_provider_terminal_handover(
    driver: Driver, inputs: Mapping[str, Any], fixtures: Mapping[str, object]
) -> HandoverProvenance:
    """Run the separately versioned handover controller and emit only validated facts."""
    access_mode = inputs.get("access_mode")
    if not isinstance(access_mode, str) or access_mode not in {"write", "branch"}:
        raise NotRun("fixture_handover_access_mode_unsupported")
    mode = cast(AccessMode, access_mode)
    create = inputs.get("create")
    prerequisites = inputs.get("prerequisites")
    if not isinstance(create, Mapping):
        raise NotRun("fixture_missing")
    supplied = fixtures.get("fuse_mount_handover_controller")
    if supplied is None or any(
        not callable(getattr(supplied, name, None))
        for name in ("observe_provider_terminal_handover", "cleanup")
    ):
        raise NotRun("fixture_missing")
    controller = cast(ProviderTerminalHandoverController, supplied)
    paths = getattr(controller, "source_files", ())
    if (
        not isinstance(paths, tuple)
        or not paths
        or any(not isinstance(path, Path) for path in paths)
    ):
        raise NotRun("fixture_source_missing")
    methods = (controller.observe_provider_terminal_handover, controller.cleanup)
    source_paths = {path.resolve() for path in paths}
    for method in methods:
        implementation = inspect.getsourcefile(method)
        if implementation is None or Path(implementation).resolve() not in source_paths:
            raise NotRun("fixture_source_missing")
    digest = controller_digest(paths)
    if digest != fixtures.get("fuse_mount_handover_controller_digest"):
        raise NotRun("fixture_source_mismatch")
    if _input_prerequisite_errors(prerequisites, access_mode=mode):
        raise NotRun("fixture_prerequisites_invalid")

    # Register owned cleanup before invoking the controller, which may allocate.
    driver.own("fuse_mount_handover_fixture", controller, controller.cleanup)
    facts = controller.observe_provider_terminal_handover(driver, create, access_mode=mode)
    if handover_fact_errors(facts, access_mode=mode):
        raise Differs("fuse_mount_handover_facts_invalid")
    binding = getattr(controller, "execution_binding", None)
    if not isinstance(binding, Mapping):
        raise Differs("fuse_mount_handover_binding_missing")
    observed_mode = facts["successor"]["access_mode"]
    scoped_prerequisites = sorted([*cast(list[str], prerequisites), "controller:" + digest])
    if handover_scope_errors(
        controller_source_digest=digest,
        execution_binding=binding,
        prerequisites=scoped_prerequisites,
        requested_access_mode=mode,
        observed_access_mode=observed_mode,
    ):
        raise Differs("fuse_mount_handover_scope_invalid")
    if controller_digest(paths) != digest:
        raise Differs("fuse_mount_handover_controller_changed")
    provenance: dict[str, object] = {
        "controller_source_digest": digest,
        "prerequisites": scoped_prerequisites,
        "execution_binding": dict(binding),
        "requested_access_mode": mode,
        "observed_access_mode": observed_mode,
    }
    provenance.update(facts)
    return cast(HandoverProvenance, provenance)


class ProviderTerminalHandoverRunner(Runner):
    """Opt-in structured handover result; the common/legacy runner stays unchanged."""

    def _step(self, step: dict[str, Any], bindings: dict[str, object]) -> dict[str, object]:
        if step.get("op") != "fixture.fuse_mount_provider_terminal_handover_130":
            return super()._step(step, bindings)
        expected = resolve(step.get("expect", {}), bindings, self.fixtures)
        if (
            not isinstance(expected, Mapping)
            or set(expected) != {"record"}
            or expected["record"] != ["fuse_mount_handover"]
        ):
            raise NotRun("fixture_handover_record_invalid")
        inputs = resolve(step.get("in", {}), bindings, self.fixtures)
        if not isinstance(inputs, Mapping):
            raise NotRun("fixture_missing")
        observation = observe_provider_terminal_handover(self.driver, inputs, self.fixtures)
        if name := step.get("as"):
            bindings[name] = observation
        return {
            "operation": "fixture.fuse_mount_provider_terminal_handover_130",
            "result": "passed",
            "observations": {"fuse_mount_handover": observation},
        }


def _is_token(value: str, prefix: str) -> bool:
    return value.startswith(prefix)
