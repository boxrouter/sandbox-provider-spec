# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Shared source and execution checks for the separate read/shared handover fixtures."""

# SPS123's source is digest-frozen; its common safety checks cannot be factored here.
# pylint: disable=duplicate-code

from __future__ import annotations

import inspect
import re
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, cast

from sandbox_provider_spec.driver import Differs, Driver, NotRun
from sandbox_provider_spec.fuse_mount import controller_digest
from sandbox_provider_spec.fuse_mount_handover import (
    AccessMode,
    ProviderTerminalHandoverController,
    _valid_utc_timestamp,
    handover_scope_errors,
)
from sandbox_provider_spec.runner import Runner, resolve

FactValidator = Callable[[object, object], list[str]]


def _input_prerequisite_errors(  # pylint: disable=too-many-boolean-expressions
    prerequisites: object, *, access_mode: str
) -> list[str]:
    if not isinstance(prerequisites, list) or any(
        not isinstance(value, str) for value in prerequisites
    ):
        return ["handover prerequisites are invalid"]
    if len(prerequisites) != len(set(prerequisites)):
        return ["handover prerequisites are duplicated"]
    if any(value.startswith("controller:") for value in prerequisites):
        return ["controller prerequisite must come from the frozen source manifest"]
    common = {"fuse_mount_account", "access_mode:" + access_mode}
    image = [value for value in prerequisites if _is_token(value, "image:")]
    egress = [value for value in prerequisites if _is_token(value, "fuse_mount_egress:")]
    if len(image) != 1 or len(egress) != 1 or not common <= set(prerequisites):
        return ["handover prerequisites are incomplete or invalid"]
    if not _valid_digest(image[0].removeprefix("image:")):
        return ["handover image prerequisite is invalid"]
    if not _valid_digest(egress[0].removeprefix("fuse_mount_egress:")):
        return ["handover egress prerequisite is invalid"]
    regions = [value for value in prerequisites if value.startswith("region:")]
    placement = [value for value in prerequisites if value.startswith("placement:")]
    plans = [value for value in prerequisites if value.startswith("native_plan:")]
    if regions:
        if (
            len(regions) != 1
            or placement
            or plans
            or regions[0] == "region:"
            or regions[0] in {"region:", "region:unknown", "region:default"}
            or re.fullmatch(r"region:[a-z0-9]+(?:-[a-z0-9]+)*", regions[0]) is None
        ):
            return ["handover observed-region prerequisites are invalid"]
        allowed = common | set(image) | set(egress) | set(regions)
    else:
        if (
            placement != ["placement:default"]
            or len(plans) != 1
            or not _valid_digest(plans[0].removeprefix("native_plan:"))
        ):
            return ["handover default-placement prerequisites are invalid"]
        allowed = common | set(image) | set(egress) | set(placement) | set(plans)
    return (
        []
        if set(prerequisites) == allowed
        else ["handover prerequisites contain unknown scope tokens"]
    )


def _common_fact_errors(  # pylint: disable=too-many-boolean-expressions
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
        "incarnation_sha256",
        "provider_state",
        "observed_at",
    }:
        return ["handover terminal receipt fields are invalid"]
    if (
        not _digest(terminal["sandbox_id_sha256"])
        or not _digest(terminal["incarnation_sha256"])
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
        if delegation["is_orphaned"] is True:
            if revoke["attempted"] is not True or revoke["outcome"] != "revoked":
                return ["orphaned handover delegation was not revoked"]
        elif revoke["attempted"] is not False or revoke["outcome"] != "not_attempted":
            return ["non-orphaned handover delegation was targeted"]
    if value["delegations_cleared"] is not True:
        return ["handover delegations were not freshly confirmed clear"]
    if value["no_force"] is not True:
        return ["handover did not use the normal no-force path"]
    successor = value["successor"]
    if not isinstance(successor, Mapping) or set(successor) != {
        "sandbox_id_sha256",
        "incarnation_sha256",
        "access_mode",
        "force",
        "mounted",
    }:
        return ["handover successor fields are invalid"]
    if (
        not _digest(successor["sandbox_id_sha256"])
        or not _digest(successor["incarnation_sha256"])
        or successor["sandbox_id_sha256"] == terminal["sandbox_id_sha256"]
        or successor["incarnation_sha256"] == terminal["incarnation_sha256"]
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


def _digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 71
        and value.startswith("sha256:")
        and all(char in "0123456789abcdef" for char in value[7:])
    )


def _valid_digest(  # pylint: disable=too-many-boolean-expressions
    value: object,
) -> bool:
    return isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None


def _is_token(value: str, prefix: str) -> bool:
    return value.startswith(prefix)


def _timestamp(value: object) -> bool:
    return _valid_utc_timestamp(value)


def observe_mode_handover(
    driver: Driver,
    inputs: Mapping[str, Any],
    fixtures: Mapping[str, object],
    *,
    access_mode: str,
    fact_errors: FactValidator,
) -> dict[str, object]:
    """Bind one locked mode to the pinned controller, facts and execution."""
    if inputs.get("access_mode") != access_mode:
        raise NotRun("fixture_handover_access_mode_unsupported")
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
    if _input_prerequisite_errors(prerequisites, access_mode=access_mode):
        raise NotRun("fixture_prerequisites_invalid")
    driver.own(f"fuse_mount_handover_{access_mode}_fixture", controller, controller.cleanup)
    facts = controller.observe_provider_terminal_handover(
        driver, create, access_mode=cast(AccessMode, access_mode)
    )
    if fact_errors(facts, access_mode):
        raise Differs(f"fuse_mount_handover_{access_mode}_facts_invalid")
    binding = getattr(controller, "execution_binding", None)
    if not isinstance(binding, Mapping):
        raise Differs("fuse_mount_handover_binding_missing")
    observed_mode = facts["successor"]["access_mode"]
    scoped = sorted([*cast(list[str], prerequisites), "controller:" + digest])
    if handover_scope_errors(
        controller_source_digest=digest,
        execution_binding=binding,
        prerequisites=scoped,
        requested_access_mode=access_mode,
        observed_access_mode=observed_mode,
    ):
        raise Differs(f"fuse_mount_handover_{access_mode}_scope_invalid")
    if controller_digest(paths) != digest:
        raise Differs(f"fuse_mount_handover_{access_mode}_controller_changed")
    provenance: dict[str, object] = {
        "controller_source_digest": digest,
        "prerequisites": scoped,
        "execution_binding": dict(binding),
        "requested_access_mode": access_mode,
        "observed_access_mode": observed_mode,
    }
    provenance.update(facts)
    return provenance


class ModeHandoverRunner(Runner):
    """Base for the two independently selected mode-specific fixture operations."""

    operation: str
    access_mode: str
    fact_errors: FactValidator

    def _step(self, step: dict[str, Any], bindings: dict[str, object]) -> dict[str, object]:
        if step.get("op") != self.operation:
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
        observation = observe_mode_handover(
            self.driver,
            inputs,
            self.fixtures,
            access_mode=self.access_mode,
            fact_errors=self.fact_errors,
        )
        if name := step.get("as"):
            bindings[name] = observation
        return {
            "operation": self.operation,
            "result": "passed",
            "observations": {"fuse_mount_handover": observation},
        }
