# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Versioned FUSE handover identity for environment credentials and prepared handles.

This profile records the actual route/account and exact Core prepared-image handle while
leaving credential version absent. It does not claim an OCI image digest or credential pool.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import re
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, cast

from sandbox_provider_spec.driver import Differs, Driver, NotRun
from sandbox_provider_spec.fuse_mount import controller_digest
from sandbox_provider_spec.fuse_mount_handover_130 import (
    AccessMode,
    ProviderTerminalHandoverController,
    handover_fact_errors,
)
from sandbox_provider_spec.fuse_mount_handover_branch_131 import (
    handover_fact_errors as branch_fact_errors,
)
from sandbox_provider_spec.fuse_mount_handover_read_130 import (
    handover_fact_errors as read_fact_errors,
)
from sandbox_provider_spec.fuse_mount_handover_shared_130 import (
    handover_fact_errors as shared_fact_errors,
)
from sandbox_provider_spec.runner import Runner, resolve

_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
_BARE_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


_LEGACY_DELEGATION_KEYS = {"delegation_sha256", "client_sha256", "is_orphaned", "revoke"}


def handover_write_fact_errors_132(value: object, access_mode: object) -> list[str]:
    """Write facts may name why a holder was revoked, then reuse the frozen 130 checks.

    Release revokes every holder that is literally orphaned or that belongs to the
    terminated owner's recorded client. A delegation with ``revoke_basis`` must be
    ``orphaned`` (flag true) or ``owner_client`` (flag false, revoked). Published
    reports without the key keep the 130 shape. The 130 reader then checks the rest on a
    copy in which the basis is removed and an owner-client holder shows as handled.
    """
    if not isinstance(value, Mapping) or not isinstance(value.get("delegations"), list):
        return handover_fact_errors(value, access_mode=access_mode)
    normalised: list[object] = []
    for delegation in value["delegations"]:
        if not isinstance(delegation, Mapping) or "revoke_basis" not in delegation:
            normalised.append(delegation)
            continue
        if set(delegation) != _LEGACY_DELEGATION_KEYS | {"revoke_basis"}:
            return ["handover delegation fields are invalid"]
        basis, orphaned = delegation["revoke_basis"], delegation["is_orphaned"]
        revoke = delegation["revoke"]
        if (basis, orphaned) not in {("orphaned", True), ("owner_client", False)}:
            return ["handover delegation revoke basis contradicts the orphan flag"]
        plain = {k: v for k, v in delegation.items() if k != "revoke_basis"}
        if basis == "owner_client":
            if (
                not isinstance(revoke, Mapping)
                or revoke.get("attempted") is not True
                or revoke.get("outcome") != "revoked"
            ):
                return ["owner-client handover delegation was not revoked"]
            plain["revoke"] = {"attempted": False, "outcome": "not_attempted"}
        normalised.append(plain)
    return handover_fact_errors({**value, "delegations": normalised}, access_mode=access_mode)


HANDOVER_IDENTITIES_132 = {
    "fuse_mount.provider_terminal_handover_env_132": (
        "write",
        "fuse_mount/provider-terminal-handover-env-132",
        "fixture.fuse_mount_provider_terminal_handover_env_132",
        handover_write_fact_errors_132,
    ),
    "fuse_mount.provider_terminal_handover_read_env_132": (
        "read",
        "fuse_mount/provider-terminal-handover-read-env-132",
        "fixture.fuse_mount_provider_terminal_handover_read_env_132",
        read_fact_errors,
    ),
    "fuse_mount.provider_terminal_handover_shared_env_132": (
        "shared",
        "fuse_mount/provider-terminal-handover-shared-env-132",
        "fixture.fuse_mount_provider_terminal_handover_shared_env_132",
        shared_fact_errors,
    ),
    "fuse_mount.provider_terminal_branch_fork_env_132": (
        "branch",
        "fuse_mount/provider-terminal-branch-fork-env-132",
        "fixture.fuse_mount_provider_terminal_branch_fork_env_132",
        branch_fact_errors,
    ),
}
_OPERATION_TO_ID = {value[2]: (key, value) for key, value in HANDOVER_IDENTITIES_132.items()}
FactValidator = Callable[[object, object], list[str]]


def handover_scope_errors_132(
    *,
    controller_source_digest: object,
    execution_binding: object,
    prerequisites: object,
    requested_access_mode: object,
    observed_access_mode: object,
) -> list[str]:
    """Require actual account, route and prepared-handle identity; credential version is absent."""
    if (
        not isinstance(controller_source_digest, str)
        or _SHA256.fullmatch(controller_source_digest) is None
        or requested_access_mode not in {"write", "read", "shared", "branch"}
        or observed_access_mode != requested_access_mode
    ):
        return ["environment handover source or access identity is invalid"]
    if not isinstance(execution_binding, Mapping) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in execution_binding.items()
    ):
        return ["environment handover binding is invalid"]
    binding = dict(execution_binding)
    required = {
        "account",
        "account_fingerprint",
        "source_account",
        "copy",
        "route",
        "source_route",
        "provider",
        "class",
        "credential_kind",
        "image_kind",
        "prepared_image_key",
        "region",
        "access_mode",
    }
    optional = {"placement_mode", "native_plan_digest"}
    if not required <= set(binding) or not set(binding) <= required | optional:
        return ["environment handover binding fields are incomplete or unknown"]
    if (  # pylint: disable=too-many-boolean-expressions
        any(
            _BARE_SHA256.fullmatch(binding[key]) is None
            for key in ("account", "source_account", "copy", "route", "source_route")
        )
        or re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", binding["provider"]) is None
        or re.fullmatch(r"[0-9a-f]{24}", binding["account_fingerprint"]) is None
        or binding["account"]
        != environment_account_digest(binding["provider"], binding["account_fingerprint"])
        or binding["route"]
        != environment_route_scope_digest(binding["provider"], binding["account"])
        or not 1 <= len(binding["class"]) <= 64
        or binding["credential_kind"] != "environment"
        or "credential_version" in binding
        or "credential_fingerprint" in binding
        or binding["image_kind"] != "prepared_handle"
        or _BARE_SHA256.fullmatch(binding["prepared_image_key"]) is None
        or binding["access_mode"] != requested_access_mode
    ):
        return ["environment handover binding values are invalid"]
    expected = {
        "prepared_image:sha256:" + binding["prepared_image_key"],
        "fuse_mount_account",
        "access_mode:" + str(requested_access_mode),
        "controller:" + controller_source_digest,
    }
    egress = (
        [
            value
            for value in prerequisites
            if isinstance(value, str)
            and re.fullmatch(r"fuse_mount_egress:sha256:[0-9a-f]{64}", value)
        ]
        if isinstance(prerequisites, list)
        else []
    )
    if len(egress) != 1:
        return ["environment handover requires one exact egress policy identity"]
    expected.add(egress[0])
    if binding.get("placement_mode") == "default":
        plan = binding.get("native_plan_digest")
        if (
            binding["region"] != "unknown"
            or not isinstance(plan, str)
            or _SHA256.fullmatch(plan) is None
        ):
            return ["environment handover default plan identity is invalid"]
        expected.update({"placement:default", "native_plan:" + plan})
    elif "placement_mode" not in binding and "native_plan_digest" not in binding:
        region = binding["region"]
        if (
            region in {"", "unknown", "default"}
            or re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", region) is None
        ):
            return ["environment handover observed region is invalid"]
        expected.add("region:" + region)
    else:
        return ["environment handover placement fields are invalid"]
    # A capture may record whether the guest's default mount path was free. It is
    # optional so published proofs without the observation stay valid; an unknown
    # or duplicated value is not.
    default_path = (
        [
            value
            for value in prerequisites
            if isinstance(value, str) and value.startswith("default_path:")
        ]
        if isinstance(prerequisites, list)
        else []
    )
    if len(default_path) > 1 or (
        default_path and default_path[0] not in {"default_path:free", "default_path:occupied"}
    ):
        return ["environment handover default path observation is invalid"]
    expected.update(default_path)
    if not isinstance(prerequisites, list) or any(
        not isinstance(item, str) for item in prerequisites
    ):
        return ["environment handover prerequisites are invalid"]
    if len(prerequisites) != len(set(prerequisites)) or set(prerequisites) != expected:
        return ["environment handover prerequisites do not match the binding"]
    return []


def environment_account_digest(provider: str, account_fingerprint: str) -> str:
    """Stable logical identity from the trusted ENV route's actual 24-hex credential suffix."""
    if (
        not isinstance(provider, str)
        or re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", provider) is None
        or not isinstance(account_fingerprint, str)
        or re.fullmatch(r"[0-9a-f]{24}", account_fingerprint) is None
    ):
        raise ValueError("environment account scope requires a trusted route fingerprint")
    return hashlib.sha256((provider + "\0" + account_fingerprint).encode("utf-8")).hexdigest()


def environment_route_scope_digest(provider: str, account_digest: str) -> str:
    """Stable logical provider/account scope, independent of workspace route IDs."""
    if (
        not isinstance(provider, str)
        or re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", provider) is None
        or not isinstance(account_digest, str)
        or _BARE_SHA256.fullmatch(account_digest) is None
    ):
        raise ValueError("environment route scope requires actual provider/account identity")
    canonical = json.dumps(
        {
            "profile": "environment-account-route/v1",
            "provider": provider,
            "account": account_digest,
        },
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _observe(  # pylint: disable=duplicate-code
    driver: Driver,
    inputs: Mapping[str, Any],
    fixtures: Mapping[str, object],
    *,
    mode: str,
    fact_errors: FactValidator,
) -> dict[str, object]:
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
    if any(
        (source := inspect.getsourcefile(method)) is None
        or Path(source).resolve() not in source_paths
        for method in methods
    ):
        raise NotRun("fixture_source_missing")
    digest = controller_digest(paths)
    if digest != fixtures.get("fuse_mount_handover_controller_digest"):
        raise NotRun("fixture_source_mismatch")
    binding = getattr(controller, "execution_binding", None)
    if not isinstance(binding, Mapping):
        raise Differs("fuse_mount_handover_binding_missing")
    scoped = sorted([*cast(list[str], prerequisites), "controller:" + digest])
    if handover_scope_errors_132(
        controller_source_digest=digest,
        execution_binding=binding,
        prerequisites=scoped,
        requested_access_mode=mode,
        observed_access_mode=mode,
    ):
        raise Differs(f"fuse_mount_handover_{mode}_scope_invalid")
    driver.own(f"fuse_mount_handover_{mode}_fixture", controller, controller.cleanup)
    facts = controller.observe_provider_terminal_handover(
        driver, create, access_mode=cast(AccessMode, mode)
    )
    if fact_errors(facts, mode):
        raise Differs(f"fuse_mount_handover_{mode}_facts_invalid")
    observed_mode = facts["successor"]["access_mode"]
    if handover_scope_errors_132(
        controller_source_digest=digest,
        execution_binding=binding,
        prerequisites=scoped,
        requested_access_mode=mode,
        observed_access_mode=observed_mode,
    ):
        raise Differs(f"fuse_mount_handover_{mode}_scope_invalid")
    if controller_digest(paths) != digest:
        raise Differs(f"fuse_mount_handover_{mode}_controller_changed")
    result: dict[str, object] = {
        "controller_source_digest": digest,
        "prerequisites": scoped,
        "execution_binding": dict(binding),
        "requested_access_mode": mode,
        "observed_access_mode": observed_mode,
        **facts,
    }
    return result


class EnvironmentHandoverRunner(Runner):
    """Run the same locked lifecycle facts under the honest ENV/prepared-handle identity."""

    def _step(  # pylint: disable=duplicate-code
        self, step: dict[str, Any], bindings: dict[str, object]
    ) -> dict[str, object]:
        operation = step.get("op")
        selected = _OPERATION_TO_ID.get(operation) if isinstance(operation, str) else None
        if selected is None:
            return super()._step(step, bindings)
        identifier, (mode, _rule, _operation, validator) = selected  # pylint: disable=unused-variable
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
        observation = _observe(
            self.driver,
            inputs,
            self.fixtures,
            mode=mode,
            fact_errors=cast(FactValidator, validator),
        )
        if name := step.get("as"):
            bindings[name] = observation
        return {
            "operation": operation,
            "result": "passed",
            "observations": {"fuse_mount_handover": observation},
        }
