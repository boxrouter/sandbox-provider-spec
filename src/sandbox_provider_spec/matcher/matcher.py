# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Match a request against provider declarations and their baseline run reports."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, TypedDict

from sandbox_provider_spec.matcher.catalog import ANY, GATES, Document
from sandbox_provider_spec.matcher.declaration import Declaration, build_declaration
from sandbox_provider_spec.matcher.matching import ProviderResult, Snapshot, match_provider
from sandbox_provider_spec.matcher.proof import Proof, Report
from sandbox_provider_spec.matcher.registry import Registry
from sandbox_provider_spec.matcher.request import Mode, Rejected, validate_request

Declared = Declaration | Document
MetNeeds = Mapping[str, Sequence[str]] | Sequence[str]


class Rejection(TypedDict):
    code: str
    reason: str
    message: str
    path: str | None
    fix: str | None
    details: Document


class MatchResult(TypedDict):
    rejected: Rejection | None
    eligible: list[str]
    chosen: str | None
    results: dict[str, ProviderResult]


class DeclaredProviderFit(TypedDict):
    """One declaration's compatibility result without proof eligibility wording."""

    provider: str
    class_name: str | None
    name: str
    compatible: bool
    gates: dict[str, Any]
    resources: dict[str, Any]
    restores_need: dict[str, Any] | None
    failed: list[Any]


class DeclaredFitResult(TypedDict):
    """Declaration compatibility only; contains no baseline or runtime eligibility claim."""

    rejected: Rejection | None
    compatible: list[str]
    chosen: str | None
    results: dict[str, DeclaredProviderFit]


def read(declarations: Sequence[Declared]) -> list[Declaration]:
    """Build typed declarations from parsed mappings, or pass through already-read values."""
    return [
        item if isinstance(item, Declaration) else build_declaration(item) for item in declarations
    ]


def _owns_snapshot(declaration: Declaration, snapshot: Snapshot) -> bool:
    """Match raw owners, plus legacy unnamed routes recorded with resolved `default`."""
    if declaration.provider != snapshot.get("provider"):
        return False
    snapshot_class = snapshot.get("class")
    return declaration.class_name == snapshot_class or (
        declaration.class_name is None and snapshot_class == "default"
    )


def _conditions_for(declaration: Declaration, answers: MetNeeds | None) -> Sequence[str]:
    if answers is None:
        return ()
    if isinstance(answers, Mapping):
        return answers.get(declaration.name, ())
    return answers


def _rejection(error: Rejected, retry: Any) -> Rejection:
    """A refusal with the alternatives relevant to a missing must-be-named knob."""
    details = dict(error.details)
    knob = details.get("knob")
    if error.reason == "knob_not_named" and knob is not None and error.path is not None:
        gate = details["gate"]
        values = [*GATES[gate].knobs[knob].values]
        if not GATES[gate].knobs[knob].one_value:
            values.append(ANY)
        details["values"] = values
        details["offered_by"] = {value: len(retry(error.path, value)) for value in values}
    return {
        "code": error.code,
        "reason": error.reason,
        "message": error.message,
        "path": error.path,
        "fix": error.fix,
        "details": details,
    }


# The public entry point requires the entire request context to keep matching explicit.
# pylint: disable=too-many-arguments
def match(
    request: Any,
    declarations: Sequence[Declared],
    *,
    reports: Sequence[Report] = (),
    registry: Registry | None = None,
    met_needs: MetNeeds | None = None,
    mode: Mode = "create",
    snapshot: Snapshot | None = None,
) -> MatchResult:
    """Return the declarations that satisfy the request, in declaration order."""
    registry = registry or Registry()
    parsed = read(declarations)
    if mode == "restore" and snapshot is not None:
        parsed = [declaration for declaration in parsed if _owns_snapshot(declaration, snapshot)]

    def eligible_for(changed: Document) -> list[str]:
        return match(
            changed,
            parsed,
            reports=reports,
            registry=registry,
            met_needs=met_needs,
            mode=mode,
            snapshot=snapshot,
        )["eligible"]

    def retry(path: str, value: str) -> list[str]:
        changed = dict(request)
        parent = changed
        *ancestors, knob = path.split(".")
        for key in ancestors:
            parent[key] = dict(parent[key])
            parent = parent[key]
        parent[knob] = value
        return eligible_for(changed)

    try:
        checked = validate_request(request, registry=registry, mode=mode)
    except Rejected as error:
        return {
            "rejected": _rejection(error, retry),
            "eligible": [],
            "chosen": None,
            "results": {},
        }
    results = {
        declaration.name: match_provider(
            declaration,
            checked,
            Proof(declaration, reports),
            registry=registry,
            met_needs=_conditions_for(declaration, met_needs),
            restore_of=snapshot,
        )
        for declaration in parsed
    }
    eligible = [name for name, result in results.items() if result["eligible"]]
    return {
        "rejected": None,
        "eligible": eligible,
        "chosen": eligible[0] if eligible else None,
        "results": results,
    }


# pylint: disable=too-many-arguments
def declared_fit(
    request: Any,
    declarations: Sequence[Declared],
    *,
    registry: Registry | None = None,
    met_needs: MetNeeds | None = None,
    mode: Mode = "create",
    snapshot: Snapshot | None = None,
) -> DeclaredFitResult:
    """Check declaration fit without requiring conformance reports.

    This answers compatibility only. It does not establish runtime availability,
    account/funding admission, or proof-gated eligibility (`match` remains strict).
    """
    registry = registry or Registry()
    parsed = read(declarations)
    if mode == "restore" and snapshot is not None:
        parsed = [declaration for declaration in parsed if _owns_snapshot(declaration, snapshot)]

    def compatible_for(changed: Document) -> list[str]:
        return declared_fit(
            changed,
            parsed,
            registry=registry,
            met_needs=met_needs,
            mode=mode,
            snapshot=snapshot,
        )["compatible"]

    def retry(path: str, value: str) -> list[str]:
        changed = dict(request)
        parent = changed
        *ancestors, knob = path.split(".")
        for key in ancestors:
            parent[key] = dict(parent[key])
            parent = parent[key]
        parent[knob] = value
        return compatible_for(changed)

    try:
        checked = validate_request(request, registry=registry, mode=mode)
    except Rejected as error:
        return {
            "rejected": _rejection(error, retry),
            "compatible": [],
            "chosen": None,
            "results": {},
        }
    results = {
        declaration.name: match_provider(
            declaration,
            checked,
            None,
            registry=registry,
            met_needs=_conditions_for(declaration, met_needs),
            restore_of=snapshot,
            require_baseline=False,
        )
        for declaration in parsed
    }
    compatible = [name for name, result in results.items() if result["eligible"]]
    return {
        "rejected": None,
        "compatible": compatible,
        "chosen": compatible[0] if compatible else None,
        "results": {
            name: {
                "provider": result["provider"],
                "class_name": result["class"],
                "name": result["name"],
                "compatible": result["eligible"],
                "gates": result["gates"],
                "resources": result["resources"],
                "restores_need": result["restores_need"],
                "failed": result["failed"],
            }
            for name, result in results.items()
        },
    }


def match_restore(
    request: Any,
    snapshot: Snapshot,
    declarations: Sequence[Declared],
    **kwargs: Any,
) -> MatchResult:
    """Match a restore on the provider and class that owns its snapshot."""
    return match(request, declarations, mode="restore", snapshot=snapshot, **kwargs)
