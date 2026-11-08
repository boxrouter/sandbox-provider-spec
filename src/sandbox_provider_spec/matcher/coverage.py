# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""What at least one provider declares and proves: the ceiling a consumer may expose.

`coverage` answers one question for a consumer that offers only part of the vocabulary: which
gates, knobs and resources can some provider back today. It reuses the matcher's own words
(`build_declaration`, `Proof`), so "backed" means what `match` means by it.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Final

from sandbox_provider_spec.matcher.catalog import UNKNOWN, Document
from sandbox_provider_spec.matcher.declaration import Declaration, Variant
from sandbox_provider_spec.matcher.matcher import Declared, read
from sandbox_provider_spec.matcher.proof import Proof, Report

#: Request resources and the declaration facts that back them, as `fit_resources` reads them.
RESOURCE_FACTS: Final[dict[str, tuple[str, ...]]] = {
    "cpu_min": ("sizes",),
    "memory_min_mib": ("sizes",),
    "disk_min_mib": ("sizes", "disk_mib"),
    "region": ("regions", "located_in"),
    "gpu_count": ("gpus", "max_gpus"),
    "gpu_model": ("gpus", "max_gpus"),
    "paused_retention_seconds": ("paused_retention_seconds",),
    "run_seconds": ("max_run_seconds",),
    "process_seconds": ("max_process_seconds",),
    "file_stream_bytes": ("file_stream_max_bytes",),
}


def _offers_something(offered: Any) -> bool:
    """A declared knob backs a request when it names a value other than `no` or `unknown`."""
    if offered is None:
        return False
    if isinstance(offered, tuple):  # a number: exact, at least, or unlimited
        return True
    return any(value is not False for value in offered)


def _declares_fact(value: Any) -> bool:
    """A resource fact is declared when it is present and neither unknown, no nor empty."""
    return value not in (None, UNKNOWN, False, [], {}, "")


def _usable(variant: Variant) -> bool:
    return variant.unusable is None


def _backed_by(declaration: Declaration, catalog: Mapping[str, Any]) -> set[str]:
    backed: set[str] = set()
    for gate, definition in catalog["gates"].items():
        declared = declaration.gates.get(gate)
        if declared is None or not declared.supported:
            continue
        variants = [variant for variant in declared.variants if _usable(variant)]
        if not variants:
            continue
        backed.add(gate)
        for knob in definition["knobs"]:
            if any(_offers_something(variant.knobs.get(knob)) for variant in variants):
                backed.add(f"{gate}.{knob}")
    for ask in catalog["resources"]:
        facts = RESOURCE_FACTS.get(ask, (ask,))
        if any(_declares_fact(declaration.resources.get(fact)) for fact in facts):
            backed.add(f"resources.{ask}")
    return backed


def coverage(
    catalog: Mapping[str, Any],
    declarations: Sequence[Declared],
    reports: Sequence[Report] = (),
    *,
    require_baseline: bool = True,
) -> set[str]:
    """The `gate`, `gate.knob` and `resources.<ask>` entries some provider declares and proves.

    A declaration backs an entry when it is usable and, for a gate, lists the gate as supported
    with at least one usable variant; for a knob, a usable variant offers a value other than
    `false` or `unknown`; for a resource, the declaration states the fact that answers it.
    With `require_baseline` (the default, as in `match`), only a declaration whose newest full
    report passed the current baseline (`Proof.baseline`) counts. Without it, as in
    `declared_fit`, a usable declaration is enough.
    """
    backed: set[str] = set()
    for declaration in read(declarations):
        if declaration.unusable:
            continue
        if require_baseline and not Proof(declaration, reports).baseline:
            continue
        backed |= _backed_by(declaration, catalog)
    return backed


def setting_backers(catalog: Mapping[str, Any]) -> dict[str, str]:
    """For each `gate.setting`, the coverage entry it follows.

    A setting with an `only_with` rule follows that gate's knob (`idle_shutdown.idle_seconds`
    follows `idle_shutdown.custom_idle_time`); any other setting follows its gate.
    """
    follows: dict[str, str] = {}
    for gate, definition in catalog["gates"].items():
        settings: Document = definition.get("settings", {})
        for setting, rules in settings.items():
            only_with = rules.get("only_with")
            follows[f"{gate}.{setting}"] = f"{gate}.{only_with['knob']}" if only_with else gate
    return follows
