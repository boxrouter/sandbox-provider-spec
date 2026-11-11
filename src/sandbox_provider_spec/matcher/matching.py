# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Matching one declaration with the specification's four checks.

The provider must have a passing baseline report; each requested gate needs a fitting variant;
the variants must not conflict with one another or requested resources; and requested facts
must fit.
"""

# The checks follow the specification's clauses in its own order so that a reader can hold
# the two side by side; splitting them further would hide that correspondence.
# pylint: disable=too-many-branches,too-many-return-statements,too-many-locals
# pylint: disable=too-many-statements,too-many-arguments,too-many-positional-arguments
# pylint: disable=too-many-lines  # Keep the four checks beside their specification clauses.
# pylint: disable=inherit-non-class

from __future__ import annotations

import itertools
from collections.abc import Iterable, Sequence
from typing import Any, NamedTuple, TypedDict

from sandbox_provider_spec.check import UNMET_LIMIT_ASKS
from sandbox_provider_spec.matcher.catalog import (
    ALL_OF,
    ALL_OF_RESOURCES,
    GATES,
    NUMBER,
    PER_OPERATION_RESOURCES,
    PICK_RESOURCES,
    SECONDS_RESOURCES,
    SIZE_ASKS,
    SIZE_KEYS,
    STAGES,
    UNKNOWN,
    Document,
)
from sandbox_provider_spec.matcher.conditions import KnobGrant, _any_granted, _granted
from sandbox_provider_spec.matcher.declaration import (
    Conflict,
    Declaration,
    Number,
    Variant,
    number,
    offers,
)
from sandbox_provider_spec.matcher.json_values import same_value
from sandbox_provider_spec.matcher.proof import Proof
from sandbox_provider_spec.matcher.registry import Registry
from sandbox_provider_spec.matcher.request import GateAsk, Request, entry_kind
from sandbox_provider_spec.matcher.resource_matching import (
    fit_all_of_resources,
    fit_per_operation_resources,
)
from sandbox_provider_spec.matcher.secret_hosts import wildcard_injection_supported

FailureFields = TypedDict(
    "FailureFields",
    {
        "gate": str,
        "knob": str,
        "asked": Any,
        "offered": Any,
        "resource": str,
        "limit": str,
        "between": list[str],
        "value": Any,
        "extra": str,
        "stage": str,
        "in": str,
    },
    total=False,
)


class Failure(FailureFields):
    """One check that failed, in the API reference's vocabulary."""

    #: The exclusion reason; `stage` says which of the five checks raised it.
    reason: str
    detail: str


Snapshot = TypedDict(
    "Snapshot",
    {
        "provider": str,
        "class": str | None,
        "keeps": str,
        "source_resources": Document | None,
    },
    total=False,
)


class GateGrant(TypedDict):
    variant: int
    knobs: dict[str, KnobGrant]


ProviderResult = TypedDict(
    "ProviderResult",
    {
        "provider": str,
        "class": str | None,
        "name": str,
        "sdk_versions": Document,
        "eligible": bool,
        "gates": dict[str, GateGrant],
        "resources": Document,
        "restores_need": dict[str, GateGrant] | None,
        "failed": list[Failure],
    },
)
Grants = dict[str, GateGrant]


class Binding(NamedTuple):
    """What a `snapshots` variant binds on the request that restores from its snapshots."""

    conflicts: Sequence[tuple[str, Conflict]] = ()
    #: The size the source was created with, when a tool recorded one.
    size: Document | None = None
    resizes: bool = True


def binds(gate: str, variant: Variant, size: Document | None) -> Binding:
    return Binding(
        conflicts=[(gate, conflict) for conflict in variant.conflicts],
        size=size,
        resizes=variant.resizes_on_restore,
    )


NOTHING_BOUND = Binding()


def _fail(stage: str, reason: str, detail: str, **fields: Any) -> tuple[str, Failure]:
    entry: Failure = {"reason": reason, "detail": detail}
    entry.update(fields)  # type: ignore[typeddict-item]
    return stage, entry


def limit_fits(limits: Document, name: str, count: int) -> bool:
    """A limit left out or `unknown` fits a single item; silence never means yes."""
    if count == 0:
        return True
    raw = limits.get(name, UNKNOWN)
    if raw == UNKNOWN:
        return count <= 1
    return offers(number(raw), count)


def _allow_entry_has_wildcard(entry: Any) -> bool:
    host = entry.get("host") if isinstance(entry, dict) else entry
    return isinstance(host, str) and host.startswith("*.")


def fit_variant(
    gate: str, variant: Variant, ask: GateAsk, met_needs: Iterable[str] = ()
) -> tuple[dict[str, KnobGrant], Failure | None]:
    """One variant against one required gate: what it grants, or the check that failed."""
    if variant.unusable:
        return {}, {"reason": "variant_unusable", "detail": variant.unusable, "gate": gate}
    answered = set(met_needs)
    blocked_variant = set(variant.needs.get("variant", [])) - answered
    if blocked_variant:
        return {}, {
            "reason": "gate_unavailable",
            "detail": "variant account conditions are unmet or unanswered: "
            + ", ".join(sorted(blocked_variant)),
            "gate": gate,
        }
    grants: dict[str, KnobGrant] = {}
    for knob, definition in GATES[gate].knobs.items():
        if knob not in ask.knobs:
            continue
        blocked_value = set(variant.needs.get(knob, [])) - answered
        if blocked_value:
            return {}, {
                "reason": "gate_unavailable",
                "detail": f"{knob} account conditions are unmet or unanswered: "
                + ", ".join(sorted(blocked_value)),
                "gate": gate,
                "knob": knob,
            }
        wanted = ask.named(knob)
        named = wanted is not None
        offered = variant.knobs.get(knob)
        if definition.only_when_any is not None and not _any_granted(
            grants, definition.only_when_any
        ):
            continue  # compared and granted only when one sibling condition holds
        if definition.only_when is not None and not isinstance(definition.only_when[1], tuple):
            other, needed = definition.only_when
            if not _granted(grants.get(other), needed):
                continue  # compared, and granted, only in the variant where the condition holds
        if definition.kind == NUMBER:
            if wanted is None:
                continue
            asked = wanted[0]
            declared = offered if isinstance(offered, tuple) else None
            if not offers(declared, asked):
                unknown = declared is None or declared[0] == "at_least"
                return {}, {
                    "reason": "knob_unknown" if unknown else "knob_mismatch",
                    "detail": f"{knob}: asked {asked}, declared {variant.raw.get(knob, UNKNOWN)}",
                    "gate": gate,
                    "knob": knob,
                    "asked": asked,
                    "offered": variant.raw.get(knob, UNKNOWN),
                }
            grants[knob] = {"values": [{"value": asked}]}
            continue
        if offered is None:
            if named:
                return {}, {
                    "reason": "knob_unknown",
                    "detail": f"{knob}: asked {wanted}, declared unknown",
                    "gate": gate,
                    "knob": knob,
                    "asked": wanted,
                }
            grants[knob] = {"values": None}  # "any" or silence is not compared, so it fits unknown
            continue
        if not offered and not named:
            return {}, {
                "reason": "knob_mismatch",
                "detail": f"{knob}: the declaration offers no defined value",
                "gate": gate,
                "knob": knob,
            }
        if definition.kind == ALL_OF and wanted is not None:
            missing = set(wanted) - set(offered)
            if missing:
                return {}, {
                    "reason": "knob_mismatch",
                    "detail": f"{knob}: asked all of {wanted}, offers {sorted(offered, key=str)}",
                    "gate": gate,
                    "knob": knob,
                    "asked": wanted,
                    "offered": sorted(offered, key=str),
                }
        accepted = set(offered) & set(wanted) if wanted is not None else set(offered)
        if not accepted:
            return {}, {
                "reason": "knob_mismatch",
                "detail": f"{knob}: asked {wanted}, offers {sorted(offered, key=str)}",
                "gate": gate,
                "knob": knob,
                "asked": wanted,
                "offered": sorted(offered, key=str),
            }
        grants[knob] = {"values": [{"value": value} for value in sorted(accepted, key=str)]}

    limits = variant.limits
    if gate == "network_lockdown":
        switches_to = ask.settings.get("switches_to")
        if ask.knobs.get("switchable") == [True] and isinstance(switches_to, list):
            offered_policies = variant.knobs.get("policy")
            established_policies = set(offered_policies or ())
            missing = set(switches_to) - established_policies
            if missing:
                asked_policies = [ask.knobs["policy"][0], *switches_to]
                return {}, {
                    "reason": "knob_mismatch",
                    "detail": (
                        f"policy: switch targets {sorted(missing)} are not offered by this variant"
                    ),
                    "gate": gate,
                    "knob": "policy",
                    "asked": asked_policies,
                    "offered": variant.raw.get("policy", UNKNOWN),
                }
        policy = ask.knobs["policy"][0]
        listing = {"allowlist": "allow", "denylist": "deny"}.get(policy)
        if listing is not None:
            entries = ask.settings.get(listing) or []
            count_limit = "max_allow" if listing == "allow" else "max_deny"
            if not limit_fits(limits, count_limit, len(entries)):
                return {}, _limit(gate, count_limit, len(entries), limits)
            asked_kinds = {entry_kind(entry, listing) for entry in entries}
            offered_kinds = limits.get("entry_kinds")
            if isinstance(offered_kinds, list) and all(
                isinstance(kind, str) for kind in offered_kinds
            ):
                established_kinds = set(offered_kinds)
                offered_kinds_display: Any = offered_kinds
            else:
                established_kinds = set()
                offered_kinds_display = UNKNOWN
            if not asked_kinds <= established_kinds:
                return {}, {
                    "reason": "limit_exceeded",
                    "detail": (
                        f"entry_kinds {offered_kinds_display} does not cover {sorted(asked_kinds)}"
                    ),
                    "gate": gate,
                    "limit": "entry_kinds",
                    "asked": sorted(asked_kinds),
                    "offered": offered_kinds_display,
                }
            if (
                listing == "allow"
                and any(_allow_entry_has_wildcard(entry) for entry in entries)
                and limits.get("allow_wildcards") is not True
            ):
                return {}, {
                    "reason": "limit_exceeded",
                    "detail": "allow_wildcards is not declared true",
                    "gate": gate,
                    "limit": "allow_wildcards",
                    "asked": True,
                    "offered": limits.get("allow_wildcards", UNKNOWN),
                }
    if gate == "previews":
        ports = ask.settings["ports"]
        if not limit_fits(limits, "max_ports", len(ports)):
            return {}, _limit(gate, "max_ports", len(ports), limits)
        reserved = sorted(variant.reserved_ports & set(ports))
        if reserved:
            return {}, {
                "reason": "limit_exceeded",
                "detail": f"reserved_ports: the provider keeps {reserved} for itself",
                "gate": gate,
                "limit": "reserved_ports",
                "asked": reserved,
                "offered": sorted(variant.reserved_ports),
            }
    if gate == "tcp_ports":
        ports = ask.settings["ports"]
        if not limit_fits(limits, "max_tcp_ports", len(ports)):
            return {}, _limit(gate, "max_tcp_ports", len(ports), limits)
    if gate == "hidden_secrets":
        hosts = ask.settings["inject_into"]
        if not limit_fits(limits, "max_inject_into", len(hosts)):
            return {}, _limit(gate, "max_inject_into", len(hosts), limits)
        if not wildcard_injection_supported(hosts, limits):
            return {}, {
                "reason": "limit_exceeded",
                "detail": "inject_wildcards is not declared true",
                "gate": gate,
                "limit": "inject_wildcards",
                "asked": True,
                "offered": limits.get("inject_wildcards", UNKNOWN),
            }
    if gate == "volumes":
        mounts = ask.settings.get("mounts") or []
        if not limit_fits(limits, "max_mounts", len(mounts)):
            return {}, _limit(gate, "max_mounts", len(mounts), limits)
    return grants, None


def _limit(gate: str, name: str, count: int, limits: Document) -> Failure:
    return {
        "reason": "limit_exceeded",
        "detail": f"{name} {limits.get(name, UNKNOWN)} does not fit {count}",
        "gate": gate,
        "limit": name,
        "asked": count,
        "offered": limits.get(name, UNKNOWN),
    }


def _size_offers(declared: Any, asked: float) -> tuple[bool, Any]:
    """One field of a declared size: a number, or `[min, max]` for a provider that sizes freely.

    A range is provisioned at exactly what was asked, and at its floor where nothing was.
    """
    if isinstance(declared, list) and len(declared) == 2:
        low, high = (number(value) for value in declared)
        if low is None or high is None or high[1] < asked:
            return False, None
        return True, max(asked, low[1])
    return (True, declared) if offers(number(declared), asked) else (False, None)


def size_asks(declaration: Declaration, request: Request) -> tuple[Document, frozenset[str]]:
    """What a size must hold, and the asks it provisions without comparing.

    Unless `disk_in_memory` is `false`, a request that names memory and disk needs memory for
    both; with `true`, the disk is that memory, so `disk_mib` is not compared.
    """
    asks = request.size_asks
    in_memory = declaration.resources.get("disk_in_memory")
    if in_memory is False or not {"memory_min_mib", "disk_min_mib"} <= set(asks):
        return asks, frozenset()
    memory = asks["memory_min_mib"] + asks["disk_min_mib"]
    uncompared = frozenset({"disk_min_mib"} if in_memory is True else ())
    return {**asks, "memory_min_mib": memory}, uncompared


def _fit_size(
    declaration: Declaration, request: Request
) -> tuple[Document, list[tuple[str, Failure]]]:
    asks, uncompared = size_asks(declaration, request)
    if not asks:
        return {}, []
    resources = declaration.resources
    sizes = resources.get("sizes")
    if not isinstance(sizes, list):
        # Nothing about sizing is established, except that a disk-only ask is compared with
        # the provider-wide `disk_mib`.
        if set(asks) == {"disk_min_mib"} and offers(
            number(resources.get("disk_mib")), asks["disk_min_mib"]
        ):
            return {"size": {"disk_mib": resources.get("disk_mib")}}, []
        return {}, [
            _fail(
                "resource",
                "resource_unknown",
                f"sizes: declared {sizes if sizes is not None else UNKNOWN}, asked {asks}",
                resource="sizes",
                asked=asks,
                offered=sizes if sizes is not None else UNKNOWN,
            )
        ]
    for size in sizes:
        if not isinstance(size, dict) or set(size) - SIZE_KEYS:
            continue  # an unrecognised key makes that size "no"
        have = {"disk_mib": resources.get("disk_mib"), **size}
        resolved: Document = dict(size)
        if "disk_min_mib" in asks and "disk_mib" not in resolved:
            resolved["disk_mib"] = have.get("disk_mib")
        for ask, field in SIZE_ASKS.items():
            fits, value = _size_offers(have.get(field), asks.get(ask, 0))
            if not fits and ask in asks and ask not in uncompared:
                break
            if field in resolved and value is not None:
                resolved[field] = value
        else:
            return {"size": resolved}, []
    return {}, [
        _fail(
            "resource",
            "resource_mismatch",
            f"no size offers {asks}"
            + (
                " (memory holds the disk: disk_in_memory is not false)"
                if asks != request.size_asks
                else ""
            ),
            resource="sizes",
            asked=asks,
            offered=sizes,
        )
    ]


def _fit_region(
    declaration: Declaration, want: str, registry: Registry
) -> tuple[Document, list[tuple[str, Failure]]]:
    resources = declaration.resources
    inside = registry.within(want)
    declared = resources.get("regions")
    pinnable = (
        [r for r in declared if registry.knows_region(r)] if isinstance(declared, list) else []
    )
    located = resources.get("located_in")
    if (
        not registry.knows_region(want)
        and isinstance(located, list)
        and located
        and inside is not None
    ):
        if all(isinstance(country, str) and country in inside for country in located):
            return {"region": None}, []  # located_in already satisfies it, so nothing is pinned
    for region in pinnable:
        countries = registry.within(region)
        if region == want or (
            not registry.knows_region(want)
            and countries is not None
            and inside is not None
            and countries <= inside
        ):
            return {"region": region}, []
    # An area or country asked, and the provider offers regions of its own that list no
    # countries: say which, because the registry never infers a country from a name.
    unplaced = [r for r in pinnable if registry.within(r) is None] if inside is not None else []
    detail = (
        f"region: asked {want}, regions {resources.get('regions', UNKNOWN)}, "
        f"located_in {resources.get('located_in', UNKNOWN)}"
    )
    if unplaced:
        names = ", ".join(unplaced)
        detail += (
            f"; {names} lists no countries, so it cannot be shown to lie in {want} "
            f"(the registry never infers a country from a region's name); "
            f"ask region {unplaced[0]!r} to use that provider's own region"
        )
    return {}, [
        _fail(
            "resource",
            "resource_unknown"
            if declared is None or not isinstance(declared, list)
            else "resource_mismatch",
            detail,
            resource="region",
            asked=want,
            offered=resources.get("regions", UNKNOWN),
        )
    ]


def _unmet_ceiling(resources: Document, fact: str, missing: set[str]) -> int | None:
    """The tightest declared ceiling over the unmet conditions of one fact, if each has one.

    A condition without a finite ceiling leaves the fact unanswered, so the fact is refused.
    """
    declared = resources.get("unmet_limits")
    declared = declared.get(fact) if isinstance(declared, dict) else None
    if fact not in UNMET_LIMIT_ASKS or not isinstance(declared, dict):
        return None
    found = [declared.get(condition) for condition in missing]
    if all(isinstance(item, int) and not isinstance(item, bool) and item > 0 for item in found):
        return min(found)  # type: ignore[type-var]
    return None


def fit_resources(
    declaration: Declaration,
    request: Request,
    registry: Registry,
    met_needs: Iterable[str] = (),
) -> tuple[Document, list[tuple[str, Failure]]]:
    """The resources: what gets provisioned, and every check that failed."""
    resources = declaration.resources
    asked = request.resources
    provisioned: Document = {}
    failed: list[tuple[str, Failure]] = []

    needs = resources.get("needs", {})
    asked_facts: set[str] = set()
    if request.lifetime_seconds is not None or request.no_lifetime:
        asked_facts.add("max_lifetime_seconds")
    if any(key in asked for key in ("cpu_min", "memory_min_mib")):
        asked_facts.add("sizes")
    if "disk_min_mib" in asked:
        asked_facts.update({"sizes", "disk_mib"})
    if "region" in asked:
        asked_facts.update({"regions", "located_in"})
    if "gpu_model" in asked or "gpu_count" in asked:
        asked_facts.update({"gpus", "max_gpus"})
    asked_facts.update(
        key for key in ("long_running", "size_is_ceiling", "extendable_lifetime") if asked.get(key)
    )
    asked_facts.update(key for key in PICK_RESOURCES if key in asked)
    asked_facts.update(key for key in ALL_OF_RESOURCES if key in asked)
    asked_facts.update(fact for ask, fact in SECONDS_RESOURCES.items() if ask in asked)
    asked_facts.update(fact for ask, fact in PER_OPERATION_RESOURCES.items() if ask in asked)
    ceilings: dict[str, int] = {}
    for fact in asked_facts:
        conditions = needs.get(fact, []) if isinstance(needs, dict) else []
        missing = set(conditions) - set(met_needs)
        if missing:
            ceiling = _unmet_ceiling(resources, fact, missing)
            if ceiling is not None:
                ceilings[fact] = ceiling
                continue
            failed.append(
                _fail(
                    "resource",
                    "resource_unknown",
                    f"{fact}: account conditions are unmet or unanswered: "
                    f"{', '.join(sorted(missing))}",
                    resource=fact,
                    offered=UNKNOWN,
                )
            )

    for fact, ceiling in sorted(ceilings.items()):
        ask = UNMET_LIMIT_ASKS[fact]
        amount = request.lifetime_seconds if ask == "lifetime_seconds" else asked.get(ask)
        if isinstance(amount, int | float) and amount > ceiling:
            failed.append(
                _fail(
                    "resource",
                    "resource_mismatch",
                    f"{ask} {amount}: {fact} is limited to {ceiling} until "
                    f"{', '.join(sorted(set(needs[fact]) - set(met_needs)))} is met",
                    resource=ask if ask == "lifetime_seconds" else "sizes",
                    asked=amount if ask == "lifetime_seconds" else {ask: amount},
                    offered=ceiling,
                )
            )

    lifetime: Number | None = number(resources.get("max_lifetime_seconds"))
    if request.lifetime_seconds is not None and not offers(lifetime, request.lifetime_seconds):
        # Above an `{at_least: N}` floor nothing is established, as it is for a number knob:
        # "asking for more is unknown" (the format), `resource_unknown` (the reference).
        unknown = lifetime is None or lifetime[0] == "at_least"
        failed.append(
            _fail(
                "resource",
                "resource_unknown" if unknown else "resource_mismatch",
                f"lifetime {request.lifetime_seconds} s: declared max_lifetime_seconds "
                f"{resources.get('max_lifetime_seconds', UNKNOWN)}",
                resource="lifetime_seconds",
                asked=request.lifetime_seconds,
                offered=resources.get("max_lifetime_seconds", UNKNOWN),
            )
        )
    minimum = declaration.lifetime_timer.get("min_seconds")
    if (
        request.lifetime_seconds is not None
        and isinstance(minimum, int)
        and not isinstance(minimum, bool)
        and request.lifetime_seconds < minimum
    ):
        failed.append(
            _fail(
                "resource",
                "resource_mismatch",
                f"lifetime {request.lifetime_seconds} s: declared lifetime_timer min_seconds "
                f"{minimum}",
                resource="lifetime_seconds",
                asked=request.lifetime_seconds,
                offered=minimum,
            )
        )
    if request.no_lifetime and (
        declaration.lifetime_timer or resources.get("max_lifetime_seconds") != "unlimited"
    ):
        declared_max = resources.get("max_lifetime_seconds", UNKNOWN)
        unknown = not declaration.lifetime_timer and declared_max == UNKNOWN
        failed.append(
            _fail(
                "resource",
                "resource_unknown" if unknown else "resource_mismatch",
                "no lifetime: the provider ends sandboxes "
                f"(lifetime_timer {'declared' if declaration.lifetime_timer else 'left out'}, "
                f"max_lifetime_seconds {declared_max})",
                resource="lifetime_seconds",
                asked=None,
                offered=declared_max,
            )
        )
    if request.at_end is not None:
        requested_end = request.at_end
        offered_ends = declaration.lifetime_timer.get("at_end", UNKNOWN)
        offered_ends = offered_ends if isinstance(offered_ends, list) else [offered_ends]
        if (
            declaration.lifetime_timer.get("enforced_by") != "provider"
            or requested_end not in offered_ends
        ):
            failed.append(
                _fail(
                    "resource",
                    "resource_unknown" if offered_ends == [UNKNOWN] else "resource_mismatch",
                    f"at_end: asked {request.at_end}, declared {offered_ends}",
                    resource="at_end",
                    asked=request.at_end,
                    offered=offered_ends,
                )
            )
    size, size_failed = _fit_size(declaration, request)
    provisioned.update(size)
    failed += size_failed

    for flag in ("extendable_lifetime", "long_running", "size_is_ceiling"):
        if asked.get(flag) and resources.get(flag) is not True:
            declared = resources.get(flag, UNKNOWN)
            failed.append(
                _fail(
                    "resource",
                    "resource_mismatch" if declared is False else "resource_unknown",
                    f"{flag}: declared {declared}",
                    resource=flag,
                    asked=True,
                    offered=declared,
                )
            )
    for ask, fact in SECONDS_RESOURCES.items():
        declared_seconds: Number | None = number(resources.get(fact))
        if ask in asked and not offers(declared_seconds, asked[ask]):
            unknown = declared_seconds is None or declared_seconds[0] == "at_least"
            failed.append(
                _fail(
                    "resource",
                    "resource_unknown" if unknown else "resource_mismatch",
                    f"{ask}: asked {asked[ask]}, {fact} declared {resources.get(fact, UNKNOWN)}",
                    resource=ask,
                    asked=asked[ask],
                    offered=resources.get(fact, UNKNOWN),
                )
            )
    for fact, known in PICK_RESOURCES.items():
        if fact not in asked:
            continue
        declared_value = resources.get(fact)
        offered_values = [
            value
            for value in (declared_value if isinstance(declared_value, list) else [declared_value])
            if value in known
        ]
        accepted = [value for value in offered_values if value in asked[fact]]
        if not accepted:
            established = bool(offered_values) or declared_value == []  # `[]` means none
            failed.append(
                _fail(
                    "resource",
                    "resource_mismatch" if established else "resource_unknown",
                    f"{fact}: asked {asked[fact]}, declared {resources.get(fact, UNKNOWN)}",
                    resource=fact,
                    asked=asked[fact],
                    offered=resources.get(fact, UNKNOWN),
                )
            )
        elif fact == "root":
            provisioned["root"] = accepted  # every way the request accepts that is declared
        elif fact in {"arch", "egress_ips"}:
            # The first declared value the request accepts; for `arch`, the default if it fits.
            provisioned[fact] = accepted[0]
    all_of, all_of_failed = fit_all_of_resources(asked, resources, _fail)
    provisioned.update(all_of)
    failed.extend(all_of_failed)
    failed.extend(fit_per_operation_resources(asked, resources, _fail))
    if "region" in asked:
        region, region_failed = _fit_region(declaration, asked["region"], registry)
        provisioned.update(region)
        failed += region_failed
    if request.asks_gpu:
        declared_gpus = resources.get("gpus")
        models = (
            [g for g in declared_gpus if g in registry.gpu_models]
            if isinstance(declared_gpus, list)
            else []
        )
        if "gpu_model" in asked:
            models = [g for g in models if g in asked["gpu_model"]]
        count = asked.get("gpu_count", 1)
        if not models:
            failed.append(
                _fail(
                    "resource",
                    "resource_mismatch" if isinstance(declared_gpus, list) else "resource_unknown",
                    f"gpus: declared {declared_gpus if declared_gpus is not None else UNKNOWN}, "
                    "none fits",
                    resource="gpu_model",
                    asked=asked.get("gpu_model", UNKNOWN),
                    offered=declared_gpus if declared_gpus is not None else UNKNOWN,
                )
            )
        elif not limit_fits(resources, "max_gpus", count):
            entry = _limit("", "max_gpus", count, resources)
            entry.pop("gate", None)
            entry["resource"] = "gpu_count"
            failed.append(("resource", entry))
        else:
            provisioned["gpu"] = {"model": models[0], "count": count}
    return provisioned, failed


def fires(
    conflict: Conflict, source: str, chosen: Grants, request: Request, provisioned: Document
) -> bool:
    """Does one conflict entry fire? A value conflict may narrow another gate's grant instead."""
    if conflict.kind == "gate":
        return conflict.gate in chosen and conflict.gate != source
    if conflict.kind == "resource":
        if conflict.resource == "gpus":
            return request.asks_gpu
        if conflict.resource == "regions":
            return provisioned.get("region") is not None
        return conflict.resource in request.resources  # fact conflicts named by a request
    if conflict.kind == "extra":
        return conflict.extra in request.extras.get(conflict.provider, {})
    if conflict.gate == source or conflict.gate not in chosen:
        return False
    granted = chosen[conflict.gate]["knobs"].get(conflict.knob)
    if granted is None:
        return False  # the knob does not apply in that variant
    if granted["values"] is None:
        return True  # against a knob that is unknown, it fires
    values = granted["values"]
    if not any(value["value"] == conflict.value for value in values):
        return request.is_switch_target(conflict.gate, conflict.knob, conflict.value)
    if len(values) == 1 or GATES[conflict.gate].knobs[conflict.knob].kind == ALL_OF:
        return True  # an all-of grant is every value the request needs, so none can go
    granted["values"] = [value for value in values if value["value"] != conflict.value]
    return False


def combination_conflict(
    declaration: Declaration,
    chosen: Grants,
    request: Request,
    provisioned: Document,
    bound: Sequence[tuple[str, Conflict]],
) -> Failure | None:
    """The chosen variants against each other, the resources, and what a snapshot binds."""
    entries: list[tuple[str, Conflict]] = [
        (gate, conflict)
        for gate, grant in chosen.items()
        for conflict in declaration.gates[gate].variants[grant["variant"]].conflicts
    ]
    for source, conflict in [*entries, *bound]:
        if fires(conflict, source, chosen, request, provisioned):
            return {
                "reason": "conflict",
                "detail": f"{source} conflicts with {conflict.text}",
                "between": [source, conflict.text],
            }
    return None


def _copy(chosen: Grants) -> Grants:
    return {
        gate: {
            "variant": grant["variant"],
            "knobs": {
                knob: {"values": None if value["values"] is None else list(value["values"])}
                for knob, value in grant["knobs"].items()
            },
        }
        for gate, grant in chosen.items()
    }


def _offers_value(variant: Variant, knob: str, value: str | None) -> bool:
    offered = variant.knobs.get(knob)
    return value is None or (isinstance(offered, frozenset) and value in offered)


def restores_from(
    declaration: Declaration, snapshot: Snapshot, available_conditions: Iterable[str]
) -> tuple[Binding, Failure | None]:
    """A restore needs the gate that makes it: today's declaration, on this account.

    One check the request does not write: the provider must still offer a `snapshots` variant
    that keeps what the snapshot keeps. That variant binds the restore, with its conflicts
    and whether it can resize.
    """
    declared = declaration.gates.get("snapshots")
    size = snapshot.get("source_resources")
    if declared is None or not declared.supported:
        return NOTHING_BOUND, {
            "reason": "gate_unsupported",
            "detail": "snapshots: this provider no longer restores",
            "gate": "snapshots",
        }
    keeps = snapshot.get("keeps")
    available = [
        variant
        for variant in declared.variants
        if not variant.unusable
        and not (set(variant.needs.get("variant", [])) - set(available_conditions))
        and not (set(variant.needs.get("keeps", [])) - set(available_conditions))
    ]
    if not available:
        return NOTHING_BOUND, {
            "reason": "gate_unavailable",
            "detail": "snapshots: no variant this account can use",
            "gate": "snapshots",
        }
    fitting = [variant for variant in available if _offers_value(variant, "keeps", keeps)]
    if not fitting:
        return NOTHING_BOUND, {
            "reason": "knob_mismatch",
            "detail": f"snapshots.keeps: the snapshot keeps {keeps}, which no variant offers now",
            "gate": "snapshots",
            "knob": "keeps",
            "asked": keeps,
        }
    return binds("snapshots", fitting[0], size), None


def fits_source_size(
    declaration: Declaration, request: Request, binding: Binding
) -> Failure | None:
    """A restore may ask for a different size only where the variant says it can."""
    (asks, uncompared), source = size_asks(declaration, request), binding.size
    if not asks or binding.resizes:
        return None
    if source is None:
        return {
            "reason": "resource_unknown",
            "detail": "the source's size is not recorded and this variant cannot resize on restore",
            "resource": "sizes",
            "asked": asks,
            "offered": UNKNOWN,
        }
    for ask, field in SIZE_ASKS.items():
        if (
            ask in asks
            and ask not in uncompared
            and not offers(number(source.get(field)), asks[ask])
        ):
            return {
                "reason": "resource_mismatch",
                "detail": f"{ask}: the source was created with {source.get(field, UNKNOWN)} "
                "and this variant cannot resize on restore",
                "resource": ask,
                "asked": asks[ask],
                "offered": source.get(field, UNKNOWN),
            }
    return None


def source_size(source: Document) -> Document:
    """The size a restore's source was created with; a field not recorded as a number is omitted."""
    return {
        field: source[field]
        for field in SIZE_ASKS.values()
        if (recorded := number(source.get(field))) is not None and recorded[0] == "exact"
    }


def match_provider(
    declaration: Declaration,
    request: Request,
    proof: Proof | None,
    *,
    registry: Registry,
    met_needs: Iterable[str] = (),
    binding: Binding = NOTHING_BOUND,
    restore_of: Snapshot | None = None,
    require_baseline: bool = True,
) -> ProviderResult:
    """Fit requested gates/resources; strict callers also require baseline proof."""
    found: list[tuple[str, Failure]] = []
    result: ProviderResult = {
        "provider": declaration.provider,
        "class": declaration.class_name,
        "name": declaration.name,
        "sdk_versions": declaration.sdk_versions,
        "eligible": False,
        "gates": {},
        "resources": {},
        "restores_need": None,
        "failed": [],
    }

    def done(eligible: bool, **fields: Any) -> ProviderResult:
        # Report checks in the spec's order; nested restore checks follow the original request.
        found.sort(key=lambda entry: (bool(entry[1].get("in")), STAGES.index(entry[0])))
        result.update(fields)  # type: ignore[typeddict-item]
        result["eligible"] = eligible
        result["failed"] = [{**entry, "stage": stage} for stage, entry in found]
        return result

    if declaration.unusable:
        found.append(_fail("declaration", "declaration_unusable", declaration.unusable))
        return done(False)
    result["class"] = declaration.resolved_class_name
    if require_baseline and (proof is None or not proof.baseline):
        found.append(
            _fail(
                "baseline",
                "baseline_failed",
                "no newest clean baseline-passing report for this provider, class and SDK set",
            )
        )
    for provider, extras in request.extras.items():
        if provider != declaration.provider:
            found.append(
                _fail(
                    "extra",
                    "extra_mismatch",
                    f"x-{provider} requires another provider",
                    extra=f"x-{provider}",
                )
            )
            continue
        for name, value in extras.items():
            if not same_value(declaration.extras.get(name, object()), value):
                found.append(
                    _fail(
                        "extra",
                        "extra_mismatch",
                        f"x-{provider}.{name} is not offered",
                        extra=f"x-{provider}.{name}",
                    )
                )
    if restore_of is not None:
        binding, why = restores_from(declaration, restore_of, met_needs)
        if why is not None:
            found.append(("gate", why))
    provisioned, resource_failed = fit_resources(declaration, request, registry, met_needs)
    found += resource_failed
    if request.image_provider and request.image_provider != declaration.provider:
        found.append(
            _fail(
                "extra",
                "image_provider_mismatch",
                f"provider_artifact belongs to {request.image_provider}",
                extra="image.provider",
            )
        )
    for gate_ask in request.gates.values():
        for mount in gate_ask.settings.get("mounts", []):
            if mount["provider"] != declaration.provider:
                found.append(
                    _fail(
                        "extra",
                        "volume_provider_mismatch",
                        f"volume belongs to {mount['provider']}",
                        extra="requirements.volumes.mounts",
                    )
                )
    size_failure = fits_source_size(declaration, request, binding)
    if size_failure is not None:
        found.append(("resource", size_failure))
    elif "size" in provisioned and not binding.resizes and binding.size is not None:
        # A restore that cannot resize is provisioned at its source's size, not at the minima.
        provisioned["size"] = source_size(binding.size)

    fitting: dict[str, list[tuple[Variant, dict[str, KnobGrant]]]] = {}
    for gate in (g for g in GATES if g in request.gates):
        declared = declaration.gates.get(gate)
        if declared is None:
            found.append(
                _fail(
                    "gate", "gate_not_listed", f"{gate}: not declared; nobody has looked", gate=gate
                )
            )
            continue
        if not declared.supported:
            found.append(_fail("gate", "gate_unsupported", f"{gate}: unsupported", gate=gate))
            continue
        ask = request.gates[gate]
        fits: list[tuple[Variant, dict[str, KnobGrant]]] = []
        reasons: list[Failure] = []
        for variant in declared.variants:
            grants, why = fit_variant(gate, variant, ask, met_needs)
            if why is None:
                fits.append((variant, grants))
            else:
                reasons.append(why)
        if not fits:
            found.append(
                (
                    "gate",
                    _gate_failure(gate, reasons),
                )
            )
        fitting[gate] = fits
    if found:
        return done(False, resources=provisioned)

    # Gates in table order, the first varying slowest: the first combination that passes every
    # check gives each earlier gate its earliest variant that leaves the later ones a fit.
    conflict: Failure | None = None
    later_failed: list[Failure] | None = None
    for combination in itertools.product(*fitting.values()):
        chosen = _copy(
            {
                gate: {"variant": variant.index, "knobs": grants}
                for gate, (variant, grants) in zip(fitting, combination, strict=True)
            }
        )
        conflict = combination_conflict(
            declaration, chosen, request, provisioned, binding.conflicts
        )
        if conflict is not None:
            continue
        later = _restores_need(
            declaration,
            request,
            proof,
            chosen,
            provisioned,
            registry,
            met_needs,
            require_baseline,
        )
        if isinstance(later, list):
            later_failed = later
            continue
        return done(True, gates=chosen, resources=provisioned, restores_need=later)
    if later_failed is not None:
        found += [(entry.get("stage", "restore"), entry) for entry in later_failed]
    elif conflict is not None:
        found.append(("conflict", conflict))
    return done(False, resources=provisioned)


def _gate_failure(gate: str, reasons: list[Failure]) -> Failure:
    if not reasons:
        return {"reason": "gate_unsupported", "detail": f"{gate}: no variants", "gate": gate}
    first = dict(reasons[0])
    first["detail"] = "; ".join(
        f"variant {index + 1}: {entry['detail']}" for index, entry in enumerate(reasons)
    )
    return first  # type: ignore[return-value]


def _restores_need(
    declaration: Declaration,
    request: Request,
    proof: Proof | None,
    chosen: Grants,
    provisioned: Document,
    registry: Registry,
    met_needs: Iterable[str],
    require_baseline: bool,
) -> dict[str, GateGrant] | list[Failure] | None:
    """The second request: matched on its own, but bound by the snapshots variant chosen here."""
    if request.restores_need is None:
        return None
    variant = declaration.gates["snapshots"].variants[chosen["snapshots"]["variant"]]
    later = match_provider(
        declaration,
        request.restores_need,
        proof,
        registry=registry,
        met_needs=met_needs,
        binding=binds("snapshots", variant, provisioned.get("size")),
        require_baseline=require_baseline,
    )
    if not later["eligible"]:
        return [{**entry, "in": "restores_need"} for entry in later["failed"]]
    return later["gates"]
