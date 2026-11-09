# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""One provider's declaration, as the declaration format writes it, already parsed.

The matcher never reads a file: a caller parses the YAML (refusing a duplicate key) and
hands over the mapping, with the parse error when there was one. A word this module does
not recognise makes its variant, its value or the whole file "no" -- never a silent yes.
"""

# pylint: disable=too-many-branches,too-many-instance-attributes

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any, Literal

from sandbox_provider_spec.check import LIFETIME_TIMER_KEYS
from sandbox_provider_spec.matcher.catalog import (
    DECLARATION_KEYS,
    DECLARATION_RESOURCES,
    FLAG,
    GATES,
    KERNELS,
    NUMBER,
    SPEC_VERSION,
    UNKNOWN,
    UNLIMITED,
    Document,
    Kind,
)

#: A declared number: how much is offered, or None when nothing is established.
Number = tuple[Literal["exact", "at_least", "unlimited"], int | float]
#: A declared knob: the values offered, a number, or None for `unknown`.
Offered = frozenset[Any] | Number | None
CONFLICT_RESOURCES = {
    f"resources.{name}": name
    for name in ("gpus", "regions", "root", "package_manager", "libc", "kernel_features")
}
VALUE_CONFLICT = re.compile(r"([a-z_]+)\.([a-z_]+)=(.+)")
EXTRA_CONFLICT = re.compile(r"x-([a-z0-9-]+)\.([a-z0-9_]+)")


def number(raw: Any) -> Number | None:
    """`unlimited`, a number or `{at_least: N}`; anything else establishes nothing."""
    if isinstance(raw, int | float) and not isinstance(raw, bool):
        if isinstance(raw, float) and not math.isfinite(raw):
            return None
        return ("exact", raw)
    if raw == UNLIMITED:
        return ("unlimited", float("inf"))
    if isinstance(raw, dict) and set(raw) == {"at_least"}:
        floor = raw["at_least"]
        if isinstance(floor, int | float) and not isinstance(floor, bool):
            if isinstance(floor, float) and not math.isfinite(floor):
                return None
            return ("at_least", floor)
    return None


def ports(raw: Any) -> frozenset[int] | None:
    """A list of distinct port numbers, or None when it is anything else."""
    if not isinstance(raw, list) or any(
        not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535
        for port in raw
    ):
        return None
    listed = frozenset(raw)
    return listed if len(listed) == len(raw) else None


def offers(declared: Number | None, asked: float) -> bool:
    return declared is not None and declared[1] >= asked


def offered(kind: Kind, values: tuple[str, ...], raw: Any) -> Offered:
    """What one declared knob offers. Unrecognised values are dropped; nothing left is unknown."""
    if kind == NUMBER:
        return number(raw)
    if raw == UNKNOWN:
        return None
    items = raw if isinstance(raw, list) else [raw]
    known = [i for i in items if (isinstance(i, bool) if kind == FLAG else i in values)]
    return frozenset(known)


@dataclass(frozen=True)
class Conflict:
    """One `conflicts` entry: it works both ways and never routes into itself."""

    kind: Literal["gate", "value", "resource", "extra"]
    text: str
    gate: str = ""
    knob: str = ""
    value: Any = None
    resource: str = ""
    provider: str = ""
    extra: str = ""


def parse_conflict(entry: Any) -> Conflict | None:
    if not isinstance(entry, str):
        return None
    if entry in GATES:
        return Conflict("gate", entry, gate=entry)
    if entry in CONFLICT_RESOURCES:
        return Conflict("resource", entry, resource=CONFLICT_RESOURCES[entry])
    value_match = VALUE_CONFLICT.fullmatch(entry)
    if value_match:
        gate, knob, text = value_match.groups()
        definition = GATES.get(gate)
        if definition and knob in definition.knobs:
            kind, values = definition.knobs[knob].kind, definition.knobs[knob].values
            if kind == NUMBER:
                if text.isdigit() and int(text) > 0:
                    return Conflict("value", entry, gate=gate, knob=knob, value=int(text))
            else:
                value = text == "true" if kind == FLAG else text
                if (kind == FLAG and text in {"true", "false"}) or (
                    kind != FLAG and text in values
                ):
                    return Conflict("value", entry, gate=gate, knob=knob, value=value)
    extra_match = EXTRA_CONFLICT.fullmatch(entry)
    if extra_match:
        provider, name = extra_match.groups()
        return Conflict("extra", entry, provider=provider, extra=name)
    return None


@dataclass
class Variant:
    """One combination of knob answers a provider really offers together."""

    index: int
    knobs: dict[str, Offered] = field(default_factory=dict)
    limits: Document = field(default_factory=dict)
    conflicts: list[Conflict] = field(default_factory=list)
    needs: Document = field(default_factory=dict)
    resizes_on_restore: bool = False
    #: The `reserved_ports` limit: ports a `previews` variant keeps for the provider, which a
    #: request must not list. Left out, none.
    reserved_ports: frozenset[int] = frozenset()
    unusable: str | None = None
    raw: Document = field(default_factory=dict)


@dataclass
class GateDeclaration:
    """A gate the declaration mentions: `unsupported`, or its variants in file order."""

    supported: bool
    variants: list[Variant] = field(default_factory=list)


@dataclass
class Declaration:
    """One provider, or one class of one provider, as its declaration describes it."""

    provider: str
    class_name: str | None = None
    sdk_versions: Document = field(default_factory=dict)
    lifetime_timer: Document = field(default_factory=dict)
    resources: Document = field(default_factory=dict)
    extras: Document = field(default_factory=dict)
    gates: dict[str, GateDeclaration] = field(default_factory=dict)
    unusable: str | None = None

    @property
    def name(self) -> str:
        return f"{self.provider}/{self.class_name}" if self.class_name else self.provider

    @property
    def resolved_class_name(self) -> str:
        """The route class; an omitted class is the provider's `default` class."""
        return "default" if self.class_name is None else self.class_name


def _variant(gate: str, index: int, raw: Any, provider: str, extras: Document) -> Variant:
    definition = GATES[gate]
    variant = Variant(index=index, raw=raw if isinstance(raw, dict) else {})
    if not isinstance(raw, dict):
        variant.unusable = "variant is not a mapping"
        return variant
    for key, value in raw.items():
        if key in definition.knobs:
            knob = definition.knobs[key]
            variant.knobs[key] = offered(knob.kind, knob.values, value)
        elif key == "reserved_ports" and key in definition.limits:
            reserved = ports(value)
            if reserved is None:
                variant.unusable = "reserved_ports is a list of distinct port numbers"
            else:
                variant.reserved_ports = reserved
        elif key in definition.limits:
            variant.limits[key] = value
        elif key == "conflicts":
            for entry in value if isinstance(value, list) else [value]:
                parsed = parse_conflict(entry)
                if parsed is None or (
                    parsed.kind == "extra"
                    and (parsed.provider != provider or parsed.extra not in extras)
                ):
                    variant.unusable = f"unrecognised conflict {entry!r}"
                else:
                    variant.conflicts.append(parsed)
        elif key == "needs":
            if (
                isinstance(value, dict)
                and all(
                    isinstance(conditions, list)
                    and conditions
                    and all(isinstance(c, str) and c for c in conditions)
                    for conditions in value.values()
                )
                and set(value) <= set(definition.knobs) | {"variant"}
            ):
                variant.needs = value
            else:
                variant.unusable = "needs maps values to lists of account conditions"
        elif key == "resizes_on_restore" and key in definition.variant_keys:
            variant.resizes_on_restore = value is True
        else:
            variant.unusable = f"unrecognised key {key!r}"
    if gate == "custom_images" and "prepared" not in variant.knobs:
        variant.knobs["prepared"] = frozenset({False})
    return variant


def build_declaration(
    raw: Any, *, error: str | None = None, provider: str | None = None
) -> Declaration:
    """Normalise one parsed declaration. `error` is the caller's parse failure, if any."""
    if not isinstance(raw, dict) or not isinstance(raw.get("provider"), str):
        return Declaration(
            provider=provider or "unknown", unusable=error or "the file names no provider"
        )
    raw = dict(raw)
    declaration = Declaration(provider=raw["provider"], class_name=raw.get("class"), unusable=error)
    if "class" in raw and not isinstance(raw["class"], str):
        declaration.unusable = declaration.unusable or "class is not a string"
    if raw.get("spec") != SPEC_VERSION:
        declaration.unusable = declaration.unusable or f"unrecognised spec {raw.get('spec')!r}"
    verified = raw.get("verified")
    if (
        not isinstance(verified, dict)
        or not isinstance(verified.get("sdks"), dict)
        or not verified["sdks"]
    ):
        declaration.unusable = declaration.unusable or "verified.sdk versions are required"
    else:
        declaration.sdk_versions = verified["sdks"]
    for key in raw:
        if key.startswith("x-"):
            if key == f"x-{declaration.provider}" and isinstance(raw[key], dict):
                declaration.extras = raw[key]
            else:
                declaration.unusable = declaration.unusable or f"unrecognised extension {key!r}"
        elif key not in DECLARATION_KEYS:
            declaration.unusable = declaration.unusable or f"unrecognised top-level key {key!r}"

    resources_value = raw.get("resources")
    resources: Document = resources_value if isinstance(resources_value, dict) else {}
    declaration.resources = dict(resources)
    if "kernel" in resources:
        kernel = resources["kernel"]
        if not isinstance(kernel, str) or kernel not in (*KERNELS, UNKNOWN):
            declaration.unusable = declaration.unusable or "kernel must be a single boundary"
    resource_needs = resources.get("needs", {})
    if not isinstance(resource_needs, dict) or any(
        name not in DECLARATION_RESOURCES - {"needs", "unmet_limits"}
        or not isinstance(conditions, list)
        or not conditions
        or any(not isinstance(condition, str) or not condition for condition in conditions)
        for name, conditions in resource_needs.items()
    ):
        if "needs" in resources:
            declaration.unusable = declaration.unusable or "resource needs have an invalid shape"
    timer = raw.get("lifetime_timer")
    declaration.lifetime_timer = timer if isinstance(timer, dict) else {}
    if set(declaration.lifetime_timer) - LIFETIME_TIMER_KEYS:
        declaration.lifetime_timer = {}

    gates = raw.get("gates")
    if not isinstance(gates, dict):
        declaration.unusable = declaration.unusable or "gates is not a mapping"
        gates = {}
    for gate, body in gates.items():
        if gate not in GATES:
            continue
        if body == "unsupported":
            declaration.gates[gate] = GateDeclaration(supported=False)
        elif isinstance(body, list):
            declaration.gates[gate] = GateDeclaration(
                supported=True,
                variants=[
                    _variant(gate, i, value, declaration.provider, declaration.extras)
                    for i, value in enumerate(body)
                ],
            )
        else:
            declaration.unusable = declaration.unusable or f"gate {gate!r} has an invalid shape"
    return declaration
