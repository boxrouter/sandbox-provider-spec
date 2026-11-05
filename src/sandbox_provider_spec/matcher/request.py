# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""A request and everything the specification rejects before matching.

A request that survives this module names only words the specification knows, so matching
never has to guess at one. Refusals carry the fix, because "a refusal leads with the fix".
"""

# The checks are the specification's "Rejected before matching" list, in its own order, so a
# reader can hold the two side by side.
# pylint: disable=too-many-branches,too-many-locals,too-many-statements
# pylint: disable=too-many-instance-attributes

from __future__ import annotations

import ipaddress
import json
import math
import re
from dataclasses import dataclass, field
from typing import Any, Literal, TypeGuard

from sandbox_provider_spec.hostnames import HOSTNAME
from sandbox_provider_spec.matcher.catalog import (
    ALL_OF_RESOURCES,
    ANY,
    AT_END,
    FILE_OPERATIONS,
    FLAG,
    GATES,
    IMAGELESS_RESOURCES,
    NUMBER,
    PER_OPERATION_RESOURCES,
    PICK_RESOURCES,
    POLICIES,
    REQUEST_KEYS,
    RESOURCE_ASKS,
    RESTORE_KEYS,
    UNKNOWN,
    WHOLE_NUMBERS,
    YES_RESOURCES,
    Document,
    must_be_named,
)
from sandbox_provider_spec.matcher.registry import Registry
from sandbox_provider_spec.matcher.secret_headers import (
    exact_secret_hosts,
    normalize_header_templates,
)
from sandbox_provider_spec.matcher.secret_hosts import (
    allow_entry_covers_secret_host,
    deny_entry_overlaps_secret_host,
    valid_secret_hostname,
)

Mode = Literal["create", "restore", "restores_need"]

#: Stable reasons for requests refused before matching.
CODES = {
    "knob_not_named": "knob_not_named",
    "unrecognised_word": "unrecognised_word",
    "any_misplaced": "invalid_request",
    "one_value": "invalid_request",
    "empty_list": "invalid_request",
    "setting": "invalid_request",
    "resource_value": "invalid_request",
    "wrong_type": "invalid_request",
    "unknown_as_value": "invalid_request",
}
IPV4_RANGE = re.compile(r"[0-9.]+(?:/[0-9]+)?")
PROVIDER_NAME = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")


class Rejected(Exception):
    """A request the specification refuses before any provider is considered."""

    def __init__(
        self,
        reason: str,
        message: str,
        *,
        path: str | None = None,
        fix: str | None = None,
        details: Document | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message
        self.path = path
        self.fix = fix
        self.details = details or {}

    @property
    def code(self) -> str:
        return CODES[self.reason]


@dataclass(frozen=True)
class GateAsk:
    """One required gate: the knob values accepted, and the settings handed over."""

    #: knob -> the accepted values, or `ANY` for "named on purpose, not compared".
    knobs: dict[str, list[Any] | str]
    settings: Document

    def named(self, knob: str) -> list[Any] | None:
        wanted = self.knobs.get(knob)
        return None if wanted is None or wanted == ANY else list(wanted)

    @property
    def names_a_value(self) -> bool:
        return any(wanted != ANY for wanted in self.knobs.values())


@dataclass(frozen=True)
class Request:
    """A checked request in the specification's vocabulary."""

    lifetime_seconds: int | None = None
    at_end: str | None = None
    gates: dict[str, GateAsk] = field(default_factory=dict)
    extras: dict[str, Document] = field(default_factory=dict)
    resources: Document = field(default_factory=dict)
    image_provider: str | None = None
    restores_need: Request | None = None

    @property
    def asks_gpu(self) -> bool:
        return "gpu_count" in self.resources or "gpu_model" in self.resources

    @property
    def size_asks(self) -> Document:
        return {
            k: v
            for k, v in self.resources.items()
            if k in {"cpu_min", "memory_min_mib", "disk_min_mib"}
        }

    def is_switch_target(self, gate: str, knob: str, value: Any) -> bool:
        if gate != "network_lockdown" or knob != "policy":
            return False
        lockdown = self.gates.get("network_lockdown")
        targets = lockdown.settings.get("switches_to") if lockdown is not None else None
        return (
            lockdown is not None
            and lockdown.knobs.get("switchable") == [True]
            and isinstance(targets, list)
            and value in targets
        )


def is_number(value: Any) -> bool:
    return (
        isinstance(value, int | float)
        and not isinstance(value, bool)
        and (isinstance(value, int) or math.isfinite(value))
    )


def _whole_number(value: Any) -> int | None:
    """Normalize a JSON Schema integer, including a finite float with no fraction."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and math.isfinite(value) and value.is_integer():
        return int(value)
    return None


def not_unknown(where: str, value: Any) -> None:
    """`unknown` is a declaration's word for "not established", never a request value."""
    if value == UNKNOWN:
        raise Rejected(
            "unknown_as_value",
            f'{where}: "unknown" is what a declaration says, not something to ask for',
            path=where,
            fix="leave it out",
        )


def _knob_values(gate: str, knob: str, raw: Any) -> list[Any] | str:
    """One knob of a request: `ANY`, or the list of values the request accepts."""
    definition = GATES[gate].knobs[knob]
    where = f"requirements.{gate}.{knob}"
    if definition.one_value and (raw == ANY or isinstance(raw, list)):
        raise Rejected(
            "one_value",
            f"{where} takes exactly one value",
            path=where,
            fix=f'"{knob}": "{definition.values[0]}"',
        )
    if raw == ANY:
        if not definition.must_be_named:
            raise Rejected(
                "any_misplaced",
                f'{where}: "any" is only for a knob that must be named',
                path=where,
                fix="leave it out",
            )
        return ANY
    not_unknown(where, raw)
    if definition.kind == NUMBER:
        if not is_number(raw) or raw <= 0:
            raise Rejected(
                "wrong_type",
                f"{where} takes how much you need, one positive number",
                path=where,
            )
        return [raw]
    if definition.kind == FLAG:
        if not isinstance(raw, bool):
            raise Rejected("wrong_type", f"{where} is true or false, and never a list", path=where)
        return [raw]
    items = raw if isinstance(raw, list) else [raw]
    if not items:
        raise Rejected("empty_list", f"{where} is an empty list", path=where)
    for item in items:
        if item == ANY:
            raise Rejected(
                "any_misplaced",
                f'{where}: "any" is the whole answer or none of it, never one of a list',
                path=where,
                fix="leave it out",
            )
        not_unknown(where, item)
        if not isinstance(item, str):
            raise Rejected("wrong_type", f"{where}: {item!r} is not a value", path=where)
        if item not in definition.values:
            raise Rejected(
                "unrecognised_word",
                f"{where}: unrecognised value {item!r}",
                path=where,
                details={"word": item, "known": list(definition.values)},
            )
    if len(set(items)) != len(items):
        raise Rejected("setting", f"{where} repeats a value", path=where)
    return list(items)


def entry_kind(entry: Any, name: str = "allow") -> str:
    """What an `allow` or `deny` entry names: `names` or `addresses`, nothing else."""
    where = f"requirements.network_lockdown.{name}"
    if not isinstance(entry, str) or not entry:
        raise Rejected("wrong_type", f"{where}: {entry!r} is not text", path=where)
    if IPV4_RANGE.fullmatch(entry):
        try:
            ipaddress.ip_network(entry, strict=False)
        except ValueError as error:
            raise Rejected(
                "setting", f"{where}: {entry!r} is not an IPv4 range", path=where
            ) from error
        return "addresses"
    if entry.startswith("*.") and name == "deny":
        raise Rejected(
            "setting",
            f"{where}: {entry!r} is a wildcard, and deny takes none",
            path=where,
            fix=f'"{entry[2:]}"',
        )
    host = entry[2:] if entry.startswith("*.") else entry
    if not HOSTNAME.fullmatch(host) or host.replace(".", "").isdigit():
        raise Rejected(
            "setting",
            f"{where}: {entry!r} is not a hostname, *.hostname or IPv4 range "
            "(no ports, paths or IPv6 addresses)",
            path=where,
        )
    return "names"


def _check_settings(gate: str, knobs: dict[str, list[Any] | str], settings: Document) -> None:
    """The settings a gate hands over, and the ones that contradict their knob."""
    where = f"requirements.{gate}"
    if "ports" in GATES[gate].settings:
        ports = settings.get("ports")
        if not isinstance(ports, list) or not ports:
            raise Rejected(
                "setting",
                f"{gate} needs the ports to open",
                path=f"{where}.ports",
                fix='"ports": [3000]',
            )
        normalized_ports = [_whole_number(port) for port in ports]
        if any(port is None or not 1 <= port <= 65535 for port in normalized_ports):
            raise Rejected("wrong_type", f"{gate}.ports holds port numbers", path=f"{where}.ports")
        settings["ports"] = [port for port in normalized_ports if port is not None]
        if len(set(settings["ports"])) != len(settings["ports"]):
            raise Rejected("setting", f"{gate}.ports names one port twice", path=f"{where}.ports")
    if gate == "network_lockdown":
        policy = knobs["policy"][0]
        for name, listing in (("allow", "allowlist"), ("deny", "denylist")):
            entries = settings.get(name)
            if entries is not None and not isinstance(entries, list):
                raise Rejected(
                    "wrong_type", f"network_lockdown.{name} is a list", path=f"{where}.{name}"
                )
            if not policy.startswith(listing):
                if entries is not None:
                    raise Rejected(
                        "setting",
                        f"{name} is used only with an {listing}, not {policy}",
                        path=f"{where}.{name}",
                        fix=f"remove {name}",
                    )
            elif not entries:
                raise Rejected(
                    "setting",
                    f"an {listing} with nothing in it",
                    path=f"{where}.{name}",
                    fix=f'"{name}": ["example.com"]',
                )
            else:
                if any(entry in entries[:index] for index, entry in enumerate(entries)):
                    raise Rejected(
                        "setting", f"{name} names one entry twice", path=f"{where}.{name}"
                    )
                for entry in entries:
                    entry_kind(entry, name)
        has_switches_to = "switches_to" in settings
        switches_to = settings.get("switches_to")
        switchable = knobs.get("switchable")
        uses_open = policy == "open" or (isinstance(switches_to, list) and "open" in switches_to)
        if uses_open and switchable != [True]:
            raise Rejected(
                "setting",
                "open without switchable",
                path=f"{where}.switchable",
                fix='"switchable": true',
            )
        if (switchable == [True] and not has_switches_to) or (
            has_switches_to and switchable is None
        ):
            raise Rejected(
                "setting",
                "switchable without switches_to, or switches_to without switchable",
                path=f"{where}.switches_to",
            )
        if has_switches_to:
            switches_to = settings["switches_to"]
            if not isinstance(switches_to, list):
                raise Rejected(
                    "wrong_type", "switches_to is a list of policies", path=f"{where}.switches_to"
                )
            if not switches_to:
                raise Rejected(
                    "empty_list", "switches_to is an empty list", path=f"{where}.switches_to"
                )
            for item in switches_to:
                if not isinstance(item, str):
                    raise Rejected(
                        "wrong_type",
                        f"switches_to value {item!r} is not a policy",
                        path=f"{where}.switches_to",
                    )
                if item not in POLICIES:
                    raise Rejected(
                        "unrecognised_word",
                        f"switches_to: unrecognised policy {item!r}",
                        path=f"{where}.switches_to",
                        details={"word": item, "known": list(POLICIES)},
                    )
            if len(set(switches_to)) != len(switches_to):
                raise Rejected(
                    "setting", "switches_to repeats a value", path=f"{where}.switches_to"
                )
            if knobs["policy"][0] in switches_to:
                raise Rejected(
                    "setting",
                    "switches_to naming the request's own policy",
                    path=f"{where}.switches_to",
                )
    if gate == "idle_shutdown" and "idle_seconds" in settings:
        idle_seconds = settings["idle_seconds"]
        normalized_idle_seconds = _whole_number(idle_seconds)
        if normalized_idle_seconds is None or normalized_idle_seconds <= 0:
            raise Rejected(
                "wrong_type",
                "idle_seconds is a positive number",
                path=f"{where}.idle_seconds",
            )
        settings["idle_seconds"] = normalized_idle_seconds
        if knobs.get("custom_idle_time") != [True]:
            raise Rejected(
                "setting",
                "idle_seconds without custom_idle_time",
                path=f"{where}.idle_seconds",
                fix='"custom_idle_time": true',
            )
    if gate == "volumes" and "mounts" in settings:
        mounts = settings["mounts"]
        if not isinstance(mounts, list) or not mounts:
            raise Rejected(
                "wrong_type", "volumes.mounts is a non-empty list", path=f"{where}.mounts"
            )
        for index, mount in enumerate(mounts):
            path = f"{where}.mounts.{index}"
            required = {"provider", "volume", "path"}
            if (
                not isinstance(mount, dict)
                or not required <= set(mount)
                or set(mount) - required - {"read_only"}
            ):
                raise Rejected(
                    "wrong_type",
                    "each volume mount has provider, volume and path, and optional read_only",
                    path=path,
                )
            if not all(isinstance(mount[key], str) and mount[key] for key in required):
                raise Rejected("wrong_type", "each volume mount field is non-empty text", path=path)
            if "read_only" in mount and not isinstance(mount["read_only"], bool):
                raise Rejected(
                    "wrong_type",
                    "volumes.mounts.read_only is a boolean",
                    path=f"{path}.read_only",
                )
            if mount.get("read_only") is True and knobs.get("read_only_mounts") != [True]:
                raise Rejected(
                    "setting",
                    "read_only on a mount unless read_only_mounts is true",
                    path=f"{path}.read_only",
                    fix='"read_only_mounts": true',
                )
            if not PROVIDER_NAME.fullmatch(mount["provider"]):
                raise Rejected("wrong_type", "mount provider is a provider name", path=path)
            if not mount["path"].startswith("/"):
                raise Rejected("setting", "a volume mount path is absolute", path=f"{path}.path")
        keys = [(mount["provider"], mount["volume"], mount["path"]) for mount in mounts]
        if len(set(keys)) != len(keys):
            raise Rejected("setting", "volumes.mounts repeats a mount", path=f"{where}.mounts")
    if gate == "hidden_secrets" and "inject_into" in settings:
        destinations = settings["inject_into"]
        if not isinstance(destinations, list) or not destinations:
            raise Rejected(
                "wrong_type",
                "hidden_secrets.inject_into is a non-empty list of host names",
                path=f"{where}.inject_into",
            )
        if len(set(map(str, destinations))) != len(destinations):
            raise Rejected(
                "setting",
                "hidden_secrets.inject_into repeats a host",
                path=f"{where}.inject_into",
            )
        for host in destinations:
            if not valid_secret_hostname(host):
                raise Rejected(
                    "setting",
                    f"{where}.inject_into entries are host names: {host!r}",
                    path=f"{where}.inject_into",
                )
    if gate == "hidden_secrets" and "inject_into" not in settings:
        raise Rejected(
            "setting",
            "hidden_secrets needs inject_into host names",
            path=f"{where}.inject_into",
        )
    if gate == "hidden_secrets":
        selected_headers = "headers" in settings
        declares_templates = knobs.get("header_templates") == [True]
        if selected_headers and not declares_templates:
            raise Rejected(
                "setting",
                "hidden_secrets.headers needs header_templates: true",
                path=f"{where}.header_templates",
                fix='"header_templates": true',
            )
        if declares_templates and not selected_headers:
            raise Rejected(
                "setting",
                "hidden_secrets.header_templates needs headers",
                path=f"{where}.headers",
                fix='"headers": [{"name": "Authorization"}]',
            )
        if selected_headers:
            if knobs.get("injection") != ["sets_header"]:
                raise Rejected(
                    "setting",
                    "hidden_secrets.headers needs injection: sets_header",
                    path=f"{where}.injection",
                    fix='"injection": "sets_header"',
                )
            normalized, error = normalize_header_templates(settings["headers"])
            if error is not None:
                raise Rejected("setting", error, path=f"{where}.headers")
            settings["headers"] = normalized
            if not exact_secret_hosts(settings.get("inject_into")):
                raise Rejected(
                    "setting",
                    "hidden_secrets.headers needs non-empty exact DNS hosts in inject_into",
                    path=f"{where}.inject_into",
                )
    if gate == "volumes" and "mounts" not in settings:
        raise Rejected("setting", "volumes needs mounts", path=f"{where}.mounts")
    if gate == "custom_images" and "image" in settings:
        source = knobs.get("source")
        if isinstance(source, list) and len(source) > 1:
            raise Rejected(
                "setting",
                f"image is one image, and {source} are different kinds of name",
                path=f"{where}.image",
                fix=f'"source": "{source[0]}"',
            )


def _gate_ask(gate: str, body: Any) -> GateAsk:
    if not isinstance(body, dict):
        raise Rejected("wrong_type", f"{gate} takes an object", path=f"requirements.{gate}")
    definition = GATES[gate]
    knobs: dict[str, list[Any] | str] = {}
    settings: Document = {}
    for key, raw in body.items():
        if key in definition.knobs:
            knobs[key] = _knob_values(gate, key, raw)
        elif key in definition.settings:
            settings[key] = raw
        else:
            raise Rejected(
                "unrecognised_word",
                f"{gate}.{key} is not one of its knobs or settings",
                path=f"requirements.{gate}.{key}",
                details={"word": key, "known": [*definition.knobs, *definition.settings]},
            )
    required = must_be_named(gate)
    if required and required not in knobs:
        example = (
            GATES[gate].knobs[required].values[0] if GATES[gate].knobs[required].one_value else ANY
        )
        raise Rejected(
            "knob_not_named",
            f"{gate}.{required} must be named",
            path=f"requirements.{gate}.{required}",
            fix=f'"{gate}": {{"{required}": "{example}"}}',
            details={"gate": gate, "knob": required},
        )
    for knob, definition_of in GATES[gate].knobs.items():
        condition = definition_of.only_when
        if condition is None or knob not in knobs:
            continue
        other, needed = condition
        held = knobs.get(other)
        if isinstance(needed, tuple):
            # Refused only when the request names that knob and none of its values is one.
            holds = not isinstance(held, list) or any(value in needed for value in held)
        elif definition_of.only_when_exact:
            holds = held == [needed]
        else:
            holds = isinstance(held, list) and needed in held
        if not holds:
            example = needed[0] if isinstance(needed, tuple) else needed
            raise Rejected(
                "setting",
                f"{gate}.{knob} without {other}: {json.dumps(needed)}",
                path=f"requirements.{gate}.{knob}",
                fix=f'"{other}": {json.dumps(example)}',
            )
    for knob, definition_of in GATES[gate].knobs.items():
        conditions = definition_of.only_when_any
        if conditions is None or knob not in knobs:
            continue
        if not any(knobs.get(other) == [needed] for other, needed in conditions):
            alternatives = " or ".join(
                f"{other}: {json.dumps(needed)}" for other, needed in conditions
            )
            raise Rejected(
                "setting",
                f"{gate}.{knob} needs one of {alternatives}",
                path=f"requirements.{gate}.{knob}",
            )
    _check_settings(gate, knobs, settings)
    return GateAsk(knobs=knobs, settings=settings)


def _resource(key: str, raw: Any) -> Any:
    where = f"resources.{key}"
    if raw is False or (is_number(raw) and raw == 0):
        raise Rejected(
            "resource_value",
            f"{key} set to false or zero: say what you need and leave the rest out",
            path=where,
        )
    not_unknown(where, raw)
    if key in WHOLE_NUMBERS:
        whole = _whole_number(raw)
        if whole is None or whole < 1:
            raise Rejected("wrong_type", f"{key} is a whole number of at least 1", path=where)
        return whole
    if key in PER_OPERATION_RESOURCES:
        return _per_operation(key, raw)
    if key in {"cpu_min", "paused_retention_seconds"}:
        if not is_number(raw) or raw <= 0:
            raise Rejected("wrong_type", f"{key} is a positive number", path=where)
        return raw
    if key in YES_RESOURCES:
        if raw is not True:
            raise Rejected("wrong_type", f"{key} can only be asked for as true", path=where)
        return True
    if key in ALL_OF_RESOURCES and not isinstance(raw, list):
        raise Rejected("wrong_type", f"{key} is a list of required features", path=where)
    if key == "region":
        if isinstance(raw, list):
            raise Rejected(
                "resource_value", "region is one region, area or country, not a list", path=where
            )
        if not isinstance(raw, str):
            raise Rejected("wrong_type", f"region: {raw!r} is not a place", path=where)
        if not raw:
            raise Rejected("wrong_type", "region is non-empty text", path=where)
        return raw
    items = raw if isinstance(raw, list) else [raw]
    if not items:
        raise Rejected("empty_list", f"{key} is an empty list", path=where)
    for item in items:
        not_unknown(where, item)
        if not isinstance(item, str):
            raise Rejected("wrong_type", f"{key}: {item!r} is not a value", path=where)
        if not item:
            raise Rejected("wrong_type", f"{key} values are non-empty text", path=where)
        allowed = PICK_RESOURCES.get(key, ALL_OF_RESOURCES.get(key))
        if allowed is not None and item not in allowed:
            raise Rejected(
                "unrecognised_word",
                f"{key}: unrecognised value {item!r}",
                path=where,
                details={"word": item, "known": list(allowed)},
            )
    if len(set(items)) != len(items):
        raise Rejected("setting", f"{key} repeats a value", path=where)
    return list(items)


def _per_operation(key: str, raw: Any) -> dict[str, int]:
    """`{read: N, write: N}`: a whole number of bytes for each direction the program uses."""
    where = f"resources.{key}"
    if not isinstance(raw, dict):
        raise Rejected("wrong_type", f"{key} is an object with read or write", path=where)
    if not raw:
        raise Rejected("setting", f"{key} names neither read nor write", path=where)
    asked: dict[str, int] = {}
    for operation, value in raw.items():
        if operation not in FILE_OPERATIONS:
            raise Rejected(
                "unrecognised_word",
                f"{key}: unrecognised direction {operation!r}",
                path=f"{where}.{operation}",
                details={"word": operation, "known": list(FILE_OPERATIONS)},
            )
        not_unknown(f"{where}.{operation}", value)
        whole = _whole_number(value)
        if whole is None or whole < 1:
            raise Rejected(
                "wrong_type", f"{key}.{operation} is a whole number of at least 1", path=where
            )
        asked[operation] = whole
    return asked


def _provider_artifact_image(image: Any) -> TypeGuard[dict[str, str]]:
    return (
        isinstance(image, dict)
        and set(image) == {"provider_artifact", "provider"}
        and isinstance(image["provider_artifact"], str)
        and bool(image["provider_artifact"])
        and isinstance(image["provider"], str)
        and bool(PROVIDER_NAME.fullmatch(image["provider"]))
    )


def _private_oci_image(image: Any) -> TypeGuard[dict[str, str]]:
    return (
        isinstance(image, dict)
        and set(image) == {"private_oci"}
        and isinstance(image["private_oci"], str)
        and bool(image["private_oci"])
    )


def validate_request(
    raw: Any,
    *,
    registry: Registry | None = None,
    mode: Mode = "create",
) -> Request:
    """Check one request against the specification, or raise `Rejected`.

    A restore is selected by its caller with a snapshot record and takes the same request
    fields except `image`, because the snapshot supplies the environment. A `restores_need`
    describes future restores with `requirements`, `resources` and `lifetime_seconds` only.
    """
    registry = registry or Registry()
    if not isinstance(raw, dict):
        raise Rejected("wrong_type", "a request is an object")
    allowed = REQUEST_KEYS - ({"image"} if mode == "restore" else set())
    if mode == "restores_need":
        allowed = RESTORE_KEYS
    for key in raw:
        if key not in allowed:
            raise Rejected(
                "unrecognised_word",
                f"unrecognised request key {key!r}",
                path=key,
                details={"word": key, "known": sorted(allowed)},
            )
    lifetime = raw.get("lifetime_seconds")
    if lifetime is not None:
        normalized_lifetime = _whole_number(lifetime)
        if normalized_lifetime is None or normalized_lifetime < 1:
            raise Rejected(
                "wrong_type",
                "lifetime_seconds is a whole number of seconds, at least 1",
                path="lifetime_seconds",
            )
        lifetime = normalized_lifetime
    at_end = raw.get("at_end")
    if at_end is not None:
        not_unknown("at_end", at_end)
    if at_end is not None and at_end not in AT_END:
        if not isinstance(at_end, str):
            raise Rejected("wrong_type", f"at_end: {at_end!r} is not an ending", path="at_end")
        raise Rejected(
            "unrecognised_word",
            f"unrecognised at_end {at_end!r}",
            path="at_end",
            details={"word": at_end, "known": list(AT_END)},
        )

    requirements = raw.get("requirements", {})
    if not isinstance(requirements, dict):
        raise Rejected("wrong_type", "requirements is an object", path="requirements")
    gates: dict[str, GateAsk] = {}
    image_knobs: dict[str, list[Any] | str] | None = None
    extras: dict[str, Document] = {}
    for name, body in requirements.items():
        if not isinstance(name, str):
            raise Rejected("wrong_type", "requirement names are strings", path="requirements")
        if name.startswith("x-"):
            provider = name[2:]
            if not PROVIDER_NAME.fullmatch(provider):
                raise Rejected("wrong_type", f"{name!r} is not a provider extension", path=name)
            if not isinstance(body, dict):
                raise Rejected(
                    "wrong_type",
                    f"{name} takes an object of extras",
                    path=f"requirements.{name}",
                )
            extras[name[2:]] = body
        elif name == "custom_images":
            # The image is the top-level `image`, and its kind is the source compared; here a
            # request names only the gate's other knobs.
            for key in ("source", "image"):
                if isinstance(body, dict) and key in body:
                    raise Rejected(
                        "setting",
                        f"custom_images.{key} under requirements: the request's top-level image "
                        "gives it",
                        path=f"requirements.custom_images.{key}",
                        fix=f"remove {key}",
                    )
            image_body = dict(body) if isinstance(body, dict) else body
            if isinstance(image_body, dict) and "build_context" in image_body:
                image = raw.get("image")
                if not isinstance(image, dict) or "dockerfile" not in image:
                    raise Rejected(
                        "setting",
                        "custom_images.build_context without a Dockerfile image",
                        path="requirements.custom_images.build_context",
                    )
                image_body["source"] = "dockerfile"
            image_knobs = _gate_ask(name, image_body).knobs
        elif name in GATES:
            gates[name] = _gate_ask(name, body)
        else:
            raise Rejected(
                "unrecognised_word",
                f"unrecognised gate {name!r}",
                path=f"requirements.{name}",
                details={"word": name, "known": list(GATES)},
            )
    if at_end == "paused" and "pause_resume" not in gates:
        raise Rejected(
            "setting",
            "at_end: paused without pause_resume",
            path="at_end",
            fix='"pause_resume": {}',
        )
    previews = gates.get("previews")
    if (
        previews is not None
        and "survives_pause" in previews.knobs
        and not {"pause_resume", "idle_shutdown"} & set(gates)
    ):
        raise Rejected(
            "setting",
            "survives_pause in a request that names neither pause_resume nor idle_shutdown",
            path="requirements.previews.survives_pause",
            fix='"pause_resume": {}',
        )

    asked = raw.get("resources", {})
    if not isinstance(asked, dict):
        raise Rejected("wrong_type", "resources is an object", path="resources")
    resources: Document = {}
    for key, value in asked.items():
        if key not in RESOURCE_ASKS:
            raise Rejected(
                "unrecognised_word",
                f"unrecognised resource {key!r}",
                path=f"resources.{key}",
                details={"word": key, "known": list(RESOURCE_ASKS)},
            )
        resources[key] = _resource(key, value)
    if resources.get("long_running") and "idle_shutdown" in gates:
        raise Rejected(
            "setting", "idle_shutdown together with long_running", path="resources.long_running"
        )

    image_provider = None
    if "image" in raw:
        image = raw["image"]
        if mode == "restore":
            raise Rejected("setting", "a restore takes its image from the snapshot", path="image")
        if isinstance(image, str) and image:
            source, image_value = "oci", image
        elif (
            isinstance(image, dict)
            and set(image) == {"dockerfile"}
            and isinstance(image["dockerfile"], str)
            and image["dockerfile"]
        ):
            source, image_value = "dockerfile", image["dockerfile"]
        elif _private_oci_image(image):
            source, image_value = "private_oci", image["private_oci"]
        elif _provider_artifact_image(image):
            source, image_value = "provider_artifact", image["provider_artifact"]
            image_provider = image["provider"]
        else:
            raise Rejected(
                "wrong_type", "image is an OCI reference or a documented image object", path="image"
            )
        if source not in GATES["custom_images"].knobs["source"].values:
            raise Rejected(
                "unrecognised_word",
                f"custom_images.source {source!r} is not defined",
                path="image",
                details={
                    "word": source,
                    "known": list(GATES["custom_images"].knobs["source"].values),
                },
            )
        named = sorted(IMAGELESS_RESOURCES & set(resources))
        if named:
            raise Rejected(
                "setting",
                f"{', '.join(named)} describe a sandbox created without an image; an image "
                "decides them itself",
                path=f"resources.{named[0]}",
                fix=f"remove {', '.join(named)}",
            )
        gates["custom_images"] = GateAsk(
            {"source": [source], "prepared": [False], **(image_knobs or {})},
            {"image": image_value},
        )
    elif image_knobs is not None:
        raise Rejected(
            "setting",
            "custom_images under requirements without an image",
            path="requirements.custom_images",
            fix='"image": "debian:stable"',
        )
    if "hidden_secrets" in gates and "network_lockdown" in gates:
        # An allowlist must name each destination; a denylist must not cover it. open lets every
        # name through; deny_all lets none through. This checks only the starting policy.
        destinations = gates["hidden_secrets"].settings.get("inject_into", [])
        lockdown = gates["network_lockdown"]
        policy = lockdown.knobs["policy"][0]
        for host in destinations:
            if policy == "open":
                shut_out = False
            elif policy == "denylist":
                shut_out = any(
                    entry_kind(entry, "deny") == "names"
                    and deny_entry_overlaps_secret_host(entry.lower(), host.lower())
                    for entry in lockdown.settings["deny"]
                )
            elif policy == "allowlist":
                secret_is_allowed = any(
                    allow_entry_covers_secret_host(pattern.lower(), host.lower())
                    for pattern in lockdown.settings["allow"]
                    if entry_kind(pattern, "allow") == "names"
                )
                shut_out = not secret_is_allowed
            else:
                shut_out = True
            if shut_out:
                raise Rejected(
                    "setting",
                    f"hidden secret destination {host!r} is not let through by name "
                    f"by network_lockdown {policy}",
                    path="requirements.hidden_secrets.inject_into",
                )

    pins = set(extras)
    if image_provider is not None:
        pins.add(image_provider)
    volume_ask = gates.get("volumes")
    if volume_ask is not None:
        pins.update(mount["provider"] for mount in volume_ask.settings.get("mounts", []))
    if len(pins) > 1:
        raise Rejected(
            "setting",
            "request pins to more than one provider",
            path="requirements",
            details={"providers": sorted(pins)},
        )

    restores_need = None
    if "restores_need" in raw:
        if "snapshots" not in gates:
            raise Rejected(
                "setting",
                "restores_need without snapshots: nothing would take the snapshots it describes",
                path="restores_need",
                fix='"snapshots": {"original_after": "any"}',
            )
        try:
            restores_need = validate_request(
                raw["restores_need"], registry=registry, mode="restores_need"
            )
        except Rejected as error:
            error.path = f"restores_need.{error.path}" if error.path else "restores_need"
            raise
    return Request(
        lifetime_seconds=lifetime,
        at_end=at_end,
        gates=gates,
        extras=extras,
        resources=resources,
        image_provider=image_provider,
        restores_need=restores_need,
    )
