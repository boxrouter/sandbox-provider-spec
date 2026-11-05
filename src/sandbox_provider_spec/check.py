# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Validate a Sandbox Provider Specification request, declaration or conformance report."""

from __future__ import annotations

# pylint: disable=too-many-lines
import ipaddress
import json
import math
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Final, TypeGuard

from jsonschema import Draft202012Validator, FormatChecker

from sandbox_provider_spec.document_cache import cached_load
from sandbox_provider_spec.evidence import check_evidence, check_report_evidence
from sandbox_provider_spec.hostnames import HOSTNAME
from sandbox_provider_spec.load import load

MISSING_KNOB = "a missing must-be-named knob"
EMPTY_LIST = "an empty list"
ALLOW_DENY = "allow with anything but an allowlist, or deny with anything but a denylist"
ALLOWLIST_EMPTY = "an allowlist or a denylist with nothing in it"
ALLOW_ENTRY = (
    "an allow or deny entry that is neither a host name nor an IPv4 address or range, or has a "
    "port, path or IPv6 address"
)
DENY_WILDCARD = "a wildcard in deny"
NO_PORTS = "previews or tcp_ports with no ports"
DUPLICATE = "duplicate ports, allowlist or denylist entries"
SECRET_HOST = (
    "an inject_into host an allowlist does not list or cover by name, a denylist lists or covers "
    "by name, or with deny_all; a wildcard host needs the same or a parent wildcard allowlist, "
    "and a denylist must not block any name under it"
)
CREDENTIAL = "credential on previews when private is not among the accepted access values"
IDLE_SECONDS = "idle_seconds without custom_idle_time"
CHANGEABLE_DENY_ALL_OR_OPEN = "changeable with deny_all or open"
OPEN_WITHOUT_SWITCHABLE = "open without switchable"
SWITCHABLE_SETTING = "switchable without switches_to, or switches_to without switchable"
SWITCHES_TO_OWN_POLICY = "switches_to naming the request's own policy"
WAKE_DESTROYED = "auto_wake with on_idle naming only destroyed"
SURVIVES_PAUSE = "survives_pause in a request that names neither pause_resume nor idle_shutdown"
CUSTOM_IMAGES = "source under requirements, or custom_images under requirements without an image"
READ_ONLY_MOUNT = "read_only on a mount unless read_only_mounts is true"
REPEATED_MOUNT = "volumes.mounts repeats a mount"
WITH_IMAGE = "root, package_manager, libc or kernel_features together with an image"
IDLE_ALWAYS = "idle_shutdown together with long_running"
AT_END_PAUSE = "at_end: paused without pause_resume"
RESOURCE_FALSE = "a resource set to false or zero"
ANY_KNOB = '"any" on a knob that need not be named'
ANY_IN_LIST = '"any" inside a list'
RESTORES_NEED_SNAPSHOTS = "a restores_need whose request does not name snapshots"
UNKNOWN_WORD = "any word the spec does not define"
UNKNOWN_KEY = "unknown key"
UNKNOWN_IN_LIST = "unknown inside a list"

#: The facts that can carry an `unmet_limits` ceiling, each with the request ask it bounds.
UNMET_LIMIT_ASKS: Final = {"max_lifetime_seconds": "lifetime_seconds", "disk_mib": "disk_min_mib"}

#: The keys a declaration's `lifetime_timer` block may carry.
LIFETIME_TIMER_KEYS: Final = frozenset(
    {
        "enforced_by",
        "counts_paused_time",
        "at_end",
        "adjustable",
        "step_seconds",
        "counts_from",
        "min_seconds",
        "after_resume",
    }
)


@dataclass(frozen=True)
class Result:
    """One check. ``kernel`` is the value a declaration reads as after the citation rule."""

    kind: str
    errors: list[str]
    warnings: list[str]
    kernel: Any = None


def spec_dir() -> Path:
    """Directory that holds catalog.yaml: the repository's spec/, or the wheel's data files."""
    here = Path(__file__).resolve().parent
    source = here.parents[1] / "spec"
    if (source / "catalog.yaml").is_file():
        return source
    data = here / "data"
    if (data / "catalog.yaml").is_file():
        return data
    raise FileNotFoundError("catalog.yaml is neither in spec/ nor in the package data")


def load_catalog() -> dict[str, Any]:
    """The catalog. catalog.yaml is the source; catalog.json must match it.

    Each call reads the file and returns a new document the caller may change.
    """
    catalog: dict[str, Any] = cached_load(spec_dir() / "catalog.yaml")
    return catalog


def catalog_documents_differ() -> bool:
    """True when the published catalog.json is not the catalog.yaml document."""
    root = spec_dir()
    yaml_doc = load(root / "catalog.yaml")
    json_doc = json.loads((root / "catalog.json").read_text(encoding="utf-8"))
    return bool(yaml_doc != json_doc)


def check_catalog() -> list[str]:
    """Check catalog structure and require its YAML and JSON forms to agree."""
    root = spec_dir()
    catalog = load(root / "catalog.yaml")
    errors = schema_errors(catalog, "catalog-schema.json")
    if catalog_documents_differ():
        errors.append("catalog.yaml and catalog.json differ")
    return errors


def _schema(name: str) -> dict[str, Any]:
    schema: dict[str, Any] = json.loads((spec_dir() / name).read_text(encoding="utf-8"))
    return schema


def schema_errors(document: Any, schema_name: str) -> list[str]:
    """JSON Schema messages for one document. Empty when it validates."""
    validator = Draft202012Validator(_schema(schema_name), format_checker=FormatChecker())
    messages: list[str] = []
    for error in sorted(validator.iter_errors(document), key=lambda item: list(item.path)):
        loc = ".".join(str(part) for part in error.path) or "(root)"
        messages.append(f"schema: {loc}: {error.message}")
    return messages


def _registries() -> dict[str, set[str]]:
    registries = spec_dir() / "registries"
    regions = load(registries / "regions.json")
    gpus = load(registries / "gpu-models.json")
    return {
        "regions": set(regions["regions"]),
        "areas": set(regions["areas"]),
        "countries": set(regions["countries"]),
        "gpus": set(gpus["gpu_models"]),
    }


def _is_number(value: Any) -> TypeGuard[int | float]:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _is_finite_number(value: Any) -> TypeGuard[int | float]:
    return _is_number(value) and (isinstance(value, int) or math.isfinite(value))


def _nonfinite_request_numbers(value: Any, path: tuple[str, ...] = ()) -> list[str]:
    """Find non-finite numbers in common request fields, leaving extensions opaque."""
    if isinstance(value, float) and not math.isfinite(value):
        return [".".join(path) or "(root)"]
    if isinstance(value, dict):
        found: list[str] = []
        for key, item in value.items():
            if (
                path
                and path[-1] == "requirements"
                and isinstance(key, str)
                and key.startswith("x-")
            ):
                continue
            found.extend(_nonfinite_request_numbers(item, (*path, str(key))))
        return found
    if isinstance(value, list):
        return [
            field_path
            for index, item in enumerate(value)
            for field_path in _nonfinite_request_numbers(item, (*path, str(index)))
        ]
    return []


def _items(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def _zero_or_false(value: Any) -> bool:
    return value is False or (_is_number(value) and value == 0)


def check_request(
    document: Any,
    catalog: dict[str, Any] | None = None,
    *,
    in_restores_need: bool = False,
    in_restore: bool = False,
) -> list[str]:
    """Rejected-before-matching failures. Each item names its condition."""
    catalog = load_catalog() if catalog is None else catalog
    if not isinstance(document, dict):
        return [f"{UNKNOWN_WORD}: (root)"]
    nonfinite = _nonfinite_request_numbers(document)
    if nonfinite:
        return [f"request: {path}: number must be finite" for path in nonfinite]
    errors: list[str] = []
    allowed = set(catalog["restores_need_keys"] if in_restores_need else catalog["request_keys"])
    for key in document:
        if key not in allowed:
            errors.append(f"{UNKNOWN_WORD}: {key}")
    if "at_end" in document and document["at_end"] not in catalog["at_end"]:
        errors.append(f"{UNKNOWN_WORD}: at_end")
    requirements = document.get("requirements") or {}
    if "requirements" in document and not isinstance(requirements, dict):
        errors.append(f"{UNKNOWN_WORD}: requirements")
        requirements = {}
    if document.get("at_end") == "paused" and "pause_resume" not in requirements:
        errors.append(AT_END_PAUSE)
    if _zero_or_false(document.get("lifetime_seconds")) and "lifetime_seconds" in document:
        errors.append(RESOURCE_FALSE)
    _check_resources(document.get("resources"), requirements, catalog, errors)
    resources = document.get("resources")
    if "image" in document and isinstance(resources, dict):
        for key in ("root", "package_manager", "libc", "kernel_features"):
            if key in resources:
                errors.append(f"{WITH_IMAGE}: resources.{key}")
    if isinstance(requirements, dict):
        if "custom_images" in requirements and "image" not in document:
            errors.append(f"{CUSTOM_IMAGES}: no image")
        custom_images = requirements.get("custom_images")
        if isinstance(custom_images, dict) and "build_context" in custom_images:
            image = document.get("image")
            if not isinstance(image, dict) or "dockerfile" not in image:
                errors.append("custom_images.build_context without a Dockerfile image")
        previews = requirements.get("previews")
        if (
            isinstance(previews, dict)
            and "survives_pause" in previews
            and not {"pause_resume", "idle_shutdown"} & set(requirements)
        ):
            errors.append(SURVIVES_PAUSE)
    restoring = in_restore or in_restores_need
    if isinstance(requirements, dict):
        for gate, body in requirements.items():
            if isinstance(gate, str) and gate.startswith("x-"):
                if not isinstance(body, dict):
                    errors.append(f"{UNKNOWN_WORD}: {gate}")
                continue
            if gate not in catalog["gates"]:
                errors.append(f"{UNKNOWN_WORD}: {gate}")
                continue
            if restoring and gate == "custom_images":
                errors.append(f"{UNKNOWN_WORD}: custom_images on a restore")
            _check_gate(gate, body, catalog, errors)
    _check_provider_pins(document, requirements, errors)
    _check_secret_destinations(requirements, errors)
    if "restores_need" in document and not in_restores_need:
        if "snapshots" not in requirements:
            errors.append(RESTORES_NEED_SNAPSHOTS)
        nested = document["restores_need"]
        if not isinstance(nested, dict):
            errors.append(f"{UNKNOWN_WORD}: restores_need")
        else:
            for nested_error in check_request(nested, catalog, in_restores_need=True):
                errors.append(f"restores_need: {nested_error}")
    if errors:
        return errors
    schema = "request-schema.json"
    return schema_errors(document, schema)


def _check_resources(
    resources: Any,
    requirements: Any,
    catalog: dict[str, Any],
    errors: list[str],
) -> None:
    if resources is None:
        resources = {}
    if not isinstance(resources, dict):
        errors.append(f"{UNKNOWN_WORD}: resources")
        return
    for key, value in resources.items():
        if key not in catalog["resources"]:
            errors.append(f"{UNKNOWN_WORD}: resources.{key}")
            continue
        if _zero_or_false(value):
            errors.append(RESOURCE_FALSE)
            continue
        spec = catalog["resources"][key]
        if spec.get("kind") in {"pick", "all_of"} and "values" in spec:
            allowed = set(spec["values"])
            for item in _items(value):
                if not isinstance(item, str) or item not in allowed:
                    errors.append(f"{UNKNOWN_WORD}: resources.{key}: {item!r}")
    if (
        isinstance(requirements, dict)
        and "idle_shutdown" in requirements
        and resources.get("long_running") is True
    ):
        errors.append(IDLE_ALWAYS)


def _check_gate(gate: str, body: Any, catalog: dict[str, Any], errors: list[str]) -> None:
    spec = catalog["gates"][gate]
    if not isinstance(body, dict):
        errors.append(f"{UNKNOWN_WORD}: {gate}")
        return
    knobs: dict[str, Any] = spec["knobs"]
    settings: dict[str, Any] = spec["settings"]
    if "request_field" in spec:
        # The setting is the request's top-level field, and `source` is compared with its kind:
        # under requirements a request names only the gate's other knobs.
        for key in ("source", spec["request_field"]):
            if key in body:
                errors.append(f"{CUSTOM_IMAGES}: {gate}.{key}")
        knobs = {name: value for name, value in knobs.items() if name != "source"}
        settings = {}
    for key in body:
        reported = "request_field" in spec and key in {"source", spec["request_field"]}
        if key not in knobs and key not in settings and not reported:
            errors.append(f"{UNKNOWN_WORD}: {gate}.{key}")
    for knob, knob_spec in knobs.items():
        if knob_spec.get("must_be_named") and knob not in body:
            errors.append(f"{MISSING_KNOB}: {gate}.{knob}")
        if knob in body:
            _check_knob(gate, knob, knob_spec, body[knob], errors)
    if "ports" in settings and ("ports" not in body or body.get("ports") == []):
        errors.append(NO_PORTS)
    if gate == "previews" and "credential" in body and not _accepts_private(body.get("access")):
        errors.append(CREDENTIAL)
    if gate == "volumes":
        mounts = body.get("mounts")
        if isinstance(mounts, list):
            if body.get("read_only_mounts") is not True and any(
                isinstance(mount, dict) and mount.get("read_only") is True for mount in mounts
            ):
                errors.append(READ_ONLY_MOUNT)
            # uniqueItems compares the whole object, so read_only alone makes two mounts distinct.
            _check_distinct_mounts(mounts, errors)
    if gate == "network_lockdown":
        _check_lists(body, settings, errors)
        if "changeable" in body and body.get("policy") in ("deny_all", "open"):
            errors.append(CHANGEABLE_DENY_ALL_OR_OPEN)
        switches_to = body.get("switches_to")
        uses_open = body.get("policy") == "open" or (
            isinstance(switches_to, list) and "open" in switches_to
        )
        if uses_open and body.get("switchable") is not True:
            errors.append(OPEN_WITHOUT_SWITCHABLE)
        if (body.get("switchable") is True and "switches_to" not in body) or (
            "switches_to" in body and "switchable" not in body
        ):
            errors.append(SWITCHABLE_SETTING)
        switches_to = body.get("switches_to")
        if isinstance(switches_to, list) and body.get("policy") in switches_to:
            errors.append(SWITCHES_TO_OWN_POLICY)
    if gate == "idle_shutdown":
        if "idle_seconds" in body and body.get("custom_idle_time") is not True:
            errors.append(IDLE_SECONDS)
        if "auto_wake" in body and _items(body.get("on_idle")) == ["destroyed"]:
            errors.append(WAKE_DESTROYED)
    for name, setting in settings.items():
        ports = name == "ports"  # reported as NO_PORTS above
        if setting.get("required") and name not in body and not ports:
            errors.append(f"{UNKNOWN_WORD}: {gate}.{name}")


def _check_distinct_mounts(mounts: list[Any], errors: list[str]) -> None:
    """Reject a repeated `(provider, volume, path)`. `read_only` is not part of the key."""
    seen: set[tuple[str, str, str]] = set()
    for mount in mounts:
        if not isinstance(mount, dict):
            continue
        provider = mount.get("provider")
        volume = mount.get("volume")
        path = mount.get("path")
        if (
            not isinstance(provider, str)
            or not isinstance(volume, str)
            or not isinstance(path, str)
        ):
            continue
        key = (provider, volume, path)
        if key in seen:
            errors.append(REPEATED_MOUNT)
            return
        seen.add(key)


def _accepts_private(access: Any) -> bool:
    """`"any"` names no access value, so it does not carry `credential`."""
    return "private" in _items(access)


def _check_knob(gate: str, knob: str, spec: dict[str, Any], value: Any, errors: list[str]) -> None:
    if isinstance(value, list) and "any" in value:
        errors.append(ANY_IN_LIST)
        return
    if value == "any":
        if not spec.get("any", False):
            errors.append(f"{ANY_KNOB}: {gate}.{knob}")
        return
    if spec.get("exactly_one") and isinstance(value, list):
        errors.append(f"{UNKNOWN_WORD}: {gate}.{knob}")
        return
    if isinstance(value, list) and value == []:
        errors.append(f"{EMPTY_LIST}: {gate}.{knob}")
        return
    if value == "unknown" or (isinstance(value, list) and "unknown" in value):
        errors.append(f"{UNKNOWN_WORD}: {gate}.{knob}")
        return
    kind = spec["kind"]
    if kind == "yes_no":
        if not isinstance(value, bool):
            errors.append(f"{UNKNOWN_WORD}: {gate}.{knob}")
        return
    if kind in {"pick", "all_of"}:
        allowed = set(spec.get("values") or [])
        for item in _items(value):
            if not isinstance(item, str) or item not in allowed:
                errors.append(f"{UNKNOWN_WORD}: {gate}.{knob}: {item!r}")
                return
        if kind == "all_of" and len(_items(value)) != len(set(_items(value))):
            errors.append(f"{DUPLICATE}: {gate}.{knob}")
        return
    if kind == "number" and (not _is_number(value) or value <= 0):
        errors.append(f"{UNKNOWN_WORD}: {gate}.{knob}")


def _check_lists(body: dict[str, Any], settings: dict[str, Any], errors: list[str]) -> None:
    """`allow` and `deny`: each goes only with the policies the catalog requires it for."""
    policy = body.get("policy")
    if not isinstance(policy, str):
        return  # a missing or listed policy is reported with the knob
    for name, setting in settings.items():
        if policy in setting.get("forbidden_with", []) and name in body:
            errors.append(f"{ALLOW_DENY}: {name}")
            continue
        if policy not in setting.get("required_for", []):
            continue
        entries = body.get(name)
        if entries is None or entries == []:
            errors.append(f"{ALLOWLIST_EMPTY}: {name}")
            continue
        if not isinstance(entries, list):
            continue  # the schema reports the shape
        if any(entry == prior for index, entry in enumerate(entries) for prior in entries[:index]):
            errors.append(f"{DUPLICATE}: {name}")
        for entry in entries:
            if setting.get("wildcards", True) is False and str(entry).startswith("*"):
                errors.append(f"{DENY_WILDCARD}: {entry}")
            elif _allow_entry_bad(policy, entry):
                errors.append(f"{ALLOW_ENTRY}: {entry}")


def _network_entry_is_address(entry: str) -> bool:
    if re.fullmatch(r"[0-9.]+(?:/[0-9]+)?", entry) is None:
        return False
    text = entry if "/" in entry else f"{entry}/32"
    try:
        ipaddress.IPv4Network(text, strict=False)
    except ValueError:
        return False
    return True


def _network_entry_hosts(entries: list[Any]) -> list[str]:
    return [entry for entry in entries if isinstance(entry, str)]


def _allow_entry_bad(policy: str, entry: Any) -> bool:
    if not isinstance(entry, str) or entry == "":
        return True
    if policy not in {"allowlist", "denylist"}:
        return True
    if _network_entry_is_address(entry):
        return False
    if re.fullmatch(r"[0-9.]+(?:/[0-9]+)?", entry):
        return True
    if "/" in entry or ":" in entry or "\\" in entry:
        return True
    name = entry.lower()[2:] if entry.lower().startswith("*.") else entry.lower()
    # An IPv4 address is not a host name, though its characters would pass for one.
    return HOSTNAME.fullmatch(name) is None or name.replace(".", "").isdigit()


def _check_provider_pins(document: dict[str, Any], requirements: Any, errors: list[str]) -> None:
    """All provider-bound request values must name at most one provider."""
    pins: set[str] = set()
    image = document.get("image")
    if isinstance(image, dict) and isinstance(image.get("provider"), str):
        pins.add(image["provider"])
    if isinstance(requirements, dict):
        for name, body in requirements.items():
            if isinstance(name, str) and name.startswith("x-"):
                pins.add(name[2:])
            if name == "volumes" and isinstance(body, dict):
                mounts = body.get("mounts")
                if isinstance(mounts, list):
                    pins.update(
                        mount["provider"]
                        for mount in mounts
                        if isinstance(mount, dict) and isinstance(mount.get("provider"), str)
                    )
    if len(pins) > 1:
        errors.append("request pins to more than one provider")


def _check_secret_destinations(requirements: Any, errors: list[str]) -> None:
    """A named network_lockdown lets every inject_into host through by name."""
    if not isinstance(requirements, dict):
        return
    secrets = requirements.get("hidden_secrets")
    if not isinstance(secrets, dict):
        return
    hosts = secrets.get("inject_into")
    network = requirements.get("network_lockdown")
    if not isinstance(hosts, list) or not isinstance(network, dict):
        return
    policy = network.get("policy")
    if policy == "open":
        return
    if policy not in ("allowlist", "denylist"):
        errors.append(f"{SECRET_HOST}: network_lockdown {policy} lets no host through by name")
        return
    entries = network.get("allow" if policy == "allowlist" else "deny")
    if not isinstance(entries, list):
        return
    for host in hosts:
        if not isinstance(host, str):
            continue
        normalized = host.lower()
        if policy == "denylist":
            if any(
                not _network_entry_is_address(entry_host)
                and _deny_entry_overlaps_secret_host(entry_host.lower(), normalized)
                for entry_host in _network_entry_hosts(entries)
            ):
                errors.append(f"{SECRET_HOST}: {host}")
            continue
        allowed = any(
            _allow_entry_covers_secret_host(entry_host.lower(), normalized)
            for entry_host in _network_entry_hosts(entries)
        )
        if not allowed:
            errors.append(f"{SECRET_HOST}: {host}")
            continue


def _allow_entry_covers_secret_host(entry: str, host: str) -> bool:
    """Whether the allowlist gives an exact or wildcard secret destination coverage."""
    if host[:2] == "*.":
        return entry[:2] == "*." and (host[2:] == entry[2:] or host[2:].endswith("." + entry[2:]))
    return entry == host or (
        entry[:2] == "*." and host.endswith(entry[1:]) and len(host) > len(entry[2:])
    )


def _deny_entry_overlaps_secret_host(entry: str, host: str) -> bool:
    """Whether a deny entry intersects the host or any subdomain in a secret wildcard."""
    if host.startswith("*."):
        domain = host[2:]
        return entry == domain or entry.endswith("." + domain) or domain.endswith("." + entry)
    return host == entry or host.endswith("." + entry)


def check_declaration(
    document: Any,
    catalog: dict[str, Any] | None = None,
    *,
    source_path: str | Path | None = None,
) -> Result:
    """Validate a declaration against the current schema, catalog and evidence map."""
    catalog = load_catalog() if catalog is None else catalog
    if not isinstance(document, dict):
        return Result("declaration", [f"{UNKNOWN_WORD}: (root)"], [], None)
    errors: list[str] = []
    warnings: list[str] = []
    top = set(catalog["declaration_top_level"])
    provider = document.get("provider")
    for key in document:
        if isinstance(key, str) and key.startswith("x-"):
            if key != f"x-{provider}":
                errors.append(f"{UNKNOWN_KEY}: {key} must name this provider")
            continue
        if key not in top:
            errors.append(f"{UNKNOWN_KEY}: {key}")
    resources = document.get("resources")
    if not isinstance(resources, dict):
        resources = {}
    for key in resources:
        if key not in catalog["declaration_resources"]:
            errors.append(f"{UNKNOWN_KEY}: resources.{key}")
    _unknown_in_lists(document, "(root)", errors)
    _check_resource_declarations(resources, catalog, errors)
    _check_lifetime_timer(document.get("lifetime_timer"), errors)
    gates = document.get("gates")
    if isinstance(gates, dict):
        for gate, body in gates.items():
            if gate not in catalog["gates"]:
                errors.append(f"{UNKNOWN_KEY}: gates.{gate}")
                continue
            if body == "unsupported":
                continue
            if not isinstance(body, list):
                continue
            spec = catalog["gates"][gate]
            allowed = set(spec["knobs"]) | set(spec.get("limits") or [])
            allowed |= set(spec.get("declaration_only") or [])
            allowed |= set(catalog["variant_keys"])
            for index, variant in enumerate(body):
                path = f"gates.{gate}.{index}"
                if not isinstance(variant, dict):
                    continue
                for key, value in variant.items():
                    if key not in allowed:
                        errors.append(f"{UNKNOWN_KEY}: {path}.{key}")
                    elif key in spec["knobs"]:
                        _check_declared_knob(gate, key, value, spec["knobs"][key], errors)
                    elif key in (spec.get("limits") or []):
                        _check_declared_limit(
                            key, value, f"{path}.{key}", catalog["limits"].get(key, {}), errors
                        )
                    elif key in (spec.get("declaration_only") or {}):
                        _check_declaration_only(
                            value, spec["declaration_only"][key], f"{path}.{key}", errors
                        )
                    elif key == "needs":
                        _check_needs(
                            value, f"{path}.needs", set(spec["knobs"]) | {"variant"}, errors
                        )
                        _check_variant_need_targets(value, variant, f"{path}.needs", errors)
                    elif key == "conflicts":
                        _conflicts(value, catalog, document, errors, path)
                _condition(gate, variant, spec, errors)
    errors.extend(schema_errors(document, "declaration-schema.json"))
    errors.extend(
        check_evidence(
            document,
            source_path=source_path,
            schema_errors=schema_errors,
            catalog=catalog,
        )
    )
    return Result("declaration", errors, warnings, resources.get("kernel"))


def _unknown_in_lists(value: Any, path: str, errors: list[str]) -> None:
    if isinstance(value, list):
        if any(item == "unknown" for item in value):
            errors.append(f"{UNKNOWN_IN_LIST}: {path}")
        for index, child in enumerate(value):
            _unknown_in_lists(child, f"{path}.{index}", errors)
    elif isinstance(value, dict):
        for key, child in value.items():
            _unknown_in_lists(child, f"{path}.{key}", errors)


def _check_resource_declarations(
    resources: dict[str, Any], catalog: dict[str, Any], errors: list[str]
) -> None:
    for key, value in resources.items():
        spec = catalog["declaration_resources"].get(key, {})
        if key == "needs":
            _check_needs(
                value,
                "resources.needs",
                set(catalog["declaration_resources"]) - {"needs", "unmet_limits"},
                errors,
            )
            if isinstance(value, dict):
                for dependent in value:
                    target = resources.get(dependent)
                    if dependent not in resources or target == "unknown":
                        errors.append(f"needs names no declared resource value: {dependent}")
        elif key == "unmet_limits":
            _check_unmet_limits(value, resources.get("needs"), errors)
        elif key == "kernel":
            if not isinstance(value, str) or value not in [*spec["values"], "unknown"]:
                errors.append(f"{UNKNOWN_WORD}: resources.kernel")
        elif "values" in spec and "kind" not in spec:
            _check_declared_knob(
                "resources", key, value, {"kind": "pick", "values": spec["values"]}, errors
            )
        elif spec.get("kind") == "list":
            if value != "unknown":
                _check_declared_list(value, spec, f"resources.{key}", errors)
        elif spec.get("kind") == "yes_no":
            if not isinstance(value, bool) and value != "unknown":
                errors.append(f"{UNKNOWN_WORD}: resources.{key}")
        elif spec.get("kind") in {"string", "absolute_path"}:
            valid = isinstance(value, str) and bool(value)
            if spec["kind"] == "absolute_path":
                valid = valid and PurePosixPath(value).is_absolute()
            if not valid:
                errors.append(f"{UNKNOWN_WORD}: resources.{key}")
        elif spec.get("kind") == "per_operation":
            _check_per_operation(value, spec, f"resources.{key}", errors)
        elif "kinds" in spec:
            floor = spec.get("floor", {}).get("at_least", 0)
            if not _declaration_number(value, floor=floor, kinds=set(spec["kinds"])):
                errors.append(f"{UNKNOWN_WORD}: resources.{key}")
        elif key == "sizes":
            _check_sizes(value, errors)
        elif key == "default_size":
            _check_default_size(value, errors)
        elif key in {"disk_mib", "max_gpus"}:
            if not _declaration_number(value):
                errors.append(f"{UNKNOWN_WORD}: resources.{key}")
        elif key in {"regions", "located_in", "gpus"}:
            if value != "unknown" and (
                not isinstance(value, list)
                or any(not isinstance(item, str) or not item for item in value)
            ):
                errors.append(f"{UNKNOWN_WORD}: resources.{key}")


def _check_per_operation(value: Any, spec: dict[str, Any], path: str, errors: list[str]) -> None:
    """`{read: N, write: N}`: each named direction is a whole number of bytes or a floor."""
    if not isinstance(value, dict) or not value:
        errors.append(f"{UNKNOWN_WORD}: {path}")
        return
    for field, amount in value.items():
        if field not in spec["fields"]:
            errors.append(f"{UNKNOWN_KEY}: {path}.{field}")
        elif amount != "unknown" and not (
            _declaration_number(amount, floor=1, kinds=set(spec["kinds"]))
            and isinstance(amount.get("at_least") if isinstance(amount, dict) else amount, int)
        ):
            errors.append(f"{UNKNOWN_WORD}: {path}.{field}")


def _declaration_number(value: Any, *, floor: float = 0, kinds: set[str] | None = None) -> bool:
    if isinstance(value, str) and value in {"unknown", "unlimited"}:
        return kinds is None or value in kinds
    if isinstance(value, dict):
        amount = value.get("at_least")
        return (
            (kinds is None or "at_least" in kinds)
            and set(value) == {"at_least"}
            and _is_finite_number(amount)
            and amount > 0
            and amount >= floor
        )
    return (
        (kinds is None or "number" in kinds)
        and _is_finite_number(value)
        and value >= floor
        and value > 0
    )


def _check_sizes(value: Any, errors: list[str]) -> None:
    if value == "unknown":
        return
    if not isinstance(value, list):
        errors.append(f"{UNKNOWN_WORD}: resources.sizes")
        return
    for index, size in enumerate(value):
        if not isinstance(size, dict) or not size:
            errors.append(f"{UNKNOWN_WORD}: resources.sizes.{index}")
            continue
        for name, amount in size.items():
            if name not in {"cpu", "memory_mib", "disk_mib"}:
                errors.append(f"{UNKNOWN_KEY}: resources.sizes.{index}.{name}")
                continue
            if isinstance(amount, list):
                if (
                    len(amount) != 2
                    or not all(_is_finite_number(item) and item > 0 for item in amount)
                    or amount[0] > amount[1]
                ):
                    errors.append(f"{UNKNOWN_WORD}: resources.sizes.{index}.{name}")
            elif not _is_finite_number(amount) or amount <= 0:
                errors.append(f"{UNKNOWN_WORD}: resources.sizes.{index}.{name}")


def _check_default_size(value: Any, errors: list[str]) -> None:
    if value == "unknown":
        return
    if not isinstance(value, dict):
        errors.append(f"{UNKNOWN_WORD}: resources.default_size")
        return
    for name in value:
        if name not in {"cpu", "memory_mib", "disk_mib"}:
            errors.append(f"{UNKNOWN_KEY}: resources.default_size.{name}")
    if not {"cpu", "memory_mib"} <= set(value):
        errors.append(f"{UNKNOWN_WORD}: resources.default_size must include cpu and memory_mib")
    cpu = value.get("cpu")
    if not _is_finite_number(cpu) or cpu <= 0:
        errors.append(f"{UNKNOWN_WORD}: resources.default_size.cpu")
    for name in ("memory_mib", "disk_mib"):
        if name in value and (
            not isinstance(value[name], int) or isinstance(value[name], bool) or value[name] < 1
        ):
            errors.append(f"{UNKNOWN_WORD}: resources.default_size.{name}")


def _check_declared_knob(
    gate: str, knob: str, value: Any, spec: dict[str, Any], errors: list[str]
) -> None:
    path = f"{gate}.{knob}"
    if isinstance(value, str) and value == "unknown":
        return
    kind = spec["kind"]
    if kind == "yes_no":
        if not isinstance(value, bool):
            errors.append(f"{UNKNOWN_WORD}: {path}")
        return
    if kind == "number":
        if not _declaration_number(value):
            errors.append(f"{UNKNOWN_WORD}: {path}")
        return
    values = value if isinstance(value, list) else [value]
    invalid = [
        item for item in values if not isinstance(item, str) or item not in spec.get("values", [])
    ]
    if not values:
        errors.append(f"{UNKNOWN_WORD}: {path}")
        return
    if invalid:
        errors.append(f"{UNKNOWN_WORD}: {path}: {invalid[0]!r}")
        return
    if len(values) != len(set(values)):
        errors.append(f"{UNKNOWN_WORD}: {path}")


def _check_declared_list(value: Any, spec: dict[str, Any], path: str, errors: list[str]) -> None:
    """A declared list: each item one of the catalog's values, or of its item kind."""
    if not isinstance(value, list) or (spec.get("nonempty") and not value):
        errors.append(f"{UNKNOWN_WORD}: {path}")
        return
    item = spec.get("item") or {}
    for entry in value:
        if "values" in spec:
            valid = isinstance(entry, str) and entry in spec["values"]
        elif item.get("kind") == "integer":
            valid = (
                isinstance(entry, int)
                and not isinstance(entry, bool)
                and item.get("minimum", entry) <= entry <= item.get("maximum", entry)
            )
        else:
            valid = False
        if not valid:
            errors.append(f"{UNKNOWN_WORD}: {path}: {entry!r}")
            return
    if len(value) != len(set(value)):
        errors.append(f"{UNKNOWN_WORD}: {path}")


def _check_declaration_only(value: Any, spec: dict[str, Any], path: str, errors: list[str]) -> None:
    """A value only a declaration writes, such as `reserved_ports` or `runs_entrypoint`."""
    if spec["kind"] == "yes_no":
        if not isinstance(value, bool) and value != "unknown":
            errors.append(f"{UNKNOWN_WORD}: {path}")
    else:
        _check_declared_list(value, spec, path, errors)


def _check_declared_limit(
    _name: str, value: Any, path: str, limit: dict[str, Any], errors: list[str]
) -> None:
    if limit.get("kinds") == ["entry_kind_list"]:
        allowed = limit.get("values", [])
        if value != "unknown" and (
            not isinstance(value, list)
            or any(not isinstance(item, str) or item not in allowed for item in value)
            or len(value) != len(set(value))
        ):
            errors.append(f"{UNKNOWN_WORD}: {path}")
        return
    if limit.get("kinds") == ["port_list"]:
        port = {"kind": "integer", "minimum": 1, "maximum": 65535}
        _check_declared_list(value, {"item": port}, path, errors)
        return
    valid = (
        isinstance(value, bool) or value == "unknown"
        if limit.get("kinds") == ["yes_no", "unknown"]
        else _declaration_number(value)
    )
    if not valid:
        errors.append(f"{UNKNOWN_WORD}: {path}")


def _check_needs(value: Any, path: str, allowed: set[str], errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append(f"{UNKNOWN_WORD}: {path}")
        return
    for name, conditions in value.items():
        if name not in allowed:
            errors.append(f"{UNKNOWN_KEY}: {path}.{name}")
        if (
            not isinstance(conditions, list)
            or not conditions
            or any(not isinstance(condition, str) or not condition for condition in conditions)
            or len(conditions) != len(set(conditions))
        ):
            errors.append(f"{UNKNOWN_WORD}: {path}.{name}")


def _check_unmet_limits(value: Any, needs: Any, errors: list[str]) -> None:
    """Each ceiling bounds one limited fact while one of that fact's own conditions is unmet."""
    if not isinstance(value, dict):
        errors.append(f"{UNKNOWN_WORD}: resources.unmet_limits")
        return
    needs = needs if isinstance(needs, dict) else {}
    for fact, ceilings in value.items():
        path = f"resources.unmet_limits.{fact}"
        if fact not in UNMET_LIMIT_ASKS:
            errors.append(f"{UNKNOWN_KEY}: {path}")
        if not isinstance(ceilings, dict) or not ceilings:
            errors.append(f"{UNKNOWN_WORD}: {path}")
            continue
        conditions = needs.get(fact)
        for condition, ceiling in ceilings.items():
            if not isinstance(conditions, list) or condition not in conditions:
                errors.append(
                    f"unmet_limits names no condition of needs.{fact}: {path}.{condition}"
                )
            if ceiling != "unknown" and not (
                isinstance(ceiling, int) and not isinstance(ceiling, bool) and ceiling > 0
            ):
                errors.append(f"{UNKNOWN_WORD}: {path}.{condition}")


def _check_variant_need_targets(
    needs: Any, variant: dict[str, Any], path: str, errors: list[str]
) -> None:
    if not isinstance(needs, dict):
        return
    for dependent in needs:
        if dependent == "variant":
            if not any(name not in {"needs", "conflicts"} for name in variant):
                errors.append(f"needs names an empty variant: {path}.variant")
        elif dependent not in variant or variant[dependent] == "unknown":
            errors.append(f"needs names no declared variant value: {path}.{dependent}")


def _check_lifetime_timer(timer: Any, errors: list[str]) -> None:
    if timer is None:
        return
    if not isinstance(timer, dict):
        errors.append(f"{UNKNOWN_WORD}: lifetime_timer")
        return
    for key in timer:
        if key not in LIFETIME_TIMER_KEYS:
            errors.append(f"{UNKNOWN_KEY}: lifetime_timer.{key}")
    if timer.get("enforced_by") != "provider":
        errors.append(f"{UNKNOWN_WORD}: lifetime_timer.enforced_by")
    paused = timer.get("counts_paused_time")
    if not isinstance(paused, bool) and paused != "unknown":
        errors.append(f"{UNKNOWN_WORD}: lifetime_timer.counts_paused_time")
    adjustable = timer.get("adjustable", "unknown")
    if not isinstance(adjustable, bool) and adjustable != "unknown":
        errors.append(f"{UNKNOWN_WORD}: lifetime_timer.adjustable")
    step = timer.get("step_seconds", "unknown")
    if step != "unknown" and (not isinstance(step, int) or isinstance(step, bool) or step < 1):
        errors.append(f"{UNKNOWN_WORD}: lifetime_timer.step_seconds")
    minimum = timer.get("min_seconds", "unknown")
    if minimum != "unknown" and (
        not isinstance(minimum, int) or isinstance(minimum, bool) or minimum < 1
    ):
        errors.append(f"{UNKNOWN_WORD}: lifetime_timer.min_seconds")
    after_resume = timer.get("after_resume", "same")
    if not isinstance(after_resume, str) or after_resume not in {"same", "pauses", "unknown"}:
        errors.append(f"{UNKNOWN_WORD}: lifetime_timer.after_resume")
    counts_from = timer.get("counts_from", "unknown")
    if not isinstance(counts_from, str) or counts_from not in {"create", "ready", "unknown"}:
        errors.append(f"{UNKNOWN_WORD}: lifetime_timer.counts_from")
    endings = timer.get("at_end")
    allowed = {"paused", "stopped", "destroyed"}
    values = endings if isinstance(endings, list) else [endings]
    if not values or any(
        not isinstance(value, str) or value not in allowed | {"unknown"} for value in values
    ):
        errors.append(f"{UNKNOWN_WORD}: lifetime_timer.at_end")


def _condition(gate: str, variant: dict[str, Any], spec: dict[str, Any], errors: list[str]) -> None:
    # This mirrors each conditional knob from the catalog in a single pass.
    for knob, knob_spec in spec["knobs"].items():
        if knob not in variant:
            continue
        rule = knob_spec.get("only_when")
        if not rule:
            continue
        alternatives = rule.get("any_of")
        holds = (
            any(
                _holds(condition, _items(variant.get(condition["knob"])))
                for condition in alternatives
            )
            if alternatives is not None
            else _holds(rule, _items(variant.get(rule["knob"])))
        )
        if not holds:
            errors.append(f"knob outside the variant where its condition holds: {gate}.{knob}")


def _holds(rule: dict[str, Any], actual: list[Any]) -> bool:
    """A catalog `only_when` condition against the values a variant declares for its knob."""
    if "equals" in rule:
        return actual == [rule["equals"]]
    if "includes" in rule:
        return rule["includes"] in actual
    return any(item in rule["in"] for item in actual)


def _conflicts(
    conflicts: Any,
    catalog: dict[str, Any],
    document: dict[str, Any],
    errors: list[str],
    path: str,
) -> None:
    if conflicts is None:
        return
    if not isinstance(conflicts, list):
        errors.append(f"{UNKNOWN_WORD}: {path}.conflicts")
        return
    for entry in conflicts:
        reason = _conflict_reason(entry, catalog, document)
        if reason is not None:
            errors.append(f"{reason}: {path}.conflicts {entry}")


def _conflict_reason(entry: Any, catalog: dict[str, Any], document: dict[str, Any]) -> str | None:
    if not isinstance(entry, str) or entry == "":
        return "conflicts names a gate that does not exist"
    if entry.startswith("resources."):
        name = entry.split(".", 1)[1]
        if name not in catalog["conflicts_may_name"]["resources"]:
            return "conflicts names a resource that does not exist"
        return None
    if entry.startswith("x-"):
        block, dot, key = entry.partition(".")
        extras = document.get(block)
        if dot == "" or not isinstance(extras, dict) or key not in extras:
            return "conflicts names a value that does not exist"
        return None
    if "=" not in entry and "." not in entry:
        if entry not in catalog["gates"]:
            return "conflicts names a gate that does not exist"
        return None
    left, separator, value = entry.partition("=")
    gate, dot, knob = left.partition(".")
    if gate not in catalog["gates"]:
        return "conflicts names a gate that does not exist"
    knobs = catalog["gates"][gate]["knobs"]
    if dot == "" or knob not in knobs:
        return "conflicts names a knob that does not exist"
    if separator == "":
        return "conflicts names a knob that does not exist"
    knob_spec = knobs[knob]
    if knob_spec["kind"] == "yes_no":
        if value not in ("true", "false"):
            return "conflicts names a value that does not exist"
        return None
    allowed = knob_spec.get("values")
    if allowed is not None and value not in allowed:
        return "conflicts names a value that does not exist"
    if allowed is None and knob_spec["kind"] == "number":
        if not value.isdigit() or int(value) <= 0:
            return "conflicts names a value that does not exist"
    return None


def check_report(document: Any, *, source_path: str | Path | None = None) -> Result:
    """Validate a native run's shape, recognized suite, results and optional source path."""
    errors = schema_errors(document, "report-schema.json")
    if not errors:
        errors.extend(check_report_evidence(document, source_path=source_path))
    return Result("report", errors, [], None)


def check_document(document: Any, *, source_path: str | Path | None = None) -> Result:
    """Check one loaded document. Requests, declarations and reports each have a shape."""
    report = isinstance(document, dict) and {
        "driver",
        "sdk_versions",
        "revision",
        "tests",
        "clean",
    } <= set(document)
    if report:
        return check_report(document, source_path=source_path)
    if isinstance(document, dict) and "spec" in document and "provider" in document:
        return check_declaration(document, source_path=source_path)
    errors = check_request(document)
    return Result("request", errors, [], None)


def check_path(path: str | Path) -> Result:
    """Load a file with the strict loader and check it."""
    source_path = Path(path)
    return check_document(load(source_path), source_path=source_path)
