# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Resolve public proof values from the exact inputs a shared test exercises."""

from __future__ import annotations

import ipaddress
import math
import re
import urllib.parse
from collections.abc import Mapping
from typing import Any, cast

from sandbox_provider_spec.driver import NotRun
from sandbox_provider_spec.hostnames import HOSTNAME
from sandbox_provider_spec.suite import Test

# These names are public quantities, never endpoints, headers or native identifiers.
PUBLIC_VALUES = {
    "test_size_value",
    "test_gpu_models",
    "max_mounts",
    "max_allow_count",
    "max_lifetime_observed_seconds",
    "link_lifetime_wait_seconds",
    "reserved_ports",
    "max_deny_count",
    "max_inject_into_count",
}
GPU_NAMES = {
    "nvidia:t4": "T4",
    "nvidia:a10": "A10",
    "nvidia:l4": "L4",
    "nvidia:l40s": "L40S",
    "nvidia:h100": "H100",
    "nvidia:h200": "H200",
    "nvidia:rtx-4090": "RTX 4090",
    "nvidia:rtx-5090": "RTX 5090",
}


def concrete_size(fixtures: Mapping[str, object]) -> list[dict[str, object]]:
    """One declaration size exercised by test_size, or not_run when it is not concrete."""
    size = fixtures.get("test_size")
    if size is None:
        raise NotRun("fixture_missing")
    fields = {"cpu_min": "cpu", "memory_min_mib": "memory_mib", "disk_min_mib": "disk_mib"}
    if (
        not isinstance(size, Mapping)
        or not size
        or any(
            key not in fields
            or not positive(value)
            or (key != "cpu_min" and not isinstance(value, int))
            for key, value in size.items()
        )
    ):
        raise NotRun("proof_fixture_invalid")
    return [{fields[key]: value for key, value in size.items()}]


def larger_size(fixtures: Mapping[str, object]) -> None:
    """Check `larger_size` names exactly a CPU and a memory minimum before anything is created."""
    size = fixtures.get("larger_size")
    if size is None:
        raise NotRun("fixture_missing")
    if (
        not isinstance(size, Mapping)
        or set(size) != {"cpu_min", "memory_min_mib"}
        or not positive(size["cpu_min"])
        or not isinstance(size["memory_min_mib"], int)
        or not positive(size["memory_min_mib"])
    ):
        raise NotRun("proof_fixture_invalid")


def positive(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and value > 0
    )


def integer(fixtures: Mapping[str, object], key: str) -> int:
    if key not in fixtures:
        raise NotRun("fixture_missing")
    value = fixtures[key]
    if not isinstance(value, int) or not positive(value):
        raise NotRun("proof_fixture_invalid")
    return value


def _deny_entry_kind(entry: str) -> str:
    if re.fullmatch(r"[0-9.]+(?:/[0-9]+)?", entry):
        try:
            ipaddress.IPv4Network(entry, strict=False)
        except ValueError:
            raise NotRun("proof_fixture_invalid") from None
        return "addresses"
    if not HOSTNAME.fullmatch(entry) or entry.replace(".", "").isdigit():
        raise NotRun("proof_fixture_invalid")
    return "names"


def deny_pairs(entries: object, pairs: object, expected_kind: str | None = None) -> None:
    """Every counted/refused entry has its own HTTP and HTTPS destination."""
    if entries is None or pairs is None:
        raise NotRun("fixture_missing")
    # pylint: disable=too-many-boolean-expressions
    if (
        not isinstance(entries, list)
        or not entries
        or any(not isinstance(entry, str) or not entry for entry in entries)
        or len(set(entry.lower() for entry in entries)) != len(entries)
        or not isinstance(pairs, list)
        or len(pairs) != len(entries)
    ):
        raise NotRun("proof_fixture_invalid")
    for entry, pair in zip(entries, pairs, strict=True):
        if not isinstance(pair, list) or len(pair) != 2:
            raise NotRun("proof_fixture_invalid")
        try:
            kind = _deny_entry_kind(entry)
            if expected_kind is not None and kind != expected_kind:
                raise ValueError
            parsed = [urllib.parse.urlsplit(url) for url in pair if isinstance(url, str)]
            if (
                len(parsed) != 2
                or {url.scheme for url in parsed} != {"http", "https"}
                or any(not url.hostname or url.username or url.port for url in parsed)
            ):
                raise ValueError
            if kind == "names":
                if any(url.hostname != entry.lower() for url in parsed):
                    raise ValueError
            else:
                network = ipaddress.IPv4Network(entry, strict=False)
                if any(ipaddress.IPv4Address(str(url.hostname)) not in network for url in parsed):
                    raise ValueError
        except ValueError:
            raise NotRun("proof_fixture_invalid") from None


def inject_host_count(hosts: object, urls: object) -> int:
    """Every counted injection host has its own HTTPS destination."""
    if hosts is None or urls is None:
        raise NotRun("fixture_missing")
    # pylint: disable=too-many-boolean-expressions
    if (
        not isinstance(hosts, list)
        or not isinstance(urls, list)
        or not hosts
        or len(hosts) > 128
        or len(hosts) != len(urls)
        or any(not isinstance(host, str) or HOSTNAME.fullmatch(host) is None for host in hosts)
        or any(not isinstance(url, str) or not url for url in urls)
        or len({host.lower() for host in cast(list[str], hosts)}) != len(hosts)
    ):
        raise NotRun("proof_fixture_invalid")
    try:
        parsed = [urllib.parse.urlsplit(url) for url in cast(list[str], urls)]
        if any(
            part.scheme != "https"
            or part.hostname != host.lower()
            or part.username is not None
            or part.password is not None
            or bool(part.fragment)
            for host, part in zip(cast(list[str], hosts), parsed, strict=True)
        ):
            raise ValueError
    except ValueError:
        raise NotRun("proof_fixture_invalid") from None
    return len(hosts)


def _ipv4_host(url: str) -> ipaddress.IPv4Address | None:
    try:
        host = urllib.parse.urlsplit(url).hostname
    except ValueError:
        raise NotRun("proof_fixture_invalid") from None
    if not isinstance(host, str) or not host:
        raise NotRun("proof_fixture_invalid")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return None
    if not isinstance(address, ipaddress.IPv4Address):
        return None
    return address


def _http_ipv4(url: str) -> ipaddress.IPv4Address | None:
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        raise NotRun("proof_fixture_invalid") from None
    if parsed.scheme != "http" or parsed.username:
        return None
    return _ipv4_host(url)


def _allowlist_range(fixtures: Mapping[str, object]) -> None:
    """Two distinct in-range HTTP addresses, and no denied literal address inside the CIDR."""
    raw = fixtures.get("allowed_ip_range")
    allowed = fixtures.get("allowed_ip_url")
    second = fixtures.get("allowed_ip_range_url")
    denied = fixtures.get("denied_url")
    if raw is None or allowed is None or second is None or denied is None:
        raise NotRun("fixture_missing")
    if (
        not isinstance(raw, str)
        or not isinstance(allowed, str)
        or not isinstance(second, str)
        or not isinstance(denied, str)
    ):
        raise NotRun("proof_fixture_invalid")
    try:
        network = ipaddress.IPv4Network(raw, strict=False)
    except ValueError:
        raise NotRun("proof_fixture_invalid") from None
    if network.prefixlen > 24:
        raise NotRun("proof_fixture_invalid")
    addresses = [_http_ipv4(allowed), _http_ipv4(second)]
    if (
        any(address is None or address not in network for address in addresses)
        or addresses[0] == addresses[1]
    ):
        raise NotRun("proof_fixture_invalid")
    denied_address = _ipv4_host(denied)
    if denied_address is not None and denied_address in network:
        raise NotRun("proof_fixture_invalid")


def proof_fixtures(test: Test, fixtures: Mapping[str, object]) -> dict[str, object]:
    """Derived values cannot be overridden independently of the tested inputs."""
    if test.id in {
        "coverage.network_lockdown.max_deny",
        "coverage.network_lockdown.denylist.names",
        "coverage.network_lockdown.denylist.addresses",
        "coverage.network_lockdown.denylist.mixed",
    }:
        limit = test.id.endswith("max_deny")
        expected_kind = None if limit else test.id.rsplit(".", 1)[-1]
        prefix = "max_deny" if limit else f"denylist_{expected_kind}"
        entries, pairs = fixtures.get(prefix + "_entries"), fixtures.get(prefix + "_urls")
        deny_pairs(entries, pairs, None if expected_kind == "mixed" else expected_kind)
        if expected_kind == "mixed" and {
            _deny_entry_kind(entry) for entry in cast(list[str], entries)
        } != {"names", "addresses"}:
            raise NotRun("proof_fixture_invalid")
        return {"max_deny_count": len(cast(list[str], entries))} if limit else {}
    if test.id == "coverage.network_lockdown.allowlist.range":
        _allowlist_range(fixtures)
        return {}
    if test.id == "coverage.previews.reserved_ports":
        ports = fixtures.get("reserved_ports")
        if ports is None:
            raise NotRun("fixture_missing")
        if (
            not isinstance(ports, list)
            or len(ports) > 64
            or any(
                not isinstance(p, int) or isinstance(p, bool) or not 1 <= p <= 65535 for p in ports
            )
            or len(set(ports)) != len(ports)
        ):
            raise NotRun("proof_fixture_invalid")
        return {}
    if test.id.startswith("previews.link_lifetime_seconds"):
        seconds = integer(fixtures, "link_lifetime_wait_seconds")
        return {
            "link_lifetime_wait_ms": seconds * 1000,
            "preview_link_lifetime_seconds": seconds + 60,
            "preview_sandbox_lifetime_seconds": ((seconds + 179) // 60) * 60,
            "preview_process_timeout_ms": (seconds + 180) * 1000,
        }
    if test.id in {"facts.max_lifetime", "coverage.facts.max_lifetime.active"}:
        delay = integer(fixtures, "max_lifetime_wait_ms")
        lifetime = integer(fixtures, "max_lifetime_seconds")
        if delay < 1000 or lifetime * 1000 <= delay + 30000:
            raise NotRun("proof_fixture_window_invalid")
        return {"max_lifetime_observed_seconds": delay // 1000}
    if test.id == "facts.sizes":
        return {"test_size_value": concrete_size(fixtures)}
    if test.id == "coverage.facts.sizes.delivered":
        larger_size(fixtures)
        return {}
    if test.id in {
        "coverage.facts.size_is_ceiling.true",
        "coverage.facts.size_is_ceiling.false",
    }:
        value = concrete_size(fixtures)
        if not {"cpu", "memory_mib"} <= set(value[0]):
            raise NotRun("proof_fixture_invalid")
        return {"test_size_value": value}
    if test.id == "facts.gpus":
        gpu = fixtures.get("test_gpu")
        if gpu is None:
            raise NotRun("fixture_missing")
        if not isinstance(gpu, Mapping):
            raise NotRun("proof_fixture_invalid")
        models = gpu.get("gpu_model")
        if not isinstance(models, list) or len(models) != 1 or models[0] not in GPU_NAMES:
            raise NotRun("gpu_identity_mapping_unavailable")
        # A single requested model is verified against its reviewed native display name.
        # An alternatives list could never establish that every alternative was allocated.
        name = GPU_NAMES[models[0]]
        return {
            "test_gpu_models": models,
            "gpu_model": name,
            "gpu_name_pattern": "(^|[[:space:]])" + name + "([[:space:]-]|$)",
        }
    if test.id in {"coverage.live_resize.grows", "coverage.live_resize.shrinks"}:
        original, restored = fixtures.get("original_size"), fixtures.get("restored_size")
        if original is None or restored is None:
            raise NotRun("fixture_missing")
        required = {"cpu_min", "memory_min_mib"}
        if (
            not isinstance(original, Mapping)
            or not isinstance(restored, Mapping)
            or set(original) != required
            or set(restored) != required
        ):
            raise NotRun("proof_fixture_invalid")
        original_cpu, restored_cpu = original["cpu_min"], restored["cpu_min"]
        original_memory, restored_memory = (
            original["memory_min_mib"],
            restored["memory_min_mib"],
        )
        if not positive(original_cpu) or not positive(restored_cpu):
            raise NotRun("proof_fixture_invalid")
        if (
            not isinstance(original_memory, int)
            or isinstance(original_memory, bool)
            or not positive(original_memory)
        ):
            raise NotRun("proof_fixture_invalid")
        if (
            not isinstance(restored_memory, int)
            or isinstance(restored_memory, bool)
            or not positive(restored_memory)
        ):
            raise NotRun("proof_fixture_invalid")
        if (
            cast(float | int, original_cpu) >= cast(float | int, restored_cpu)
            or original_memory >= restored_memory
        ):
            raise NotRun("proof_fixture_invalid")
    if test.id == "snapshots.resizes_on_restore":
        original, restored = fixtures.get("original_size"), fixtures.get("restored_size")
        if original is None or restored is None:
            raise NotRun("fixture_missing")
        if (
            not isinstance(original, Mapping)
            or not isinstance(restored, Mapping)
            or original == restored
        ):
            raise NotRun("proof_fixture_invalid")
    if test.id == "coverage.hidden_secrets.max_inject_into":
        return {
            "max_inject_into_count": inject_host_count(
                fixtures.get("max_inject_into_hosts"),
                fixtures.get("max_inject_into_urls"),
            )
        }
    if test.id == "network_lockdown.max_allow":
        entries, urls = fixtures.get("max_allow_entries"), fixtures.get("max_allow_urls")
        if entries is None or urls is None:
            raise NotRun("fixture_missing")
        # Every distinct allowlist entry needs its own exercised endpoint.
        # pylint: disable=too-many-boolean-expressions
        if (
            not isinstance(entries, list)
            or not isinstance(urls, list)
            or not 1 <= len(entries) <= 32
            or len(entries) != len(urls)
            or any(not isinstance(entry, str) for entry in entries)
            or any(not isinstance(url, str) for url in urls)
            or len(set(entries)) != len(entries)
            or [urllib.parse.urlsplit(url).hostname for url in urls] != entries
        ):
            raise NotRun("proof_fixture_invalid")
        return {"max_allow_count": len(entries)}
    if test.id == "volumes.max_mounts":
        count = integer(fixtures, "max_mounts")
        if count > 32 or fixtures.get("volume_kind") not in {"filesystem", "object_store"}:
            raise NotRun("proof_fixture_invalid")
    return {}


def proof_targets(
    test: Test,
    fixtures: Mapping[str, object],
    observations: Mapping[str, object] | None = None,
) -> list[dict[str, Any]]:
    def value(item: Any) -> Any:
        if isinstance(item, str) and item.startswith("$"):
            key = item.removeprefix("$runner.")
            if not item.startswith("$runner.") or key not in PUBLIC_VALUES:
                raise NotRun("proof_fixture_not_public")
            if key not in fixtures:
                raise NotRun("fixture_missing")
            return fixtures[key]
        if isinstance(item, dict):
            return {key: value(nested) for key, nested in item.items()}
        if isinstance(item, list):
            return [value(nested) for nested in item]
        return item

    targets = []
    for target in test.proves:
        proposed = target["value"]
        if isinstance(proposed, str) and proposed.startswith("$observed."):
            key = proposed.removeprefix("$observed.")
            if (
                key not in {"default_user", "default_cwd"}
                or test.id != "facts." + key
                or target.get("fact") != "resources." + key
            ):
                raise NotRun("proof_observation_not_public")
            if observations is None:
                continue
            if key not in observations:
                raise NotRun("observation_unmapped")
            proposed = observations[key]
        else:
            proposed = value(proposed)
        targets.append({**target, "value": proposed})
    for target in targets:
        result = target["value"]
        if isinstance(result, Mapping) and "at_least" in result:
            if set(result) != {"at_least"} or not positive(result["at_least"]):
                raise NotRun("proof_fixture_invalid")
    return targets
