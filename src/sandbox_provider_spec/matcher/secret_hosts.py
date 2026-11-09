# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Hostname syntax and policy coverage for secret destinations."""

from collections.abc import Mapping, Sequence
from typing import Any

from sandbox_provider_spec.hostnames import HOSTNAME


def valid_secret_hostname(host: Any) -> bool:
    """Whether a secret destination is an exact hostname or a leading-wildcard hostname."""
    if not isinstance(host, str):
        return False
    name = host[2:] if host.startswith("*.") else host
    return HOSTNAME.fullmatch(name) is not None and not name.replace(".", "").isdigit()


def allow_entry_covers_secret_host(entry: str, host: str) -> bool:
    """Whether one allowlist hostname covers an exact or wildcard secret destination."""
    if host.startswith("*."):
        if not entry.startswith("*."):
            return False
        host_domain = host[2:]
        entry_domain = entry[2:]
        return host_domain == entry_domain or host_domain.endswith("." + entry_domain)
    if entry.startswith("*."):
        return host.endswith(entry[1:]) and host != entry[2:]
    return host == entry


def deny_entry_overlaps_secret_host(entry: str, host: str) -> bool:
    """Whether a denylisted hostname blocks an exact host or any name under a wildcard."""
    if not host.startswith("*."):
        return host == entry or host.endswith("." + entry)
    host_domain = host[2:]
    # A denied parent may also shut out every name under it, so the bare domain overlaps.
    return (
        entry == host_domain
        or entry.endswith("." + host_domain)
        or host_domain.endswith("." + entry)
    )


def wildcard_injection_supported(hosts: Sequence[Any], limits: Mapping[str, Any]) -> bool:
    """Whether a provider explicitly declares support for every requested wildcard host."""
    return not any(isinstance(host, str) and host.startswith("*.") for host in hosts) or (
        limits.get("inject_wildcards") is True
    )
