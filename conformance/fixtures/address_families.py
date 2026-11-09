# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""DNS-free TCP probes for literal address families and explicitly supplied NAT64 prefixes."""

from __future__ import annotations

import errno
import ipaddress
import json
import os
import socket
import urllib.parse
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

_DEFINITE_NO_ROUTE = {errno.ENETUNREACH, errno.EADDRNOTAVAIL}
_CONNECT_TIMEOUT_SECONDS = 4.0
_READ_TIMEOUT_SECONDS = 0.05


def ipv4_address_present(fib_trie: str | None) -> bool | None:
    """Whether proc's local IPv4 table has any assigned non-loopback address."""
    if not isinstance(fib_trie, str) or "Main:" not in fib_trie or "Local:" not in fib_trie:
        return None
    lines = fib_trie.splitlines()
    present = False
    found_local = False
    for index, line in enumerate(lines):
        if "host LOCAL" not in line:
            continue
        prior = next((item.strip() for item in reversed(lines[:index]) if item.strip()), None)
        if not isinstance(prior, str) or "|-- " not in prior:
            return None
        literal = prior.rsplit("|-- ", maxsplit=1)[1]
        try:
            address = ipaddress.IPv4Address(literal)
        except ipaddress.AddressValueError:
            return None
        found_local = True
        present |= not address.is_loopback
    return present if found_local else None


def ipv6_global_address_present(if_inet6: str | None) -> bool | None:
    """Whether proc lists a universe-scope IPv6 address on a non-loopback interface."""
    if not isinstance(if_inet6, str):
        return None
    present = False
    for line in if_inet6.splitlines():
        parts = line.split()
        if len(parts) != 6:
            return None
        raw_address, _index, prefix_length, scope, _flags, interface = parts
        if (
            len(raw_address) != 32
            or any(character not in "0123456789abcdefABCDEF" for character in raw_address)
            or len(prefix_length) != 2
            or len(scope) != 2
        ):
            return None
        try:
            address = ipaddress.IPv6Address(bytes.fromhex(raw_address))
            int(prefix_length, 16)
            scope_value = int(scope, 16)
        except (ValueError, ipaddress.AddressValueError):
            return None
        present |= interface != "lo" and scope_value == 0 and not address.is_loopback
    return present


def ipv4_default_route_present(routes: str | None) -> bool | None:
    """Whether proc's IPv4 route table has a default route outside loopback."""
    if not isinstance(routes, str):
        return None
    lines = routes.splitlines()
    if not lines or not {"Iface", "Destination", "Mask"} <= set(lines[0].split()):
        return None
    present = False
    for line in lines[1:]:
        parts = line.split()
        if len(parts) != 11:
            return None
        interface, destination = parts[0], parts[1]
        mask = parts[7]
        if (
            len(destination) != 8
            or len(mask) != 8
            or any(char not in "0123456789abcdefABCDEF" for char in destination + mask)
        ):
            return None
        present |= interface != "lo" and destination == "00000000" and mask == "00000000"
    return present


def ipv6_default_route_present(routes: str | None) -> bool | None:
    """Whether proc's IPv6 route table has a default route outside loopback."""
    if not isinstance(routes, str):
        return None
    present = False
    for line in routes.splitlines():
        parts = line.split()
        if len(parts) != 10:
            return None
        destination, prefix_length = parts[0], parts[1]
        interface = parts[9]
        if (
            len(destination) != 32
            or any(char not in "0123456789abcdefABCDEF" for char in destination)
            or len(prefix_length) != 2
            or any(char not in "0123456789abcdefABCDEF" for char in prefix_length)
        ):
            return None
        present |= interface != "lo" and destination == "0" * 32 and prefix_length.lower() == "00"
    return present


def family_absence_evidence(
    family: str,
    *,
    ipv4_fib_trie: str | None = None,
    ipv4_routes: str | None = None,
    ipv6_if_inet6: str | None = None,
    ipv6_routes: str | None = None,
) -> bool | None:
    """Complete route and address evidence, or unknown when any source is incomplete."""
    if family == "ipv4":
        address_present = ipv4_address_present(ipv4_fib_trie)
        route_present = ipv4_default_route_present(ipv4_routes)
    elif family == "ipv6":
        address_present = ipv6_global_address_present(ipv6_if_inet6)
        route_present = ipv6_default_route_present(ipv6_routes)
    else:
        raise ValueError("address family must be ipv4 or ipv6")
    if address_present is None or route_present is None:
        return None
    return not address_present and not route_present


def classify_attempt(connected: bool, error_number: int | None, absent: bool | None) -> bool | None:
    """Only a successful handshake or typed local absence plus complete evidence decides."""
    if connected:
        return True
    if error_number in _DEFINITE_NO_ROUTE and absent is True:
        return False
    return None


def translate_ipv4(prefix_value: object, address_value: object) -> str:
    """Embed an IPv4 literal under an explicit RFC 6052 prefix; never discover a prefix."""
    network = ipaddress.IPv6Network(prefix_value, strict=True)
    address = ipaddress.IPv4Address(address_value)
    if network.prefixlen not in {32, 40, 48, 56, 64, 96}:
        raise ValueError("NAT64 prefix length must be one of the RFC 6052 lengths")
    result = int(network.network_address)
    packed = address.packed
    if network.prefixlen == 96:
        result |= int(address)
    else:
        before_u = (64 - network.prefixlen) // 8
        before_value = int.from_bytes(packed[:before_u], "big")
        result |= before_value << (128 - network.prefixlen - 8 * before_u)
        after_u = packed[before_u:]
        if after_u:
            result |= int.from_bytes(after_u, "big") << (128 - 72 - 8 * len(after_u))
    return str(ipaddress.IPv6Address(result))


def _read(path: str) -> str | None:
    try:
        return Path(path).read_text(encoding="ascii")
    except (OSError, UnicodeError):
        return None


def _route_evidence(family: str) -> bool | None:
    if family == "ipv4":
        return family_absence_evidence(
            family,
            ipv4_fib_trie=_read("/proc/net/fib_trie"),
            ipv4_routes=_read("/proc/net/route"),
        )
    return family_absence_evidence(
        family,
        ipv6_if_inet6=_read("/proc/net/if_inet6"),
        ipv6_routes=_read("/proc/net/ipv6_route"),
    )


def _target(family: int, address: str, port: int) -> tuple[object, ...]:
    return (address, port) if family == socket.AF_INET else (address, port, 0, 0)


def _connect_once(family: int, address: str, port: int) -> tuple[bool, int | None]:
    """Connect to an IP literal with an explicit family; never ask the resolver."""
    client = socket.socket(family, socket.SOCK_STREAM)
    try:
        client.settimeout(_CONNECT_TIMEOUT_SECONDS)
        client.connect(_target(family, address, port))
        client.settimeout(_READ_TIMEOUT_SECONDS)
        try:
            client.recv(1)
        except (TimeoutError, BlockingIOError, OSError):
            pass
        return True, None
    except OSError as error:
        number = error.errno if isinstance(error.errno, int) else None
        return False, number
    finally:
        client.close()


def _provenance(value: object) -> bool:
    if not isinstance(value, Mapping):
        return False
    source = value.get("source")
    scope = value.get("scope")
    if not isinstance(source, str) or not isinstance(scope, str) or not scope.strip():
        return False
    try:
        parsed = urllib.parse.urlsplit(source)
        hostname = parsed.hostname
    except ValueError:
        return False
    return parsed.scheme in {"http", "https"} and bool(hostname)


def _validated_fixture(
    value: object,
) -> tuple[dict[str, Any], ipaddress.IPv4Address, ipaddress.IPv6Address]:
    if not isinstance(value, Mapping) or not _provenance(value.get("provenance")):
        raise ValueError("address_families requires an explicit fixture with provenance")
    try:
        ipv4 = ipaddress.IPv4Address(value["ipv4_literal"])
        ipv6 = ipaddress.IPv6Address(value["ipv6_literal"])
        port = value["port"]
    except (KeyError, ipaddress.AddressValueError, TypeError):
        raise ValueError("address_families fixture literals are invalid") from None
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("address_families fixture port is invalid")
    fixture = {
        "ipv4_literal": str(ipv4),
        "ipv6_literal": str(ipv6),
        "port": port,
        "provenance": dict(value["provenance"]),
    }
    prefix = value.get("nat64_prefix")
    if prefix is not None:
        if not isinstance(prefix, Mapping) or not _provenance(prefix.get("provenance")):
            raise ValueError("NAT64 prefix requires explicit provenance")
        try:
            network = ipaddress.IPv6Network(prefix["prefix"], strict=True)
        except (KeyError, ipaddress.AddressValueError, ipaddress.NetmaskValueError, TypeError):
            raise ValueError("NAT64 prefix fixture is invalid") from None
        if network.prefixlen not in {32, 40, 48, 56, 64, 96}:
            raise ValueError("NAT64 prefix length is invalid")
        fixture["nat64_prefix"] = {
            "prefix": str(network),
            "provenance": dict(prefix["provenance"]),
        }
    return fixture, ipv4, ipv6


def observe(
    arguments: Mapping[str, object],
    *,
    connect: Callable[[int, str, int], tuple[bool, int | None]] = _connect_once,
    route_evidence: Callable[[str], bool | None] = _route_evidence,
) -> dict[str, object]:
    """Return native family results and informative IPv4 destination reach."""
    if arguments.get("probe") != "address_families":
        raise ValueError("unknown address family probe")
    fixture, ipv4, ipv6 = _validated_fixture(arguments.get("fixture"))
    v4_connected, v4_errno = connect(socket.AF_INET, str(ipv4), fixture["port"])
    v4_absent = (
        route_evidence("ipv4") if not v4_connected and v4_errno in _DEFINITE_NO_ROUTE else None
    )
    ipv4_native = classify_attempt(v4_connected, v4_errno, v4_absent)
    v6_connected, v6_errno = connect(socket.AF_INET6, str(ipv6), fixture["port"])
    v6_absent = (
        route_evidence("ipv6") if not v6_connected and v6_errno in _DEFINITE_NO_ROUTE else None
    )
    ipv6_native = classify_attempt(v6_connected, v6_errno, v6_absent)

    nat64_target = None
    ipv4_via_nat64 = None
    prefix = fixture.get("nat64_prefix")
    if prefix is not None:
        nat64_target = translate_ipv4(prefix["prefix"], str(ipv4))
        nat64_connected, _nat64_errno = connect(socket.AF_INET6, nat64_target, fixture["port"])
        if nat64_connected:
            ipv4_via_nat64 = True

    families = None
    if ipv4_native is not None and ipv6_native is not None:
        families = [
            family
            for family, connected in (("ipv4", ipv4_native), ("ipv6", ipv6_native))
            if connected
        ]
    destination = (
        "native"
        if ipv4_native is True
        else "nat64"
        if ipv4_native is False and ipv4_via_nat64 is True
        else None
    )
    return {
        "ipv4_native": ipv4_native,
        "ipv6_native": ipv6_native,
        "ipv4_errno": v4_errno,
        "ipv6_errno": v6_errno,
        "ipv4_absence_evidence": v4_absent,
        "ipv6_absence_evidence": v6_absent,
        "ipv4_via_nat64": ipv4_via_nat64,
        "outbound_ip_families": families,
        "ipv4_destination_reach": destination,
        "ipv4_tuple": f"{ipv4}:{fixture['port']}",
        "ipv6_tuple": f"[{ipv6}]:{fixture['port']}",
        "ipv4_nat64_target": nat64_target,
        "nat64_prefix": prefix,
    }


if __name__ == "__main__":
    arguments = json.loads(os.environ["SPS_ADDRESS_FAMILY_ARGUMENTS"])
    print(json.dumps(observe(arguments)))
