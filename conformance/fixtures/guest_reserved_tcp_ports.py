# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Point-in-time guest listener ownership and candidate-only TCP bind probes."""

from __future__ import annotations

import errno
import hashlib
import ipaddress
import json
import os
import re
import socket
import sys
import urllib.parse
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

_LISTEN = "0A"
_MAX_CANDIDATES = 16
_MAX_IDENTITIES = 16
_MAX_EXECUTABLE_BYTES = 64 * 1024 * 1024
_MAX_OUTPUT_BYTES = 4096
_SOCKET_LINK = re.compile(r"socket:\[(\d+)\]")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_WILDCARDS = {"ipv4": "0.0.0.0", "ipv6": "::"}


def parse_tcp_table(value: str, family: str) -> list[dict[str, Any]] | None:
    """Parse a complete proc TCP table, returning LISTEN rows or None if incomplete."""
    if family not in _WILDCARDS or not value.endswith("\n"):
        return None
    lines = value.splitlines()
    if not lines or not {"local_address", "st", "inode"} <= set(lines[0].split()):
        return None
    rows: list[dict[str, Any]] = []
    for line in lines[1:]:
        fields = line.split()
        if len(fields) < 10:
            return None
        local = fields[1].split(":")
        state = fields[3]
        inode_text = fields[9]
        if (
            len(local) != 2
            or len(state) != 2
            or not fields[7].isdecimal()
            or not fields[8].isdecimal()
            or not inode_text.isdecimal()
        ):
            return None
        raw_address, raw_port = local
        if not re.fullmatch(r"[0-9a-fA-F]+", raw_address) or not re.fullmatch(
            r"[0-9a-fA-F]{4}", raw_port
        ):
            return None
        try:
            packed = bytes.fromhex(raw_address)
            if family == "ipv4" and len(packed) == 4:
                ordered = packed[::-1] if sys.byteorder == "little" else packed
                address = str(ipaddress.IPv4Address(ordered))
            elif family == "ipv6" and len(packed) == 16:
                # Linux formats each 32-bit IPv6 word in native byte order.
                ordered = (
                    b"".join(packed[index : index + 4][::-1] for index in range(0, 16, 4))
                    if sys.byteorder == "little"
                    else packed
                )
                address = str(ipaddress.IPv6Address(ordered))
            else:
                return None
            port = int(raw_port, 16)
        except (ValueError, ipaddress.AddressValueError):
            return None
        if state.upper() == _LISTEN:
            rows.append(
                {
                    "family": family,
                    "address": address,
                    "port": port,
                    "inode": int(inode_text),
                    "owner_sha256": None,
                    "owner_token": None,
                    "ipv6_v6only": None,
                }
            )
    return rows


def _start_time(stat_value: str) -> str | None:
    """Read only proc stat's start-time field; never inspect cmdline or environ."""
    closing = stat_value.rfind(")")
    if closing < 0:
        return None
    fields = stat_value[closing + 1 :].split()
    if len(fields) <= 19 or not fields[19].isdecimal():
        return None
    return fields[19]


def _executable_digest(path: Path) -> str:
    if path.stat().st_size > _MAX_EXECUTABLE_BYTES:
        raise OSError("executable exceeds the identity hashing bound")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_listener_snapshot(
    proc_root: str | Path = "/proc",
    trusted_executable_sha256s: set[str] | frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """Read both full TCP tables and resolve LISTEN inodes to stable process identities.

    PIDs, inodes, executable hashes and start times stay internal to the probe and are never
    returned by `probe` in its public observation.
    """
    root = Path(proc_root)
    try:
        tcp4_text = (root / "net" / "tcp").read_text(encoding="ascii")
        tcp6_text = (root / "net" / "tcp6").read_text(encoding="ascii")
    except (OSError, UnicodeError):
        return {"complete": False, "listeners": []}
    tcp4 = parse_tcp_table(tcp4_text, "ipv4")
    tcp6 = parse_tcp_table(tcp6_text, "ipv6")
    if tcp4 is None or tcp6 is None:
        return {"complete": False, "listeners": []}
    listeners = [*tcp4, *tcp6]
    listener_inodes = {row["inode"] for row in listeners}
    inode_owners: dict[int, set[int]] = {inode: set() for inode in listener_inodes}
    complete = True
    try:
        processes = [entry for entry in root.iterdir() if entry.name.isdecimal()]
    except OSError:
        return {"complete": False, "listeners": []}
    for process in processes:
        fd_dir = process / "fd"
        try:
            descriptors = list(fd_dir.iterdir())
        except FileNotFoundError:
            # A process exited during this scoped scan; ownership could have raced.
            complete = False
            continue
        except OSError:
            complete = False
            continue
        for descriptor in descriptors:
            try:
                target = os.readlink(descriptor)
            except OSError:
                complete = False
                continue
            match = _SOCKET_LINK.fullmatch(target)
            if match is not None:
                inode = int(match.group(1))
                if inode in inode_owners:
                    inode_owners[inode].add(int(process.name))
    for listener in listeners:
        owners = inode_owners[listener["inode"]]
        if len(owners) != 1:
            listener["owner_state"] = "unknown"
            continue
        pid = next(iter(owners))
        process = root / str(pid)
        try:
            start = _start_time((process / "stat").read_text(encoding="ascii"))
            digest = _executable_digest(process / "exe")
            start_after = _start_time((process / "stat").read_text(encoding="ascii"))
        except (OSError, UnicodeError):
            listener["owner_state"] = "unknown"
            complete = False
            continue
        if start is None or start != start_after:
            listener["owner_state"] = "unknown"
            complete = False
            continue
        listener["owner_sha256"] = digest
        listener["owner_token"] = f"{pid}:{start}:{digest}"
        listener["owner_state"] = (
            "provider" if digest in trusted_executable_sha256s else "untrusted"
        )
    return {"complete": complete, "listeners": listeners}


def _candidate(value: object) -> dict[str, Any] | None:
    if not isinstance(value, Mapping) or set(value) - {
        "family",
        "address",
        "port",
        "ipv6_v6only",
    }:
        return None
    family = value.get("family")
    if not isinstance(family, str) or family not in _WILDCARDS:
        return None
    raw_address = value.get("address")
    if not isinstance(raw_address, str):
        return None
    try:
        parsed = ipaddress.ip_address(raw_address)
    except (ValueError, TypeError):
        return None
    if (family == "ipv4" and not isinstance(parsed, ipaddress.IPv4Address)) or (
        family == "ipv6" and not isinstance(parsed, ipaddress.IPv6Address)
    ):
        return None
    port = value.get("port")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        return None
    v6only = value.get("ipv6_v6only")
    if (family == "ipv4" and "ipv6_v6only" in value) or (
        family == "ipv6" and not isinstance(v6only, bool)
    ):
        return None
    return {
        "family": family,
        "address": str(parsed),
        "port": port,
        "ipv6_v6only": v6only if family == "ipv6" else None,
    }


def _validate_fixture(value: object) -> tuple[list[dict[str, Any]], set[str]] | None:
    if not isinstance(value, Mapping) or set(value) != {"candidates", "provider_executables"}:
        return None
    raw_candidates = value.get("candidates")
    raw_identities = value.get("provider_executables")
    if (
        not isinstance(raw_candidates, list)
        or not raw_candidates
        or len(raw_candidates) > _MAX_CANDIDATES
        or not isinstance(raw_identities, list)
        or not raw_identities
        or len(raw_identities) > _MAX_IDENTITIES
    ):
        return None
    candidates = [_candidate(item) for item in raw_candidates]
    if any(item is None for item in candidates):
        return None
    normalized = [item for item in candidates if item is not None]
    keys = [
        (item["family"], item["address"], item["port"], item["ipv6_v6only"]) for item in normalized
    ]
    if len(keys) != len(set(keys)):
        return None
    hashes: set[str] = set()
    for identity in raw_identities:
        if not isinstance(identity, Mapping) or set(identity) != {"sha256", "provenance"}:
            return None
        digest = identity.get("sha256")
        provenance = identity.get("provenance")
        if (
            not isinstance(digest, str)
            or not _SHA256.fullmatch(digest)
            or not isinstance(provenance, Mapping)
            or set(provenance) != {"source", "scope"}
            or not isinstance(provenance.get("source"), str)
            or not isinstance(provenance.get("scope"), str)
        ):
            return None
        source = provenance["source"]
        scope = provenance["scope"]
        try:
            source_parts = urllib.parse.urlsplit(source)
            source_host = source_parts.hostname
        except (TypeError, ValueError):
            return None
        if (
            source_parts.scheme != "https"
            or not source_host
            or not scope.strip()
            or len(source) > 256
            or len(scope) > 160
        ):
            return None
        hashes.add(digest)
    return normalized, hashes


def _matching_listeners(
    snapshot: Mapping[str, Any], candidate: Mapping[str, Any]
) -> list[dict[str, Any]]:
    family_wildcard = _WILDCARDS[str(candidate["family"])]
    candidate_wildcard = candidate["address"] == family_wildcard
    return [
        row
        for row in snapshot.get("listeners", [])
        if isinstance(row, dict)
        and row.get("family") == candidate["family"]
        and row.get("port") == candidate["port"]
        and (candidate_wildcard or row.get("address") in {candidate["address"], family_wildcard})
    ]


def _cross_family_ambiguous(snapshot: Mapping[str, Any], candidate: Mapping[str, Any]) -> bool:
    """Treat unobservable dual-stack overlap as unknown, never as attribution."""
    candidate_family = str(candidate["family"])
    candidate_port = candidate["port"]
    candidate_address = ipaddress.ip_address(str(candidate["address"]))
    for row in snapshot.get("listeners", []):
        if not isinstance(row, dict) or row.get("port") != candidate_port:
            continue
        row_family = row.get("family")
        row_address = row.get("address")
        if not isinstance(row_address, str):
            continue
        if candidate_family == "ipv6" and not candidate["ipv6_v6only"] and row_family == "ipv4":
            if candidate_address.is_unspecified:
                return True
            if isinstance(candidate_address, ipaddress.IPv6Address):
                mapped = candidate_address.ipv4_mapped
                if mapped is not None and row_address in {"0.0.0.0", str(mapped)}:
                    return True
        if candidate_family == "ipv4" and row_family == "ipv6":
            if row.get("ipv6_v6only") is True:
                continue
            try:
                listener_address = ipaddress.IPv6Address(row_address)
            except ipaddress.AddressValueError:
                return True
            if listener_address.is_unspecified:
                return True
            mapped = listener_address.ipv4_mapped
            if mapped is not None and candidate_address in {
                ipaddress.IPv4Address("0.0.0.0"),
                mapped,
            }:
                return True
    return False


def _same_listener(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    keys = (
        "family",
        "address",
        "port",
        "inode",
        "owner_sha256",
        "owner_token",
        "owner_state",
    )
    return all(left.get(key) == right.get(key) for key in keys)


def bind_candidate(
    candidate: Mapping[str, Any], socket_factory: Callable[..., Any] = socket.socket
) -> dict[str, Any]:
    """Attempt exactly one configured bind, without SO_REUSEADDR, and always close it."""
    family = socket.AF_INET if candidate["family"] == "ipv4" else socket.AF_INET6
    listener: Any | None = None
    actual_v6only: bool | None = None
    try:
        sock = socket_factory(family, socket.SOCK_STREAM)
        listener = sock
        if family == socket.AF_INET6:
            desired = 1 if candidate["ipv6_v6only"] else 0
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, desired)
            actual_v6only = bool(sock.getsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY))
            if actual_v6only != bool(candidate["ipv6_v6only"]):
                return {"errno": errno.EOPNOTSUPP, "ipv6_v6only": actual_v6only}
        address = (
            (candidate["address"], candidate["port"])
            if family == socket.AF_INET
            else (candidate["address"], candidate["port"], 0, 0)
        )
        sock.bind(address)
        return {"errno": None, "ipv6_v6only": actual_v6only}
    except OSError as error:
        number = error.errno if isinstance(error.errno, int) else None
        return {"errno": number, "ipv6_v6only": actual_v6only}
    finally:
        if listener is not None:
            listener.close()


def _public_observation(
    candidate: Mapping[str, Any],
    result: str,
    error_number: object,
    actual_v6only: object = None,
) -> dict[str, Any]:
    return {
        "port": candidate["port"],
        "address": candidate["address"],
        "family": candidate["family"],
        "ipv6_v6only_requested": candidate["ipv6_v6only"],
        "ipv6_v6only_observed": actual_v6only if isinstance(actual_v6only, bool) else None,
        "result": result,
        "errno": error_number
        if isinstance(error_number, int) and not isinstance(error_number, bool)
        else None,
    }


def probe(
    arguments: Mapping[str, object],
    *,
    snapshot_reader: Callable[[set[str]], Mapping[str, Any]] | None = None,
    bind_candidate: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Produce a bounded positive subset; no candidate or empty table means unknown."""
    if arguments.get("probe") != "guest_reserved_tcp_ports":
        raise ValueError("unknown guest reserved port probe")
    validated = _validate_fixture(arguments.get("fixture"))
    if validated is None:
        raise ValueError("guest_reserved_tcp_ports requires explicit candidate and owner fixtures")
    candidates, trusted_hashes = validated
    read_snapshot = snapshot_reader or (lambda hashes: read_listener_snapshot("/proc", hashes))
    bind_one = bind_candidate or (lambda candidate: bind_candidate_default(candidate))
    observations: list[dict[str, Any]] = []
    for candidate in candidates:
        before = read_snapshot(trusted_hashes)
        if before.get("complete") is not True:
            observations.append(_public_observation(candidate, "unknown", None))
            continue
        attempt = bind_one(candidate)
        error_number = attempt.get("errno")
        actual_v6only = attempt.get("ipv6_v6only")
        if candidate["family"] == "ipv6" and actual_v6only != candidate["ipv6_v6only"]:
            observations.append(
                _public_observation(candidate, "unknown", error_number, actual_v6only)
            )
            continue
        after = read_snapshot(trusted_hashes)
        if after.get("complete") is not True:
            observations.append(
                _public_observation(candidate, "unknown", error_number, actual_v6only)
            )
            continue
        before_matches = _matching_listeners(before, candidate)
        after_matches = _matching_listeners(after, candidate)
        if _cross_family_ambiguous(before, candidate) or _cross_family_ambiguous(after, candidate):
            observations.append(
                _public_observation(candidate, "unknown", error_number, actual_v6only)
            )
            continue
        stable_provider_listener = (
            len(before_matches) == 1
            and len(after_matches) == 1
            and _same_listener(before_matches[0], after_matches[0])
            and before_matches[0].get("owner_state") == "provider"
            and before_matches[0].get("owner_sha256") in trusted_hashes
        )
        if error_number == errno.EADDRINUSE and stable_provider_listener:
            state = "reserved"
        elif error_number is None and not before_matches and not after_matches:
            state = "bindable"
        else:
            state = "unknown"
        observations.append(_public_observation(candidate, state, error_number, actual_v6only))

    by_port: dict[int, set[str]] = {}
    for observation in observations:
        by_port.setdefault(observation["port"], set()).add(observation["result"])
    ambiguous_ports = {port for port, states in by_port.items() if len(states) > 1}
    for observation in observations:
        if observation["port"] in ambiguous_ports:
            observation["result"] = "unknown"
    members = sorted(
        port
        for port, states in by_port.items()
        if port not in ambiguous_ports and states == {"reserved"}
    )
    result: dict[str, Any] = {
        "guest_reserved_tcp_ports": members if members else "unknown",
        "observations": observations,
    }
    encoded = json.dumps(result, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) > _MAX_OUTPUT_BYTES:
        raise ValueError("guest_reserved_tcp_ports observation exceeds its output bound")
    return result


def bind_candidate_default(candidate: Mapping[str, Any]) -> Mapping[str, Any]:
    """Default binding implementation; separate name keeps test injection explicit."""
    return bind_candidate(candidate)


if __name__ == "__main__":
    arguments = json.loads(os.environ["SPS_GUEST_RESERVED_TCP_PORTS_ARGUMENTS"])
    print(json.dumps(probe(arguments), sort_keys=True, separators=(",", ":")))
