# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Independent literal-address controls and orchestration for the IP-family fact probe."""

from __future__ import annotations

import base64
import errno
import ipaddress
import json
import socket
import urllib.parse
from collections.abc import Callable, Mapping
from typing import Any

from sandbox_provider_spec.driver import Driver, NativeFailure, NotRun
from sandbox_provider_spec.runner import Runner
from sandbox_provider_spec.suite import suite_path

_GUEST_SCRIPT = "address_families.py"
_GUEST_PATH = "/tmp/sps-address-families.py"
_CONNECT_TIMEOUT_SECONDS = 2.0
_READ_TIMEOUT_SECONDS = 0.05
_MAX_OUTPUT_BYTES = 2048
_MAX_DIAGNOSTIC_BYTES = 1024
_DEFINITE_NO_ROUTE = {errno.ENETUNREACH, errno.EADDRNOTAVAIL}


def _provenance(value: object, label: str) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise NotRun(f"{label}_provenance_missing")
    source = value.get("source")
    scope = value.get("scope")
    if not isinstance(source, str) or not isinstance(scope, str):
        raise NotRun(f"{label}_provenance_invalid")
    try:
        parts = urllib.parse.urlsplit(source)
        hostname = parts.hostname
    except ValueError:
        parts = None
        hostname = None
    if not _valid_provenance(parts, hostname, source, scope):
        raise NotRun(f"{label}_provenance_invalid")
    return {"source": str(source), "scope": scope.strip()}


def _valid_provenance(
    parts: urllib.parse.SplitResult | None,
    hostname: str | None,
    source: str,
    scope: str,
) -> bool:
    return bool(
        parts is not None
        and parts.scheme in {"http", "https"}
        and hostname
        and scope.strip()
        and len(source) <= 256
        and len(scope) <= 160
    )


def validate_fixture(value: object) -> dict[str, Any]:
    """Validate only explicitly supplied endpoints; the probe has no implicit targets."""
    if not isinstance(value, Mapping):
        raise NotRun("address_families_fixture_missing")
    try:
        ipv4 = ipaddress.IPv4Address(value["ipv4_literal"])
        ipv6 = ipaddress.IPv6Address(value["ipv6_literal"])
    except (KeyError, ipaddress.AddressValueError, TypeError):
        raise NotRun("address_families_fixture_invalid") from None
    port = value.get("port")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise NotRun("address_families_fixture_invalid")
    result: dict[str, Any] = {
        "ipv4_literal": str(ipv4),
        "ipv6_literal": str(ipv6),
        "port": port,
        "provenance": _provenance(value.get("provenance"), "address_families"),
    }
    if "nat64_prefix" in value:
        prefix = value["nat64_prefix"]
        if not isinstance(prefix, Mapping):
            raise NotRun("nat64_prefix_fixture_invalid")
        raw_prefix = prefix.get("prefix")
        try:
            network = ipaddress.IPv6Network(raw_prefix, strict=True)
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, TypeError):
            raise NotRun("nat64_prefix_fixture_invalid") from None
        if network.prefixlen not in {32, 40, 48, 56, 64, 96}:
            raise NotRun("nat64_prefix_fixture_invalid")
        result["nat64_prefix"] = {
            "prefix": str(network),
            "provenance": _provenance(prefix.get("provenance"), "nat64_prefix"),
        }
    return result


def _address_tuple(family: int, address: str, port: int) -> tuple[object, ...]:
    if family == socket.AF_INET:
        return (address, port)
    return (address, port, 0, 0)


def _control_one(
    family: int,
    address: str,
    port: int,
    socket_factory: Callable[..., Any] = socket.socket,
) -> dict[str, object]:
    """Make one fresh TCP health/control connection and read at most one byte."""
    target = _address_tuple(family, address, port)
    client: Any | None = None
    try:
        active_client = socket_factory(family, socket.SOCK_STREAM)
        client = active_client
        active_client.settimeout(_CONNECT_TIMEOUT_SECONDS)
        active_client.connect(target)
        active_client.settimeout(_READ_TIMEOUT_SECONDS)
        read_error: int | None = None
        try:
            data = active_client.recv(1)
            read_bytes = len(data)
        except (TimeoutError, BlockingIOError):
            read_bytes = 0
        except OSError as error:
            read_bytes = 0
            read_error = error.errno if isinstance(error.errno, int) else None
        return {
            "address": address,
            "port": port,
            "tuple": list(target),
            "connected": True,
            "read_bytes": read_bytes,
            "read_errno": read_error,
        }
    except OSError:
        raise NotRun("address_families_fixture_unhealthy") from None
    finally:
        if client is not None:
            client.close()


def check_fixture_health(
    fixture: Mapping[str, Any], socket_factory: Callable[..., Any] = socket.socket
) -> dict[str, object]:
    """Independently control each family through a new socket to its literal tuple."""
    return {
        "ipv4": _control_one(
            socket.AF_INET, fixture["ipv4_literal"], fixture["port"], socket_factory
        ),
        "ipv6": _control_one(
            socket.AF_INET6, fixture["ipv6_literal"], fixture["port"], socket_factory
        ),
        "provenance": dict(fixture["provenance"]),
    }


def _validate_observation(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise NativeFailure("address_families_probe_invalid")
    expected = {
        "ipv4_native",
        "ipv6_native",
        "ipv4_errno",
        "ipv6_errno",
        "ipv4_absence_evidence",
        "ipv6_absence_evidence",
        "ipv4_via_nat64",
        "outbound_ip_families",
        "ipv4_destination_reach",
        "ipv4_tuple",
        "ipv6_tuple",
        "ipv4_nat64_target",
        "nat64_prefix",
    }
    if set(value) != expected:
        raise NativeFailure("address_families_probe_invalid")
    for key in ("ipv4_native", "ipv6_native", "ipv4_via_nat64"):
        if value[key] is not None and not isinstance(value[key], bool):
            raise NativeFailure("address_families_probe_invalid")
    for key in ("ipv4_errno", "ipv6_errno"):
        if value[key] is not None and (
            isinstance(value[key], bool) or not isinstance(value[key], int)
        ):
            raise NativeFailure("address_families_probe_invalid")
    for key in ("ipv4_absence_evidence", "ipv6_absence_evidence"):
        if value[key] is not None and not isinstance(value[key], bool):
            raise NativeFailure("address_families_probe_invalid")
    for family in ("ipv4", "ipv6"):
        native_result = value[f"{family}_native"]
        error_number = value[f"{family}_errno"]
        if native_result is False and (
            isinstance(error_number, bool)
            or not isinstance(error_number, int)
            or error_number not in _DEFINITE_NO_ROUTE
            or value[f"{family}_absence_evidence"] is not True
        ):
            raise NativeFailure("address_families_probe_invalid")
        if native_result is True and error_number is not None:
            raise NativeFailure("address_families_probe_invalid")
    families = value["outbound_ip_families"]
    if families is not None:
        if not isinstance(families, list) or any(
            not isinstance(item, str) or item not in {"ipv4", "ipv6"} for item in families
        ):
            raise NativeFailure("address_families_probe_invalid")
        if len(families) != len(set(families)):
            raise NativeFailure("address_families_probe_invalid")
    native = (value["ipv4_native"], value["ipv6_native"])
    expected_families = (
        [family for family, result in zip(("ipv4", "ipv6"), native, strict=True) if result is True]
        if all(isinstance(result, bool) for result in native)
        else None
    )
    if families != expected_families:
        raise NativeFailure("address_families_probe_invalid")
    destination = value["ipv4_destination_reach"]
    if destination is not None and (
        not isinstance(destination, str) or destination not in {"native", "nat64"}
    ):
        raise NativeFailure("address_families_probe_invalid")
    if destination == "native" and value["ipv4_native"] is not True:
        raise NativeFailure("address_families_probe_invalid")
    if destination == "nat64" and not (
        value["ipv4_native"] is False and value["ipv4_via_nat64"] is True
    ):
        raise NativeFailure("address_families_probe_invalid")
    for key in ("ipv4_tuple", "ipv6_tuple", "ipv4_nat64_target"):
        if value[key] is not None and not isinstance(value[key], str):
            raise NativeFailure("address_families_probe_invalid")
    prefix = value["nat64_prefix"]
    if prefix is not None:
        if not isinstance(prefix, dict) or set(prefix) != {"prefix", "provenance"}:
            raise NativeFailure("address_families_probe_invalid")
        if not isinstance(prefix["prefix"], str) or not isinstance(prefix["provenance"], dict):
            raise NativeFailure("address_families_probe_invalid")
    return value


def guest(driver: Driver, target: object, inputs: Mapping[str, object]) -> Mapping[str, object]:
    """Run guest probes only after independently checking the explicit fixture endpoints."""
    fixture = validate_fixture(inputs.get("fixture"))
    controls = check_fixture_health(fixture)
    script = (suite_path().parent / "fixtures" / _GUEST_SCRIPT).read_bytes()
    driver.call(
        "files.write", target, {"path": _GUEST_PATH, "data": base64.b64encode(script).decode()}
    )
    arguments = {"probe": "address_families", "fixture": fixture}
    result = driver.call(
        "run",
        target,
        {
            "bash_script": "python3 " + _GUEST_PATH,
            "timeout_ms": 15000,
            "environment": {"SPS_ADDRESS_FAMILY_ARGUMENTS": json.dumps(arguments)},
        },
    )
    if result.get("exit_code") != 0:
        raise NativeFailure("address_families_probe_failed")
    payload = result.get("stdout")
    if not isinstance(payload, (bytes, str)) or len(payload) > _MAX_OUTPUT_BYTES:
        raise NativeFailure("address_families_probe_invalid")
    try:
        value = json.loads(payload)
    except (TypeError, json.JSONDecodeError):
        raise NativeFailure("address_families_probe_invalid") from None
    observations = _validate_observation(value)
    if observations["nat64_prefix"] != fixture.get("nat64_prefix"):
        raise NativeFailure("address_families_probe_invalid")
    observations["fixture_controls"] = controls
    diagnostic = json.dumps(observations, sort_keys=True, separators=(",", ":"))
    if len(diagnostic.encode("utf-8")) > _MAX_DIAGNOSTIC_BYTES:
        raise NativeFailure("address_families_probe_invalid")
    observations["stdout"] = diagnostic
    return observations


class AddressFamiliesRunner(Runner):
    """Opt-in fixture operation keeps this probe outside the shared dispatcher."""

    def _test_operation(
        self, operation: str, target: object, inputs: Mapping[str, Any]
    ) -> Mapping[str, object]:
        if operation == "fixture.address_families":
            return guest(self.driver, target, inputs)
        return super()._test_operation(operation, target, inputs)
