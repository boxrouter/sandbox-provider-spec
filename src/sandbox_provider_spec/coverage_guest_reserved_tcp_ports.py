# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Orchestration for the isolated guest-reserved TCP-port fixture operation."""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from typing import Any, cast

from sandbox_provider_spec.driver import Driver, NativeFailure, NotRun
from sandbox_provider_spec.runner import Runner
from sandbox_provider_spec.suite import suite_path

_SCRIPT = "guest_reserved_tcp_ports.py"
_GUEST_PATH = "/tmp/sps-guest-reserved-tcp-ports.py"
_MAX_OUTPUT_BYTES = 4096
_MAX_CANDIDATES = 16


def _valid_observation(item: object) -> bool:
    if not isinstance(item, dict) or set(item) != {
        "port",
        "address",
        "family",
        "ipv6_v6only_requested",
        "ipv6_v6only_observed",
        "result",
        "errno",
    }:
        return False
    port = item["port"]
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        return False
    family = item["family"]
    if not isinstance(family, str) or family not in {"ipv4", "ipv6"}:
        return False
    if not isinstance(item["address"], str):
        return False
    if not isinstance(item["result"], str) or item["result"] not in {
        "reserved",
        "bindable",
        "unknown",
    }:
        return False
    error_number = item["errno"]
    if error_number is not None and (
        isinstance(error_number, bool) or not isinstance(error_number, int)
    ):
        return False
    if family == "ipv6":
        if not isinstance(item["ipv6_v6only_requested"], bool):
            return False
        observed = item["ipv6_v6only_observed"]
        return observed is None or isinstance(observed, bool)
    return item["ipv6_v6only_requested"] is None and item["ipv6_v6only_observed"] is None


def _valid_fixture(value: object) -> bool:
    if not isinstance(value, Mapping) or set(value) != {"candidates", "provider_executables"}:
        return False
    candidates = value.get("candidates")
    identities = value.get("provider_executables")
    return bool(
        isinstance(candidates, list)
        and 1 <= len(candidates) <= _MAX_CANDIDATES
        and isinstance(identities, list)
        and identities
    )


def _validate_observation(value: object, fixture: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"guest_reserved_tcp_ports", "observations"}:
        raise NativeFailure("guest_reserved_tcp_ports_probe_invalid")
    observations = value["observations"]
    if not isinstance(observations, list) or len(observations) != len(fixture["candidates"]):
        raise NativeFailure("guest_reserved_tcp_ports_probe_invalid")
    expected = {
        (
            item.get("family"),
            item.get("address"),
            item.get("port"),
            item.get("ipv6_v6only"),
        )
        for item in fixture["candidates"]
        if isinstance(item, Mapping)
    }
    actual: set[tuple[object, ...]] = set()
    for item in observations:
        if not _valid_observation(item):
            raise NativeFailure("guest_reserved_tcp_ports_probe_invalid")
        assert isinstance(item, dict)
        port = item["port"]
        actual.add(
            (
                item["family"],
                item["address"],
                port,
                item["ipv6_v6only_requested"],
            )
        )
    if actual != expected:
        raise NativeFailure("guest_reserved_tcp_ports_probe_invalid")
    members = value["guest_reserved_tcp_ports"]
    if members != "unknown":
        if (
            not isinstance(members, list)
            or not members
            or any(isinstance(port, bool) or not isinstance(port, int) for port in members)
            or members != sorted(set(members))
            or any(not 1 <= port <= 65535 for port in members)
        ):
            raise NativeFailure("guest_reserved_tcp_ports_probe_invalid")
        reserved = {item["port"] for item in observations if item["result"] == "reserved"}
        if set(members) != reserved:
            raise NativeFailure("guest_reserved_tcp_ports_probe_invalid")
    elif any(item["result"] == "reserved" for item in observations):
        raise NativeFailure("guest_reserved_tcp_ports_probe_invalid")
    return value


def guest(driver: Driver, target: object, inputs: Mapping[str, object]) -> Mapping[str, object]:
    """Run the point-in-time table/ownership observation and candidate-only binds."""
    fixture = inputs.get("fixture")
    if not _valid_fixture(fixture):
        raise NotRun("guest_reserved_tcp_ports_fixture_missing")
    script = (suite_path().parent / "fixtures" / _SCRIPT).read_bytes()
    driver.call(
        "files.write", target, {"path": _GUEST_PATH, "data": base64.b64encode(script).decode()}
    )
    arguments = {"probe": "guest_reserved_tcp_ports", "fixture": fixture}
    run_input = {
        "bash_script": "python3 " + _GUEST_PATH,
        "timeout_ms": 15000,
        "environment": {
            "SPS_GUEST_RESERVED_TCP_PORTS_ARGUMENTS": json.dumps(arguments, separators=(",", ":"))
        },
    }
    result = driver.call("run", target, run_input)
    if result.get("exit_code") != 0:
        raise NativeFailure("guest_reserved_tcp_ports_probe_failed")
    output = result.get("stdout")
    if not isinstance(output, (bytes, str)) or len(output) > _MAX_OUTPUT_BYTES:
        raise NativeFailure("guest_reserved_tcp_ports_probe_invalid")
    try:
        observation = json.loads(output)
    except (TypeError, json.JSONDecodeError):
        raise NativeFailure("guest_reserved_tcp_ports_probe_invalid") from None
    normalized = _validate_observation(observation, cast(Mapping[str, Any], fixture))
    diagnostic = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
    return {
        "guest_reserved_tcp_ports": normalized["guest_reserved_tcp_ports"],
        "stdout": diagnostic,
    }


class GuestReservedTcpPortsRunner(Runner):
    """New operation keeps guest port observation out of shared fixture modules."""

    def _test_operation(
        self, operation: str, target: object, inputs: Mapping[str, Any]
    ) -> Mapping[str, object]:
        if operation == "fixture.guest_reserved_tcp_ports":
            return guest(self.driver, target, inputs)
        return super()._test_operation(operation, target, inputs)
