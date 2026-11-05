# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Offline controls for literal address-family observations and their host fixture checks."""

from __future__ import annotations

import errno
import json
import runpy
import socket
from typing import Any, cast

import pytest
from jsonschema import validate

from sandbox_provider_spec import coverage_address_families
from sandbox_provider_spec.driver import NotRun
from sandbox_provider_spec.suite import suite_path

_SCRIPT = suite_path().parent / "fixtures" / "address_families.py"
_GUEST = runpy.run_path(str(_SCRIPT))
_PROVENANCE = {
    "source": "https://fixture.example.test/address-families",
    "scope": "synthetic unit-test fixture; not a live endpoint",
}
_FIXTURE = {
    "ipv4_literal": "1.1.1.1",
    "ipv6_literal": "2606:4700:4700::1111",
    "port": 443,
    "provenance": _PROVENANCE,
}
_V4_FIB_LOOPBACK_ONLY = """\
Main:
  +-- 0.0.0.0/0 3 0 2
     +-- 127.0.0.0/8 2 0 2
        |-- 127.0.0.1
           /32 host LOCAL
Local:
  +-- 127.0.0.0/8 2 0 2
     |-- 127.0.0.1
        /32 host LOCAL
"""
_V4_ROUTE_HEADER = "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n"
_V6_LOOPBACK_ONLY = "00000000000000000000000000000001 01 80 10 00000000 lo\n"


def _observe(
    connect_results: list[tuple[bool, int | None]],
    *,
    fixture: dict[str, object] | None = None,
    v4_absent: bool | None = True,
    v6_absent: bool | None = True,
) -> dict[str, object]:
    calls: list[tuple[int, str, int]] = []

    def connect(family: int, address: str, port: int) -> tuple[bool, int | None]:
        calls.append((family, address, port))
        return connect_results[len(calls) - 1]

    evidence_calls: list[str] = []

    def route_evidence(family: str) -> bool | None:
        evidence_calls.append(family)
        return v4_absent if family == "ipv4" else v6_absent

    value = _GUEST["observe"](
        {"probe": "address_families", "fixture": fixture or _FIXTURE},
        connect=connect,
        route_evidence=route_evidence,
    )
    value["_connect_calls"] = calls
    value["_route_calls"] = evidence_calls
    return cast(dict[str, object], value)


@pytest.mark.parametrize("error_number", [errno.ENETUNREACH, errno.EADDRNOTAVAIL])
def test_false_requires_definite_local_error_and_complete_absence(
    error_number: int,
) -> None:
    assert _GUEST["classify_attempt"](False, error_number, True) is False
    assert _GUEST["classify_attempt"](False, error_number, False) is None
    assert _GUEST["classify_attempt"](False, error_number, None) is None


@pytest.mark.parametrize(
    "error_number", [None, errno.ETIMEDOUT, errno.ECONNREFUSED, errno.ECONNRESET, errno.EPERM]
)
def test_transient_or_unrelated_errors_never_prove_absence(error_number: int | None) -> None:
    assert _GUEST["classify_attempt"](False, error_number, True) is None


def test_success_is_positive_without_route_absence() -> None:
    assert _GUEST["classify_attempt"](True, None, None) is True


def test_ipv4_route_evidence_requires_address_and_route_sources() -> None:
    assert _GUEST["ipv4_address_present"](_V4_FIB_LOOPBACK_ONLY) is False
    assert _GUEST["ipv4_default_route_present"](_V4_ROUTE_HEADER) is False
    assert (
        _GUEST["family_absence_evidence"](
            "ipv4", ipv4_fib_trie=_V4_FIB_LOOPBACK_ONLY, ipv4_routes=_V4_ROUTE_HEADER
        )
        is True
    )
    with_address = _V4_FIB_LOOPBACK_ONLY.replace(
        "Local:", "     |-- 10.0.0.2\n        /32 host LOCAL\nLocal:"
    )
    assert (
        _GUEST["family_absence_evidence"](
            "ipv4", ipv4_fib_trie=with_address, ipv4_routes=_V4_ROUTE_HEADER
        )
        is False
    )
    default_route = _V4_ROUTE_HEADER + "eth0 00000000 0100000A 0003 0 0 100 00000000 0 0 0\n"
    assert (
        _GUEST["family_absence_evidence"](
            "ipv4", ipv4_fib_trie=_V4_FIB_LOOPBACK_ONLY, ipv4_routes=default_route
        )
        is False
    )
    assert _GUEST["family_absence_evidence"]("ipv4", ipv4_routes=_V4_ROUTE_HEADER) is None


def test_ipv6_route_evidence_requires_complete_address_and_route_sources() -> None:
    assert _GUEST["ipv6_global_address_present"](_V6_LOOPBACK_ONLY) is False
    assert (
        _GUEST["family_absence_evidence"]("ipv6", ipv6_if_inet6=_V6_LOOPBACK_ONLY, ipv6_routes="")
        is True
    )
    global_v6 = "20010db8000000000000000000000001 02 40 00 00000000 eth0\n"
    assert (
        _GUEST["family_absence_evidence"]("ipv6", ipv6_if_inet6=global_v6, ipv6_routes="") is False
    )
    default_route = (
        "0" * 32
        + " 00 "
        + "0" * 32
        + " 00 "
        + "0" * 32
        + " 00000000 00000000 00000000 00000000 eth0\n"
    )
    assert (
        _GUEST["family_absence_evidence"](
            "ipv6", ipv6_if_inet6=_V6_LOOPBACK_ONLY, ipv6_routes=default_route
        )
        is False
    )
    assert _GUEST["family_absence_evidence"]("ipv6", ipv6_if_inet6=None, ipv6_routes="") is None


def test_no_nat64_prefix_means_no_translated_attempt_and_unknown() -> None:
    value = _observe([(False, errno.ENETUNREACH), (True, None)])

    assert value["ipv4_native"] is False
    assert value["ipv6_native"] is True
    assert value["ipv4_errno"] == errno.ENETUNREACH
    assert value["ipv4_absence_evidence"] is True
    assert value["ipv6_errno"] is None
    assert value["ipv6_absence_evidence"] is None
    assert value["ipv4_via_nat64"] is None
    assert value["ipv4_destination_reach"] is None
    assert value["ipv4_nat64_target"] is None
    assert value["nat64_prefix"] is None
    connect_calls = cast(list[tuple[int, str, int]], value["_connect_calls"])
    assert len(connect_calls) == 2
    assert value["_route_calls"] == ["ipv4"]


def test_explicit_provenance_bearing_nat64_candidate_can_prove_handshake() -> None:
    fixture = {
        **_FIXTURE,
        "nat64_prefix": {
            "prefix": "2001:db8:64::/96",
            "provenance": {
                "source": "https://fixture.example.test/nat64-prefix",
                "scope": "synthetic unit-test-only explicit prefix",
            },
        },
    }
    value = _observe([(False, errno.ENETUNREACH), (True, None), (True, None)], fixture=fixture)

    assert value["ipv4_via_nat64"] is True
    assert value["ipv4_destination_reach"] == "nat64"
    assert value["ipv4_nat64_target"] == "2001:db8:64::101:101"
    assert value["nat64_prefix"] == fixture["nat64_prefix"]
    connect_calls = cast(list[tuple[int, str, int]], value["_connect_calls"])
    assert connect_calls[-1] == (
        socket.AF_INET6,
        "2001:db8:64::101:101",
        443,
    )


def test_failed_nat64_candidate_stays_unknown_never_none() -> None:
    fixture = {
        **_FIXTURE,
        "nat64_prefix": {
            "prefix": "2001:db8:64::/96",
            "provenance": {
                "source": "https://fixture.example.test/nat64-prefix",
                "scope": "synthetic unit-test-only explicit prefix",
            },
        },
    }
    value = _observe(
        [(False, errno.ENETUNREACH), (True, None), (False, errno.ENETUNREACH)],
        fixture=fixture,
    )

    assert value["ipv4_via_nat64"] is None
    assert value["ipv4_destination_reach"] is None


def test_native_ipv4_takes_precedence_even_if_nat64_handshake_also_succeeds() -> None:
    fixture = {
        **_FIXTURE,
        "nat64_prefix": {
            "prefix": "2001:db8:64::/96",
            "provenance": {
                "source": "https://fixture.example.test/nat64-prefix",
                "scope": "synthetic unit-test-only explicit prefix",
            },
        },
    }
    value = _observe([(True, None), (True, None), (True, None)], fixture=fixture)

    assert value["ipv4_via_nat64"] is True
    assert value["ipv4_destination_reach"] == "native"


@pytest.mark.parametrize("prefix", ["2001:db8::/96", "2001:db8:64::/48"])
def test_prefix_must_be_explicit_and_use_supported_rfc6052_length(prefix: str) -> None:
    assert _GUEST["translate_ipv4"](prefix, "1.2.3.4")


def test_missing_prefix_provenance_is_rejected() -> None:
    fixture = {
        **_FIXTURE,
        "nat64_prefix": {"prefix": "2001:db8:64::/96"},
    }
    with pytest.raises(ValueError, match="explicit provenance"):
        _GUEST["observe"]({"probe": "address_families", "fixture": fixture})


def test_explicit_prefix_translation_obeys_rfc6052_u_octet() -> None:
    assert _GUEST["translate_ipv4"]("2001:db8:64::/96", "1.2.3.4") == ("2001:db8:64::102:304")
    assert _GUEST["translate_ipv4"]("2001:db8:122:344::/64", "1.2.3.4") == (
        "2001:db8:122:344:1:203:400:0"
    )


def test_guest_probe_uses_explicit_literals_and_never_dns() -> None:
    source = _SCRIPT.read_text(encoding="utf-8")
    assert "getaddrinfo" not in source
    assert "gethostbyname" not in source
    assert "create_connection" not in source
    assert "DEFAULT_NAT64_PREFIX" not in source
    assert "socket.socket(family, socket.SOCK_STREAM)" in source
    assert "client.connect(_target(family, address, port))" in source


def test_cloudflare_fixture_example_matches_explicit_fixture_schema() -> None:
    fixtures = suite_path().parent / "fixtures"
    example = json.loads((fixtures / "address_families.example.json").read_text())
    schema = json.loads((fixtures / "address_families.schema.json").read_text())
    validate(example, schema)
    assert "nat64_prefix" not in example["address_families"]


def test_address_families_runner_dispatches_its_own_operation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected: dict[str, object] = {"outbound_ip_families": ["ipv4"]}

    def guest(_driver: object, _target: object, _inputs: object) -> dict[str, object]:
        return expected

    monkeypatch.setattr(coverage_address_families, "guest", guest)
    runner = coverage_address_families.AddressFamiliesRunner(cast(Any, None))
    assert runner._test_operation("fixture.address_families", None, {}) == expected


class FakeSocket:
    def __init__(self, family: int, kind: int) -> None:
        self.family = family
        self.kind = kind
        self.timeouts: list[float] = []
        self.target: tuple[object, ...] | None = None
        self.closed = False

    def settimeout(self, timeout: float) -> None:
        self.timeouts.append(timeout)

    def connect(self, target: tuple[object, ...]) -> None:
        self.target = target

    def recv(self, maximum: int) -> bytes:
        assert maximum == 1
        return b""

    def close(self) -> None:
        self.closed = True


def test_fixture_health_uses_independent_fresh_literal_tuple_controls() -> None:
    sockets: list[FakeSocket] = []

    def socket_factory(family: int, kind: int) -> FakeSocket:
        created = FakeSocket(family, kind)
        sockets.append(created)
        return created

    fixture = coverage_address_families.validate_fixture(_FIXTURE)
    controls = coverage_address_families.check_fixture_health(fixture, socket_factory)

    assert len(sockets) == 2
    assert sockets[0] is not sockets[1]
    assert sockets[0].target == ("1.1.1.1", 443)
    assert sockets[1].target == ("2606:4700:4700::1111", 443, 0, 0)
    assert all(item.closed for item in sockets)
    assert all(item.timeouts == [2.0, 0.05] for item in sockets)
    assert controls["ipv4"] == {
        "address": "1.1.1.1",
        "port": 443,
        "tuple": ["1.1.1.1", 443],
        "connected": True,
        "read_bytes": 0,
        "read_errno": None,
    }
    ipv6_control = cast(dict[str, object], controls["ipv6"])
    assert ipv6_control["address"] == "2606:4700:4700::1111"
    assert ipv6_control["tuple"] == ["2606:4700:4700::1111", 443, 0, 0]


def test_missing_or_invalid_fixture_is_not_run_and_never_negative() -> None:
    with pytest.raises(NotRun, match="fixture_missing"):
        coverage_address_families.validate_fixture(None)
    with pytest.raises(NotRun, match="provenance_missing"):
        coverage_address_families.validate_fixture({**_FIXTURE, "provenance": None})


def test_unhealthy_fixture_control_is_not_run(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_socket(_family: int, _kind: int) -> FakeSocket:
        raise OSError(errno.EHOSTUNREACH, "unavailable")

    fixture = coverage_address_families.validate_fixture(_FIXTURE)
    with pytest.raises(NotRun, match="fixture_unhealthy"):
        coverage_address_families.check_fixture_health(fixture, fail_socket)


class FakeDriver:
    def __init__(self, output: dict[str, object]) -> None:
        self.output = output
        self.calls: list[tuple[str, object, object]] = []

    def call(self, operation: str, target: object, inputs: object) -> dict[str, object]:
        self.calls.append((operation, target, inputs))
        if operation == "run":
            return {"exit_code": 0, "stdout": json.dumps(self.output)}
        return {}


def test_guest_orchestration_records_controls_and_never_opens_host_socket_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output: dict[str, object] = {
        "ipv4_native": True,
        "ipv6_native": None,
        "ipv4_errno": None,
        "ipv6_errno": None,
        "ipv4_absence_evidence": None,
        "ipv6_absence_evidence": None,
        "ipv4_via_nat64": None,
        "outbound_ip_families": None,
        "ipv4_destination_reach": "native",
        "ipv4_tuple": "1.1.1.1:443",
        "ipv6_tuple": "[2606:4700:4700::1111]:443",
        "ipv4_nat64_target": None,
        "nat64_prefix": None,
    }
    driver = FakeDriver(output)
    monkeypatch.setattr(
        coverage_address_families,
        "check_fixture_health",
        lambda _fixture: {
            "ipv4": {"connected": True, "tuple": ["1.1.1.1", 443]},
            "ipv6": {
                "connected": True,
                "tuple": ["2606:4700:4700::1111", 443, 0, 0],
            },
            "provenance": _PROVENANCE,
        },
    )

    result = coverage_address_families.guest(cast(Any, driver), "box", {"fixture": _FIXTURE})

    assert result["ipv4_native"] is True
    controls = cast(dict[str, object], result["fixture_controls"])
    ipv4_control = cast(dict[str, object], controls["ipv4"])
    assert ipv4_control["connected"] is True
    recorded = json.loads(str(result["stdout"]))
    assert recorded["fixture_controls"]["ipv4"]["tuple"] == ["1.1.1.1", 443]
    assert recorded["fixture_controls"]["ipv6"]["tuple"] == [
        "2606:4700:4700::1111",
        443,
        0,
        0,
    ]
    assert recorded["fixture_controls"]["provenance"] == _PROVENANCE
    run_call = next(call for call in driver.calls if call[0] == "run")
    run_inputs = cast(dict[str, object], run_call[2])
    environment = cast(dict[str, str], run_inputs["environment"])
    assert "nat64_prefix" not in environment["SPS_ADDRESS_FAMILY_ARGUMENTS"]
