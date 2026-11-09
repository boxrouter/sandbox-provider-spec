# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Offline controls for point-in-time guest-reserved TCP-port observations."""

from __future__ import annotations

import errno
import hashlib
import json
import runpy
import socket
from pathlib import Path
from typing import Any

import pytest

from sandbox_provider_spec import check_digests
from sandbox_provider_spec.suite import Test as Scenario
from sandbox_provider_spec.suite import suite_path

_SCRIPT = suite_path().parent / "fixtures" / "guest_reserved_tcp_ports.py"
_PROBE = runpy.run_path(str(_SCRIPT))
_PROVIDER_BYTES = b"synthetic-provider-listener"
_PROVIDER_SHA256 = hashlib.sha256(_PROVIDER_BYTES).hexdigest()
_GUEST_SHA256 = hashlib.sha256(b"synthetic-guest-server").hexdigest()
_PROVENANCE = {
    "source": "https://fixture.example.test/provider-listener",
    "scope": "synthetic fixture",
}


def test_fixture_operation_dependencies_are_isolated() -> None:
    test = Scenario(
        id="coverage.facts.guest_reserved_tcp_ports.offline",
        title="Guest-reserved TCP-port probe source dependencies are isolated.",
        steps=({"op": "fixture.guest_reserved_tcp_ports"},),
        proves=(),
        rules=(),
    )
    dependencies = set(check_digests.test_dependencies(test))
    assert dependencies == {
        "coverage_guest_reserved_tcp_ports.py",
        "fixtures/guest_reserved_tcp_ports.py",
        "fixtures/guest_reserved_tcp_ports.schema.json",
        "fixtures/guest_reserved_tcp_ports.md",
    }
    assert not {"coverage_probe.py", "environment_facts.py"} & dependencies


def _candidate(
    family: str = "ipv4", port: int = 8080, *, v6only: bool | None = None
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "family": family,
        "address": "0.0.0.0" if family == "ipv4" else "::",
        "port": port,
    }
    if family == "ipv6":
        result["ipv6_v6only"] = v6only
    return result


def _fixture(*candidates: dict[str, Any]) -> dict[str, Any]:
    return {
        "candidates": list(candidates),
        "provider_executables": [{"sha256": _PROVIDER_SHA256, "provenance": _PROVENANCE}],
    }


def _listener(
    *,
    family: str = "ipv4",
    address: str = "0.0.0.0",
    port: int = 8080,
    inode: int = 41,
    owner: str = "provider",
    owner_token: str | None = None,
    v6only: bool | None = None,
) -> dict[str, Any]:
    digest = (
        _PROVIDER_SHA256 if owner == "provider" else _GUEST_SHA256 if owner == "guest" else None
    )
    return {
        "family": family,
        "address": address,
        "port": port,
        "inode": inode,
        "owner_sha256": digest,
        "owner_token": (owner_token or f"123:1:{digest}") if digest is not None else None,
        "owner_state": "provider"
        if owner == "provider"
        else "untrusted"
        if owner == "guest"
        else "unknown",
        "ipv6_v6only": v6only,
    }


def _snapshot(*listeners: dict[str, Any], complete: bool = True) -> dict[str, Any]:
    return {"complete": complete, "listeners": list(listeners)}


def _run(
    candidates: list[dict[str, Any]],
    snapshots: list[dict[str, Any]],
    bind_errors: list[int | None],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    snapshot_calls: list[dict[str, Any]] = []
    bind_calls: list[dict[str, Any]] = []

    def read_snapshot(_trusted_hashes: set[str]) -> dict[str, Any]:
        value = snapshots[len(snapshot_calls)]
        snapshot_calls.append(value)
        return value

    def bind(candidate: dict[str, Any]) -> dict[str, Any]:
        bind_calls.append(candidate)
        return {
            "errno": bind_errors[len(bind_calls) - 1],
            "ipv6_v6only": candidate.get("ipv6_v6only"),
        }

    result = _PROBE["probe"](
        {"probe": "guest_reserved_tcp_ports", "fixture": _fixture(*candidates)},
        snapshot_reader=read_snapshot,
        bind_candidate=bind,
    )
    return result, bind_calls


def _tcp_row(address_hex: str, port: int, inode: int, *, state: str = "0A") -> str:
    return (
        f"  0: {address_hex}:{port:04X} 00000000:0000 {state} "
        f"00000000:00000000 00:00000000 00000000 0 0 {inode}\n"
    )


def _proc_tree(
    root: Path,
    *,
    tcp4: str | None = None,
    tcp6: str | None = None,
    owner_bytes: bytes | None = _PROVIDER_BYTES,
    inode: int = 41,
) -> None:
    (root / "net").mkdir(parents=True, exist_ok=True)
    if tcp4 is not None:
        (root / "net" / "tcp").write_text(
            "sl local_address rem_address st tx_queue:rx_queue tr:tm->when "
            "retrnsmt uid timeout inode\n" + tcp4
        )
    if tcp6 is not None:
        (root / "net" / "tcp6").write_text(
            "sl local_address rem_address st tx_queue:rx_queue tr:tm->when "
            "retrnsmt uid timeout inode\n" + tcp6
        )
    if owner_bytes is not None:
        fd = root / "123" / "fd"
        fd.mkdir(parents=True, exist_ok=True)
        (root / "123" / "exe").write_bytes(owner_bytes)
        stat_fields = ["S", *(["0"] * 19)]
        stat_fields[19] = "1"
        (root / "123" / "stat").write_text(f"123 (synthetic) {' '.join(stat_fields)}\n")
        (fd / "4").symlink_to(f"socket:[{inode}]")


def test_genuine_provider_listener_requires_owned_stable_socket_and_eaddrinuse() -> None:
    listener = _listener()
    result, binds = _run(
        [_candidate()], [_snapshot(listener), _snapshot(listener)], [errno.EADDRINUSE]
    )
    assert result["guest_reserved_tcp_ports"] == [8080]
    assert result["observations"] == [
        {
            "port": 8080,
            "address": "0.0.0.0",
            "family": "ipv4",
            "ipv6_v6only_requested": None,
            "ipv6_v6only_observed": None,
            "result": "reserved",
            "errno": errno.EADDRINUSE,
        }
    ]
    assert binds == [{**_candidate(), "ipv6_v6only": None}]


def test_guest_owned_listener_does_not_become_provider_reservation() -> None:
    listener = _listener(owner="guest")
    result, _ = _run([_candidate()], [_snapshot(listener), _snapshot(listener)], [errno.EADDRINUSE])
    assert result["guest_reserved_tcp_ports"] == "unknown"
    assert result["observations"][0]["result"] == "unknown"


def test_unknown_owner_and_unmapped_inode_are_unknown() -> None:
    listener = _listener(owner="unknown")
    result, _ = _run([_candidate()], [_snapshot(listener), _snapshot(listener)], [errno.EADDRINUSE])
    assert result["guest_reserved_tcp_ports"] == "unknown"


def test_real_proc_scan_attributes_provider_executable_without_process_names(
    tmp_path: Path,
) -> None:
    _proc_tree(tmp_path, tcp4=_tcp_row("00000000", 8080, 41), tcp6="")
    snapshot = _PROBE["read_listener_snapshot"](tmp_path, {_PROVIDER_SHA256})
    assert snapshot["complete"] is True
    assert snapshot["listeners"] == [_listener()]


def test_guest_executable_hash_is_not_provider_attribution(tmp_path: Path) -> None:
    _proc_tree(
        tmp_path,
        tcp4=_tcp_row("00000000", 8080, 41),
        tcp6="",
        owner_bytes=b"synthetic-guest-server",
    )
    snapshot = _PROBE["read_listener_snapshot"](tmp_path, {_PROVIDER_SHA256})
    assert snapshot["complete"] is True
    assert snapshot["listeners"][0]["owner_sha256"] == _GUEST_SHA256
    result, _ = _run([_candidate()], [snapshot, snapshot], [errno.EADDRINUSE])
    assert result["guest_reserved_tcp_ports"] == "unknown"


def test_missing_proc_table_makes_snapshot_incomplete(tmp_path: Path) -> None:
    _proc_tree(tmp_path, tcp4=_tcp_row("00000000", 8080, 41), tcp6=None)
    snapshot = _PROBE["read_listener_snapshot"](tmp_path, {_PROVIDER_SHA256})
    assert snapshot["complete"] is False
    result, _ = _run([_candidate()], [snapshot, snapshot], [errno.EADDRINUSE])
    assert result["guest_reserved_tcp_ports"] == "unknown"


def test_socket_race_between_full_snapshots_is_unknown() -> None:
    before = _snapshot(_listener(inode=41, owner_token="pid-start-a"))
    after = _snapshot(_listener(inode=52, owner_token="pid-start-b"))
    result, _ = _run([_candidate()], [before, after], [errno.EADDRINUSE])
    assert result["guest_reserved_tcp_ports"] == "unknown"
    assert result["observations"][0]["result"] == "unknown"


def test_dual_stack_results_keep_tuple_and_v6only_and_do_not_collapse_ambiguity() -> None:
    candidates = [_candidate("ipv4"), _candidate("ipv6", v6only=False)]
    v4_listener = _snapshot(_listener(family="ipv4", address="0.0.0.0"))
    no_listener = _snapshot()
    result, binds = _run(
        candidates, [v4_listener, v4_listener, no_listener, no_listener], [errno.EADDRINUSE, None]
    )
    assert result["guest_reserved_tcp_ports"] == "unknown"
    assert [entry["family"] for entry in result["observations"]] == ["ipv4", "ipv6"]
    assert result["observations"][1]["ipv6_v6only_requested"] is False
    assert result["observations"][1]["ipv6_v6only_observed"] is False
    assert [call["family"] for call in binds] == ["ipv4", "ipv6"]


def test_dual_stack_v6only_false_with_v4_and_v6_listeners_is_ambiguous() -> None:
    candidates = [_candidate("ipv6", v6only=False)]
    overlap = _snapshot(
        _listener(family="ipv4", address="0.0.0.0"),
        _listener(family="ipv6", address="::"),
    )
    result, _ = _run(candidates, [overlap, overlap], [errno.EADDRINUSE])
    assert result["guest_reserved_tcp_ports"] == "unknown"
    assert result["observations"][0]["family"] == "ipv6"
    assert result["observations"][0]["ipv6_v6only_requested"] is False
    assert result["observations"][0]["ipv6_v6only_observed"] is False
    assert result["observations"][0]["result"] == "unknown"


def test_dual_stack_v6only_true_is_not_ambiguous_with_v4_listener() -> None:
    candidate = _candidate("ipv6", v6only=True)
    overlap = _snapshot(
        _listener(family="ipv4", address="0.0.0.0"),
        _listener(family="ipv6", address="::"),
    )
    result, _ = _run([candidate], [overlap, overlap], [errno.EADDRINUSE])
    assert result["guest_reserved_tcp_ports"] == [8080]
    assert result["observations"][0]["ipv6_v6only_requested"] is True
    assert result["observations"][0]["ipv6_v6only_observed"] is True


def test_ipv6_v6only_mismatch_is_unknown_and_retains_both_values() -> None:
    candidate = _candidate("ipv6", v6only=True)
    empty = _snapshot()
    result = _PROBE["probe"](
        {"probe": "guest_reserved_tcp_ports", "fixture": _fixture(candidate)},
        snapshot_reader=lambda _hashes: empty,
        bind_candidate=lambda _candidate: {"errno": None, "ipv6_v6only": False},
    )
    assert result["guest_reserved_tcp_ports"] == "unknown"
    assert result["observations"][0]["ipv6_v6only_requested"] is True
    assert result["observations"][0]["ipv6_v6only_observed"] is False


def test_empty_complete_snapshot_never_becomes_empty_or_class_wide_list() -> None:
    empty = _snapshot()
    result, _ = _run([_candidate()], [empty, empty], [None])
    assert result["guest_reserved_tcp_ports"] == "unknown"
    assert result["observations"][0]["result"] == "bindable"


@pytest.mark.parametrize("error_number", [errno.EACCES, errno.ETIMEDOUT, errno.EPERM, errno.EINTR])
def test_non_eaddrinuse_errors_never_mean_reserved(error_number: int) -> None:
    listener = _snapshot(_listener())
    result, _ = _run([_candidate()], [listener, listener], [error_number])
    assert result["guest_reserved_tcp_ports"] == "unknown"


def test_bindable_candidate_is_only_point_in_time_and_has_no_empty_list() -> None:
    empty = _snapshot()
    result, binds = _run([_candidate(port=9000)], [empty, empty], [None])
    assert result["guest_reserved_tcp_ports"] == "unknown"
    assert binds == [{**_candidate(port=9000), "ipv6_v6only": None}]


def test_ipv6_bind_sets_and_reads_v6only_and_closes_socket() -> None:
    class FakeSocket:
        def __init__(self) -> None:
            self.options: list[tuple[int, int, int]] = []
            self.closed = False

        def setsockopt(self, level: int, option: int, value: int) -> None:
            self.options.append((level, option, value))

        def getsockopt(self, level: int, option: int) -> int:
            return 1

        def bind(self, address: tuple[Any, ...]) -> None:
            self.address = address

        def close(self) -> None:
            self.closed = True

    made: list[FakeSocket] = []

    def factory(family: int, kind: int) -> FakeSocket:
        sock = FakeSocket()
        made.append(sock)
        return sock

    value = _PROBE["bind_candidate"](_candidate("ipv6", v6only=True), socket_factory=factory)
    assert value == {"errno": None, "ipv6_v6only": True}
    assert made[0].options == [(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)]
    assert made[0].closed is True


def test_public_observation_omits_process_socket_identifiers_and_hashes() -> None:
    listener = _snapshot(_listener())
    result, _ = _run([_candidate()], [listener, listener], [errno.EADDRINUSE])
    rendered = json.dumps(result)
    for private_field in ("inode", "owner_sha256", "owner_token", "pid", "cmdline", "environ"):
        assert private_field not in rendered


def test_candidate_count_is_bounded_and_there_is_no_port_range_scan() -> None:
    candidates = [_candidate(port=8080 + index) for index in range(2)]
    empty = _snapshot()
    result, binds = _run(candidates, [empty] * 4, [None, None])
    assert len(binds) == len(candidates)
    assert {candidate["port"] for candidate in binds} == {8080, 8081}
    assert result["guest_reserved_tcp_ports"] == "unknown"
