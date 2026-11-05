# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""V6 fixtures run offline with local endpoints and a fake driver."""

from __future__ import annotations

import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, cast

import pytest

from sandbox_provider_spec import coverage_v6
from sandbox_provider_spec.driver import Driver, Inputs, NotRun, Observation

pytestmark = [pytest.mark.integration, pytest.mark.loopback]


class KernelDriver(Driver):
    def __init__(self) -> None:
        super().__init__()
        self.calls: list[tuple[str, Inputs]] = []

    def call(self, operation: str, target: object, inputs: Inputs) -> Observation:
        del target
        self.calls.append((operation, inputs))
        feature = cast(dict[str, str], inputs["environment"])["SPS_KERNEL_FEATURE"]
        return {
            "exit_code": 0,
            "stdout": json.dumps({"works": feature in coverage_v6.KERNEL_FEATURES}),
        }


class LocalDriver(Driver):
    def call(self, operation: str, target: object, inputs: Inputs) -> Observation:
        del target
        assert operation == "run"
        environment = os.environ.copy()
        environment.update(cast(dict[str, str], inputs["environment"]))
        result = subprocess.run(
            ["bash", "-c", str(inputs["bash_script"])],
            capture_output=True,
            env=environment,
            timeout=cast(int, inputs["timeout_ms"]) / 1000,
            check=False,
        )
        return {"exit_code": result.returncode, "stdout": result.stdout}


class LocalPrivateNetworkDriver(Driver):
    def __init__(self) -> None:
        super().__init__()
        self.address_calls = 0
        self.run_calls = 0

    def network_private_address(self, target: object, inputs: Inputs) -> Observation:
        del target, inputs
        self.address_calls += 1
        return {"address": "127.0.0.1", "ip_version": 4}

    def run(self, target: object, inputs: Inputs) -> Observation:
        del target
        self.run_calls += 1
        environment = os.environ.copy()
        environment.update(cast(dict[str, str], inputs["environment"]))
        result = subprocess.run(
            ["bash", "-c", str(inputs["bash_script"])],
            capture_output=True,
            env=environment,
            timeout=cast(int, inputs["timeout_ms"]) / 1000,
            check=False,
        )
        return {"exit_code": result.returncode, "stdout": result.stdout}


def test_fuse_probe_paces_eperm_before_mount_connects_device() -> None:
    lines = [line.strip() for line in coverage_v6._KERNEL_SCRIPT.splitlines()]
    for index, line in enumerate(lines):
        if line == "if exc.errno == errno.EPERM:":
            following = [item for item in lines[index + 1 :] if item]
            assert following[:3] == [
                "# select() reports /dev/fuse readable before mount connects it.",
                "time.sleep(0.01)",
                "continue",
            ]
            return
    else:
        pytest.fail("kernel script does not handle EPERM")


@pytest.mark.parametrize("feature", sorted(coverage_v6.KERNEL_FEATURES))
def test_kernel_feature_uses_root_probe_and_returns_only_works(feature: str) -> None:
    driver = KernelDriver()
    compile(coverage_v6._KERNEL_SCRIPT, "coverage_v6_kernel_probe", "exec")
    assert coverage_v6.kernel_feature(driver, {"box": True}, {"feature": feature}) == {
        "works": True
    }
    assert len(driver.calls) == 1
    operation, inputs = driver.calls[0]
    assert operation == "run.as_root"
    assert "SPS_KERNEL_FEATURE" in str(inputs["bash_script"])
    assert "SPS_KERNEL_FEATURE" in cast(dict[str, str], inputs["environment"])


def test_fuse_reply_serializes_header_and_payload_with_real_builder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = coverage_v6._KERNEL_SCRIPT
    helper = script.split('    def reply(unique, payload=b"", error=0):\n', 1)[1].split(
        "\n    def serve():", 1
    )[0]
    namespace: dict[str, Any] = {
        "os": os,
        "struct": struct,
        "fd": 17,
        "failed": threading.Event(),
        "out_header": struct.Struct("<IiQ"),
    }
    function = 'def reply(unique, payload=b"", error=0):\n' + "\n".join(
        "    " + line for line in helper.splitlines()
    )
    exec(function, namespace)
    replies: list[bytes] = []

    def write(_fd: int, data: bytes) -> int:
        replies.append(data)
        return len(data)

    monkeypatch.setattr(namespace["os"], "write", write)
    payload = struct.pack("<QQQQII", 2, 0, 1, 0, 0, 0) + b"a" * 88
    namespace["reply"](7, payload)

    assert len(replies) == 1
    out_header = namespace["struct"].Struct("<IiQ")
    length, error, unique = out_header.unpack_from(replies[0])
    assert (length, error, unique) == (16 + len(payload), 0, 7)
    entry = replies[0][out_header.size :]
    assert struct.unpack_from("<QQQQII", entry) == (2, 0, 1, 0, 0, 0)
    assert entry[40:] == b"a" * 88


@pytest.mark.parametrize("name, error", [(b"proof", 0), (b"other", 2)])
def test_fuse_lookup_builds_the_production_entry_payload(name: bytes, error: int) -> None:
    script = coverage_v6._KERNEL_SCRIPT
    branch = script.split("                elif op == 1:  # LOOKUP\n", 1)[1].split(
        "                elif op == 3:  # GETATTR", 1
    )[0]
    namespace: dict[str, Any] = {
        "errno": __import__("errno"),
        "struct": struct,
        "fuse_attr": lambda ino: b"attr:" + bytes([ino]),
    }
    replies: list[tuple[int, bytes, int]] = []
    namespace["reply"] = lambda unique, payload=b"", error=0: replies.append(
        (unique, payload, error)
    )
    namespace.update({"op": 1, "body": name + b"\0", "unique": 23})
    exec("if True:\n" + "\n".join("    " + line for line in branch.splitlines()), namespace)

    if name == b"proof":
        payload = struct.pack("<QQQQII", 2, 0, 1, 0, 0, 0) + b"attr:\x02"
        assert replies == [(23, payload, 0)]
    else:
        assert replies == [(23, b"", error)]


@pytest.mark.parametrize("feature", sorted(coverage_v6.KERNEL_FEATURES))
@pytest.mark.parametrize("result", [False, True])
def test_kernel_script_dispatches_to_the_selected_probe(
    monkeypatch: pytest.MonkeyPatch, feature: str, result: bool
) -> None:
    monkeypatch.delenv("SPS_KERNEL_FEATURE", raising=False)
    monkeypatch.setenv("SPS_KERNEL_FEATURE", feature)
    namespace: dict[str, Any] = {"__name__": "kernel_probe"}
    calls: list[str] = []
    exec(coverage_v6._KERNEL_SCRIPT, namespace)
    for name in coverage_v6.KERNEL_FEATURES:

        def probe(name: str = name) -> bool:
            calls.append(name)
            return result if name == feature else False

        namespace["probes"][name] = probe

    output: list[str] = []
    monkeypatch.setitem(namespace, "print", lambda value: output.append(value))
    dispatch = coverage_v6._KERNEL_SCRIPT.split("try:\n    works = bool(probes.get", 1)[1]
    exec("try:\n    works = bool(probes.get" + dispatch, namespace)

    assert calls == [feature]
    assert json.loads(output[0]) == {"works": result}


def test_kernel_probe_moves_a_process_into_nested_cgroup_and_cleans_nft_table() -> None:
    assert "import sys" in coverage_v6._KERNEL_SCRIPT
    assert 'open(path + "/cgroup.procs", "w"' in coverage_v6._KERNEL_SCRIPT
    assert '"delete", "table", "inet", table' in coverage_v6._KERNEL_SCRIPT


def _kernel_probe_namespace(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    monkeypatch.delenv("SPS_KERNEL_FEATURE", raising=False)
    namespace: dict[str, Any] = {"__name__": "kernel_probe"}
    exec(coverage_v6._KERNEL_SCRIPT, namespace)
    monkeypatch.setattr(namespace["time"], "sleep", lambda _seconds: None)
    return namespace


def test_netfilter_delete_retries_after_a_lock_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    namespace = _kernel_probe_namespace(monkeypatch)
    calls: list[list[str]] = []

    def fake_run(
        args: list[str],
        input: bytes | None = None,
        capture_output: bool = False,
        timeout: float = 5,
        check: bool = False,
    ) -> subprocess.CompletedProcess[bytes]:
        del input, capture_output, timeout, check
        calls.append(args)
        failed = len(calls) < 3
        return subprocess.CompletedProcess(
            args,
            1 if failed else 0,
            stderr=b"Another app is currently holding the xtables lock.",
        )

    monkeypatch.setattr(namespace["subprocess"], "run", fake_run)
    assert namespace["delete_until_gone"](["iptables", "-D", "OUTPUT"], ["iptables", "-C"]) is True
    assert calls == [
        ["iptables", "-D", "OUTPUT"],
        ["iptables", "-C"],
        ["iptables", "-D", "OUTPUT"],
    ]


def test_netfilter_delete_stops_when_the_rule_is_already_gone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    namespace = _kernel_probe_namespace(monkeypatch)
    calls: list[list[str]] = []

    def fake_run(
        args: list[str],
        input: bytes | None = None,
        capture_output: bool = False,
        timeout: float = 5,
        check: bool = False,
    ) -> subprocess.CompletedProcess[bytes]:
        del input, capture_output, timeout, check
        calls.append(args)
        return subprocess.CompletedProcess(
            args,
            1,
            stderr=b"Bad rule (does a matching rule exist in that chain?)",
        )

    monkeypatch.setattr(namespace["subprocess"], "run", fake_run)
    assert namespace["delete_until_gone"](["iptables", "-D"], ["iptables", "-C"]) is True
    assert len(calls) == 2


def test_netfilter_delete_retries_are_bounded_by_probe_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    namespace = _kernel_probe_namespace(monkeypatch)
    namespace["PROBE_DEADLINE"] = 10
    elapsed = 0.0
    timeouts: list[float] = []

    def monotonic() -> float:
        return elapsed

    def slow_run(
        args: list[str],
        input: bytes | None = None,
        capture_output: bool = False,
        timeout: float = 5,
        check: bool = False,
    ) -> subprocess.CompletedProcess[bytes]:
        nonlocal elapsed
        del input, capture_output, check
        timeouts.append(timeout)
        elapsed += timeout
        return subprocess.CompletedProcess(args, 1, stderr=b"xtables lock timeout")

    monkeypatch.setattr(namespace["time"], "monotonic", monotonic)
    monkeypatch.setattr(namespace["subprocess"], "run", slow_run)

    assert namespace["delete_until_gone"](["iptables", "-D"], ["iptables", "-C"]) is False
    assert timeouts == [5, 3]
    assert elapsed == 8


def test_netfilter_delete_does_not_treat_a_lock_error_as_removal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    namespace = _kernel_probe_namespace(monkeypatch)
    calls: list[list[str]] = []

    def fake_run(
        args: list[str],
        input: bytes | None = None,
        capture_output: bool = False,
        timeout: float = 5,
        check: bool = False,
    ) -> subprocess.CompletedProcess[bytes]:
        del input, capture_output, timeout, check
        calls.append(args)
        return subprocess.CompletedProcess(
            args,
            1,
            stderr=b"Another app is currently holding the xtables lock.",
        )

    monkeypatch.setattr(namespace["subprocess"], "run", fake_run)
    assert namespace["delete_until_gone"](["nft", "delete", "table"], ["nft", "list", "table"]) is (
        False
    )
    assert len(calls) == 10


def test_firewall_attempt_cleans_up_when_probe_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    namespace = _kernel_probe_namespace(monkeypatch)
    cleanup_calls: list[tuple[list[str], list[str]]] = []

    class Listener:
        def setsockopt(self, *_args: Any) -> None:
            pass

        def bind(self, _address: tuple[str, int]) -> None:
            pass

        def listen(self, _backlog: int) -> None:
            pass

        def getsockname(self) -> tuple[str, int]:
            return ("127.0.0.1", 12345)

        def close(self) -> None:
            pass

    monkeypatch.setattr(namespace["socket"], "socket", lambda *_args: Listener())
    monkeypatch.setattr(namespace["socket"], "SOL_SOCKET", 1)
    monkeypatch.setattr(namespace["socket"], "SO_REUSEADDR", 2)
    monkeypatch.setattr(namespace["socket"], "AF_INET", 3)
    monkeypatch.setattr(namespace["socket"], "SOCK_STREAM", 4)
    monkeypatch.setattr(namespace["shutil"], "which", lambda _name: "/sbin/iptables")
    monkeypatch.setattr(namespace["uuid"], "uuid4", lambda: type("UUID", (), {"hex": "a" * 32})())
    monkeypatch.setitem(namespace, "connect", lambda _port: True)

    def command(args: list[str], data: bytes | None = None) -> bool:
        del data
        return "-I" not in args

    def delete_until_gone(delete: list[str], check: list[str]) -> bool:
        cleanup_calls.append((delete, check))
        return True

    monkeypatch.setitem(namespace, "command", command)
    monkeypatch.setitem(namespace, "delete_until_gone", delete_until_gone)

    assert namespace["firewall_attempt"]("iptables") is False
    assert len(cleanup_calls) == 1


def test_kernel_feature_refuses_an_unknown_feature() -> None:
    with pytest.raises(ValueError, match="unknown kernel feature"):
        coverage_v6.kernel_feature(KernelDriver(), {}, {"feature": "systemd"})


def test_outbound_http_requires_healthy_runner_control_and_guest_2xx() -> None:
    requests: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            requests.append(self.path)
            self.send_response(204)
            self.end_headers()

        def log_message(self, *_: Any) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/health"
        assert coverage_v6.outbound_traffic(LocalDriver(), {}, {"traffic": "http", "url": url}) == {
            "reached": True
        }
        assert requests == ["/health", "/health", "/health"]
    finally:
        server.shutdown()
        server.server_close()
        worker.join()


def test_outbound_http_control_refusal_is_not_reported_as_no_egress(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(coverage_v6, "_http_status", lambda _: 503)
    with pytest.raises(NotRun, match="outbound_http_control_unavailable"):
        coverage_v6.outbound_traffic(
            LocalDriver(), {}, {"traffic": "http", "url": "http://fixture.invalid/"}
        )


def test_outbound_tcp_echo_uses_a_unique_payload_and_runner_controls() -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    listener.settimeout(0.1)
    stopped = threading.Event()
    payloads: list[bytes] = []

    def serve() -> None:
        while not stopped.is_set():
            try:
                connection, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                if stopped.is_set():
                    return
                raise
            with connection:
                while data := connection.recv(4096):
                    payloads.append(data)
                    connection.sendall(data)

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    try:
        result = coverage_v6.outbound_traffic(
            LocalDriver(),
            {},
            {"traffic": "any_tcp", "host": "127.0.0.1", "port": listener.getsockname()[1]},
        )
        assert result == {"reached": True}
        assert len(payloads) == 3
        assert len(set(payloads)) == 1
        assert payloads[0].startswith(b"sps-v6-")
    finally:
        stopped.set()
        listener.close()
        worker.join()


def test_outbound_udp_echo_uses_a_unique_payload_and_runner_controls() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    server.settimeout(0.1)
    stopped = threading.Event()
    payloads: list[bytes] = []

    def serve() -> None:
        while not stopped.is_set():
            try:
                data, address = server.recvfrom(65536)
            except TimeoutError:
                continue
            except OSError:
                if stopped.is_set():
                    return
                raise
            payloads.append(data)
            server.sendto(data, address)

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    try:
        result = coverage_v6.outbound_traffic(
            LocalDriver(),
            {},
            {"traffic": "udp", "host": "127.0.0.1", "port": server.getsockname()[1]},
        )
        assert result == {"reached": True}
        assert len(payloads) == 3
        assert len(set(payloads)) == 1
        assert payloads[0].startswith(b"sps-v6-")
    finally:
        stopped.set()
        server.close()
        worker.join()


def test_private_network_reaches_members_through_driver_endpoints() -> None:
    driver = LocalPrivateNetworkDriver()

    result = coverage_v6.private_network(
        driver,
        {"members": [{"identity": "one"}, {"identity": "two"}], "ip_version": "ipv4"},
    )

    assert result == {"members_reached": True, "ip_version_matches": True}
    assert driver.address_calls == 2
    assert driver.run_calls == 6


def test_private_network_requires_requested_address_family_for_reachability() -> None:
    class WrongFamilyDriver(LocalPrivateNetworkDriver):
        def run(self, target: object, inputs: Inputs) -> Observation:
            result = cast(dict[str, object], super().run(target, inputs))
            environment = cast(dict[str, str], inputs["environment"])
            config = json.loads(environment["SPS_V6_PRIVATE_NETWORK"])
            if "ip_version" in config and result.get("stdout"):
                probe = json.loads(cast(bytes | str, result["stdout"]))
            else:
                return result
            if config.get("ip_version") == 4 and "ip_version_matches" in probe:
                probe["ip_version_matches"] = False
                result["stdout"] = json.dumps(probe)
            return result

    result = coverage_v6.private_network(
        WrongFamilyDriver(),
        {"members": [{"identity": "one"}, {"identity": "two"}], "ip_version": "ipv4"},
    )

    assert result == {"members_reached": False, "ip_version_matches": False}


def test_private_network_stop_accepts_an_already_exited_listener() -> None:
    listener = subprocess.Popen([sys.executable, "-c", "pass"])
    time.sleep(0.1)
    environment = os.environ.copy()
    environment["SPS_V6_PRIVATE_NETWORK"] = json.dumps({"pid": listener.pid})

    result = subprocess.run(
        ["python", "-c", coverage_v6._PRIVATE_NETWORK_STOP_SCRIPT],
        capture_output=True,
        env=environment,
        timeout=5,
        check=False,
    )

    assert result.returncode == 0
    assert listener.wait(timeout=5) == 0
