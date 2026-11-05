# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Kernel, unrestricted egress and private-network observations."""

from __future__ import annotations

import base64
import ipaddress
import json
import shlex
import socket
import subprocess
import sys
from collections.abc import Mapping
from typing import cast
from urllib.parse import urlsplit
from uuid import uuid4

from sandbox_provider_spec.driver import Driver, NativeFailure, NotRun

KERNEL_FEATURES = {"fuse", "ebpf", "nested_cgroups", "netfilter"}

_KERNEL_SCRIPT = r"""
import ctypes
import errno
import json
import os
import platform
import select
import shutil
import socket
import stat
import struct
import sys
import subprocess
import tempfile
import threading
import time
import uuid

PROBE_DEADLINE = time.monotonic() + 45
PROBE_CLEANUP_RESERVE = 2


def fuse_attr(ino):
    directory = ino == 1
    return struct.pack(
        "<QQQQQQIIIIIIIIII",
        ino,
        0 if directory else len(b"sps-fuse-proof"),
        1,
        0, 0, 0,
        0, 0, 0,
        stat.S_IFDIR | 0o755 if directory else stat.S_IFREG | 0o444,
        2 if directory else 1,
        0, 0, 0, 4096, 0,
    )


def fuse_probe():
    if not os.path.exists("/dev/fuse"):
        return False
    fd = os.open("/dev/fuse", os.O_RDWR | os.O_CLOEXEC)
    mountpoint = tempfile.mkdtemp(prefix="sps-v6-fuse-")
    mounted = False
    stopped = threading.Event()
    failed = threading.Event()
    header = struct.Struct("<IIQQIIIHH")
    out_header = struct.Struct("<IiQ")
    init_out = struct.Struct("<IIIIHHIIHHI7I")

    def reply(unique, payload=b"", error=0):
        response = out_header.pack(out_header.size + len(payload), -error, unique) + payload
        if os.write(fd, response) != len(response):
            failed.set()

    def serve():
        try:
            while not stopped.is_set():
                ready, _, _ = select.select([fd], [], [], 0.1)
                if not ready:
                    continue
                # /dev/fuse polls as readable and read() returns EPERM until mount connects it.
                try:
                    message = os.read(fd, 131072)
                except OSError as exc:
                    if exc.errno == errno.EPERM:
                        # select() reports /dev/fuse readable before mount connects it.
                        time.sleep(0.01)
                        continue
                    raise
                if len(message) < header.size:
                    failed.set()
                    return
                length, op, unique, nodeid, _, _, _, _, _ = header.unpack_from(message)
                if length > len(message):
                    failed.set()
                    return
                body = message[header.size:length]
                if op == 26:  # INIT
                    major, minor, readahead, _ = struct.unpack_from("<IIII", body)
                    reply(
                        unique,
                        init_out.pack(
                            min(major, 7), min(minor, 38), readahead, 0,
                            16, 12, 4096, 1, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0,
                        ),
                    )
                elif op == 1:  # LOOKUP
                    name = body.split(b"\0", 1)[0]
                    if name != b"proof":
                        reply(unique, error=errno.ENOENT)
                    else:
                        entry = struct.pack("<QQQQII", 2, 0, 1, 0, 0, 0) + fuse_attr(2)
                        reply(unique, entry)
                elif op == 3:  # GETATTR
                    attr = fuse_attr(1 if nodeid == 1 else 2)
                    reply(unique, struct.pack("<QII", 1, 0, 0) + attr)
                elif op == 14:  # OPEN
                    reply(unique, struct.pack("<QII", 1, 0, 0))
                elif op == 15:  # READ
                    _, offset, size, _, _, _, _ = struct.unpack_from("<QQIIQII", body)
                    content = b"sps-fuse-proof"[offset:offset + size]
                    reply(unique, content)
                elif op in {2, 38, 42}:  # FORGET, DESTROY and BATCH_FORGET have no reply.
                    continue
                else:
                    reply(unique, error=errno.ENOSYS)
        except OSError:
            if not stopped.is_set():
                failed.set()

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mount.argtypes = [
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_ulong,
        ctypes.c_char_p,
    ]
    libc.mount.restype = ctypes.c_int
    data = f"fd={fd},rootmode=40000,user_id={os.getuid()},group_id={os.getgid()}".encode()
    success = False
    try:
        mounted = libc.mount(b"sps-v6", mountpoint.encode(), b"fuse", 6, data) == 0
        if not mounted or failed.is_set() or not os.path.ismount(mountpoint):
            success = False
        else:
            with open(os.path.join(mountpoint, "proof"), "rb") as source:
                success = source.read() == b"sps-fuse-proof" and not failed.is_set()
    finally:
        # Stop before unmount so the disconnect is not recorded as a failed proof.
        stopped.set()
        if mounted:
            libc.umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]
            libc.umount2.restype = ctypes.c_int
            unmounted = libc.umount2(mountpoint.encode(), 0) == 0
            if not unmounted:
                libc.umount2(mountpoint.encode(), 2)
            success = success and unmounted
        worker.join(timeout=1)
        os.close(fd)
        try:
            os.rmdir(mountpoint)
        except OSError:
            pass
    return success and not failed.is_set()


def ebpf_probe():
    numbers = {"x86_64": 321, "amd64": 321, "aarch64": 280, "arm64": 280}
    number = numbers.get(platform.machine().lower())
    if number is None:
        return False

    class Instruction(ctypes.Structure):
        _fields_ = [("code", ctypes.c_ubyte), ("regs", ctypes.c_ubyte),
                    ("offset", ctypes.c_short), ("immediate", ctypes.c_int)]

    class Attribute(ctypes.Structure):
        _fields_ = [("program_type", ctypes.c_uint), ("instruction_count", ctypes.c_uint),
                    ("instructions", ctypes.c_uint64), ("license", ctypes.c_uint64),
                    ("log_level", ctypes.c_uint), ("log_size", ctypes.c_uint),
                    ("log_buffer", ctypes.c_uint64), ("kernel_version", ctypes.c_uint),
                    ("program_flags", ctypes.c_uint)]

    instructions = (Instruction * 2)(Instruction(0xB7, 0, 0, 0), Instruction(0x95, 0, 0, 0))
    license_text = ctypes.create_string_buffer(b"GPL\0")
    log = ctypes.create_string_buffer(65536)
    attr = Attribute(
        1, len(instructions), ctypes.addressof(instructions), ctypes.addressof(license_text),
        1, len(log), ctypes.addressof(log), 0, 0,
    )
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    program = int(libc.syscall(number, 5, ctypes.byref(attr), ctypes.sizeof(attr)))
    if program < 0:
        return False
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        receiver.bind(("127.0.0.1", 0))
        receiver.setsockopt(socket.SOL_SOCKET, 50, struct.pack("i", program))
        receiver.settimeout(0.5)
        sender.sendto(b"sps-ebpf-proof", receiver.getsockname())
        try:
            receiver.recvfrom(128)
            return False
        except socket.timeout:
            return True
    finally:
        receiver.close()
        sender.close()
        os.close(program)


def nested_cgroups_probe():
    root = "/sys/fs/cgroup"
    with open(root + "/cgroup.controllers", encoding="ascii") as source:
        controllers = set(source.read().split())
    with open(root + "/cgroup.subtree_control", encoding="ascii") as source:
        enabled = set(source.read().replace("+", "").split())
    if "memory" not in controllers or "memory" not in enabled:
        return False
    path = root + "/sps-v6-" + uuid.uuid4().hex[:12]
    os.mkdir(path)
    child = None
    try:
        child = subprocess.Popen(
            [sys.executable, "-c", "import sys; sys.stdin.read(1)"],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        with open(path + "/cgroup.procs", "w", encoding="ascii") as target:
            target.write(str(child.pid))
        with open(path + "/memory.max", "w", encoding="ascii") as target:
            target.write("16777216")
        with open(path + "/memory.max", encoding="ascii") as source:
            configured = source.read().strip() == "16777216"
        if child.stdin is None:
            raise OSError("nested cgroup probe child has no stdin")
        child.stdin.close()
        return configured and child.wait(timeout=5) == 0
    finally:
        if child is not None:
            if child.stdin is not None and not child.stdin.closed:
                child.stdin.close()
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=2)
        os.rmdir(path)


def connect(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            return True
    except OSError:
        return False


def run_command(args, *, data=None):
    remaining = PROBE_DEADLINE - time.monotonic() - PROBE_CLEANUP_RESERVE
    if remaining <= 0:
        return None
    try:
        return subprocess.run(
            args, input=data, capture_output=True, timeout=min(5, remaining), check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def command(args, *, data=None):
    completed = run_command(args, data=data)
    return completed is not None and completed.returncode == 0


def rule_is_gone(args):
    # A lock timeout is also a non-zero exit. Only an explicit absence message counts.
    completed = run_command(args)
    if completed is None or completed.returncode == 0:
        return False
    text = completed.stderr.decode("utf-8", "replace").lower()
    return "does a matching rule exist" in text or "bad rule" in text or "no such" in text


def delete_until_gone(delete_args, check_args):
    for attempt in range(5):
        if PROBE_DEADLINE - time.monotonic() <= PROBE_CLEANUP_RESERVE:
            return False
        if command(delete_args) or rule_is_gone(check_args):
            return True
        if attempt != 4:
            time.sleep(0.2)
    return False


def firewall_attempt(kind):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    installed = False
    delete = None
    check = None
    outcome = False
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        port = listener.getsockname()[1]
        if not connect(port):
            return False
        binary = shutil.which("iptables" if kind == "iptables" else "nft")
        if binary is None:
            return False
        table = "spsv6" + uuid.uuid4().hex[:12]
        if kind == "iptables":
            rule = [
                "-p", "tcp", "-o", "lo", "-d", "127.0.0.1", "--dport", str(port), "-j", "REJECT",
            ]
            delete = [binary, "-w", "2", "-D", "OUTPUT", *rule]
            check = [binary, "-w", "2", "-C", "OUTPUT", *rule]
            installed = True
            added = command([binary, "-w", "2", "-I", "OUTPUT", "1", *rule])
        else:
            rules = (
                f"add table inet {table}\n"
                f"add chain inet {table} output {{ type filter hook output priority 0; "
                "policy accept; }\n"
                f"add rule inet {table} output oifname lo ip daddr 127.0.0.1 "
                f"tcp dport {port} reject\n"
            )
            delete = [binary, "delete", "table", "inet", table]
            check = [binary, "list", "table", "inet", table]
            installed = True
            added = command([binary, "-f", "-"], data=rules.encode())
        outcome = added and (not connect(port))
    finally:
        if installed and delete is not None and check is not None:
            cleaned = delete_until_gone(delete, check)
            outcome = outcome and cleaned
        listener.close()
    return outcome


def netfilter_probe():
    return firewall_attempt("iptables") or firewall_attempt("nft")


feature = os.environ.get("SPS_KERNEL_FEATURE", "")
probes = {
    "fuse": fuse_probe,
    "ebpf": ebpf_probe,
    "nested_cgroups": nested_cgroups_probe,
    "netfilter": netfilter_probe,
}
try:
    works = bool(probes.get(feature, lambda: False)())
except (OSError, subprocess.TimeoutExpired, TimeoutError, struct.error):
    works = False
print(json.dumps({"works": works}))
"""

_HTTP_STATUS_SCRIPT = r"""
import json
import sys
import urllib.error
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
try:
    with opener.open(sys.argv[1], timeout=5) as response:
        response.read(1)
        status = response.status
except urllib.error.HTTPError as error:
    status = error.code
except (OSError, urllib.error.URLError, TimeoutError):
    status = None
print(json.dumps({"status": status}))
"""

_OUTBOUND_SCRIPT = r"""
import base64
import json
import os
import socket
import urllib.error
import urllib.request


def http_success(url):
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(url, timeout=5) as response:
            response.read(1)
            return 200 <= response.status < 300
    except urllib.error.HTTPError as error:
        return 200 <= error.code < 300
    except (OSError, urllib.error.URLError, TimeoutError):
        return False


def recv_exact(connection, length):
    data = bytearray()
    while len(data) < length:
        chunk = connection.recv(length - len(data))
        if not chunk:
            return bytes(data)
        data.extend(chunk)
    return bytes(data)


args = json.loads(os.environ["SPS_V6_OUTBOUND"])
traffic = args["traffic"]
if traffic == "http":
    reached = http_success(args["url"])
else:
    payload = base64.b64decode(args["payload"], validate=True)
    try:
        if traffic == "any_tcp":
            with socket.create_connection((args["host"], args["port"]), timeout=5) as connection:
                connection.settimeout(5)
                connection.sendall(payload)
                reached = recv_exact(connection, len(payload)) == payload
        else:
            family, socket_type, protocol, _, address = socket.getaddrinfo(
                args["host"], args["port"], type=socket.SOCK_DGRAM
            )[0]
            with socket.socket(family, socket_type, protocol) as connection:
                connection.settimeout(5)
                connection.connect(address)
                connection.send(payload)
                reached = connection.recv(65536) == payload
    except (OSError, TimeoutError):
        reached = False
print(json.dumps({"reached": bool(reached)}))
"""


def _result(payload: object, field: str, operation: str) -> bool:
    if not isinstance(payload, (bytes, str)) or len(payload) > 1024:
        raise NativeFailure(operation + "_response_invalid")
    try:
        value = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise NativeFailure(operation + "_response_invalid") from None
    if not isinstance(value, dict) or set(value) != {field} or not isinstance(value[field], bool):
        raise NativeFailure(operation + "_response_invalid")
    return cast(bool, value[field])


def kernel_feature(
    driver: Driver, target: object, inputs: Mapping[str, object]
) -> Mapping[str, object]:
    feature = inputs.get("feature")
    if not isinstance(feature, str) or feature not in KERNEL_FEATURES:
        raise ValueError("unknown kernel feature")
    result = driver.call(
        "run.as_root",
        target,
        {
            "bash_script": "python3 -c " + shlex.quote(_KERNEL_SCRIPT),
            "environment": {"SPS_KERNEL_FEATURE": feature},
            "timeout_ms": 45000,
        },
    )
    if result.get("exit_code") != 0:
        raise NativeFailure("kernel_feature_probe_failed")
    return {"works": _result(result.get("stdout"), "works", "kernel_feature")}


def _http_status(url: str) -> int | None:
    try:
        completed = subprocess.run(
            [sys.executable, "-I", "-c", _HTTP_STATUS_SCRIPT, url],
            capture_output=True,
            timeout=8,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise NativeFailure("outbound_http_control_timeout") from None
    if completed.returncode != 0 or len(completed.stdout) > 256:
        raise NativeFailure("outbound_http_control_failed")
    try:
        value = json.loads(completed.stdout)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise NativeFailure("outbound_http_control_invalid") from None
    status = value.get("status") if isinstance(value, dict) and set(value) == {"status"} else False
    if status is None:
        return None
    if not isinstance(status, int) or isinstance(status, bool):
        raise NativeFailure("outbound_http_control_invalid")
    return status


def _http_fixture(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("HTTP outbound fixture URL must be text")
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        raise ValueError("invalid HTTP outbound fixture URL") from None
    if parts.scheme != "http" or not parts.hostname:
        raise ValueError("invalid HTTP outbound fixture URL")
    if parts.username is not None or parts.password is not None:
        raise ValueError("invalid HTTP outbound fixture URL")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("invalid HTTP outbound fixture URL")
    return value


def _echo_fixture(inputs: Mapping[str, object]) -> tuple[str, int]:
    host, port = inputs.get("host"), inputs.get("port")
    if not isinstance(host, str) or not host:
        raise ValueError("invalid outbound echo endpoint")
    if len(host) > 253 or any(ch.isspace() for ch in host) or "/" in host:
        raise ValueError("invalid outbound echo endpoint")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ValueError("invalid outbound echo endpoint")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        try:
            host.encode("idna")
        except UnicodeError:
            raise ValueError("invalid outbound echo endpoint") from None
    return host, port


def _echo_control(traffic: str, host: str, port: int, payload: bytes) -> bool:
    try:
        if traffic == "any_tcp":
            with socket.create_connection((host, port), timeout=5) as connection:
                connection.settimeout(5)
                connection.sendall(payload)
                received = bytearray()
                while len(received) < len(payload):
                    chunk = connection.recv(len(payload) - len(received))
                    if not chunk:
                        break
                    received.extend(chunk)
                return bytes(received) == payload
        family, socket_type, protocol, _, address = socket.getaddrinfo(
            host, port, type=socket.SOCK_DGRAM
        )[0]
        with socket.socket(family, socket_type, protocol) as connection:
            connection.settimeout(5)
            connection.connect(address)
            connection.send(payload)
            return connection.recv(65536) == payload
    except (OSError, TimeoutError):
        return False


def outbound_traffic(
    driver: Driver, target: object, inputs: Mapping[str, object]
) -> Mapping[str, object]:
    traffic = inputs.get("traffic")
    if not isinstance(traffic, str):
        raise ValueError("unknown outbound traffic fixture")
    if traffic == "http":
        url = _http_fixture(inputs.get("url"))
        if not 200 <= (_http_status(url) or 0) < 300:
            raise NotRun("outbound_http_control_unavailable")
        guest_inputs: dict[str, object] = {"traffic": traffic, "url": url}
        payload = b""
        endpoint = ("", 0)
    elif traffic in {"any_tcp", "udp"}:
        host, port = _echo_fixture(inputs)
        payload = ("sps-v6-" + uuid4().hex).encode()
        if not _echo_control(traffic, host, port, payload):
            raise NotRun("outbound_echo_control_unavailable")
        guest_inputs = {
            "traffic": traffic,
            "host": host,
            "port": port,
            "payload": base64.b64encode(payload).decode(),
        }
        endpoint = (host, port)
    else:
        raise ValueError("unknown outbound traffic fixture")

    result = driver.call(
        "run",
        target,
        {
            "bash_script": "python3 -c " + shlex.quote(_OUTBOUND_SCRIPT),
            "environment": {"SPS_V6_OUTBOUND": json.dumps(guest_inputs)},
            "timeout_ms": 15000,
        },
    )
    if result.get("exit_code") != 0:
        raise NativeFailure("outbound_traffic_probe_failed")
    reached = _result(result.get("stdout"), "reached", "outbound_traffic")
    if traffic == "http":
        if not 200 <= (_http_status(cast(str, guest_inputs["url"])) or 0) < 300:
            raise NotRun("outbound_http_control_unavailable")
    elif not _echo_control(traffic, endpoint[0], endpoint[1], payload):
        raise NotRun("outbound_echo_control_unavailable")
    return {"reached": reached}


_PRIVATE_NETWORK_SERVER_SCRIPT = r"""
import json
import socket
import sys
import time

config = json.loads(sys.argv[1])
family = config["family"]
if family == 4:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("0.0.0.0", 0))
else:
    try:
        listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, family == 6)
        listener.bind(("::", 0))
    except OSError:
        if family == 6:
            raise
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("0.0.0.0", 0))
listener.listen(max(1, config["expected_clients"]))
listener.settimeout(1)
with open(config["port_file"], "w", encoding="ascii") as output:
    output.write(str(listener.getsockname()[1]))
served = 0
deadline = time.monotonic() + 90
while served < config["expected_clients"] and time.monotonic() < deadline:
    try:
        connection, _ = listener.accept()
    except TimeoutError:
        continue
    with connection:
        connection.settimeout(5)
        expected = config["nonce"].encode("ascii")
        request = bytearray()
        while len(request) < len(expected):
            chunk = connection.recv(len(expected) - len(request))
            if not chunk:
                break
            request.extend(chunk)
        if bytes(request) == expected:
            connection.sendall(config["response"].encode("ascii"))
            served += 1
listener.close()
"""

_PRIVATE_NETWORK_START_SCRIPT = r"""
import json
import os
import subprocess
import sys
import tempfile
import time

config = json.loads(os.environ["SPS_V6_PRIVATE_NETWORK"])
server_script = config.pop("server_script")
fd, port_file = tempfile.mkstemp(prefix="sps-v6b-private-network-")
os.close(fd)
os.unlink(port_file)
config["port_file"] = port_file
process = subprocess.Popen(
    [sys.executable, "-c", server_script, json.dumps(config)],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    start_new_session=True,
)
try:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            with open(port_file, encoding="ascii") as source:
                port = int(source.read())
            break
        except (FileNotFoundError, ValueError):
            # The listener creates the file before it writes the port.
            if process.poll() is not None:
                raise RuntimeError("listener exited before binding")
            time.sleep(0.05)
    else:
        raise TimeoutError("listener did not bind")
    print(json.dumps({"port": port, "pid": process.pid}))
except Exception:
    process.terminate()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
    raise
finally:
    try:
        os.unlink(port_file)
    except FileNotFoundError:
        pass
"""

_PRIVATE_NETWORK_STOP_SCRIPT = r"""
import json
import os
import signal
import time

pid = json.loads(os.environ["SPS_V6_PRIVATE_NETWORK"])["pid"]
try:
    os.kill(pid, signal.SIGTERM)
except ProcessLookupError:
    pass
else:
    for _ in range(20):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        try:
            with open(f"/proc/{pid}/stat", encoding="ascii") as source:
                state = source.read().rsplit(")", 1)[1].split()[0]
            if state == "Z":
                break
        except FileNotFoundError:
            break
        time.sleep(0.05)
    else:
        raise TimeoutError("listener did not stop")
"""

_PRIVATE_NETWORK_PROBE_SCRIPT = r"""
import ipaddress
import json
import socket

config = json.loads(__import__("os").environ["SPS_V6_PRIVATE_NETWORK"])
requested = config.get("ip_version")
family = {None: socket.AF_UNSPEC, 4: socket.AF_INET, 6: socket.AF_INET6}[requested]
matched = False
reached = False
try:
    addresses = socket.getaddrinfo(config["address"], config["port"], family, socket.SOCK_STREAM)
except OSError:
    addresses = []
for result_family, kind, protocol, _, endpoint in addresses:
    if requested is not None and result_family != family:
        continue
    matched = True
    try:
        with socket.socket(result_family, kind, protocol) as connection:
            connection.settimeout(5)
            connection.connect(endpoint)
            connection.sendall(config["nonce"].encode("ascii"))
            expected = config["response"].encode("ascii")
            response = bytearray()
            while len(response) < len(expected):
                chunk = connection.recv(len(expected) - len(response))
                if not chunk:
                    break
                response.extend(chunk)
        if bytes(response) == expected:
            reached = True
            break
    except (OSError, TimeoutError, UnicodeDecodeError):
        continue
result = {"reached": reached}
if requested is not None:
    result["ip_version_matches"] = matched and any(
        ipaddress.ip_address(endpoint[0].split("%", 1)[0]).version == requested
        for result_family, _, _, _, endpoint in addresses
        if result_family == family
    )
print(json.dumps(result))
"""


def _private_network_run(
    driver: Driver, target: object, script: str, config: Mapping[str, object]
) -> Mapping[str, object]:
    return driver.call(
        "run",
        target,
        {
            "bash_script": "python3 -c " + shlex.quote(script),
            "environment": {"SPS_V6_PRIVATE_NETWORK": json.dumps(dict(config))},
            "timeout_ms": 15000,
        },
    )


def _private_network_json(payload: object, fields: set[str], operation: str) -> dict[str, object]:
    if not isinstance(payload, (bytes, str)) or len(payload) > 1024:
        raise NativeFailure(operation + "_response_invalid")
    try:
        value = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise NativeFailure(operation + "_response_invalid") from None
    if not isinstance(value, dict) or set(value) != fields:
        raise NativeFailure(operation + "_response_invalid")
    return value


def private_network(driver: Driver, inputs: Mapping[str, object]) -> Mapping[str, object]:
    """Verify direct member-to-member TCP access through SDK-provided endpoints."""
    members = inputs.get("members")
    if not isinstance(members, list) or not 2 <= len(members) <= 3:
        raise ValueError("members must contain two or three sandbox bindings")
    requested = inputs.get("ip_version")
    if requested not in {None, "ipv4", "ipv6"}:
        raise ValueError("ip_version must be ipv4 or ipv6")
    if requested is None:
        family = None
    elif requested == "ipv4":
        family = 4
    else:
        family = 6
    outside = inputs.get("outside")
    if outside is not None and not isinstance(outside, Mapping):
        raise ValueError("outside must be a sandbox binding")

    nonce = "sps-v6b-" + uuid4().hex
    endpoints: list[dict[str, object]] = []
    for member in members:
        endpoint = driver.call(
            "network.private_address",
            member,
            {"ip_version": requested} if requested is not None else {},
        )
        address = endpoint.get("address")
        version = endpoint.get("ip_version")
        if (
            set(endpoint) != {"address", "ip_version"}
            or not isinstance(address, str)
            or not address
            or len(address) > 253
            or version not in (None, 4, 6)
        ):
            raise NativeFailure("private_address_response_invalid")
        try:
            literal_version = ipaddress.ip_address(address.split("%", 1)[0]).version
        except ValueError:
            literal_version = None
        endpoints.append(
            {
                "address": address,
                "ip_version": version if version is not None else literal_version,
                "sandbox": member,
            }
        )

    listeners: list[dict[str, object]] = []
    try:
        for index, endpoint in enumerate(endpoints):
            response = nonce + "-" + str(index)
            listener_family = family or cast(int | None, endpoint["ip_version"])
            config = {
                "family": listener_family or 0,
                "expected_clients": len(members) - 1 + (outside is not None),
                "nonce": nonce,
                "response": response,
            }
            result = _private_network_run(
                driver,
                endpoint["sandbox"],
                _PRIVATE_NETWORK_START_SCRIPT,
                {**config, "server_script": _PRIVATE_NETWORK_SERVER_SCRIPT},
            )
            if result.get("exit_code") != 0:
                raise NativeFailure("private_network_listener_start_failed")
            # Only the listener's controlled port and pid are consumed.
            started = _private_network_json(
                result.get("stdout"), {"port", "pid"}, "private_network_listener"
            )
            port, pid = started["port"], started["pid"]
            if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
                raise NativeFailure("private_network_listener_response_invalid")
            if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
                raise NativeFailure("private_network_listener_response_invalid")
            listeners.append({**endpoint, "port": port, "pid": pid, "response": response})

        members_reached = True
        ip_version_matches = True
        for source_index, source in enumerate(members):
            for endpoint_index, endpoint in enumerate(listeners):
                if source_index == endpoint_index:
                    continue
                if family is not None and endpoint["ip_version"] not in {None, family}:
                    ip_version_matches = False
                result = _private_network_run(
                    driver,
                    source,
                    _PRIVATE_NETWORK_PROBE_SCRIPT,
                    {
                        "address": endpoint["address"],
                        "port": endpoint["port"],
                        "nonce": nonce,
                        "response": endpoint["response"],
                        "ip_version": family,
                    },
                )
                if result.get("exit_code") != 0:
                    raise NativeFailure("private_network_probe_failed")
                fields = {"reached"} | ({"ip_version_matches"} if family is not None else set())
                probe = _private_network_json(result.get("stdout"), fields, "private_network_probe")
                if result.get("exit_code") != 0 or probe["reached"] is not True:
                    members_reached = False
                if family is not None and probe["ip_version_matches"] is not True:
                    ip_version_matches = False
                    members_reached = False

        observation: dict[str, object] = {"members_reached": members_reached}
        if outside is not None:
            outside_blocked = True
            for endpoint in listeners:
                result = _private_network_run(
                    driver,
                    outside,
                    _PRIVATE_NETWORK_PROBE_SCRIPT,
                    {
                        "address": endpoint["address"],
                        "port": endpoint["port"],
                        "nonce": nonce,
                        "response": endpoint["response"],
                        "ip_version": None,
                    },
                )
                probe = _private_network_json(
                    result.get("stdout"), {"reached"}, "private_network_probe"
                )
                if result.get("exit_code") != 0:
                    raise NativeFailure("private_network_probe_failed")
                if probe["reached"] is not False:
                    outside_blocked = False
            observation["outside_blocked"] = outside_blocked
        if family is not None:
            observation["ip_version_matches"] = ip_version_matches
        return observation
    finally:
        for listener in reversed(listeners):
            result = _private_network_run(
                driver,
                listener["sandbox"],
                _PRIVATE_NETWORK_STOP_SCRIPT,
                {"pid": listener["pid"]},
            )
            if result.get("exit_code") != 0:
                raise NativeFailure("private_network_listener_cleanup_failed")
