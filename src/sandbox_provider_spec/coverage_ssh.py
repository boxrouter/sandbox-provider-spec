# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Reach a sandbox with standard OpenSSH clients and the credential its SDK handed out.

The `access` binding is the result of `ssh.access`: the credential kind (`key`, `token` or
`password`), where to connect, and the private material. Where to connect is either `host`,
`port` and `user`, or the SDK's own `ssh_command`, which is parsed and never executed. The
material is `private_key`, `token` (carried as the user name) or `password`.
`host_key` names the server public keys. The client pins them and does not
authenticate when they are absent, so a password or token is never presented
to an unverified peer.
"""

from __future__ import annotations

import base64
import os
import re
import shlex
import shutil
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

from sandbox_provider_spec.driver import Driver, NativeFailure, NotRun

KINDS = ("key", "token", "password")
SECRET_FIELD = {"key": "private_key", "token": "token", "password": "password"}
ACCOUNT_KEY_NAMES = ("KEY", "TOKEN", "SECRET", "PASSWORD")
HOST_KEY_ALGORITHMS = frozenset(
    {
        "ssh-ed25519",
        "ssh-rsa",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "sk-ssh-ed25519@openssh.com",
        "sk-ecdsa-sha2-nistp256@openssh.com",
    }
)
TIMEOUT_SECONDS = 60


@dataclass(frozen=True)
class Connection:
    host: str
    port: int
    user: str
    kind: str
    secret: str
    host_key: str | None


def destination(command: object) -> tuple[str, int, str]:
    """Parse an SDK-provided `ssh` command into host, port and user; never run it."""
    if not isinstance(command, str):
        raise NativeFailure("ssh_native_endpoint_invalid")
    try:
        words = shlex.split(command)
    except ValueError:
        raise NativeFailure("ssh_native_endpoint_invalid") from None
    if not words or Path(words.pop(0)).name != "ssh":
        raise NativeFailure("ssh_native_endpoint_invalid")
    port = 22
    endpoint = None
    try:
        while words:
            word = words.pop(0)
            if word == "-p" and words:
                port = int(words.pop(0))
            elif word == "-o" and words:
                words.pop(0)  # Provider convenience flags never become client options.
            elif word.startswith("-") or endpoint is not None:
                raise NativeFailure("ssh_native_endpoint_invalid")
            else:
                endpoint = word
    except ValueError:
        raise NativeFailure("ssh_native_endpoint_invalid") from None
    if not endpoint or "@" not in endpoint or not 1 <= port <= 65535:
        raise NativeFailure("ssh_native_endpoint_invalid")
    user, host = endpoint.rsplit("@", 1)
    return host, port, user


def connection(access: object) -> Connection:
    if not isinstance(access, Mapping):
        raise ValueError("SSH probe requires an access binding")
    kind = access.get("credential")
    if kind not in KINDS:
        raise NativeFailure("ssh_native_credential_invalid")
    secret = access.get(SECRET_FIELD[str(kind)])
    if not isinstance(secret, str) or not secret:
        raise NativeFailure("ssh_native_credential_invalid")
    endpoint: tuple[object, object, object] = (
        destination(access["ssh_command"])
        if "ssh_command" in access
        else (access.get("host"), access.get("port"), access.get("user"))
    )
    host, port, user = endpoint
    if (
        not isinstance(host, str)
        or not isinstance(port, int)
        or isinstance(port, bool)
        or not isinstance(user, str)
    ):
        raise NativeFailure("ssh_native_endpoint_invalid")
    if kind == "token":
        if user != secret:
            raise NativeFailure("ssh_native_credential_invalid")
    if (
        not host
        or not user
        or not 1 <= port <= 65535
        or host.startswith("-")
        or any(char.isspace() for char in host + user)
    ):
        raise NativeFailure("ssh_native_endpoint_invalid")
    return Connection(host, port, user, str(kind), secret, host_key(access))


def host_key(access: Mapping[str, object]) -> str | None:
    """OpenSSH public keys the server must present, or None when the binding names none."""
    if "host_key" not in access:
        return None
    value = access["host_key"]
    if not isinstance(value, str):
        raise NativeFailure("ssh_native_host_key_invalid")
    lines = [line.strip() for line in value.splitlines() if line.strip()]
    if not lines or len(lines) > 8:
        raise NativeFailure("ssh_native_host_key_invalid")
    return "\n".join(_public_key(line) for line in lines)


def _public_key(line: str) -> str:
    parts = line.split()
    if len(parts) < 2 or len(parts) > 16 or parts[0] not in HOST_KEY_ALGORITHMS:
        raise NativeFailure("ssh_native_host_key_invalid")
    algorithm, blob = parts[0], parts[1]
    if len(blob) > 16384 or any(
        any(ord(char) < 33 or ord(char) > 126 for char in part) for part in parts
    ):
        raise NativeFailure("ssh_native_host_key_invalid")
    try:
        raw = base64.b64decode(blob, validate=True)
    except ValueError:
        raise NativeFailure("ssh_native_host_key_invalid") from None
    prefix = algorithm.encode()
    if (
        len(raw) < 4 + len(prefix)
        or int.from_bytes(raw[:4], "big") != len(prefix)
        or raw[4 : 4 + len(prefix)] != prefix
    ):
        raise NativeFailure("ssh_native_host_key_invalid")
    return f"{algorithm} {blob}"


def is_account_key(secret: str) -> bool:
    """True when the credential is a value the runner holds as a provider account secret."""
    return any(
        len(value) >= 12 and value in secret
        for name, value in os.environ.items()
        if any(word in name.upper() for word in ACCOUNT_KEY_NAMES)
    )


def ssh_config_argument(value: str) -> str:
    """Quote one ssh_config value so a `#` or quote stays part of the value."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def known_hosts(link: Connection, directory: Path) -> Path:
    """Pin `host_key` for this host and port. A pattern in the host is not a known_hosts pattern."""
    pinned = link.host_key
    if pinned is None:
        raise NotRun("ssh_host_key_unverified")
    if any(character in link.host for character in "*?!,[]|#\\"):
        raise NativeFailure("ssh_native_endpoint_invalid")
    marker = link.host if link.port == 22 else f"[{link.host}]:{link.port}"
    path = directory / "known_hosts"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        handle.write("".join(f"{marker} {line}\n" for line in pinned.splitlines()))
    return path


def client_options(link: Connection, directory: Path) -> tuple[list[str], dict[str, str]]:
    # Password and token authentication happen only after the pinned host key matches.
    # A token credential is the user name. A private config keeps it off the command
    # line, which any local account can read from the process list.
    hosts = known_hosts(link, directory)
    config = directory / "config"
    descriptor = os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        handle.write(f"Host *\n    User {ssh_config_argument(link.user)}\n")
    options = [
        "-F",
        str(config),
        "-o",
        "IdentityAgent=none",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "ConnectTimeout=15",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "UserKnownHostsFile=" + str(hosts),
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-o",
        "UpdateHostKeys=no",
        "-o",
        "CheckHostIP=no",
        "-o",
        "HashKnownHosts=no",
        "-o",
        "LogLevel=ERROR",
    ]
    environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    if link.kind == "password":
        askpass = directory / "askpass"
        askpass.write_text('#!/bin/sh\nprintf "%s\\n" "$SPS_SSH_PASSWORD"\n')
        askpass.chmod(0o700)
        environment |= {
            "SSH_ASKPASS": str(askpass),
            "SSH_ASKPASS_REQUIRE": "force",
            "SPS_SSH_PASSWORD": link.secret,
        }
        options += [
            "-o",
            "BatchMode=no",
            "-o",
            "PubkeyAuthentication=no",
            "-o",
            "PasswordAuthentication=yes",
            "-o",
            "KbdInteractiveAuthentication=yes",
            "-o",
            "NumberOfPasswordPrompts=1",
        ]
    else:
        options += ["-o", "BatchMode=yes", "-o", "PasswordAuthentication=no"]
        if link.kind == "key":
            identity = directory / "identity"
            descriptor = os.open(identity, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w") as handle:
                handle.write(link.secret if link.secret.endswith("\n") else link.secret + "\n")
            options += ["-o", "IdentityFile=" + str(identity)]
        else:
            options += ["-o", "PubkeyAuthentication=no"]
    return options, environment


def classic_scp_flag() -> tuple[str, ...]:
    """`-O` selects the classic SCP protocol that gateways without SFTP serve (OpenSSH 8.7+)."""
    try:
        banner = subprocess.run(
            ["ssh", "-V"],
            capture_output=True,
            text=True,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
            check=False,
            timeout=TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ()
    found = re.search(r"OpenSSH_(\d+)\.(\d+)", banner.stderr + banner.stdout)
    return ("-O",) if found and (int(found[1]), int(found[2])) >= (8, 7) else ()


def run(tool: str, link: Connection, *arguments: str) -> subprocess.CompletedProcess[bytes] | None:
    """Run one OpenSSH client with its own private key or askpass file; None if it timed out."""
    port = ["-P" if tool == "scp" else "-p", str(link.port)]
    with TemporaryDirectory(prefix="sps-ssh-") as directory:
        options, environment = client_options(link, Path(directory))
        if tool == "scp":
            command = ["scp", *classic_scp_flag(), *options, *port, *arguments]
        else:
            command = ["ssh", *options, *port, link.host, *arguments]
        try:
            return subprocess.run(
                command,
                capture_output=True,
                stdin=subprocess.DEVNULL,
                env=environment,
                timeout=TIMEOUT_SECONDS,
                check=False,
                start_new_session=True,
            )
        except subprocess.TimeoutExpired:
            return None


def read_file(link: Connection, path: str) -> bytes | None:
    result = run("ssh", link, "cat " + shlex.quote(path))
    return result.stdout if result is not None and result.returncode == 0 else None


def write_file(driver: Driver, target: object, path: str, data: bytes) -> None:
    driver.call("files.write", target, {"path": path, "data": base64.b64encode(data).decode()})


def observe(driver: Driver, inputs: Mapping[str, object]) -> Mapping[str, object]:
    link = connection(inputs["access"])
    sandbox = inputs["sandbox"]
    if not shutil.which("ssh") or not shutil.which("scp"):
        raise NotRun("openssh_client_missing")
    if is_account_key(link.secret):
        return {
            "shell_reached": False,
            "file_copied": False,
            "credential_is_account_key": True,
            "scope_confirmed": False,
        }
    if link.host_key is None:
        raise NotRun("ssh_host_key_unverified")
    nonce = uuid4().hex
    marker, path = f"sps-ssh-own-{nonce}".encode(), f"/tmp/sps-ssh-{nonce}"
    write_file(driver, sandbox, path, marker)
    shell_reached = read_file(link, path) == marker
    with TemporaryDirectory(prefix="sps-ssh-") as name:
        upload = Path(name) / "upload"
        upload.write_bytes(b"sps-ssh-upload-" + nonce.encode())
        host = f"[{link.host}]" if ":" in link.host else link.host
        copy = run("scp", link, str(upload), f"{host}:{path}-upload")
        file_copied = False
        if copy is not None and copy.returncode == 0:
            stored = driver.call("files.read_bytes", sandbox, {"path": path + "-upload"})
            file_copied = stored.get("data") == upload.read_bytes()
    scope_confirmed = shell_reached and scope(driver, link, nonce)
    return {
        "shell_reached": shell_reached,
        "file_copied": file_copied,
        "credential_is_account_key": False,
        "scope_confirmed": scope_confirmed,
    }


def scope(driver: Driver, link: Connection, nonce: str) -> bool:
    """The credential opens its own sandbox and does not open a second one of the same kind."""
    other = driver.call(
        "create",
        None,
        {"requirements": {"ssh": {"credential": link.kind}}, "lifetime_seconds": 300},
    )
    other_link = connection(driver.call("ssh.access", other, {"credential": link.kind}))
    marker, path = f"sps-ssh-other-{nonce}".encode(), f"/tmp/sps-ssh-{nonce}"
    write_file(driver, other, path, marker)
    if read_file(other_link, path) != marker:
        raise NotRun("ssh_scope_control_failed")
    # The first credential, presented at the second sandbox's endpoint. A token is the user name.
    crossed = replace(
        other_link,
        user=link.user if link.kind == "token" else other_link.user,
        secret=link.secret,
    )
    refused = run("ssh", crossed, "cat " + shlex.quote(path))
    if refused is None:
        raise NotRun("ssh_scope_attempt_unfinished")
    return refused.stdout != marker
