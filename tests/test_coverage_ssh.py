# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""SSH probe: OpenSSH clients reach a fake gateway; no provider account is used."""

from __future__ import annotations

import base64
import json
import os
import shutil
import stat
import subprocess
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import cast

import pytest

from sandbox_provider_spec import coverage_ssh as probe
from sandbox_provider_spec.driver import Driver, Inputs, NativeFailure, NotRun, Observation
from sandbox_provider_spec.runner import Runner
from sandbox_provider_spec.suite import Test as Scenario

HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBEg6ne0Zv3L25f1gqDYf1dJsr+JkIlgucbqxS4U1hQN"

FAKE_OPENSSH = '''#!{python}
"""A gateway that serves `ssh` and `scp` from a directory of fake sandboxes."""
import json, os, subprocess, sys
from pathlib import Path

def config_user(path):
    """The user name from the probe's private ssh_config, which is where a token lives."""
    if not path or path == "/dev/null":
        return None
    found = None
    for raw in Path(path).read_text().splitlines():
        line = raw.strip()
        if not line.startswith("User ") and line != "User":
            continue
        value = line[4:].strip()
        if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
            chars, cursor, limit = [], 1, len(value) - 1
            while cursor < limit:
                if value[cursor] == "\\\\" and cursor + 1 < limit:
                    chars.append(value[cursor + 1])
                    cursor += 2
                else:
                    chars.append(value[cursor])
                    cursor += 1
            value = "".join(chars)
        found = value
    assert oct(Path(path).stat().st_mode & 0o777) == "0o600"
    return found

world = Path(__file__).resolve().parent / "world"
tool, argv = Path(sys.argv[0]).name, sys.argv[1:]
options, rest, port, user, config_path = {{}}, [], None, None, None
index = 0
while index < len(argv):
    word = argv[index]
    if word in {{"-p", "-P"}}:
        port = argv[index + 1]; index += 2
    elif word == "-l":
        user = argv[index + 1]; index += 2
    elif word == "-o":
        key, _, value = argv[index + 1].partition("=")
        options[key] = value; index += 2
    elif word == "-F":
        config_path = argv[index + 1]; index += 2
    elif word == "-O":
        index += 1
    else:
        rest.append(word); index += 1
with (world / "calls.jsonl").open("a") as log:
    log.write(json.dumps({{"tool": tool, "argv": argv, "env": sorted(os.environ)}}) + "\\n")
if options.get("StrictHostKeyChecking") != "yes":
    sys.exit(255)
known_hosts_path = options.get("UserKnownHostsFile")
if not known_hosts_path or known_hosts_path == "/dev/null":
    sys.exit(255)
marker = "[gw.fixture]:" + str(port)
entries = [line.split() for line in Path(known_hosts_path).read_text().splitlines()]
server_key = (world / "host-key").read_text().strip().split()
if [marker, *server_key] not in entries:
    sys.exit(255)
user = user or options.get("User") or config_user(config_path)
sandbox = world / str(port)
if not sandbox.is_dir():
    sys.exit(255)
secret = (sandbox / "secret").read_text()
kind = (sandbox / "kind").read_text()
leaky = (world / "leaky").exists()
accepted = [secret]
if leaky:
    accepted += [p.joinpath("secret").read_text() for p in world.iterdir() if p.is_dir()]
if kind == "key":
    identity = Path(options["IdentityFile"])
    presented = identity.read_text().strip()
    assert oct(identity.stat().st_mode & 0o777) == "0o600"
elif kind == "token":
    presented = user
else:
    asked = subprocess.run([os.environ["SSH_ASKPASS"]], capture_output=True, text=True)
    presented = asked.stdout.strip()
    assert os.environ["SSH_ASKPASS_REQUIRE"] == "force" and options["BatchMode"] == "no"
if presented not in accepted:
    sys.exit(255)
if kind != "token" and user != (sandbox / "user").read_text() and not leaky:
    sys.exit(255)
if (world / "no-scp").exists() and tool == "scp":
    sys.exit(1)
files = sandbox / "files"
if tool == "ssh":
    command = rest[-1]
    assert command.startswith("cat ")
    target = files / command[4:].strip("'").lstrip("/")
    if not target.is_file():
        sys.exit(1)
    sys.stdout.buffer.write(target.read_bytes())
else:
    local, remote = rest[-2], rest[-1].partition(":")[2]
    target = files / remote.lstrip("/")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(Path(local).read_bytes())
'''


class Gateway(Driver):
    """The driver half: sandboxes are directories the fake clients also read."""

    def __init__(self, root: Path, kind: str) -> None:
        super().__init__()
        self.root, self.kind, self.created = root, kind, 0
        self.operations: list[str] = []

    @property
    def world(self) -> Path:
        return self.root / "world"

    def call(self, operation: str, target: object, inputs: Inputs) -> Observation:
        self.operations.append(operation)
        return super().call(operation, target, inputs)

    def create(self, target: object, inputs: Inputs) -> Observation:
        del target
        requirements = cast(Mapping[str, Mapping[str, str]], inputs["requirements"])
        assert requirements["ssh"]["credential"] == self.kind
        self.created += 1
        port = 2200 + self.created
        (self.world / str(port) / "files").mkdir(parents=True)
        owned = self.own("sandbox", port, lambda: {"result": "deleted"})
        return {"resource": owned, "port": port}

    def ssh_access(self, target: object, inputs: Inputs) -> Observation:
        port = cast(int, cast(Mapping[str, object], target)["port"])
        assert inputs["credential"] == self.kind
        user, secret = f"user{port}", f"secret-for-{port}-" + "x" * 12
        sandbox = self.world / str(port)
        sandbox.joinpath("user").write_text(user)
        sandbox.joinpath("kind").write_text(self.kind)
        sandbox.joinpath("secret").write_text(secret)
        field = probe.SECRET_FIELD[self.kind]
        owned = self.own("ssh_access", port, lambda: {"result": "deleted"})
        base: dict[str, object] = {
            "resource": owned,
            "credential": self.kind,
            field: secret,
            "host_key": HOST_KEY,
        }
        if self.kind == "token":
            base["ssh_command"] = f"ssh -o StrictHostKeyChecking=no -p {port} {secret}@gw.fixture"
        else:
            base |= {"host": "gw.fixture", "port": port, "user": user}
        return base

    def files_write(self, target: object, inputs: Inputs) -> Observation:
        port = cast(int, cast(Mapping[str, object], target)["port"])
        path = self.world / str(port) / "files" / str(inputs["path"]).lstrip("/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(base64.b64decode(str(inputs["data"])))
        return {}

    def files_read_bytes(self, target: object, inputs: Inputs) -> Observation:
        port = cast(int, cast(Mapping[str, object], target)["port"])
        return {
            "data": (
                self.world / str(port) / "files" / str(inputs["path"]).lstrip("/")
            ).read_bytes()
        }


@pytest.fixture
def gateway(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Callable[[str], Gateway]:
    (tmp_path / "world").mkdir()
    (tmp_path / "world" / "host-key").write_text(HOST_KEY)
    for name in ("ssh", "scp"):
        script = tmp_path / name
        script.write_text(FAKE_OPENSSH.format(python=sys.executable))
        script.chmod(script.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")
    for name in list(os.environ):
        if any(word in name.upper() for word in probe.ACCOUNT_KEY_NAMES):
            monkeypatch.delenv(name)
    return lambda kind: Gateway(tmp_path, kind)


def start(driver: Gateway) -> tuple[Mapping[str, object], Mapping[str, object]]:
    box = driver.call("create", None, {"requirements": {"ssh": {"credential": driver.kind}}})
    access = driver.call("ssh.access", box, {"credential": driver.kind})
    return box, access


def calls(driver: Gateway) -> list[dict[str, object]]:
    log = driver.world / "calls.jsonl"
    return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []


@pytest.mark.parametrize("kind", ["key", "token", "password"])
def test_each_credential_kind_reaches_a_shell_and_copies_a_file_into_the_sandbox(
    gateway: Callable[[str], Gateway], kind: str
) -> None:
    driver = gateway(kind)
    box, access = start(driver)
    assert probe.observe(driver, {"access": access, "sandbox": box}) == {
        "shell_reached": True,
        "file_copied": True,
        "credential_is_account_key": False,
        "scope_confirmed": True,
    }
    assert driver.created == 2
    secret = str(access[probe.SECRET_FIELD[kind]])
    recorded = calls(driver)
    assert {call["tool"] for call in recorded} == {"ssh", "scp"}
    assert all(secret not in json.dumps(call["argv"]) for call in recorded)
    options = [word for call in recorded for word in cast(list[str], call["argv"])]
    assert "StrictHostKeyChecking=yes" in options
    assert "StrictHostKeyChecking=no" not in options
    assert "UserKnownHostsFile=/dev/null" not in options


def test_the_known_hosts_entry_matches_the_server_and_a_mismatch_is_refused(
    gateway: Callable[[str], Gateway],
) -> None:
    driver = gateway("key")
    box, access = start(driver)
    assert probe.observe(driver, {"access": access, "sandbox": box})["shell_reached"] is True

    # The client now trusts the pinned key, while the fake server presents another key.
    driver.world.joinpath("host-key").write_text(
        HOST_KEY[:-1] + ("A" if HOST_KEY[-1] != "A" else "B")
    )
    path = "/tmp/host-key-refusal"
    driver.files_write(
        box, {"path": path, "data": base64.b64encode(b"should not be read").decode()}
    )
    assert probe.read_file(probe.connection(access), path) is None


def test_a_token_stays_in_a_private_config_file(monkeypatch: pytest.MonkeyPatch) -> None:
    token = 'sec"ret#tok'
    recorded: list[list[str]] = []
    config_text: list[str] = []
    config_mode: list[str] = []

    def capture(command: list[str], **_: object) -> subprocess.CompletedProcess[bytes]:
        # The config is removed when run() returns, so read it while the client would.
        config = Path(command[command.index("-F") + 1])
        recorded.append(command)
        config_text.append(config.read_text())
        config_mode.append(oct(config.stat().st_mode & 0o777))
        return subprocess.CompletedProcess(command, 0, b"", b"")

    monkeypatch.setattr(subprocess, "run", capture)
    link = probe.connection(
        {
            "credential": "token",
            "token": token,
            "host": "gw.fixture",
            "port": 2222,
            "user": token,
            "host_key": HOST_KEY,
        }
    )
    assert probe.run("ssh", link, "true") is not None
    argv = recorded[0]
    assert token not in json.dumps(argv)
    assert "-l" not in argv
    assert "StrictHostKeyChecking=yes" in argv
    assert config_text == ['Host *\n    User "sec\\"ret#tok"\n']
    assert config_mode == ["0o600"]


def test_openssh_parses_the_token_username_from_its_private_config(tmp_path: Path) -> None:
    ssh = shutil.which("ssh")
    if ssh is None:
        pytest.skip("OpenSSH client is not installed")

    token = 'sec"ret#tok'
    link = probe.connection(
        {
            "credential": "token",
            "token": token,
            "host": "gw.fixture",
            "port": 2222,
            "user": token,
            "host_key": HOST_KEY,
        }
    )
    options, _ = probe.client_options(link, tmp_path)
    result = subprocess.run(
        [ssh, *options, "-G", "gw.fixture"],
        capture_output=True,
        text=True,
        check=True,
        timeout=probe.TIMEOUT_SECONDS,
    )
    assert f"user {token}" in result.stdout.splitlines()


def test_a_password_travels_only_through_the_askpass_environment(
    gateway: Callable[[str], Gateway],
) -> None:
    driver = gateway("password")
    box, access = start(driver)
    probe.observe(driver, {"access": access, "sandbox": box})
    password = str(access["password"])
    assert all(password not in json.dumps(call) for call in calls(driver))
    credential_calls = [call for call in calls(driver) if call["argv"] != ["-V"]]
    assert credential_calls
    assert all("SPS_SSH_PASSWORD" in cast(list[str], call["env"]) for call in credential_calls)


def test_a_credential_that_is_a_provider_account_key_is_reported_and_never_sent(
    gateway: Callable[[str], Gateway], monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = gateway("password")
    box, access = start(driver)
    monkeypatch.setenv("EXAMPLE_API_KEY", str(access["password"]))
    assert probe.observe(driver, {"access": access, "sandbox": box}) == {
        "shell_reached": False,
        "file_copied": False,
        "credential_is_account_key": True,
        "scope_confirmed": False,
    }
    assert calls(driver) == []
    assert driver.created == 1


def test_the_provider_environment_never_reaches_the_clients(
    gateway: Callable[[str], Gateway], monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = gateway("key")
    box, access = start(driver)
    monkeypatch.setenv("EXAMPLE_API_KEY", "an-unrelated-account-secret")
    probe.observe(driver, {"access": access, "sandbox": box})
    assert all("EXAMPLE_API_KEY" not in cast(list[str], call["env"]) for call in calls(driver))


def test_a_credential_that_opens_another_sandbox_fails_the_scope_check(
    gateway: Callable[[str], Gateway],
) -> None:
    driver = gateway("key")
    (driver.world / "leaky").write_text("")
    box, access = start(driver)
    result = probe.observe(driver, {"access": access, "sandbox": box})
    assert result["shell_reached"] is True
    assert result["scope_confirmed"] is False


def test_a_wrong_credential_reaches_nothing_and_creates_no_second_sandbox(
    gateway: Callable[[str], Gateway],
) -> None:
    driver = gateway("key")
    box, access = start(driver)
    driver.world.joinpath(str(box["port"]), "secret").write_text("other")
    assert probe.observe(driver, {"access": access, "sandbox": box}) == {
        "shell_reached": False,
        "file_copied": False,
        "credential_is_account_key": False,
        "scope_confirmed": False,
    }
    assert driver.created == 1


def test_a_failing_copy_is_reported_without_hiding_the_shell(
    gateway: Callable[[str], Gateway],
) -> None:
    driver = gateway("token")
    (driver.world / "no-scp").write_text("")
    box, access = start(driver)
    result = probe.observe(driver, {"access": access, "sandbox": box})
    assert (result["shell_reached"], result["file_copied"]) == (True, False)


def test_a_second_sandbox_that_cannot_be_reached_leaves_the_scope_unobserved(
    gateway: Callable[[str], Gateway], monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = gateway("token")
    box, access = start(driver)
    issue = Gateway.ssh_access

    def spoiled(self: Gateway, target: object, inputs: Inputs) -> Observation:
        result = issue(self, target, inputs)
        if target is not box:
            self.world.joinpath(
                str(cast(Mapping[str, object], target)["port"]), "secret"
            ).write_text("x")
        return result

    monkeypatch.setattr(Gateway, "ssh_access", spoiled)
    with pytest.raises(NotRun, match="ssh_scope_control_failed"):
        probe.observe(driver, {"access": access, "sandbox": box})


def test_missing_openssh_clients_prove_nothing(
    gateway: Callable[[str], Gateway], monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = gateway("key")
    box, access = start(driver)
    monkeypatch.setattr(shutil, "which", lambda _: None)
    with pytest.raises(NotRun, match="openssh_client_missing"):
        probe.observe(driver, {"access": access, "sandbox": box})


@pytest.mark.parametrize(
    "access",
    [
        {"credential": "certificate", "private_key": "x", "host": "h", "port": 22, "user": "u"},
        {"credential": "key", "host": "h", "port": 22, "user": "u"},
        {
            "credential": "key",
            "private_key": "x",
            "host": "-oProxyCommand=x",
            "port": 22,
            "user": "u",
        },
        {"credential": "key", "private_key": "x", "host": "h", "port": 0, "user": "u"},
        {"credential": "key", "private_key": "x", "host": "h", "port": 22, "user": "u v"},
        {"credential": "key", "private_key": "x", "host": "h", "port": True, "user": "u"},
        {"credential": "token", "token": "abc", "host": "h", "port": 22, "user": "other"},
        {"credential": "token", "token": "abc", "ssh_command": "ssh h"},
    ],
)
def test_malformed_connection_material_is_refused(access: Mapping[str, object]) -> None:
    with pytest.raises(NativeFailure, match="ssh_native"):
        probe.connection(access)


def test_a_host_key_comment_is_not_part_of_the_pin() -> None:
    link = probe.connection(
        {
            "credential": "key",
            "private_key": "x",
            "host": "h",
            "port": 22,
            "user": "u",
            "host_key": HOST_KEY + " root@sandbox",
        }
    )
    assert link.host_key == HOST_KEY


@pytest.mark.parametrize(
    "host_key",
    [
        "",
        1,
        "ssh-ed25519 not-base64",
        "@cert-authority * " + HOST_KEY,
        "ecdsa-sha2-nistp256 " + HOST_KEY.split(" ", 1)[1],
        "ssh-ed25519 " + ("A" * 16),
    ],
)
def test_a_bad_host_key_is_refused(host_key: object) -> None:
    with pytest.raises(NativeFailure, match="ssh_native_host_key_invalid"):
        probe.connection(
            {
                "credential": "key",
                "private_key": "x",
                "host": "h",
                "port": 22,
                "user": "u",
                "host_key": host_key,
            }
        )


@pytest.mark.parametrize("kind", ["key", "token", "password"])
def test_a_missing_host_key_never_presents_the_credential(
    gateway: Callable[[str], Gateway], kind: str
) -> None:
    driver = gateway(kind)
    box, access = start(driver)
    opened = dict(access)
    opened.pop("host_key")
    with pytest.raises(NotRun, match="ssh_host_key_unverified"):
        probe.observe(driver, {"access": opened, "sandbox": box})
    assert calls(driver) == []
    assert driver.created == 1


def test_a_wildcard_host_is_not_pinned_as_a_known_hosts_pattern(tmp_path: Path) -> None:
    link = probe.connection(
        {
            "credential": "key",
            "private_key": "x",
            "host": "*",
            "port": 22,
            "user": "u",
            "host_key": HOST_KEY,
        }
    )
    with pytest.raises(NativeFailure, match="ssh_native_endpoint_invalid"):
        probe.client_options(link, tmp_path)


@pytest.mark.parametrize(
    "command",
    [
        "ssh fixture@gateway.fixture cat /etc/passwd",
        "ssh -J outside.fixture fixture@gateway.fixture",
        "sh -c 'ssh fixture@gateway.fixture'",
        "ssh fixture@gateway.fixture -oProxyCommand=unexpected",
        "ssh -p high fixture@gateway.fixture",
        "ssh 'unbalanced",
        None,
    ],
)
def test_a_provider_command_line_is_parsed_never_executed(command: object) -> None:
    with pytest.raises(NativeFailure, match="ssh_native_endpoint_invalid"):
        probe.destination(command)


def test_native_ssh_endpoint_is_parsed_without_executing_options() -> None:
    assert probe.destination("ssh -o StrictHostKeyChecking=no -p 2222 fixture@gateway.fixture") == (
        "gateway.fixture",
        2222,
        "fixture",
    )


@pytest.mark.parametrize("kind", ["key", "token", "password"])
def test_the_shipped_tests_run_through_the_runner(
    gateway: Callable[[str], Gateway], kind: str
) -> None:
    driver = gateway(kind)
    # Keep this runner unit test independent of active catalog cases: SSH is waitlisted.
    test = Scenario(
        f"synthetic.ssh.{kind}",
        "Synthetic SSH probe through the runner.",
        (
            {
                "op": "create",
                "as": "box",
                "in": {"lifetime_seconds": 300, "requirements": {"ssh": {"credential": kind}}},
            },
            {"op": "ssh.access", "target": "box", "in": {"credential": kind}, "as": "access"},
            {
                "op": "probe.ssh",
                "in": {"access": "$access", "sandbox": "$box"},
                "expect": {
                    "equals": {
                        "shell_reached": True,
                        "file_copied": True,
                        "credential_is_account_key": False,
                        "scope_confirmed": True,
                    }
                },
            },
        ),
        (),
    )
    result = Runner(driver).run_test(test)
    assert result["result"] == "passed", result
    steps = cast(list[dict[str, object]], result["steps"])
    assert [step["operation"] for step in steps] == ["create", "ssh.access", "probe.ssh"]


def test_a_crossed_attempt_that_never_finishes_is_not_a_refusal(
    gateway: Callable[[str], Gateway], monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = gateway("key")
    box, access = start(driver)
    original, seen = probe.run, []

    def hang_on_the_second_attempt(
        tool: str, link: probe.Connection, *arguments: str
    ) -> subprocess.CompletedProcess[bytes] | None:
        seen.append(link.port)
        if seen.count(2202) == 2:  # The control reached the second sandbox once already.
            return None
        return original(tool, link, *arguments)

    monkeypatch.setattr(probe, "run", hang_on_the_second_attempt)
    with pytest.raises(NotRun, match="ssh_scope_attempt_unfinished"):
        probe.observe(driver, {"access": access, "sandbox": box})


@pytest.mark.parametrize(
    "banner,flag",
    [
        ("OpenSSH_9.6p1 Ubuntu-3ubuntu13.19, OpenSSL 3.0.13 30 Jan 2024", ("-O",)),
        ("OpenSSH_8.7p1, OpenSSL 3.0.7", ("-O",)),
        ("OpenSSH_8.6p1, LibreSSL 3.3.6", ()),
        ("OpenSSH_7.4p1, OpenSSL 1.0.2k-fips", ()),
        ("not a known client", ()),
    ],
)
def test_the_classic_scp_flag_is_used_only_where_the_client_has_it(
    monkeypatch: pytest.MonkeyPatch, banner: str, flag: tuple[str, ...]
) -> None:
    def version(*_: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert kwargs.get("env") == {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
        return subprocess.CompletedProcess([], 0, "", banner)

    monkeypatch.setattr(subprocess, "run", version)
    assert probe.classic_scp_flag() == flag


def test_a_stalled_ssh_version_check_returns_no_classic_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def stall(*_: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert kwargs.get("timeout") == probe.TIMEOUT_SECONDS
        raise subprocess.TimeoutExpired(["ssh", "-V"], probe.TIMEOUT_SECONDS)

    monkeypatch.setattr(subprocess, "run", stall)
    assert probe.classic_scp_flag() == ()


def test_a_stalled_ssh_version_check_is_retried(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def recover(*_: object, **__: object) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise subprocess.TimeoutExpired(["ssh", "-V"], probe.TIMEOUT_SECONDS)
        return subprocess.CompletedProcess([], 0, "", "OpenSSH_9.6p1")

    monkeypatch.setattr(subprocess, "run", recover)
    assert probe.classic_scp_flag() == ()
    assert probe.classic_scp_flag() == ("-O",)
    assert calls == 2
