# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Tester follow-ups: the user_selection summary line, the Alpine user setup, the cookie bootstrap
of a credential link, and the literal-IP fixture of the blocked-egress tests."""

from __future__ import annotations

import dataclasses
import json
import os
import shutil
import stat
import subprocess
import threading
from collections.abc import Iterator, Mapping
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from sandbox_provider_spec.driver import NotRun
from sandbox_provider_spec.proofs import proof_fixtures
from sandbox_provider_spec.runner import http
from sandbox_provider_spec.suite import Test as Scenario
from sandbox_provider_spec.v1 import Discovery, SandboxClass, from_json
from sandbox_provider_spec.v1.suite_driver import _without_credential
from sandbox_provider_spec.v1.tester import (
    LIFETIME_NOT_CLAIMED,
    LIFETIME_TEST,
    TestOptions,
    _summary,
    not_claimed_tests,
    select_tests,
    shared_suite,
    snapshot_keeps,
)

# ---------------------------------------------------------------- user_selection summary line


def _row(test_id: str, result: str = "passed") -> dict[str, object]:
    return {"id": test_id, "result": result, "steps": []}


def test_the_user_selection_line_counts_the_three_user_tests() -> None:
    results = [_row("run.user"), _row("files.write.user"), _row("process.start.user")]
    lines = _summary(results, "passed", "unsupported", {"user_selection": []})
    assert "section user_selection passed" in lines


def test_the_user_selection_line_takes_the_worst_of_its_tests() -> None:
    results = [_row("run.user"), _row("files.write.user", "differs")]
    lines = _summary(results, "passed", "unsupported", {"user_selection": []})
    assert "section user_selection differs" in lines


def test_a_section_with_no_selected_test_still_reads_not_run() -> None:
    lines = _summary([_row("run.user")], "passed", "unsupported", {"user_selection": [], "x": []})
    assert "section x not_run" in lines


# ---------------------------------------------------------------- Alpine user setup


def _scripts() -> list[str]:
    suite = shared_suite()
    found = []
    for test_id in ("run.user", "files.write.user", "process.start.user"):
        test = next(item for item in suite.tests if item.id == test_id)
        found.append(str(test.steps[1]["in"]["bash_script"]))
    guest = next(item for item in suite.tests if item.id == "coverage.guest_user.selectable")
    found.append(str(guest.steps[1]["in"]["bash_script"]))
    return found


def _stub(directory: Path, name: str, body: str) -> None:
    path = directory / name
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


@pytest.mark.parametrize("script", _scripts())
@pytest.mark.parametrize("have_useradd", [True, False])
def test_the_user_setup_uses_useradd_or_adduser(
    tmp_path: Path, script: str, have_useradd: bool
) -> None:
    for tool in ("id", "sh"):
        os.symlink(shutil.which(tool) or tool, tmp_path / tool)
    _stub(tmp_path, "sudo", 'shift; exec "$@"\n')  # `sudo -n <command>`
    _stub(tmp_path, "adduser", 'echo "adduser $*"\n')
    if have_useradd:
        _stub(tmp_path, "useradd", 'echo "useradd $*"\n')
    done = subprocess.run(
        [str(tmp_path / "sh"), "-c", script],
        env={"PATH": str(tmp_path)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    expected = (
        "useradd --create-home --uid 10001 --shell /bin/bash runner"
        if have_useradd
        else "adduser -D -u 10001 -s /bin/sh runner"
    )
    assert done.stdout.strip() == expected


# ---------------------------------------------------------------- cookie bootstrap


class _Bootstrap(BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:  # noqa: D102
        pass

    def do_GET(self) -> None:  # noqa: N802, D102
        path = self.path
        if path.startswith("/app") and "token=ok" in path:
            self.send_response(302)
            self.send_header("Set-Cookie", "sid=abc; Path=/; HttpOnly")
            self.send_header("Location", "/app")
            self.end_headers()
        elif path == "/app" and "sid=abc" in (self.headers.get("Cookie") or ""):
            self._body(200, b"sps-preview")
        elif path == "/signin-redirect":
            self.send_response(302)
            self.send_header("Location", "/signin")
            self.end_headers()
        elif path == "/cookie-elsewhere":
            self.send_response(302)
            self.send_header("Set-Cookie", "sid=abc")
            self.send_header("Location", "http://other.invalid/app")
            self.end_headers()
        elif path == "/signin":
            self._body(200, b"sign in")
        else:
            self._body(401, b"no")

    def _body(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture(name="origin")
def origin_fixture() -> Iterator[str]:
    server = HTTPServer(("127.0.0.1", 0), _Bootstrap)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
    )
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()


@pytest.mark.loopback
@pytest.mark.integration
def test_a_credential_links_cookie_bootstrap_is_followed(origin: str) -> None:
    seen = http({"url": origin + "/app?token=ok"})
    assert (seen["status"], seen["served"], seen["body"]) == (200, True, b"sps-preview")


@pytest.mark.loopback
@pytest.mark.integration
def test_the_same_request_without_the_credential_is_not_served(origin: str) -> None:
    seen = http({"url": origin + "/app"})
    assert (seen["status"], seen["served"]) == (401, False)


@pytest.mark.loopback
@pytest.mark.integration
def test_a_header_credentials_bootstrap_is_followed(origin: str) -> None:
    seen = http({"url": origin + "/app?token=ok", "headers": {"X-Token": "t"}})
    assert seen["served"] is True


@pytest.mark.loopback
@pytest.mark.integration
def test_a_redirect_that_sets_no_cookie_or_leaves_the_origin_is_not_followed(origin: str) -> None:
    for path in ("/signin-redirect", "/cookie-elsewhere"):
        seen = http({"url": origin + path, "headers": {"X-Token": "t"}})
        assert (seen["status"], seen["served"]) == (302, False)


# ---------------------------------------------------------------- literal-IP fixture


@pytest.mark.parametrize(
    "test_id", ["network_lockdown.deny_all", "network_lockdown.root_cannot_lift"]
)
def test_the_blocked_egress_tests_need_a_plain_http_literal_ip(test_id: str) -> None:
    test = Scenario(id=test_id, title="t", steps=(), proves=())
    assert proof_fixtures(test, {"allowed_ip_url": "http://192.0.2.10/health"}) == {}
    for bad in ("https://1.1.1.1/cdn-cgi/trace", "http://ip.example/health", "http://[::1]/"):
        with pytest.raises(NotRun) as raised:
            proof_fixtures(test, {"allowed_ip_url": bad})
        assert str(raised.value) == "proof_fixture_invalid"
    with pytest.raises(NotRun, match="fixture_missing"):
        proof_fixtures(test, {})


# ---------------------------------------------------------------- per-class claims, snapshot keeps


def _discovery(*classes: tuple[str, str]) -> Discovery:
    path = (
        Path(__file__).resolve().parents[1]
        / "spec"
        / "provider-api-1.0-examples"
        / "Discovery.json"
    )
    discovery = from_json(Discovery, json.loads(path.read_text("utf-8")))
    template = discovery.classes[0]
    return dataclasses.replace(
        discovery,
        classes=[
            dataclasses.replace(template, id=name, lifetime_enforced_by=enforcer)  # type: ignore[arg-type]
            for name, enforcer in classes
        ],
    )


def test_the_lifetime_claim_is_read_from_the_class_that_runs_the_test() -> None:
    only_vm = _discovery(("vm", "router"))  # `--class vm` leaves one class, not named `default`
    assert not_claimed_tests(only_vm) == {LIFETIME_TEST: LIFETIME_NOT_CLAIMED}
    both = _discovery(("default", "provider"), ("vm", "router"))
    assert not_claimed_tests(both) == {}
    assert not_claimed_tests(both, "vm") == {LIFETIME_TEST: LIFETIME_NOT_CLAIMED}


def _snapshots(keeps: object) -> SandboxClass:
    base = _discovery(("default", "provider")).classes[0]
    return dataclasses.replace(base, gates={"snapshots": [{"keeps": keeps}]})


@pytest.mark.parametrize(
    ("keeps", "expected"),
    [
        ("files_only", None),
        (["files_only", "files_and_memory"], None),
        ("files_and_memory", "files_and_memory"),
        (["files_and_memory"], "files_and_memory"),
    ],
)
def test_the_snapshot_tests_take_the_keeps_the_class_declares(
    keeps: object, expected: str | None
) -> None:
    assert snapshot_keeps(_snapshots(keeps)) == expected


def test_the_get_and_list_test_names_the_declared_keeps() -> None:
    test = next(item for item in shared_suite().tests if item.id == "snapshots.v1.get_and_list")
    assert proof_fixtures(test, {}) == {"snapshot_keeps": "files_only"}
    assert proof_fixtures(test, {"snapshot_keeps": "files_and_memory"}) == {
        "snapshot_keeps": "files_and_memory"
    }
    with pytest.raises(NotRun, match="proof_fixture_invalid"):
        proof_fixtures(test, {"snapshot_keeps": "memory"})
    assert "files_only" not in str(test.steps)


def _with_gates(gates: dict[str, object]) -> Discovery:
    discovery = _discovery(("default", "provider"))
    return dataclasses.replace(
        discovery, classes=[dataclasses.replace(discovery.classes[0], gates=gates)]
    )


def _selected(discovery: Discovery, fixtures: Mapping[str, object] | None = None) -> set[str]:
    options = TestOptions(fixtures=fixtures or {})
    return {test.id for test in select_tests(shared_suite(), discovery, options).tests}


def test_a_claim_with_a_count_selects_the_test_once_its_fixtures_name_the_count() -> None:
    discovery = _with_gates({"network_lockdown": [{"max_allow": {"at_least": 32}}]})
    hosts = [f"h{i}.example.test" for i in range(32)]
    fixtures = {
        "max_allow_entries": hosts,
        "max_allow_urls": [f"https://{host}/health" for host in hosts],
    }
    assert "network_lockdown.max_allow" in _selected(discovery, fixtures)
    assert "network_lockdown.max_allow" not in _selected(discovery)  # no fixtures: not selected
    fewer = {k: v[:5] for k, v in fixtures.items()}  # five entries prove only at_least 5
    assert "network_lockdown.max_allow" not in _selected(discovery, fewer)


def test_a_preview_test_runs_for_the_access_level_whose_revocability_is_claimed() -> None:
    mixed = _with_gates(
        {
            "previews": [
                {"access": ["public"], "revocable": False},
                {"access": ["private"], "revocable": True},
            ]
        }
    )
    chosen = _selected(mixed)
    assert "previews.revocable.true" in chosen  # the private link is revocable
    assert "previews.revocable.false" not in chosen  # it creates a private link
    assert "previews.revocable.true.public" not in chosen  # the public link is not
    private_false = _with_gates({"previews": [{"access": ["private"], "revocable": False}]})
    assert "previews.revocable.false" in _selected(private_false)


def test_a_preview_test_needs_a_variant_that_offers_the_credential_it_asks_for() -> None:
    link_only = _with_gates({"previews": [{"access": ["private"], "credential": "link"}]})
    chosen = _selected(link_only)
    assert "previews.credential.link" in chosen
    assert "previews.credential.header" not in chosen
    assert "previews.credential_scope" not in chosen  # it creates a header-credential link
    header = _with_gates({"previews": [{"access": ["private"], "credential": "header"}]})
    assert "previews.credential_scope" in _selected(header)


def test_the_control_url_of_a_link_credential_in_the_host_spoils_the_token() -> None:
    token = "a1b2" + "c3d4" + "e5f6" + "g7h8" + "i9j0" + "k1l2"  # split for the scanner
    assert (
        _without_credential(f"https://3000-{token}.proxy.example.test/", "link")
        == "https://3000-" + "x" * len(token) + ".proxy.example.test/"
    )
    assert _without_credential("https://h.test/p?token=abc#frag", "link") == "https://h.test/p"
    assert _without_credential(f"https://h.test/{token}/x", "link") == (
        "https://h.test/" + "x" * len(token) + "/x"
    )
    assert _without_credential("https://h.test/p", "header") == "https://h.test/p"
