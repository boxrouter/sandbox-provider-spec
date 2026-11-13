# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Offline controls for isolated regular-file write usability checks."""

from __future__ import annotations

import hashlib
import json
import os
import runpy
import stat
from pathlib import Path
from typing import Any, cast

import pytest

import sandbox_provider_spec
from sandbox_provider_spec import check_digests
from sandbox_provider_spec.coverage_regular_write import (
    BYTE_BOUND,
    CASES,
    EXECUTABLE_WARNING,
    RegularWriteUsabilityRunner,
    guest,
)
from sandbox_provider_spec.driver import Driver, Inputs, NativeFailure, Observation
from sandbox_provider_spec.suite import Test as Scenario
from sandbox_provider_spec.suite import read_suite, suite_path

_SCRIPT = suite_path().parent / "fixtures" / "regular_write_usability.py"
_PROBE = runpy.run_path(str(_SCRIPT))
EXISTING_PREFIX = "files.regular_write.usability.v1."


class FakeFs(Driver):
    """In-memory files plus local observer; no provider dispatch."""

    def __init__(self) -> None:
        super().__init__()
        self.files: dict[str, bytes] = {}
        self.modes: dict[str, int] = {}
        self.writes: list[tuple[str, int]] = []
        self.staging = {"owned_staging_present": False, "uncertain_identity_retained": False}
        self.refuse: set[str] = set()
        self.closed: list[str] = []

    def create(self, target: object, inputs: Inputs) -> Observation:
        del target, inputs
        return {"identity": "box"}

    def destroy(self, target: object, inputs: Inputs) -> Observation:
        del target, inputs
        self.closed.append("sandbox")
        return {}

    def files_write(self, target: object, inputs: Inputs) -> Observation:
        del target
        path = str(inputs["path"])
        data = __import__("base64").b64decode(str(inputs["data"]), validate=True)
        if path in self.refuse:
            raise NativeFailure("authorization")
        parent = str(Path(path).parent)
        if parent not in {"/", ""}:
            self.files.setdefault(parent, b"")
        self.files[path] = data
        self.modes.setdefault(path, 0o600)
        self.writes.append((path, len(data)))
        return {"written_bytes": len(data)}

    def run(self, target: object, inputs: Inputs) -> Observation:
        del target
        script = str(inputs.get("bash_script", ""))
        env = dict(cast(dict[str, str], inputs.get("environment") or {}))
        if "python3 /tmp/sps-regular-write-usability.py" in script:
            os.environ.update(env)
            payload = json.loads(env["SPS_REGULAR_WRITE_ARGUMENTS"])
            observation = _PROBE["observe"](payload["path"])
            # Reconstruct from in-memory files when the path is our fake path.
            path = payload["path"]
            if path in self.files:
                data = self.files[path]
                mode = self.modes.get(path, 0o600)
                observation = {
                    "exists": True,
                    "size": len(data),
                    "mode": oct(mode),
                    "uid": 1000,
                    "gid": 1000,
                    "readable": True,
                    "writable": True,
                    "executable": bool(mode & stat.S_IXUSR),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
            elif path not in self.files:
                observation = {"exists": False, "errno": 2}
            return {"exit_code": 0, "stdout": json.dumps(observation)}
        if script.startswith("mkdir -p "):
            return {"exit_code": 0, "stdout": ""}
        if script.startswith("id -un") or script == "id -u":
            return {"exit_code": 0, "stdout": "user\n1000\n1000\n1000\n"}
        if "chmod " in script:
            parts = script.replace(";", " ").split()
            while "chmod" in parts:
                index = parts.index("chmod")
                mode_token = parts[index + 1]
                path = parts[index + 2]
                self.modes[path] = int(mode_token, 8)
                self.files.setdefault(path, b"fixture")
                parts = parts[index + 3 :]
            return {"exit_code": 0, "stdout": ""}
        if "chown 0:0" in script:
            return {"exit_code": 0, "stdout": ""}
        if "sudo -n true" in script:
            return {"exit_code": 0, "stdout": ""}
        return {"exit_code": 0, "stdout": ""}

    def staging_state(self) -> dict[str, bool]:
        return dict(self.staging)


def test_fixture_operation_dependencies_are_isolated() -> None:
    test = Scenario(
        id="files.regular_write.usability.v1.offline",
        title="Regular-write usability source dependencies are isolated.",
        steps=({"op": "fixture.regular_write_usability"},),
        proves=(),
        rules=(),
    )
    dependencies = set(check_digests.test_dependencies(test))
    assert dependencies == {
        "coverage_regular_write.py",
        "fixtures/regular_write_usability.py",
        "fixtures/regular_write_usability.schema.json",
        "fixtures/regular_write_usability.md",
    }
    assert not {"runner.py", "coverage_probe.py"} & dependencies


def test_existing_check_ids_and_bodies_are_unchanged() -> None:
    suite = read_suite(suite_path().with_name("coverage.yaml"))
    new_ids = [test.id for test in suite.tests if test.id.startswith(EXISTING_PREFIX)]
    assert new_ids == [f"{EXISTING_PREFIX}{suffix}" for suffix in CASES]
    core = read_suite()
    assert [test.id for test in core.tests if test.id.startswith(EXISTING_PREFIX)] == []
    # Existing coverage ids are everything before the new family.
    later = (
        EXISTING_PREFIX,
        "file_links.v1.",
        "files.stream.v1.",
        "coverage.custom_images.prepare.dockerfile_distro",
        "coverage.custom_images.prepare.dockerfile_distro_context",
        "coverage.custom_images.prepare.dockerfile_standard_base_context",
    )
    prior = [test.id for test in suite.tests if not test.id.startswith(later)]
    assert "files.regular_write.usability.v1.exact_bytes" not in prior
    assert prior[-1] == "coverage.facts.guest_reserved_tcp_ports.8080"
    assert len(prior) == 120


@pytest.mark.parametrize("case", CASES)
def test_each_case_passes_on_the_fake(case: str) -> None:
    driver = FakeFs()
    if case == "authority":
        driver.refuse.add("/tmp/sps-rw-offline/protected/secret")
    if case == "staging_cleanup":
        driver.staging = {"owned_staging_present": False, "uncertain_identity_retained": True}
    result = guest(driver, {"identity": "box"}, {"case": case}, {"run_nonce": "offline"})
    assert result["passed"] is True
    assert result["case"] == case
    if case == "byte_bound":
        oversized = [item for item in driver.writes if item[1] > BYTE_BOUND]
        assert oversized == []
    if case == "executable_effect":
        assert result["files_write_executable_effect"] == "unverified"
        assert EXECUTABLE_WARNING in str(result["warning"])


def test_e2b_style_refusal_happens_before_upload() -> None:
    driver = FakeFs()
    driver.refuse.add("/tmp/sps-rw-offline/protected/secret")
    result = guest(driver, {"identity": "box"}, {"case": "authority"}, {"run_nonce": "offline"})
    assert result["refused"] is True
    assert ("/tmp/sps-rw-offline/protected/secret", 6) not in driver.writes


def test_byte_bound_refuses_before_dispatch() -> None:
    driver = FakeFs()
    guest(driver, {"identity": "box"}, {"case": "byte_bound"}, {"run_nonce": "offline"})
    assert all(size <= BYTE_BOUND for _path, size in driver.writes)


def test_runner_dispatches_only_the_named_case() -> None:
    driver = FakeFs()
    scenario = Scenario(
        id="files.regular_write.usability.v1.exact_bytes",
        title="offline",
        steps=(
            {"op": "create", "as": "box"},
            {
                "op": "fixture.regular_write_usability",
                "target": "box",
                "in": {"case": "exact_bytes"},
                "expect": {"equals": {"passed": True, "case": "exact_bytes"}},
            },
        ),
        proves=(),
        rules=("files/regular-write-exact-bytes",),
    )
    outcome = RegularWriteUsabilityRunner(cast(Any, driver)).run_test(scenario)
    assert outcome["result"] == "passed"


def test_declaration_field_accepts_the_three_values() -> None:
    for value in ("preserved", "may_clear", "unverified"):
        declaration = {
            "spec": "sandbox-provider-spec/0.1",
            "provider": "acme",
            "verified": {"date": "2026-10-27", "sdks": {"acme": "1.0"}},
            "resources": {"files_write_executable_effect": value},
            "gates": {},
            "evidence": {
                "resources.files_write_executable_effect": {
                    "tests": ["files.regular_write.usability.v1.executable_effect"],
                    "report": "reports/example.json",
                }
            },
        }
        assert sandbox_provider_spec.schema_errors(declaration, "declaration-schema.json") == []
    invalid = {
        **declaration,
        "resources": {"files_write_executable_effect": "always"},
    }
    assert sandbox_provider_spec.schema_errors(invalid, "declaration-schema.json")
