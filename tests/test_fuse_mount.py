# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The opt-in fixture refuses missing inputs before mutation and hashes its entire harness."""

import base64
import json
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

import pytest

from sandbox_provider_spec.check_digests import check_digests
from sandbox_provider_spec.check_digests import test_dependencies as dependencies
from sandbox_provider_spec.driver import Driver, Inputs, Observation
from sandbox_provider_spec.fuse_mount import (
    FuseMountRunner,
    binding_digest,
    controller_digest,
    guest_identity_digest,
)
from sandbox_provider_spec.fuse_mount_identity import CALIBRATION_METRIC
from sandbox_provider_spec.matcher import build_declaration, match
from sandbox_provider_spec.runner import Runner
from sandbox_provider_spec.suite import Test as Scenario
from sandbox_provider_spec.suite import read_suite, suite_path


def scenario() -> Scenario:
    return next(
        test
        for test in read_suite(suite_path().with_name("coverage.yaml")).tests
        if test.id == "fuse_mount.lifecycle"
    )


class TestDriver(Driver):
    __test__ = False

    def __init__(self, *, fenced: bool = True) -> None:
        super().__init__()
        self.calls: list[str] = []
        self.fenced = fenced

    def call(self, operation: str, target: object, inputs: Inputs) -> Observation:
        del target
        self.calls.append(operation)
        if operation == "create":
            return {"sandbox": len(self.calls)}
        if operation == "run.as_root":
            return {"exit_code": 0, "stdout": "0\n"}
        if operation == "run":
            script = str(inputs["bash_script"])
            return {
                "exit_code": 0,
                "stdout": "ready" if script.startswith("cat ") else '{"verified":true}',
            }
        if operation == "files.write":
            encoded = inputs["data"]
            assert isinstance(encoded, str)
            assert base64.b64decode(encoded, validate=True) == b"fence-complete"
        if operation == "process.wait":
            return {"exit_code": 0}
        if operation == "process.output":
            return {"stdout": json.dumps({"fenced": self.fenced, "errno": 5 if self.fenced else 0})}
        return {}


class Controller:
    def __init__(self, source: Path) -> None:
        self.source_files: tuple[Path, ...] = (Path(__file__), source)
        self.calls: list[str] = []
        self.execution_binding: dict[str, str] | None = None

    def mount(self, *_args: Any) -> None:
        self.calls.append("mount")

    def checkpoint(self, *_args: Any) -> object:
        self.calls.append("checkpoint")
        return object()

    def fence(self, *_args: Any) -> None:
        self.calls.append("fence")

    def release(self, *_args: Any) -> None:
        self.calls.append("release")

    def resume(self, *_args: Any) -> None:
        self.calls.append("resume")

    def cleanup(self) -> Mapping[str, object]:
        self.calls.append("cleanup")
        return {"result": "deleted"}


def test_missing_controller_never_allocates() -> None:
    driver = TestDriver()
    result = FuseMountRunner(
        driver, {"fuse_mount_create": {}, "fuse_mount_prerequisites": []}
    ).run_test(scenario())
    assert result["result"] == "not_run"
    assert result["reason"] == "fixture_missing"
    assert driver.calls == []


def test_ordinary_dispatch_cannot_attest_new_fixture() -> None:
    result = Runner(Driver(), {"fuse_mount_create": {}, "fuse_mount_prerequisites": []}).run_test(
        scenario()
    )
    assert result["result"] == "not_run"


@pytest.mark.parametrize("fenced", [False, True])
def test_fixture_runs_lifecycle_and_requires_stale_descriptor_failure(
    tmp_path: Path, fenced: bool
) -> None:
    source = tmp_path / "controller.py"
    source.write_text("# controlled test implementation\n")
    controller = Controller(source)
    driver = TestDriver(fenced=fenced)
    digest = controller_digest(controller.source_files)
    result = FuseMountRunner(
        driver,
        {
            "fuse_mount_create": {},
            "fuse_mount_prerequisites": [
                "image:sha256:" + "a" * 64,
                "region:test",
                "fuse_mount_account",
                "fuse_mount_egress:sha256:" + "b" * 64,
            ],
            "fuse_mount_controller": controller,
            "fuse_mount_controller_digest": digest,
        },
    ).run_test(scenario())
    assert result["result"] == ("passed" if fenced else "differs")
    if fenced:
        assert controller.calls == [
            "mount",
            "checkpoint",
            "fence",
            "release",
            "resume",
            "release",
            "cleanup",
        ]
        assert driver.calls.count("create") == 2
    else:
        # A no-op fence cannot borrow success from release or successor force-mount.
        assert controller.calls == ["mount", "checkpoint", "fence", "cleanup"]
        assert driver.calls.count("create") == 1
    assert ("controller_source_digest" in str(result)) is fenced
    assert str(tmp_path) not in str(result)


def test_wrong_controller_source_never_allocates(tmp_path: Path) -> None:
    source = tmp_path / "controller.py"
    source.write_text("# source\n")
    driver = TestDriver()
    result = FuseMountRunner(
        driver,
        {
            "fuse_mount_create": {},
            "fuse_mount_prerequisites": [
                "image:sha256:" + "a" * 64,
                "region:test",
                "fuse_mount_account",
                "fuse_mount_egress:sha256:" + "b" * 64,
            ],
            "fuse_mount_controller": Controller(source),
            "fuse_mount_controller_digest": "sha256:" + "0" * 64,
        },
    ).run_test(scenario())
    assert result["reason"] == "fixture_source_mismatch"
    assert driver.calls == []


def test_new_check_binds_harness_controller_protocol_and_guest_observer() -> None:
    bound = dependencies(scenario())
    assert "fuse_mount.py" in bound
    assert "fixtures/fuse_mount.py" in bound
    assert check_digests((scenario(),))[scenario().id].startswith("sha256:")


def test_new_gate_unknown_and_unconfirmed_needs_never_match() -> None:
    from_document: dict[str, Any] = {
        "spec": "sandbox-provider-spec/0.1",
        "provider": "fixture",
        "verified": {"sdks": {"test": "1"}},
        "resources": {},
        "gates": {},
    }
    missing = build_declaration(from_document)
    assert "fuse_mount" not in missing.gates
    offered = build_declaration(
        {**from_document, "gates": {"fuse_mount": [{"needs": {"variant": ["account"]}}]}}
    )
    assert offered.gates["fuse_mount"].variants[0].needs == {"variant": ["account"]}
    # Synthetic baseline evidence isolates matcher prerequisites; it is never published.
    baseline = {
        "spec": "sandbox-provider-spec/0.1",
        "provider": "fixture",
        "sdk_versions": {"test": "1"},
        "finished_at": "2026-10-22T00:00:00Z",
        "clean": True,
        "selected_tests": list(read_suite().baseline_ids),
        "tests": [
            {"id": identifier, "result": "passed"} for identifier in read_suite().baseline_ids
        ],
    }
    request: dict[str, Any] = {"requirements": {"fuse_mount": {}}}
    assert match(request, [missing], reports=[baseline])["eligible"] == []
    assert match(request, [offered], reports=[baseline])["eligible"] == []
    assert match(request, [offered], reports=[baseline], met_needs=["account"])["eligible"] == [
        "fixture"
    ]


def test_guest_observer_refuses_a_plain_directory(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(suite_path().parent / "fixtures/fuse_mount.py"),
            "write",
            str(tmp_path),
            str(tmp_path / "control"),
            "probe",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "fixture path is not an exact FUSE mount" in result.stderr
    assert not (tmp_path / "sps-fuse-probe").exists()


def test_controller_manifest_must_include_actual_method_source(tmp_path: Path) -> None:
    source = tmp_path / "unrelated.py"
    source.write_text("# not the controller implementation\n")
    controller = Controller(source)
    controller.source_files = (source,)
    driver = TestDriver()
    result = FuseMountRunner(
        driver,
        {
            "fuse_mount_create": {},
            "fuse_mount_prerequisites": [],
            "fuse_mount_controller": controller,
            "fuse_mount_controller_digest": controller_digest((source,)),
        },
    ).run_test(scenario())
    assert result["reason"] == "fixture_source_missing"
    assert driver.calls == []


@pytest.mark.parametrize("invalid", [False, True])
def test_execution_binding_is_bounded_sanitized_report_material(
    tmp_path: Path, invalid: bool
) -> None:
    source = tmp_path / "controller.py"
    source.write_text("# source\n")
    controller = Controller(source)
    binding = {
        "account": "a" * 64,
        "copy": "b" * 64,
        "class": "default",
        "image_kind": "standard_source",
        "image_hash": "sha256:" + "c" * 64,
        "region": "observed-region",
        "credential_kind": "managed_binding",
        "credential_version": "1",
        "credential_fingerprint": "d" * 64,
    }
    if invalid:
        binding["credential_secret"] = "must-not-be-recorded"
    controller.execution_binding = binding
    result = FuseMountRunner(
        TestDriver(),
        {
            "fuse_mount_create": {},
            "fuse_mount_prerequisites": [
                "image:sha256:" + "c" * 64,
                "region:observed-region",
                "fuse_mount_account",
                "fuse_mount_egress:sha256:" + "e" * 64,
            ],
            "fuse_mount_controller": controller,
            "fuse_mount_controller_digest": controller_digest(controller.source_files),
        },
    ).run_test(scenario())
    assert result["result"] == ("differs" if invalid else "passed")
    assert "must-not-be-recorded" not in str(result)
    if not invalid:
        output = cast(Any, result["steps"])[0]["observations"]["stdout"]
        assert len(output) <= 1024
        assert json.loads(output)["execution_binding"] == binding


class DefaultDriver(TestDriver):
    def call(self, operation: str, target: object, inputs: Inputs) -> Observation:
        result = super().call(operation, target, inputs)
        if operation == "create":
            return {**result, "identity": "fixture-" + str(result["sandbox"])}
        return result


class DefaultController(Controller):
    def __init__(self, source: Path, *, wrong_guest: bool = False) -> None:
        super().__init__(source)
        self.wrong_guest = wrong_guest
        self.execution_binding = {
            "account": "a" * 64,
            "copy": "b" * 64,
            "route": "c" * 64,
            "class": "default",
            "image_kind": "standard_source",
            "image_hash": "sha256:" + "d" * 64,
            "region": "unknown",
            "credential_kind": "byok_version",
            "credential_version": "1",
            "placement_mode": "default",
            "native_plan_digest": "sha256:" + "e" * 64,
        }
        self.execution_observations: list[dict[str, object]] = []
        self.calibration_observations: list[dict[str, object]] = []

    def _observe(self, box: Mapping[str, Any]) -> None:
        assert self.execution_binding is not None
        self.execution_observations.append(
            {
                "guest_sha256": guest_identity_digest(
                    "wrong" if self.wrong_guest else box["identity"]
                ),
                "session_sha256": None,
                "binding_digest": binding_digest(self.execution_binding),
                "physical_region": "unknown",
            }
        )

    def mount(self, driver: Driver, box: Mapping[str, Any], path: str) -> None:
        super().mount(driver, box, path)
        self._observe(box)

    def resume(self, driver: Driver, box: Mapping[str, Any], path: str, checkpoint: object) -> None:
        super().resume(driver, box, path, checkpoint)
        self._observe(box)

    def calibrate(self, _driver: Driver, box: Mapping[str, Any]) -> Mapping[str, object]:
        assert self.execution_binding is not None
        self.calls.append("calibrate")
        record = {
            "guest_sha256": guest_identity_digest(box["identity"]),
            "binding_digest": binding_digest(self.execution_binding),
            "storage_identity_sha256": "sha256:" + "f" * 64,
            "storage_region": "aws-us-east-1",
            "metric": CALIBRATION_METRIC,
            "measured_at": "2026-01-01T00:00:00Z",
            "samples_ms": [1.0, 3.0, 2.0],
            "p50_ms": 2.0,
        }
        self.calibration_observations.append(record)
        return record


def default_fixtures(controller: DefaultController) -> dict[str, object]:
    return {
        "fuse_mount_create": {},
        "fuse_mount_prerequisites": [
            "image:sha256:" + "d" * 64,
            "placement:default",
            "native_plan:sha256:" + "e" * 64,
            "fuse_mount_account",
            "fuse_mount_egress:sha256:" + "b" * 64,
        ],
        "fuse_mount_controller": controller,
        "fuse_mount_controller_digest": controller_digest(controller.source_files),
    }


def default_scenario() -> Scenario:
    return next(
        test
        for test in read_suite(suite_path().with_name("coverage.yaml")).tests
        if test.id == "fuse_mount.default_placement"
    )


@pytest.mark.parametrize("failure", [None, "fence", "guest"])
def test_default_profile_requires_actual_guests_calibration_and_unchanged_fence(
    tmp_path: Path, failure: str | None
) -> None:
    source = tmp_path / "controller.py"
    source.write_text("# controlled implementation")
    controller = DefaultController(source, wrong_guest=failure == "guest")
    driver = DefaultDriver(fenced=failure != "fence")
    result = FuseMountRunner(driver, default_fixtures(controller)).run_test(default_scenario())
    assert result["result"] == ("passed" if failure is None else "differs"), result
    if failure is None:
        assert controller.calls.count("calibrate") == 2
        assert driver.calls.count("create") == 2
        assert default_scenario().proves == ()  # Diagnostics cannot grant volume admission.


@pytest.mark.parametrize(
    "create",
    [
        {"resources": {"region": "example:us"}},
        {"requirements": {"resources": {"located_in": "US"}}},
    ],
)
def test_default_profile_never_authorizes_caller_location_before_allocation(
    tmp_path: Path, create: dict[str, Any]
) -> None:
    source = tmp_path / "controller.py"
    source.write_text("# controlled implementation")
    controller = DefaultController(source)
    driver = DefaultDriver()
    fixture = default_fixtures(controller)
    fixture["fuse_mount_create"] = create
    result = FuseMountRunner(driver, fixture).run_test(default_scenario())
    assert result["reason"] == "fixture_default_location_selected"
    assert driver.calls == []
