# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Opt-in remote FUSE lifecycle conformance; the ordinary runner stays unchanged.

The controller is a host-side test fixture, not a provider driver. Its source manifest is
hashed, pinned by the runner input and recorded without paths or credentials in the report.
"""

from __future__ import annotations

import base64
import hashlib
import inspect
import json
import re
import shlex
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, Protocol, cast
from uuid import uuid4

from sandbox_provider_spec.driver import Differs, Driver, NativeFailure, NotRun
from sandbox_provider_spec.fuse_mount_identity import (
    BINDING_FIELDS,
    DEFAULT_PROOF_PROFILE,
    binding_digest,
    checkpoint_calibration_script,
    default_proof_errors,
    guest_identity_digest,
    native_plan_digest,
)
from sandbox_provider_spec.runner import Runner
from sandbox_provider_spec.suite import suite_path

__all__ = [
    "FuseMountRunner",
    "MountController",
    "controller_digest",
    "observe",
    "binding_digest",
    "checkpoint_calibration_script",
    "guest_identity_digest",
    "native_plan_digest",
]


class MountController(Protocol):
    """Host fixture owns its remote storage and credentials, and only those resources.

    ``mount`` prepares default-user access using native root commands. ``checkpoint``
    synchronizes and saves. ``fence`` invalidates an active writer without a successor.
    ``release`` revokes credentials; ``resume`` mounts the saved checkpoint with fresh
    credentials. ``cleanup`` must prove removal of every resource the fixture allocated.
    """

    source_files: tuple[Path, ...]

    def mount(self, driver: Driver, box: object, path: str) -> None: ...
    def checkpoint(self, driver: Driver, box: object) -> object: ...
    def fence(self, driver: Driver, box: object) -> None: ...
    def release(self, driver: Driver, box: object) -> None: ...
    def resume(self, driver: Driver, box: object, path: str, checkpoint: object) -> None: ...
    def cleanup(self) -> Mapping[str, object]: ...


def controller_digest(paths: tuple[Path, ...]) -> str:
    """Ordered complete implementation manifest; filenames are never report material."""
    if not paths or any(not path.is_file() for path in paths):
        raise NotRun("fixture_source_missing")
    digest = hashlib.sha256()
    for path in paths:
        content = path.read_bytes()
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return "sha256:" + digest.hexdigest()


def _observation(driver: Driver, box: object, script: str) -> Mapping[str, Any]:
    result = driver.call("run", box, {"bash_script": script, "timeout_ms": 30000})
    if result.get("exit_code") != 0:
        raise Differs("fuse_mount_guest_observation")
    try:
        parsed = json.loads(cast(str | bytes, result["stdout"]))
    except (KeyError, TypeError, ValueError):
        raise NativeFailure("fuse_mount_observation_invalid") from None
    if not isinstance(parsed, dict) or parsed.get("verified") is not True:
        raise Differs("fuse_mount_guest_observation")
    return parsed


def _actual_guest_digest(box: object) -> str:
    identity = box.get("identity") if isinstance(box, Mapping) else None
    if not isinstance(identity, str) or not identity:
        raise Differs("fuse_mount_actual_guest_identity_missing")
    return guest_identity_digest(identity)


def observe(
    driver: Driver, inputs: Mapping[str, Any], fixtures: Mapping[str, object]
) -> Mapping[str, object]:
    """Exercise mount/edit/save/fence/release/resume; absence allocates nothing."""
    supplied = fixtures.get("fuse_mount_controller")
    methods = ("mount", "checkpoint", "fence", "release", "resume", "cleanup")
    if supplied is None or any(not callable(getattr(supplied, name, None)) for name in methods):
        raise NotRun("fixture_missing")
    controller = cast(MountController, supplied)
    default = inputs.get("placement_mode") == "default"
    calibrate_method = getattr(controller, "calibrate", None)
    if default and not callable(calibrate_method):
        raise NotRun("fixture_default_calibration_missing")
    calibrate = cast(Callable[[Driver, object], Mapping[str, object]], calibrate_method)
    paths = getattr(controller, "source_files", ())
    if not isinstance(paths, tuple) or not all(isinstance(path, Path) for path in paths):
        raise NotRun("fixture_source_missing")
    implementations = {inspect.getsourcefile(getattr(controller, name)) for name in methods}
    if default:
        implementations.add(inspect.getsourcefile(calibrate))
    if None in implementations or not {
        Path(path).resolve() for path in implementations if path is not None
    } <= {path.resolve() for path in paths}:
        raise NotRun("fixture_source_missing")
    digest = controller_digest(paths)
    if digest != fixtures.get("fuse_mount_controller_digest"):
        raise NotRun("fixture_source_mismatch")
    create = inputs.get("create")
    if not isinstance(create, Mapping):
        raise NotRun("fixture_missing")
    requirements = create.get("requirements")
    required = requirements if isinstance(requirements, Mapping) else {}
    if default and any(
        isinstance(values, Mapping)
        and any(name in values for name in ("region", "regions", "located_in"))
        for values in (create, create.get("resources"), required, required.get("resources"))
    ):
        raise NotRun("fixture_default_location_selected")
    # Validate the complete fixture before the first allocation.
    # pylint: disable=too-many-boolean-expressions
    prerequisites = inputs.get("prerequisites")
    if (
        not isinstance(prerequisites, list)
        or not all(isinstance(value, str) for value in prerequisites)
        or len(set(prerequisites)) != len(prerequisites)
        or "fuse_mount_account" not in prerequisites
        or sum(bool(re.fullmatch(r"image:sha256:[a-f0-9]{64}", value)) for value in prerequisites)
        != 1
        or (
            sum(value.startswith("region:") and len(value) > 7 for value in prerequisites)
            != (0 if default else 1)
        )
        or (
            default
            and (
                prerequisites.count("placement:default") != 1
                or sum(
                    bool(re.fullmatch(r"native_plan:sha256:[a-f0-9]{64}", value))
                    for value in prerequisites
                )
                != 1
            )
        )
        or (
            not default
            and any(value.startswith(("placement:", "native_plan:")) for value in prerequisites)
        )
        or sum(
            bool(re.fullmatch(r"fuse_mount_egress:sha256:[a-f0-9]{64}", value))
            for value in prerequisites
        )
        != 1
        or any(value.startswith("controller:") for value in prerequisites)
    ):
        raise NotRun("fixture_prerequisites_missing")
    prerequisites = sorted([*prerequisites, f"controller:{digest}"])
    # Register cleanup before even a possibly uncertain controller mutation.
    driver.own("fuse_mount_fixture", controller, controller.cleanup)
    nonce = uuid4().hex
    mount = "/tmp/sps-fuse-" + nonce
    control = "/tmp/sps-fuse-control-" + nonce
    source = (suite_path().parent / "fixtures/fuse_mount.py").read_text()

    def command(phase: str) -> str:
        return (
            "python3 -c " + shlex.quote(source) + " " + shlex.join([phase, mount, control, nonce])
        )

    box = driver.call("create", None, create)
    actual_guests = {_actual_guest_digest(box)} if default else set()
    root = driver.call("run.as_root", box, {"bash_script": "id -u", "timeout_ms": 10000})
    if root.get("exit_code") != 0 or root.get("stdout") not in ("0\n", b"0\n"):
        raise Differs("fuse_mount_root_command")
    controller.mount(driver, box, mount)
    calibrations = [calibrate(driver, box)] if default else []
    _observation(driver, box, command("write"))
    _observation(driver, box, command("edit"))
    checkpoint = controller.checkpoint(driver, box)
    writer = driver.call(
        "process.start", box, {"bash_script": command("hold"), "timeout_ms": 90000}
    )
    deadline = time.monotonic() + 20
    while True:
        ready = driver.call(
            "run", box, {"bash_script": "cat " + shlex.quote(control), "timeout_ms": 1000}
        )
        if ready.get("exit_code") == 0 and ready.get("stdout") in ("ready", b"ready"):
            break
        if time.monotonic() >= deadline:
            raise Differs("fuse_mount_writer_not_ready")
        time.sleep(0.05)
    controller.fence(driver, box)
    driver.call(
        "files.write",
        box,
        {"path": control, "data": base64.b64encode(b"fence-complete").decode("ascii")},
    )
    stopped = driver.call("process.wait", writer, {"timeout_ms": 30000})
    if stopped.get("exit_code") != 0:
        raise Differs("fuse_mount_writer_observation")
    output = driver.call("process.output", writer, {})
    try:
        observation = json.loads(cast(str | bytes, output["stdout"]))
    except (KeyError, TypeError, ValueError):
        raise Differs("fuse_mount_writer_observation") from None
    if not isinstance(observation, dict) or observation.get("fenced") is not True:
        raise Differs("fuse_mount_stale_writer")
    # Observe the old descriptor before release or any successor can fence it for us.
    controller.release(driver, box)
    successor = driver.call("create", None, create)
    if default:
        guest = _actual_guest_digest(successor)
        if guest in actual_guests:
            raise Differs("fuse_mount_actual_guest_identity_repeated")
        actual_guests.add(guest)
    controller.resume(driver, successor, mount, checkpoint)
    if default:
        calibrations.append(calibrate(driver, successor))
    _observation(driver, successor, command("resume"))
    _observation(driver, successor, command("verify"))
    controller.release(driver, successor)
    if controller_digest(paths) != digest:
        raise Differs("fuse_mount_controller_changed")
    provenance: dict[str, object] = {
        "controller_source_digest": digest,
        "prerequisites": prerequisites,
    }
    binding = getattr(controller, "execution_binding", None)
    if binding is not None:
        fields = BINDING_FIELDS
        if not isinstance(binding, Mapping) or any(
            key not in fields or not isinstance(value, str) for key, value in binding.items()
        ):
            raise Differs("fuse_mount_execution_binding_invalid")
        provenance["execution_binding"] = dict(binding)
    if default:
        provenance.update(
            proof_profile=DEFAULT_PROOF_PROFILE,
            execution_observations=getattr(controller, "execution_observations", None),
            calibration_observations=getattr(controller, "calibration_observations", None),
        )
        if default_proof_errors(provenance):
            raise Differs("fuse_mount_default_proof_invalid")
        if provenance["calibration_observations"] != calibrations:
            raise Differs("fuse_mount_calibration_observation_changed")
        observations = cast(list[Mapping[str, str]], provenance["execution_observations"])
        observed = {item["guest_sha256"] for item in observations}
        if actual_guests != observed:
            raise Differs("fuse_mount_actual_guest_identity_mismatch")
        default_binding = cast(Mapping[str, str], binding)
        if "native_plan:" + default_binding["native_plan_digest"] not in prerequisites:
            raise Differs("fuse_mount_native_plan_changed")
    if default:
        return {"verified": True, "fuse_mount_default": provenance}
    return {
        "verified": True,
        "stdout": json.dumps(provenance, separators=(",", ":")),
    }


class FuseMountRunner(Runner):
    """Explicit feature harness; no hidden change to ordinary conformance dispatch."""

    def _test_operation(
        self, operation: str, target: object, inputs: Mapping[str, Any]
    ) -> Mapping[str, object]:
        if operation == "fixture.fuse_mount":
            return observe(self.driver, inputs, self.fixtures)
        return super()._test_operation(operation, target, inputs)
