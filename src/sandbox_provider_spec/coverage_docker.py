# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Docker workloads against the engine the provider supplies for this gate."""

from __future__ import annotations

import base64
import json
import shlex
from collections.abc import Mapping
from typing import cast

from sandbox_provider_spec.coverage_network import healthy
from sandbox_provider_spec.driver import Driver, NativeFailure, NotRun
from sandbox_provider_spec.suite import suite_path


def create(driver: Driver, inputs: Mapping[str, object]) -> Mapping[str, object]:
    """Create a sandbox on the provider's engine.

    The driver selects a provider image or creation option from the docker requirement.
    This helper does not build an image or install Docker.
    """
    requirements = inputs.get("requirements")
    if not isinstance(requirements, Mapping) or not isinstance(requirements.get("docker"), Mapping):
        raise ValueError("invalid Docker fixture")
    return driver.call("create", None, {**inputs, "user": "root"})


def observe(driver: Driver, box: object, inputs: Mapping[str, object]) -> Mapping[str, object]:
    mode, url = inputs["networking"], inputs["outbound_url"]
    if mode not in {"bridge", "host"} or not isinstance(url, str):
        raise ValueError("invalid Docker fixture")
    healthy([url])
    script = (suite_path().parent / "fixtures/docker_workload.sh").read_bytes()
    path = "/tmp/sps-docker-workload.sh"
    driver.call("files.write", box, {"path": path, "data": base64.b64encode(script).decode()})
    # Prefer a native per-command root selector when the driver exposes one.
    # Otherwise the root user selected at create is used. The engine is the one
    # the provider already runs; this helper does not install or start one.
    operation = (
        "run.as_root"
        if "run.as_root" not in driver.unsupported
        and callable(getattr(driver, "run_as_root", None))
        else "run"
    )
    result = driver.call(
        operation,
        box,
        {
            "bash_script": "bash "
            + path
            + " "
            + " ".join(
                shlex.quote(str(inputs[key])) for key in ("networking", "image", "outbound_url")
            ),
            "timeout_ms": 360000,
        },
    )
    if result.get("exit_code") != 0:
        raise NativeFailure("docker_workload_failed")
    data = result.get("stdout")
    if not isinstance(data, (bytes, str)) or len(data) > 1024:
        raise NativeFailure("docker_workload_result_invalid")
    payload = json.loads(data)
    if payload.get("not_run") in {"docker_fixture_image_unavailable", "docker_fixture_cli_missing"}:
        raise NotRun(payload["not_run"])
    fields = {"outbound", "published_reachable", "network_mode_matches"}
    if set(payload) != fields or any(not isinstance(value, bool) for value in payload.values()):
        raise NativeFailure("docker_workload_result_invalid")
    healthy([url])
    return cast(Mapping[str, object], payload)
