# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Container workload evidence checks the actual mode and exact owned cleanup."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from sandbox_provider_spec.coverage_docker import observe
from sandbox_provider_spec.driver import Driver, Inputs, Observation
from sandbox_provider_spec.runner import Runner
from sandbox_provider_spec.suite import Test as Scenario

DOCKER_WORKLOAD = Path(__file__).parents[1] / "conformance" / "fixtures" / "docker_workload.sh"


def run_docker_workload(tmp_path: Path, *, fail: str = "") -> subprocess.CompletedProcess[str]:
    docker = tmp_path / "docker"
    docker.write_text(
        "#!/bin/sh\n"
        'printf \'%s\\n\' "$*" >> "$DOCKER_CALLS"\n'
        'case "$1" in\n'
        "  info|pull) exit 0 ;;\n"
        '  run) [ "${DOCKER_FAIL:-}" != run ] ;;\n'
        "  inspect) printf '%s\\n' \"$DOCKER_MODE\" ;;\n"
        "  exec) exit 1 ;;\n"
        '  rm) [ "${DOCKER_FAIL:-}" != rm ] ;;\n'
        "  container) exit 0 ;;\n"
        "  *) exit 99 ;;\n"
        "esac\n"
    )
    docker.chmod(0o755)
    calls = tmp_path / "calls"
    env = os.environ | {
        "PATH": f"{tmp_path}{os.pathsep}{os.environ['PATH']}",
        "DOCKER_CALLS": str(calls),
        "DOCKER_MODE": "bridge",
        "DOCKER_FAIL": fail,
    }
    return subprocess.run(
        ["bash", str(DOCKER_WORKLOAD), "bridge", "python:3.11-alpine", "https://fixture.example/"],
        check=False,
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )


def test_docker_workload_uses_requested_network_mode_and_cleans_up(tmp_path: Path) -> None:
    result = run_docker_workload(tmp_path)

    assert result.returncode == 0
    calls = (tmp_path / "calls").read_text().splitlines()
    run = next(call for call in calls if call.startswith("run "))
    assert "--network bridge" in run
    assert "--publish 127.0.0.1:38741:38741" in run
    assert any(call.startswith("rm --force sps-") for call in calls)
    assert '"network_mode_matches":true' in result.stdout


def test_docker_workload_cleans_up_after_failed_startup(tmp_path: Path) -> None:
    result = run_docker_workload(tmp_path, fail="run")

    assert result.returncode == 0
    calls = (tmp_path / "calls").read_text().splitlines()
    assert any(call.startswith("rm --force sps-") for call in calls)
    assert '"network_mode_matches":false' in result.stdout


def test_docker_workload_fails_when_removal_is_not_confirmed(tmp_path: Path) -> None:
    result = run_docker_workload(tmp_path, fail="rm")

    assert result.returncode != 0
    assert "owned Docker container cleanup not confirmed" in result.stderr


def test_create_uses_the_provider_engine_without_installing_one() -> None:
    prepared = False

    class Native(Driver):
        def image_prepare(self, target: object, inputs: Inputs) -> Observation:
            del target, inputs
            nonlocal prepared
            prepared = True
            return {}

        def create(self, target: object, inputs: Inputs) -> Observation:
            del target
            assert "image" not in inputs
            assert "dockerfile" not in inputs
            assert inputs["user"] == "root"
            requirements = inputs["requirements"]
            assert isinstance(requirements, dict)
            assert requirements["docker"] == {"networking": "host"}
            raise RuntimeError("native creation observed")

    test = Scenario(
        "coverage.docker.host",
        "Docker",
        (
            {
                "op": "fixture.coverage_docker_create",
                "in": {"requirements": {"docker": {"networking": "host"}}},
            },
        ),
        (),
    )
    result = Runner(Native()).run_test(test)
    assert result["result"] == "error"
    assert prepared is False


def test_observe_starts_workload_without_sandbox_python(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, object]] = []

    class Native(Driver):
        def call(self, operation: str, target: object, inputs: Inputs) -> Observation:
            del target
            calls.append((operation, inputs))
            if operation == "files.write":
                return {}
            return {
                "exit_code": 0,
                "stdout": (
                    b'{"outbound":true,"published_reachable":true,"network_mode_matches":true}'
                ),
            }

    monkeypatch.setattr("sandbox_provider_spec.coverage_docker.healthy", lambda _urls: None)
    observe(
        Native(),
        object(),
        {
            "networking": "bridge",
            "outbound_url": "https://fixture.example/",
            "image": "python:3.11-alpine",
        },
    )
    run = next(inputs for operation, inputs in calls if operation == "run")
    assert isinstance(run, dict)
    assert run["bash_script"].startswith("bash /tmp/sps-docker-workload.sh bridge ")
    assert "python3 /tmp/" not in run["bash_script"]


def _observe_calls(monkeypatch: pytest.MonkeyPatch, driver: Driver) -> list[str]:
    calls: list[str] = []

    def call(operation: str, target: object, inputs: Inputs) -> Observation:
        del target, inputs
        calls.append(operation)
        if operation == "files.write":
            return {}
        return {
            "exit_code": 0,
            "stdout": (b'{"outbound":true,"published_reachable":true,"network_mode_matches":true}'),
        }

    driver.call = call  # type: ignore[method-assign]
    monkeypatch.setattr("sandbox_provider_spec.coverage_docker.healthy", lambda _urls: None)
    observe(
        driver,
        object(),
        {
            "networking": "bridge",
            "outbound_url": "https://fixture.example/",
            "image": "python:3.11-alpine",
        },
    )
    return calls


def test_observe_uses_run_as_root_when_the_driver_exposes_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Native(Driver):
        def run_as_root(self, target: object, inputs: Inputs) -> Observation:
            del target, inputs
            raise AssertionError("observe must dispatch through call")

    calls = _observe_calls(monkeypatch, Native())
    assert "run.as_root" in calls
    assert "run" not in calls


def test_observe_uses_run_when_as_root_is_unsupported(monkeypatch: pytest.MonkeyPatch) -> None:
    class Native(Driver):
        unsupported = {"run.as_root": "no per-command user selector"}

        def run_as_root(self, target: object, inputs: Inputs) -> Observation:
            del target, inputs
            raise AssertionError("unsupported as_root must not be selected")

    calls = _observe_calls(monkeypatch, Native())
    assert "run" in calls
    assert "run.as_root" not in calls
