# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Reserved-port proof needs successful forwarding controls and native refusal."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Mapping
from typing import cast

import pytest

from sandbox_provider_spec import coverage_ports as probe
from sandbox_provider_spec.driver import Driver, Inputs, NotRun, Observation, Unsupported


class PortDriver(Driver):
    def __init__(self, blocked: set[int], unavailable: set[int] | None = None) -> None:
        super().__init__()
        self.blocked = blocked
        self.unavailable = unavailable or set()
        self.created: list[int] = []

    def call(self, operation: str, target: object, inputs: Inputs) -> Observation:
        if operation == "create":
            requirements = cast(Mapping[str, Mapping[str, object]], inputs["requirements"])
            ports = cast(list[int], requirements["previews"]["ports"])
            assert len(ports) == 1
            port = ports[0]
            self.created.append(port)
            if port in self.unavailable:
                raise Unsupported("native_port_unavailable")
            return {"port": port}
        port = cast(Mapping[str, int], target)["port"]
        if operation == "run":
            return {"exit_code": 0, "stdout": json.dumps({"available": port not in self.blocked})}
        assert operation == "preview.link"
        return {"url": "https://fixture.invalid/", "port": port}


def helpers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(probe, "server", lambda *_: {})
    monkeypatch.setattr(probe, "preview", lambda _: True)


def test_each_port_gets_its_own_create_and_common_controls_run_first(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helpers(monkeypatch)
    driver = PortDriver({22})
    assert probe.observe(driver, {"reserved": [22], "common": [3000, 5173]}) == {
        "reserved_refused": True,
        "common_served": True,
    }
    assert driver.created == [3000, 5173, 22]


def test_reserved_port_that_serves_the_program_contradicts_the_list(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helpers(monkeypatch)
    assert probe.observe(PortDriver(set()), {"reserved": [22], "common": [3000]}) == {
        "reserved_refused": False,
        "common_served": True,
    }


def test_unavailable_common_control_cannot_prove_a_reserved_list(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helpers(monkeypatch)
    driver = PortDriver(set(), {3000, 22})
    with pytest.raises(Unsupported):
        probe.observe(driver, {"reserved": [22], "common": [3000]})
    assert driver.created == [3000]


def test_audited_native_refusal_after_positive_control_proves_reserved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helpers(monkeypatch)
    driver = PortDriver(set(), {22})
    assert probe.observe(driver, {"reserved": [22], "common": [3000]})["reserved_refused"]


@pytest.mark.parametrize("output", [b'{"matched":false}', b""])
def test_timeout_or_unrelated_response_is_not_reservation_proof(
    monkeypatch: pytest.MonkeyPatch, output: bytes
) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_, **__: subprocess.CompletedProcess([], 0 if output else 1, output, b"private"),
    )
    with pytest.raises(NotRun, match="reserved_port_forwarding_unobservable"):
        probe.preview({"url": "https://fixture.invalid/"})


def test_dns_is_inside_the_observer_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    def timeout(*_: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        assert kwargs["timeout"] == 12
        assert kwargs["capture_output"] is True
        raise subprocess.TimeoutExpired("private", 12)

    monkeypatch.setattr(subprocess, "run", timeout)
    with pytest.raises(NotRun, match="reserved_port_forwarding_unobservable"):
        probe.preview({"url": "https://fixture.invalid/"})


def test_reserved_port_is_never_also_required_as_a_common_control(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helpers(monkeypatch)
    driver = PortDriver({8080})
    assert probe.observe(driver, {"reserved": [8080], "common": [3000, 5173, 8000, 8080]}) == {
        "reserved_refused": True,
        "common_served": True,
    }
    assert driver.created == [3000, 5173, 8000, 8080]


def test_all_common_ports_reserved_establishes_no_positive_control() -> None:
    driver = PortDriver({8080})
    with pytest.raises(NotRun, match="reserved_port_common_control_missing"):
        probe.observe(driver, {"reserved": [8080], "common": [8080]})
    assert driver.created == []
