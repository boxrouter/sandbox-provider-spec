# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Shared private-address operation defaults and Modal i6pn observation."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from sandbox_provider_spec.driver import Driver, NativeFailure, Resource, Unsupported
from sandbox_provider_spec.drivers import daytona as daytona_native
from sandbox_provider_spec.drivers import modal as modal_native


class _Output:
    def __init__(self, value: bytes) -> None:
        self.value = value

    def read(self) -> bytes:
        return self.value


class _Process:
    def __init__(self, stdout: bytes, exit_code: int = 0) -> None:
        self.stdout = _Output(stdout)
        self.exit_code = exit_code

    def wait(self) -> int:
        return self.exit_code


class _Sandbox:
    def __init__(self, result: _Process) -> None:
        self.result = result
        self.calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def exec(self, *args: object, **kwargs: object) -> _Process:
        self.calls.append((args, kwargs))
        return self.result


def _resource(value: object) -> dict[str, Resource]:
    return {"resource": Resource("sandbox", value, lambda: {"result": "deleted"})}


def test_driver_private_address_is_unsupported_by_default() -> None:
    with pytest.raises(Unsupported, match="provider SDK does not expose a private network address"):
        Driver().call("network.private_address", None, {})


def test_modal_private_address_reads_i6pn_ipv6_from_the_guest() -> None:
    sandbox = _Sandbox(_Process(b"fd00::10\n"))
    driver = modal_native.ModalDriver()

    result = driver.network_private_address(_resource(sandbox), {})

    assert result == {"address": "fd00::10", "ip_version": 6}
    assert len(sandbox.calls) == 1
    args, kwargs = sandbox.calls[0]
    assert args[:2] == ("python3", "-c")
    assert isinstance(args[2], str)
    assert "i6pn.modal.local" in args[2]
    assert kwargs == {"text": False, "timeout": 15}


def test_modal_private_address_rejects_ipv4_without_calling_the_sdk() -> None:
    sandbox = _Sandbox(_Process(b"fd00::10\n"))
    with pytest.raises(Unsupported, match="Modal i6pn private networking uses IPv6"):
        modal_native.ModalDriver().call(
            "network.private_address", _resource(sandbox), {"ip_version": "ipv4"}
        )
    assert sandbox.calls == []


def test_modal_private_address_refuses_non_ip_sdk_output() -> None:
    sandbox = _Sandbox(_Process(b"not-an-ip\n"))
    with pytest.raises(NativeFailure, match="private_address_response_invalid"):
        modal_native.ModalDriver().call("network.private_address", _resource(sandbox), {})


def test_modal_private_address_marks_guest_failures_without_sdk_details() -> None:
    sandbox = _Sandbox(_Process(b"private sandbox data", exit_code=1))
    with pytest.raises(NativeFailure, match="private_address_unavailable") as raised:
        modal_native.ModalDriver().call("network.private_address", _resource(sandbox), {})
    assert str(raised.value) == "private_address_unavailable"


def test_daytona_private_network_address_uses_sdk_id_as_dns_alias() -> None:
    driver = daytona_native.DaytonaDriver.__new__(daytona_native.DaytonaDriver)
    sandbox = SimpleNamespace(id="sandbox-v6b-id")

    result = driver.network_private_address(_resource(sandbox), {})

    assert result == {"address": "sandbox-v6b-id", "ip_version": None}


def test_daytona_private_network_address_rejects_ipv6() -> None:
    driver = daytona_native.DaytonaDriver.__new__(daytona_native.DaytonaDriver)
    sandbox = SimpleNamespace(id="sandbox-v6b-id")

    with pytest.raises(Unsupported, match="Daytona linked sandboxes have no IPv6 selector"):
        driver.call("network.private_address", _resource(sandbox), {"ip_version": "ipv6"})
