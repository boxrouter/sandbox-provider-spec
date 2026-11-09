# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Native coverage resource bindings survive reconnect and creation failures."""

from __future__ import annotations

from types import SimpleNamespace
from typing import cast

import pytest
from daytona import CreateSecretParams, UpdateSecretParams
from daytona_api_client.exceptions import NotFoundException
from e2b.sandbox_sync.commands.command_handle import CommandHandle

from sandbox_provider_spec.drivers import daytona, e2b


def test_daytona_vault_readiness_failure_cleans_only_exact_reserved_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entries: dict[str, SimpleNamespace] = {"foreign": SimpleNamespace(id="foreign", name="foreign")}

    class Vault:
        def create(self, params: CreateSecretParams) -> None:
            entries["owned"] = SimpleNamespace(id="owned", name=params.name)
            assert params.hosts == ["receiver.fixture"]
            raise RuntimeError("create failed after allocating")

        def list(self, *, name: str, limit: int, cursor: str | None = None) -> SimpleNamespace:
            del limit, cursor
            # A substring search can return other secrets: cleanup must compare exactly.
            return SimpleNamespace(items=list(entries.values()), next_cursor=None)

        def delete(self, identity: str) -> None:
            del entries[identity]

        def get(self, identity: str) -> None:
            if identity not in entries:
                raise NotFoundException(status=404)

    monkeypatch.setattr(daytona, "Daytona", lambda config: SimpleNamespace(secret=Vault()))
    driver = daytona.DaytonaDriver("container", {})
    with pytest.raises(RuntimeError):
        driver.secret_create(None, {"value": "generated-fixture", "hosts": ["receiver.fixture"]})
    assert driver.release(driver.resources[0]) == {"kind": "secret", "result": "deleted"}
    assert set(entries) == {"foreign"}


def test_daytona_rotation_updates_the_existing_native_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, str | None]] = []

    class Vault:
        def update(self, identity: str, params: UpdateSecretParams) -> None:
            calls.append((identity, params.value))

    monkeypatch.setattr(daytona, "Daytona", lambda config: SimpleNamespace(secret=Vault()))
    driver = daytona.DaytonaDriver("container", {})
    owned = driver.own("secret", SimpleNamespace(id="existing"), lambda: {})
    driver.secret_rotate({"resource": owned}, {"value": "generated-fixture"})
    assert calls == [("existing", "generated-fixture")]


def test_e2b_terminal_reconnect_uses_pty_identity_and_preserves_cleanup_parent() -> None:
    calls: list[int] = []

    class PTY:
        def connect(self, identity: int, *, timeout: int) -> CommandHandle:
            assert timeout == 15
            calls.append(identity)
            return cast(CommandHandle, SimpleNamespace(pid=identity, disconnect=lambda: None))

    driver = e2b.E2BDriver()
    original = driver.own("terminal", SimpleNamespace(pid=134), lambda: {"result": "deleted"})
    parent = SimpleNamespace(pty=PTY())
    attached = driver.terminal_reattach({"resource": original, "sandbox": parent}, {})
    assert attached["sandbox"] is parent
    assert calls == [134]
    assert not original.released
    assert driver.resources[-1].kind == "observer"
    assert driver.release(driver.resources[-1]) == {"kind": "observer", "result": "deleted"}
    assert not original.released
