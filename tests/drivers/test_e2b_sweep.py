# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The stale sweeper deletes only a run's own resources older than the TTL."""

from __future__ import annotations

import time
from collections.abc import Sequence
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from e2b import Sandbox, Secret, SecretException, Volume

from sandbox_provider_spec import run_id
from sandbox_provider_spec.drivers import e2b as native


class Pages:
    def __init__(self, items: Sequence[object]) -> None:
        self.items, self.has_next = list(items), True

    def next_items(self) -> list[object]:
        self.has_next = False
        return self.items


def test_only_old_run_labelled_resources_are_swept(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(run_id, "_RUN", "crashed")
    now = time.time()
    with monkeypatch.context() as past:
        past.setattr(time, "time", lambda: now - 10_000)
        old = run_id.native_name()
    monkeypatch.setattr(run_id, "_RUN", "live")
    recent = run_id.native_name()
    started = datetime.fromtimestamp(time.time() - 10_000, UTC)
    sandboxes = [
        SimpleNamespace(
            sandbox_id="old-run", metadata={"sps.run_id": "crashed"}, started_at=started
        ),
        SimpleNamespace(
            sandbox_id="young-run",
            metadata={"sps.run_id": "live"},
            started_at=datetime.fromtimestamp(time.time(), UTC),
        ),
        SimpleNamespace(sandbox_id="other-tool", metadata={"owner": "x"}, started_at=started),
        SimpleNamespace(sandbox_id="unlabelled", metadata={}, started_at=started),
    ]
    killed: list[str] = []
    destroyed: list[str] = []
    monkeypatch.setattr(Sandbox, "list", lambda **_: Pages(sandboxes))
    monkeypatch.setattr(Sandbox, "kill", lambda **values: killed.append(values["sandbox_id"]))
    volumes = [
        SimpleNamespace(name=old),
        SimpleNamespace(name=recent),
        SimpleNamespace(name="mine"),
    ]
    monkeypatch.setattr(Volume, "list", lambda **_: volumes)

    def delete_named_volume(name: str) -> dict[str, str]:
        destroyed.append(name)
        return {"result": "deleted"}

    monkeypatch.setattr(native.E2BDriver, "_delete_named_volume", staticmethod(delete_named_volume))
    refused = SecretException("403: Secrets are not available for this team")

    def no_secrets(**_: object) -> None:
        raise refused

    monkeypatch.setattr(Secret, "list", no_secrets)
    monkeypatch.setattr(Sandbox, "list_snapshots", lambda **_: Pages([]))
    swept = native.E2BDriver().sweep_stale(7200)
    assert killed == ["old-run"]
    assert destroyed == [old]
    assert swept[0] == "sandbox:old-run"
