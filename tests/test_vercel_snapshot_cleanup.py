# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The conformance report must fail when Vercel cleanup leaves a snapshot."""

from __future__ import annotations

import httpx2
import pytest
from vercel.sandbox.sync import SandboxApiError

from sandbox_provider_spec.drivers import vercel as vercel_driver
from sandbox_provider_spec.report import report
from sandbox_provider_spec.runner import Runner, now
from sandbox_provider_spec.suite import Suite
from sandbox_provider_spec.suite import Test as Scenario


def test_a_remaining_vercel_snapshot_makes_the_conformance_report_unclean(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Snapshot:
        id = "snapshot-example"
        status = "created"
        creation_method = "automatic"

        def delete(self) -> None:
            return None

    class Sandbox:
        def destroy(self, *, delete_orphan_snapshots: bool) -> None:
            assert delete_orphan_snapshots

    request = httpx2.Request("GET", "https://api.vercel.com/")
    missing = SandboxApiError(httpx2.Response(404, request=request), "not found")
    existing: set[str] = set()

    def create_sandbox(*, name: str, **options: object) -> Sandbox:
        del options
        existing.add(name)
        return Sandbox()

    def get_sandbox(*, name: str) -> Sandbox:
        if name not in existing:
            raise missing
        existing.remove(name)
        return Sandbox()

    monkeypatch.setattr(vercel_driver, "create_sandbox", create_sandbox)
    monkeypatch.setattr(vercel_driver, "query_snapshots", lambda *, name: iter([Snapshot()]))
    monkeypatch.setattr(vercel_driver, "get_sandbox", get_sandbox)
    monkeypatch.setattr(vercel_driver, "get_snapshot", lambda *, snapshot_id: Snapshot())
    monotonic_values = iter(float(value) for value in range(0, 10_000, 61))
    monkeypatch.setattr(
        "sandbox_provider_spec.driver.time.monotonic", lambda: next(monotonic_values)
    )

    driver = vercel_driver.VercelDriver()
    scenario = Scenario("snapshot.cleanup", "", ({"op": "create", "as": "box"},), (), ())
    results = Runner(driver).run(Suite("digest", (scenario,), ()))
    document = report(
        driver,
        Suite("digest", (scenario,), ()),
        results,
        spec_revision="revision",
        started_at=now(),
    )

    assert results[0]["cleanup"] == [
        {"kind": "sandbox", "result": "error", "reason": "NativeFailure"}
    ]
    assert document["clean"] is False
