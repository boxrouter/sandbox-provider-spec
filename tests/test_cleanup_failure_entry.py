# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""A failed cleanup says why in the report (code, outcome, retry hint) and names the resource on
stderr only: reports are committed and mirrored, so no id enters one."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import pytest

from sandbox_provider_spec.driver import NativeFailure
from sandbox_provider_spec.v1.errors import SpsError
from sandbox_provider_spec.v1.suite_driver import ProviderDriver, SandboxHandle


def _driver(error: Exception) -> ProviderDriver:
    async def destroy(sandbox_id: str) -> None:
        del sandbox_id
        raise error

    return ProviderDriver(cast(Any, SimpleNamespace(destroy=destroy)), provider_id="stub")


def _owned(driver: ProviderDriver) -> Any:
    return driver.own("sandbox", SandboxHandle("sbx-secret-id"), lambda: driver._destroy("x"))


def test_a_failed_destroy_names_its_code_outcome_and_retry_hint_but_no_id(
    capsys: pytest.CaptureFixture[str],
) -> None:
    driver = _driver(SpsError("provider_error", "boom", outcome="unknown", retry_after_seconds=4))
    entry = driver.release(_owned(driver))
    assert entry == {
        "kind": "sandbox",
        "result": "error",
        "reason": "NativeFailure",
        "code": "provider_error",
        "outcome": "unknown",
        "retry_after_seconds": 4,
    }
    assert "sbx-secret-id" not in str(entry) and "boom" not in str(entry)
    line = capsys.readouterr().err.strip()
    assert line == (
        "cleanup failed: kind=sandbox id=sbx-secret-id reason=NativeFailure"
        " code=provider_error outcome=unknown"
    )


def test_a_failure_with_no_retry_hint_leaves_the_field_out() -> None:
    driver = _driver(SpsError("conflict", "no", outcome="failed"))
    entry = driver.release(_owned(driver))
    assert entry["code"] == "conflict" and entry["outcome"] == "failed"
    assert "retry_after_seconds" not in entry


def test_a_step_that_releases_still_raises_the_failure() -> None:
    driver = _driver(SpsError("conflict", "no", outcome="failed"))
    owned = _owned(driver)
    with pytest.raises(NativeFailure) as caught:
        driver.release_or_raise(owned)
    assert caught.value.code == "conflict"
    assert not owned.released


def test_a_release_that_works_is_unchanged() -> None:
    async def destroy(sandbox_id: str) -> SimpleNamespace:
        return SimpleNamespace(sandbox_id=sandbox_id, state="destroyed")

    driver = ProviderDriver(cast(Any, SimpleNamespace(destroy=destroy)), provider_id="stub")
    assert driver.release(_owned(driver)) == {"kind": "sandbox", "result": "deleted"}
