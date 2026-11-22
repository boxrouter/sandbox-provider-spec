# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The tester sends a key as a host would: its first use is a vouched first send, a repeat has no
hint, so a provider that reads `v1.idempotency` is tested on both of its paths."""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any, ClassVar, cast

import pytest

from sandbox_provider_spec.v1 import CreateRequest, CredentialField, Provider, Sandbox, from_json
from sandbox_provider_spec.v1.idempotency import first_send, resend
from sandbox_provider_spec.v1.suite_driver import ProviderDriver

EXAMPLES = Path(__file__).resolve().parents[2] / "spec" / "provider-api-1.0-examples"


class Recorder(Provider, manifest=False):
    """Records, per create, the key and what `v1.idempotency` said about it."""

    provider_id = "recorder"
    name = "Recorder"
    spec_version = "1.0"
    credential_fields: ClassVar[tuple[CredentialField, ...]] = (CredentialField("api_key"),)

    def __init__(self) -> None:
        super().__init__({"api_key": "k"})
        self.seen: list[tuple[str, bool, bool]] = []

    async def create(self, request: CreateRequest, *, idempotency_key: str) -> Sandbox:
        del request
        self.seen.append((idempotency_key, first_send(idempotency_key), resend(idempotency_key)))
        box = from_json(Sandbox, json.loads((EXAMPLES / "Sandbox.json").read_text("utf-8")))
        return dataclasses.replace(box, id=f"box-{len(self.seen)}")

    async def destroy(self, sandbox_id: str) -> Any:
        return None

    discovery = get = list = run = files_read = files_write = process_start = process_output = cast(
        Any, create
    )


@pytest.fixture(name="driver")
def driver_fixture() -> Iterator[ProviderDriver]:
    driver = ProviderDriver(Recorder(), run="run-1")
    yield driver
    driver.close()


def seen(driver: ProviderDriver) -> list[tuple[str, bool, bool]]:
    return cast(Recorder, driver.api).seen


def test_a_fresh_key_is_a_first_send(driver: ProviderDriver) -> None:
    driver.call("create", None, {})
    driver.call("create", None, {})
    (key_a, first_a, _), (key_b, first_b, _) = seen(driver)
    assert key_a != key_b
    assert first_a and first_b


def test_a_named_key_is_a_first_send_once_then_a_repeat_without_a_hint(
    driver: ProviderDriver,
) -> None:
    driver.call("create", None, {"idempotency_key": "same-body"})
    driver.call("create", None, {"idempotency_key": "same-body"})
    (key_a, first_a, resend_a), (key_b, first_b, resend_b) = seen(driver)
    assert key_a == key_b
    assert (first_a, resend_a) == (True, False)
    assert (first_b, resend_b) == (False, False)
