# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""`ProviderDriver` runs `secret.create`: the hidden-secret tests no longer stop at
`driver_unimplemented`."""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any, ClassVar

import pytest

from sandbox_provider_spec.driver import resource
from sandbox_provider_spec.v1 import CreateRequest, CredentialField, Provider, Sandbox, from_json
from sandbox_provider_spec.v1.suite_driver import ProviderDriver
from sandbox_provider_spec.v1.types import SecretHeader

EXAMPLES = Path(__file__).resolve().parents[2] / "spec" / "provider-api-1.0-examples"
VALUE = "sps-generated-test-secret"


class Keeper(Provider, manifest=False):
    """Keeps the create requests it receives."""

    provider_id = "keeper"
    name = "Keeper"
    spec_version = "1.0"
    credential_fields: ClassVar[tuple[CredentialField, ...]] = (CredentialField("api_key"),)

    def __init__(self) -> None:
        super().__init__({"api_key": "k"})
        self.requests: list[CreateRequest] = []

    async def create(self, request: CreateRequest, *, idempotency_key: str) -> Sandbox:
        self.requests.append(request)
        box = from_json(Sandbox, json.loads((EXAMPLES / "Sandbox.json").read_text("utf-8")))
        return dataclasses.replace(box, id=f"box-{len(self.requests)}")

    async def destroy(self, sandbox_id: str) -> Any:
        return None

    discovery = get = list = run = files_read = files_write = process_start = process_output = (
        create
    )


@pytest.fixture(name="driver")
def driver_fixture() -> Iterator[ProviderDriver]:
    driver = ProviderDriver(Keeper(), run="run-1")
    yield driver
    driver.close()


def sent(driver: ProviderDriver) -> CreateRequest:
    return driver.api.requests[-1]  # type: ignore[attr-defined]


def test_a_secret_is_bound_by_the_create_that_names_it(driver: ProviderDriver) -> None:
    secret = driver.call("secret.create", None, {"value": VALUE})
    driver.call(
        "create",
        None,
        {"secret": secret, "requirements": {"hidden_secrets": {"inject_into": ["a.example"]}}},
    )
    request = sent(driver)
    (item,) = request.secrets
    assert (item.value, item.hosts, item.headers) == (VALUE, ("a.example",), ())
    assert request.env == {"SPS_SECRET_PLACEHOLDER": item.placeholder}
    assert VALUE not in item.placeholder
    assert VALUE not in repr(resource(secret).native) and VALUE not in repr(request)


def test_header_templates_come_from_the_request_else_the_secret(driver: ProviderDriver) -> None:
    template = [{"name": "Authorization", "prefix": "Bearer ", "suffix": "-sps"}]
    made = driver.call(
        "secret.create", None, {"value": VALUE, "hosts": ["a.example"], "headers": template}
    )
    driver.call("create", None, {"secret": made, "requirements": {"hidden_secrets": {}}})
    assert sent(driver).secrets[0].headers == (SecretHeader("Authorization", "Bearer ", "-sps"),)
    assert sent(driver).secrets[0].hosts == ("a.example",)
    asked = {"inject_into": ["b.example"], "headers": [{"name": "X-Key"}]}
    driver.call("create", None, {"secret": made, "requirements": {"hidden_secrets": asked}})
    assert sent(driver).secrets[0].headers == (SecretHeader("X-Key"),)
    assert sent(driver).secrets[0].hosts == ("b.example",)


def test_a_create_without_a_secret_sends_none_and_a_secret_needs_hosts(
    driver: ProviderDriver,
) -> None:
    driver.call("create", None, {})
    assert sent(driver).secrets == ()
    secret = driver.call("secret.create", None, {"value": VALUE})
    with pytest.raises(ValueError, match="hosts"):
        driver.call("create", None, {"secret": secret})


def test_the_secret_resource_releases_without_a_provider_call(driver: ProviderDriver) -> None:
    secret = driver.call("secret.create", None, {"value": VALUE})
    assert driver.release(resource(secret)) == {"kind": "secret", "result": "already_released"}
