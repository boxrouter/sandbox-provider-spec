# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""`cost.capture` and `account.capacity`: the types, the wire form, the OpenAPI file, the reference
server and `HttpProvider`, end to end (contract section 10)."""

from __future__ import annotations

import asyncio
import dataclasses
import json
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any, ClassVar

import httpx
import pytest
import yaml
from jsonschema import Draft202012Validator

from sandbox_provider_spec.v1 import (
    AccountCapacity,
    Concurrency,
    Cost,
    CredentialField,
    Prepaid,
    Provider,
    SpsError,
    StartWindow,
    WireError,
    from_json,
    to_json,
)
from sandbox_provider_spec.v1 import types as v1_types
from sandbox_provider_spec.v1.http_client import HttpProvider
from sandbox_provider_spec.v1.server import create_app
from sandbox_provider_spec.v1.tester import TestOptions, select_tests, shared_suite

SPEC = Path(__file__).resolve().parents[2] / "spec"
EXAMPLES = SPEC / "provider-api-1.0-examples"
OPENAPI = yaml.safe_load((SPEC / "provider-api-1.0.openapi.yaml").read_text(encoding="utf-8"))
IDEM = "capture-key-1"
BASE = "https://sps.test"
AUTH = {"Authorization": "Bearer t-0123456789"}


def example(name: str) -> Any:
    return json.loads((EXAMPLES / f"{name}.json").read_text(encoding="utf-8"))


class Plain(Provider, manifest=False):
    """Implements only the required operations, so both new ones keep their default."""

    provider_id = "plain"
    name = "Plain"
    spec_version = "1.0"
    credential_fields: ClassVar[tuple[CredentialField, ...]] = (CredentialField("api_key"),)

    async def discovery(self) -> Any:
        raise NotImplementedError

    create = get = list = destroy = run = files_read = files_write = discovery  # type: ignore[assignment]
    process_start = process_output = discovery  # type: ignore[assignment]


class Capturing(Plain, manifest=False):
    """Fixes a figure on the first capture and returns it again after that."""

    provider_id = "capturing"
    captured: ClassVar[dict[str, Cost]] = {}
    seen: ClassVar[list[tuple[str, ...]]] = []

    async def cost_capture(self, sandbox_id: str, *, idempotency_key: str) -> Cost:
        type(self).seen.append(("cost_capture", sandbox_id, idempotency_key))
        if sandbox_id == "sbx-gone":
            raise SpsError("not_found", "No such sandbox")
        if sandbox_id == "sbx-busy":
            raise SpsError("conflict", "The sandbox is being destroyed")
        return type(self).captured.setdefault(sandbox_id, from_json(Cost, example("Cost")))

    async def account_capacity(self) -> AccountCapacity:
        type(self).seen.append(("account_capacity",))
        return from_json(AccountCapacity, example("AccountCapacity"))


@pytest.fixture(autouse=True)
def reset() -> None:
    Capturing.captured, Capturing.seen = {}, []


async def _awaited(pending: Awaitable[Any]) -> Any:
    return await pending


def served(
    run: Callable[[HttpProvider], Awaitable[Any]], provider: type[Provider] = Capturing
) -> Any:
    """Run `run` with an `HttpProvider` that talks to the reference server, in this process."""

    async def main() -> Any:
        transport = httpx.ASGITransport(app=create_app(provider))
        client = HttpProvider(BASE, "token-0123456789", transport=transport)
        try:
            return await run(client)
        finally:
            await client.aclose()

    return asyncio.run(main())


# --- the OpenAPI file and the examples --------------------------------------------------------


def test_both_operations_are_in_the_openapi_file() -> None:
    capture = OPENAPI["paths"]["/v1/sandboxes/{sandbox_id}/cost/capture"]["post"]
    assert capture["operationId"] == "cost_capture"
    assert {"$ref": "#/components/parameters/IdempotencyKey"} in capture["parameters"]
    assert set(capture["responses"]) >= {"200", "404", "409", "422"}
    capacity = OPENAPI["paths"]["/v1/account/capacity"]["get"]
    assert capacity["operationId"] == "account_capacity"
    assert "parameters" not in capacity
    assert hasattr(Provider, "cost_capture")
    assert hasattr(Provider, "account_capacity")


def test_the_operations_list_takes_the_two_alone_and_the_directory_four_together() -> None:
    schema = OPENAPI["components"]["schemas"]["SandboxClass"]["properties"]["operations"]
    validator = Draft202012Validator(schema)
    four = ["files.list", "files.mkdir", "files.remove", "files.exists"]
    for allowed in (
        [],
        ["cost.capture"],
        ["account.capacity"],
        ["cost.capture", "account.capacity"],
    ):
        assert validator.is_valid(allowed), allowed
    assert validator.is_valid(four + ["cost.capture", "account.capacity"])
    for refused in (four[:3], ["cost.capture"] + four[:1], ["cost.capture", "cost.capture"], ["x"]):
        assert not validator.is_valid(refused), refused


def test_a_class_may_list_cost_capture_and_account_capacity() -> None:
    data = example("SandboxClass")
    for listed in (["cost.capture"], ["account.capacity"], ["cost.capture", "account.capacity"]):
        value = from_json(v1_types.SandboxClass, {**data, "operations": listed})
        assert tuple(value.operations) == tuple(listed)
        assert to_json(value)["operations"] == listed
    with pytest.raises(WireError):
        from_json(v1_types.SandboxClass, {**data, "operations": ["files.list", "cost.capture"]})


# --- the wire form ----------------------------------------------------------------------------


def test_the_capacity_example_round_trips_into_typed_values() -> None:
    value = from_json(AccountCapacity, example("AccountCapacity"))
    assert value.as_of == datetime(2026, 11, 20, 9, 0, tzinfo=UTC)
    assert value.starts == (StartWindow(3600, 12, 100, 88), StartWindow(86400, 140, 1000, 860))
    assert (value.can_start, value.paid_overage_enabled) == (True, False)
    assert value.concurrency == Concurrency(active=3, limit=20)
    assert value.prepaid == Prepaid(Decimal("42.50"), past_due=False)
    assert to_json(value) == example("AccountCapacity")


def test_a_null_capacity_field_means_unknown_and_stays_null() -> None:
    unknown = {
        "as_of": "2026-11-20T09:00:00Z",
        "starts": [],
        "can_start": None,
        "paid_overage_enabled": None,
        "concurrency": None,
        "prepaid": None,
    }
    value = from_json(AccountCapacity, unknown)
    assert (value.starts, value.can_start, value.concurrency, value.prepaid) == (
        (),
        None,
        None,
        None,
    )
    assert to_json(value) == unknown


@pytest.mark.parametrize(
    "broken",
    [
        {"starts": [{"window_seconds": 0, "used": 0, "limit": 1, "remaining": 1}]},
        {"starts": [{"window_seconds": 60, "used": -1, "limit": 1, "remaining": 1}]},
        {"starts": [{"window_seconds": 60, "used": 0, "limit": 1}]},
        {"concurrency": {"active": 1}},
        {"prepaid": {"balance_usd": 4.5, "past_due": False}},
        {"prepaid": {"balance_usd": "4.5"}},
        {"can_start": "yes"},
        {"unknown_field": 1},
    ],
)
def test_a_malformed_capacity_is_refused(broken: dict[str, Any]) -> None:
    with pytest.raises(WireError):
        from_json(AccountCapacity, {**example("AccountCapacity"), **broken})


def test_every_capacity_field_is_required() -> None:
    for name in example("AccountCapacity"):
        data = {key: item for key, item in example("AccountCapacity").items() if key != name}
        with pytest.raises(WireError):
            from_json(AccountCapacity, data)


# --- the defaults -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("operation", "call"),
    [
        ("cost.capture", lambda p: p.cost_capture("sbx-1", idempotency_key=IDEM)),
        ("account.capacity", lambda p: p.account_capacity()),
    ],
)
def test_a_provider_that_does_not_override_them_answers_unsupported(
    operation: str, call: Callable[[Plain], Awaitable[Any]]
) -> None:
    with pytest.raises(SpsError) as raised:
        asyncio.run(_awaited(call(Plain({"api_key": "k"}))))
    assert raised.value.code == "unsupported"
    assert operation in str(raised.value)


# --- the server and the client, end to end ----------------------------------------------------


def test_capture_sends_the_key_and_returns_the_cost() -> None:
    cost = served(lambda p: p.cost_capture("sbx-17", idempotency_key=IDEM))
    assert cost == from_json(Cost, example("Cost"))
    assert Capturing.seen == [("cost_capture", "sbx-17", IDEM)]


def test_a_repeated_capture_returns_the_same_figures() -> None:
    async def twice(p: HttpProvider) -> tuple[Cost, Cost]:
        first = await p.cost_capture("sbx-17", idempotency_key=IDEM)
        return first, await p.cost_capture("sbx-17", idempotency_key="capture-key-2")

    first, second = served(twice)
    assert first == second


@pytest.mark.parametrize(
    ("sandbox_id", "code"), [("sbx-gone", "not_found"), ("sbx-busy", "conflict")]
)
def test_capture_errors_keep_their_code(sandbox_id: str, code: str) -> None:
    with pytest.raises(SpsError) as raised:
        served(lambda p: p.cost_capture(sandbox_id, idempotency_key=IDEM))
    assert raised.value.code == code


def test_capture_refuses_a_missing_or_malformed_key() -> None:
    with pytest.raises(SpsError) as raised:
        served(lambda p: p.cost_capture("sbx-17", idempotency_key="Bad Key"))
    assert raised.value.code == "invalid_request"

    async def without_key() -> httpx.Response:
        transport = httpx.ASGITransport(app=create_app(Capturing))
        async with httpx.AsyncClient(transport=transport, base_url=BASE, headers=AUTH) as client:
            return await client.post("/v1/sandboxes/sbx-17/cost/capture")

    reply = asyncio.run(without_key())
    assert reply.status_code == 400
    assert Capturing.seen == []  # neither the client nor the server let it through


def test_capacity_returns_typed_values_over_http() -> None:
    value = served(lambda p: p.account_capacity())
    assert value == from_json(AccountCapacity, example("AccountCapacity"))
    assert Capturing.seen == [("account_capacity",)]


def test_a_provider_without_the_operations_answers_unsupported_over_http() -> None:
    async def both(client: HttpProvider) -> list[str]:
        codes: list[str] = []
        for call in (
            lambda: client.cost_capture("sbx-17", idempotency_key=IDEM),
            client.account_capacity,
        ):
            with pytest.raises(SpsError) as raised:
                await call()
            codes.append(raised.value.code)
        return codes

    assert served(both, Plain) == ["unsupported", "unsupported"]


def test_capacity_takes_no_query_and_each_route_has_one_method() -> None:
    async def probe() -> tuple[int, int, int]:
        transport = httpx.ASGITransport(app=create_app(Capturing))
        async with httpx.AsyncClient(transport=transport, base_url=BASE, headers=AUTH) as c:
            query = await c.get("/v1/account/capacity", params={"x": "1"})
            wrong = await c.get("/v1/sandboxes/sbx-17/cost/capture")
            post = await c.post("/v1/account/capacity")
            return query.status_code, wrong.status_code, post.status_code

    assert asyncio.run(probe()) == (400, 404, 404)


# --- the tester -------------------------------------------------------------------------------


def test_a_run_leaves_out_the_after_the_end_cost_read_for_a_capture_class() -> None:
    discovery = from_json(v1_types.Discovery, example("Discovery"))
    plain = {t.id for t in select_tests(shared_suite(), discovery, TestOptions()).tests}
    assert "contract.cost_final" in plain
    capturing = tuple(
        dataclasses.replace(item, operations=(*item.operations, "cost.capture"))
        for item in discovery.classes
    )
    listed = dataclasses.replace(discovery, classes=capturing)
    chosen = {t.id for t in select_tests(shared_suite(), listed, TestOptions()).tests}
    assert "contract.cost_final" not in chosen
    assert chosen == plain - {"contract.cost_final"}
    # An explicit selection is the caller's word and is kept.
    named = select_tests(shared_suite(), listed, TestOptions(tests=("contract.cost_final",)))
    assert [t.id for t in named.tests] == ["contract.cost_final"]
