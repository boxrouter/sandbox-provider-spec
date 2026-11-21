# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Secrets on create, `Sandbox.times`, `account.cost` and the `created_at` hint on `cost`."""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar, get_args

import httpx
import pytest
import yaml

from sandbox_provider_spec.v1 import (
    AccountCost,
    Cost,
    CreateRequest,
    CredentialField,
    Limits,
    Provider,
    Sandbox,
    Secret,
    SecretHeader,
    SpsError,
    WireError,
    from_json,
    to_json,
)
from sandbox_provider_spec.v1.http_client import HttpProvider
from sandbox_provider_spec.v1.server import create_app
from sandbox_provider_spec.v1.types import TimeKind
from sandbox_provider_spec.v1.wire import parse_timestamp, timestamp

EXAMPLES = Path(__file__).resolve().parents[2] / "spec" / "provider-api-1.0-examples"
VALUE = "known-secret-value-7f3a9c"
IDEM = "key-12345678"
START = datetime(2026, 11, 13, 10, tzinfo=UTC)
END = datetime(2026, 11, 13, 11, tzinfo=UTC)


def example(name: str) -> Any:
    return json.loads((EXAMPLES / f"{name}.json").read_text(encoding="utf-8"))


def secret_body(**fields: Any) -> dict[str, Any]:
    """A create body with one secret, as a caller sends it."""
    secret = {"placeholder": "{{KEY}}", "value": VALUE, "hosts": ["api.example.com"]}
    return {
        "requirements": {"hidden_secrets": {"inject_into": ["api.example.com"]}},
        "secrets": [secret],
        **fields,
    }


class Recorder(Provider, manifest=False):
    """Answers with the OpenAPI examples and records what it was called with."""

    provider_id = "recorder"
    name = "Recorder"
    spec_version = "1.0"
    credential_fields: ClassVar[tuple[CredentialField, ...]] = (CredentialField("api_key"),)
    calls: ClassVar[list[tuple[str, tuple[Any, ...], dict[str, Any]]]] = []
    explode: ClassVar[BaseException | None] = None

    def _note(self, name: str, *args: Any, **kwargs: Any) -> None:
        type(self).calls.append((name, args, kwargs))
        failure = type(self).explode
        if failure is not None:
            raise failure

    async def discovery(self) -> Any: ...
    async def get(self, sandbox_id: str) -> Any: ...
    async def list(self, *, labels: Any = None, cursor: Any = None, limit: int = 100) -> Any: ...
    async def destroy(self, sandbox_id: str) -> Any: ...
    async def run(self, sandbox_id: str, request: Any) -> Any: ...
    async def files_read(self, sandbox_id: str, path: str) -> Any: ...
    async def files_write(
        self,
        sandbox_id: str,
        path: str,
        data: AsyncIterable[bytes],
        *,
        size: int,
        user: str | None = None,
    ) -> Any: ...
    async def process_start(self, sandbox_id: str, request: Any) -> Any: ...
    async def process_output(
        self, sandbox_id: str, process_id: str, *, cursor: Any = None, wait_ms: int = 0
    ) -> Any: ...

    async def create(self, request: CreateRequest, *, idempotency_key: str) -> Sandbox:
        self._note("create", request)
        return from_json(Sandbox, example("Sandbox"))

    async def cost(self, sandbox_id: str, *, created_at: datetime | None = None) -> Cost:
        self._note("cost", sandbox_id, created_at=created_at)
        return from_json(Cost, example("Cost"))

    async def account_cost(self, start: datetime, end: datetime) -> AccountCost:
        self._note("account_cost", start, end)
        return from_json(AccountCost, example("AccountCost"))


class OldCost(Recorder, manifest=False):
    """A provider written before the hint existed: its `cost` has no `created_at`."""

    async def cost(self, sandbox_id: str) -> Cost:  # type: ignore[override]
        self._note("cost", sandbox_id)
        return from_json(Cost, example("Cost"))


@pytest.fixture(autouse=True)
def reset() -> None:
    Recorder.calls = []
    Recorder.explode = None


def serve(
    provider_class: type[Provider] = Recorder,
) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(provider_class))
    return httpx.AsyncClient(
        transport=transport, base_url="http://t", headers={"Authorization": "Bearer tok-abcdef"}
    )


def send(method: str, path: str, **kwargs: Any) -> httpx.Response:
    async def main() -> httpx.Response:
        provider_class = kwargs.pop("provider_class", Recorder)
        async with serve(provider_class) as client:
            return await client.request(method, path, **kwargs)

    return asyncio.run(main())


def create(body: dict[str, Any], **kwargs: Any) -> httpx.Response:
    return send("POST", "/v1/sandboxes", json=body, headers={"Idempotency-Key": IDEM}, **kwargs)


# --- secrets --------------------------------------------------------------------------------


def test_secret_example_round_trips_and_a_create_carries_it() -> None:
    secret = from_json(Secret, example("Secret"))
    assert secret.headers == (SecretHeader("Authorization", "Bearer ", ""),)
    assert to_json(secret) == example("Secret")
    request = from_json(CreateRequest, secret_body())
    assert request.secrets == (Secret("{{KEY}}", VALUE, ("api.example.com",)),)
    assert to_json(request) == {
        **to_json(CreateRequest(requirements=secret_body()["requirements"])),
        "secrets": secret_body()["secrets"],
    }


def test_secret_value_is_left_out_of_every_repr() -> None:
    request = from_json(CreateRequest, secret_body())
    assert VALUE not in repr(request)
    assert VALUE not in repr(request.secrets[0])
    assert VALUE not in str(request)


def test_secret_reaches_the_provider_and_no_response_carries_it(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.DEBUG):
        reply = create(secret_body())
    assert reply.status_code == 201
    assert VALUE not in reply.text
    request = Recorder.calls[0][1][0]
    assert request.secrets[0].value == VALUE
    assert not [record for record in caplog.records if VALUE in record.getMessage()]


def test_secrets_need_the_hidden_secrets_requirement() -> None:
    body = secret_body()
    for requirements in ({}, {"network_lockdown": {"policy": "open"}}):
        reply = create({**body, "requirements": requirements})
        assert reply.status_code == 400
        assert VALUE not in reply.text
    reply = create({"secrets": body["secrets"]})
    assert reply.status_code == 400
    assert VALUE not in reply.text
    assert Recorder.calls == []


@pytest.mark.parametrize(
    "secret",
    [
        {"placeholder": "", "value": VALUE, "hosts": ["a.example"]},
        {"placeholder": "{{K}}", "value": "", "hosts": ["a.example"]},
        {"placeholder": "{{K}}", "value": VALUE, "hosts": []},
        {"placeholder": "{{K}}", "value": VALUE, "hosts": ["a.example", "a.example"]},
        {"placeholder": "{{K}}", "value": VALUE, "hosts": ["a.example"], "extra": VALUE},
        {"placeholder": "{{K}}", "value": VALUE, "hosts": ["a.example"], "headers": []},
        {"placeholder": "{{K}}", "value": VALUE, "hosts": ["a.example"], "headers": [{}]},
        {
            "placeholder": "{{K}}",
            "value": VALUE,
            "hosts": ["bad host"],
            "headers": [{"name": "a b"}],
        },
        {"placeholder": "{{K}}", "value": 12345, "hosts": ["a.example"]},
        {"placeholder": "{{K}}", "hosts": ["a.example"]},
    ],
)
def test_a_malformed_secret_is_refused_without_its_value(secret: dict[str, Any]) -> None:
    reply = create(secret_body(secrets=[secret]))
    assert reply.status_code == 400
    assert VALUE not in reply.text and "12345" not in reply.text
    assert Recorder.calls == []


def test_secret_values_stay_out_of_errors_about_other_fields(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The error of a create that is wrong elsewhere may quote the whole body: it must not
    show a secret value, in plain, `repr` or JSON spelling."""
    tricky = "q\"u\\o'te-" + VALUE
    secret = {"placeholder": "{{K}}", "value": tricky, "hosts": ["api.example.com"]}
    bodies = [
        secret_body(secrets=[secret], lifetime_seconds=None, at_end="destroyed"),  # a `not` rule
        secret_body(secrets=[secret], sandbox_class=5),
        secret_body(secrets=[secret], labels={"bad key": "x"}),
        secret_body(secrets=[secret], unknown_field=tricky),
        secret_body(secrets=[secret], env={"A": tricky, "B": 1}),
    ]
    with caplog.at_level(logging.DEBUG):
        for body in bodies:
            reply = create(body)
            assert reply.status_code == 400, reply.text
            assert VALUE not in reply.text
            assert tricky not in reply.text
            assert json.dumps(tricky)[1:-1] not in reply.text
    assert Recorder.calls == []
    assert not [record for record in caplog.records if VALUE in record.getMessage()]


def test_secret_values_stay_out_of_a_failing_provider_and_the_wire_error(
    caplog: pytest.LogCaptureFixture,
) -> None:
    Recorder.explode = RuntimeError(f"upstream refused {VALUE}")
    with caplog.at_level(logging.DEBUG):
        reply = create(secret_body())
    assert reply.status_code == 500
    assert VALUE not in reply.text
    assert not [record for record in caplog.records if VALUE in record.getMessage()]
    # the client side: a request that does not fit its schema names no value either
    with pytest.raises(WireError) as raised:
        to_json(CreateRequest(secrets=[Secret("{{K}}", VALUE, [])]))
    assert VALUE not in str(raised.value)


def test_secret_value_never_reaches_a_log_through_the_client(
    caplog: pytest.LogCaptureFixture,
) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(201, json=example("Sandbox"))

    async def main() -> Sandbox:
        client = HttpProvider(
            "https://api.example.test", "tok", transport=httpx.MockTransport(handler)
        )
        try:
            return await client.create(
                from_json(CreateRequest, secret_body()), idempotency_key=IDEM
            )
        finally:
            await client.aclose()

    with caplog.at_level(logging.DEBUG):
        asyncio.run(main())
    assert json.loads(seen[0].content)["secrets"][0]["value"] == VALUE
    assert VALUE not in "".join(record.getMessage() for record in caplog.records)


# --- Sandbox.times --------------------------------------------------------------------------


def test_times_round_trip_on_a_sandbox_and_are_optional() -> None:
    sandbox = from_json(Sandbox, example("Sandbox"))
    assert [(t.kind, t.source) for t in sandbox.times] == [
        ("created", "createdAt"),
        ("billed_start", "startedAt"),
    ]
    assert sandbox.times[1].at == datetime(2026, 11, 13, 10, 0, 2, tzinfo=UTC)
    assert to_json(sandbox) == example("Sandbox")
    bare = {k: v for k, v in example("Sandbox").items() if k != "times"}
    assert from_json(Sandbox, bare).times == ()
    assert "times" not in to_json(from_json(Sandbox, bare))


@pytest.mark.parametrize(
    "time",
    [
        {"kind": "billed_start", "at": "2026-11-13T10:00:02Z"},
        {"kind": "born", "at": "2026-11-13T10:00:02Z", "source": "x"},
        {"kind": "created", "at": "2026-11-13 10:00:02", "source": "x"},
        {"kind": "created", "at": "2026-11-13T10:00:02Z", "source": ""},
        {"kind": "created", "at": "2026-11-13T10:00:02Z", "source": "x", "note": 1},
    ],
)
def test_a_malformed_time_on_a_sandbox_is_refused(time: dict[str, Any]) -> None:
    with pytest.raises(WireError):
        from_json(Sandbox, {**example("Sandbox"), "times": [time]})


def test_times_kinds_are_the_fourteen_provider_time_kinds() -> None:
    document = yaml.safe_load(
        (EXAMPLES.parent / "provider-api-1.0.openapi.yaml").read_text(encoding="utf-8")
    )
    kinds = document["components"]["schemas"]["ProviderTime"]["properties"]["kind"]["enum"]
    assert kinds == list(get_args(TimeKind))
    assert len(kinds) == 14


# --- account.cost ---------------------------------------------------------------------------


def test_account_cost_round_trips_and_is_claimed_by_its_window() -> None:
    cost = from_json(AccountCost, example("AccountCost"))
    assert cost.total_usd is not None and len(cost.lines) == 2
    assert to_json(cost) == example("AccountCost")
    limits = {**example("Limits"), "account_cost_window_seconds": 86400}
    assert from_json(Limits, limits).account_cost_window_seconds == 86400
    assert to_json(from_json(Limits, limits)) == limits
    assert from_json(Limits, example("Limits")).account_cost_window_seconds is None
    with pytest.raises(WireError):
        from_json(Limits, {**example("Limits"), "account_cost_window_seconds": 0})


def test_a_usage_account_cost_states_quantities_and_no_amount_and_round_trips() -> None:
    document = {
        **example("AccountCost"),
        "source": "usage",
        "total_usd": None,
        "lines": [
            {**line, "amount_usd": None, "start": None, "end": None}
            for line in (
                {"item": "cpu", "quantity": "2.5", "unit": "vcpu_hour"},
                {"item": "memory", "quantity": "9", "unit": "gib_hour"},
            )
        ],
    }
    cost = from_json(AccountCost, document)
    assert cost.source == "usage" and cost.total_usd is None
    assert all(line.amount_usd is None and line.quantity is not None for line in cost.lines)
    assert to_json(cost) == document


def test_account_cost_reaches_the_provider_with_typed_times() -> None:
    reply = send(
        "GET", "/v1/cost", params={"start": "2026-11-13T10:00:00Z", "end": "2026-11-13T11:00:00Z"}
    )
    assert reply.status_code == 200
    assert reply.json() == example("AccountCost")
    assert Recorder.calls == [("account_cost", (START, END), {})]


@pytest.mark.parametrize(
    "query",
    [
        "",
        "start=2026-11-13T10:00:00Z",
        "end=2026-11-13T11:00:00Z",
        "start=2026-11-13T11:00:00Z&end=2026-11-13T10:00:00Z",
        "start=2026-11-13T10:00:00Z&end=2026-11-13T10:00:00Z",
        "start=yesterday&end=2026-11-13T11:00:00Z",
        "start=2026-11-13T10:00:00%2B01:00&end=2026-11-13T11:00:00Z",
        "start=2026-11-13T10:00:00Z&start=2026-11-13T10:00:00Z&end=2026-11-13T11:00:00Z",
        "start=2026-11-13T10:00:00Z&end=2026-11-13T11:00:00Z&window=1",
    ],
)
def test_a_malformed_account_cost_window_is_invalid_request(query: str) -> None:
    reply = send("GET", f"/v1/cost?{query}")
    assert reply.status_code == 400
    assert reply.json()["error"]["code"] == "invalid_request"
    assert Recorder.calls == []


def test_account_cost_is_unsupported_unless_the_provider_offers_it() -> None:
    class Plain(Recorder, manifest=False):
        async def account_cost(self, start: datetime, end: datetime) -> AccountCost:
            return await Provider.account_cost(self, start, end)

    reply = send(
        "GET", "/v1/cost?start=2026-11-13T10:00:00Z&end=2026-11-13T11:00:00Z", provider_class=Plain
    )
    assert reply.status_code == 422
    assert "account.cost" in reply.json()["error"]["message"]


def test_account_cost_over_the_client_sends_the_window() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=example("AccountCost"))

    async def main() -> AccountCost:
        client = HttpProvider(
            "https://api.example.test", "tok", transport=httpx.MockTransport(handler)
        )
        try:
            return await client.account_cost(START, END)
        finally:
            await client.aclose()

    result = asyncio.run(main())
    assert result == from_json(AccountCost, example("AccountCost"))
    assert seen[0].url.path == "/v1/cost"
    assert dict(seen[0].url.params) == {
        "start": "2026-11-13T10:00:00Z",
        "end": "2026-11-13T11:00:00Z",
    }


# --- the creation-time hint on cost ---------------------------------------------------------


def test_cost_hint_reaches_the_provider_as_a_time() -> None:
    reply = send("GET", "/v1/sandboxes/sbx-17/cost", params={"created_at": "2026-11-13T10:00:00Z"})
    assert reply.status_code == 200
    assert Recorder.calls == [("cost", ("sbx-17",), {"created_at": START})]


def test_cost_hint_is_none_when_the_caller_sends_none() -> None:
    assert send("GET", "/v1/sandboxes/sbx-17/cost").status_code == 200
    assert Recorder.calls == [("cost", ("sbx-17",), {"created_at": None})]


def test_cost_hint_is_not_passed_to_a_provider_written_without_it() -> None:
    reply = send("GET", "/v1/sandboxes/sbx-17/cost", provider_class=OldCost)
    assert reply.status_code == 200
    assert Recorder.calls == [("cost", ("sbx-17",), {})]


@pytest.mark.parametrize(
    "value", ["", "yesterday", "2026-11-13T10:00:00", "2026-11-13T10:00:00+01:00"]
)
def test_a_malformed_cost_hint_is_invalid_request(value: str) -> None:
    reply = send("GET", "/v1/sandboxes/sbx-17/cost", params={"created_at": value})
    assert reply.status_code == 400
    assert Recorder.calls == []


def test_cost_hint_over_the_client_is_the_created_at_query_parameter() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=example("Cost"))

    async def main() -> None:
        client = HttpProvider(
            "https://api.example.test", "tok", transport=httpx.MockTransport(handler)
        )
        try:
            await client.cost("sbx-17", created_at=START)
            await client.cost("sbx-17")
        finally:
            await client.aclose()

    asyncio.run(main())
    assert dict(seen[0].url.params) == {"created_at": "2026-11-13T10:00:00Z"}
    assert dict(seen[1].url.params) == {}


def test_timestamps_parse_only_in_utc_with_a_z() -> None:
    assert parse_timestamp("2026-11-13T10:00:00Z") == START
    assert timestamp(START) == "2026-11-13T10:00:00Z"
    for text in ("2026-11-13T10:00:00", "2026-11-13T10:00:00+00:00", "x"):
        with pytest.raises(WireError):
            parse_timestamp(text)


def test_the_provider_base_class_answers_the_new_operation_with_unsupported() -> None:
    provider = Recorder({"api_key": "k"})
    with pytest.raises(SpsError) as raised:
        asyncio.run(Provider.account_cost(provider, START, END))
    assert raised.value.code == "unsupported"
