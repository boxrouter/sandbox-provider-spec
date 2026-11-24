# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""`cost.batch`: the costs of several sandboxes in one call, over HTTP and as the tester reads it"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterable, Sequence
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, ClassVar

import httpx
import pytest

from sandbox_provider_spec import cost_batch_checks
from sandbox_provider_spec.driver import Unsupported
from sandbox_provider_spec.v1 import (
    Cost,
    CostBatch,
    CreateRequest,
    CredentialField,
    Limits,
    Provider,
    from_json,
    to_json,
)
from sandbox_provider_spec.v1.http_client import HttpProvider
from sandbox_provider_spec.v1.server import create_app

EXAMPLES = Path(__file__).resolve().parents[2] / "spec" / "provider-api-1.0-examples"


def example(name: str) -> Any:
    return json.loads((EXAMPLES / f"{name}.json").read_text(encoding="utf-8"))


class Batching(Provider, manifest=False):
    provider_id = "batching"
    name = "Batching"
    spec_version = "1.0"
    credential_fields: ClassVar[tuple[CredentialField, ...]] = (CredentialField("api_key"),)
    calls: ClassVar[list[tuple[str, ...]]] = []

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
    async def create(self, request: CreateRequest, *, idempotency_key: str) -> Any: ...

    async def cost_batch(self, sandbox_ids: Sequence[str]) -> CostBatch:
        type(self).calls.append(tuple(sandbox_ids))
        return from_json(CostBatch, example("CostBatch"))


@pytest.fixture(autouse=True)
def reset() -> None:
    Batching.calls = []


def send(path: str, provider_class: type[Provider] = Batching) -> httpx.Response:
    async def main() -> httpx.Response:
        transport = httpx.ASGITransport(app=create_app(provider_class))
        async with httpx.AsyncClient(
            transport=transport, base_url="http://t", headers={"Authorization": "Bearer tok-abcdef"}
        ) as client:
            return await client.get(path)

    return asyncio.run(main())


def test_the_limit_and_the_answer_round_trip() -> None:
    assert from_json(Limits, {**example("Limits"), "cost_batch_max": 25}).cost_batch_max == 25
    assert from_json(Limits, example("Limits")).cost_batch_max is None
    with pytest.raises(ValueError):
        from_json(Limits, {**example("Limits"), "cost_batch_max": 0})
    batch = from_json(CostBatch, example("CostBatch"))
    assert [cost.sandbox_id for cost in batch.costs] == ["sbx_1", "sbx_2"]
    assert to_json(batch) == example("CostBatch")


def test_the_ids_reach_the_provider_once_each_and_in_order() -> None:
    reply = send("/v1/costs?sandbox_id=sbx_1&sandbox_id=sbx_2")
    assert reply.status_code == 200
    assert reply.json() == example("CostBatch")
    assert Batching.calls == [("sbx_1", "sbx_2")]


@pytest.mark.parametrize(
    "query",
    ["", "sandbox_id=sbx_1&sandbox_id=sbx_1", "sandbox_id=bad%20id", "sandbox_id=sbx_1&other=1"],
)
def test_no_id_a_repeated_id_a_bad_id_or_another_parameter_is_invalid_request(query: str) -> None:
    reply = send(f"/v1/costs?{query}")
    assert reply.status_code == 400
    assert reply.json()["error"]["code"] == "invalid_request"
    assert Batching.calls == []


def test_cost_batch_is_unsupported_unless_the_provider_offers_it() -> None:
    class Plain(Batching, manifest=False):
        async def cost_batch(self, sandbox_ids: Sequence[str]) -> CostBatch:
            return await Provider.cost_batch(self, sandbox_ids)

    reply = send("/v1/costs?sandbox_id=sbx_1", Plain)
    assert reply.status_code == 422
    assert "cost.batch" in reply.json()["error"]["message"]


def test_the_client_sends_one_sandbox_id_parameter_for_each_id() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=example("CostBatch"))

    async def main() -> CostBatch:
        client = HttpProvider(
            "https://api.example.test", "tok", transport=httpx.MockTransport(handler)
        )
        try:
            return await client.cost_batch(["sbx_1", "sbx_2"])
        finally:
            await client.aclose()

    result = asyncio.run(main())
    assert result == from_json(CostBatch, example("CostBatch"))
    assert seen[0].url.path == "/v1/costs"
    assert seen[0].url.params.get_list("sandbox_id") == ["sbx_1", "sbx_2"]


# --- the tester's check (`cost.batch`) -------------------------------------------------------


def final_cost(sandbox_id: str, total: str = "0.5") -> Cost:
    cost = from_json(Cost, example("Cost"))
    return replace(
        cost, sandbox_id=sandbox_id, total_usd=cost.total_usd and type(cost.total_usd)(total)
    )


class Api:
    """A provider that states `cost_batch_max` and answers `cost` and `cost_batch`."""

    def __init__(self, *, limit: int | None = 10, total: str = "0.5", extra: bool = False) -> None:
        self.limit, self.total, self.extra = limit, total, extra

    async def discovery(self) -> Any:
        return SimpleNamespace(
            limits=SimpleNamespace(cost_final_within_seconds=60, cost_batch_max=self.limit)
        )

    async def cost(self, sandbox_id: str, *, created_at: Any = None) -> Cost:
        return final_cost(sandbox_id)

    async def cost_batch(self, sandbox_ids: Sequence[str]) -> CostBatch:
        costs = [
            final_cost(item, self.total)
            for item in sandbox_ids
            if not item.startswith("sps-test-unknown-")
        ]
        if self.extra:
            costs.append(final_cost("sbx-nobody-asked-for"))
        return CostBatch(tuple(costs))


def check(api: Api) -> dict[str, object]:
    driver = SimpleNamespace(api=api, wait=lambda call: asyncio.run(call))
    return dict(cost_batch_checks.batch(driver, ["sbx-1", "sbx-2"], {}))  # type: ignore[arg-type]


def test_the_check_passes_a_provider_that_batches_what_it_reads_alone() -> None:
    assert check(Api()) == {
        "same_sandboxes": True,
        "same_costs": True,
        "none_unasked": True,
        "unknown_absent": True,
    }


def test_the_check_names_a_batch_that_states_other_figures_or_adds_a_sandbox() -> None:
    assert check(Api(total="0.6"))["same_costs"] is False
    added = check(Api(extra=True))
    assert added["none_unasked"] is False and added["same_sandboxes"] is False


def test_the_check_leaves_the_unknown_id_out_when_the_call_is_at_the_limit() -> None:
    assert check(Api(limit=2))["unknown_absent"] is True


def test_the_check_is_unsupported_without_cost_batch_max() -> None:
    with pytest.raises(Unsupported):
        check(Api(limit=None))
