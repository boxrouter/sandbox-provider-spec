# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The 1.0 Python interface: it mirrors the OpenAPI file, the examples round-trip, and a
provider package declares itself through `sps-provider.yaml`."""

from __future__ import annotations

import asyncio
import importlib
import inspect
import json
import sys
import textwrap
import typing
from collections.abc import AsyncIterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml

from sandbox_provider_spec.v1 import (
    ERROR_TABLE,
    PROVIDER_FAULT,
    CreateRequest,
    Provider,
    SpsError,
    WireError,
    error_from_json,
    error_to_json,
    from_json,
    to_json,
    wire,
)
from sandbox_provider_spec.v1 import types as v1_types
from sandbox_provider_spec.v1.tokens import decode, encode

SPEC = Path(__file__).resolve().parents[2] / "spec"
OPENAPI = yaml.safe_load((SPEC / "provider-api-1.0.openapi.yaml").read_text(encoding="utf-8"))
EXAMPLES = SPEC / "provider-api-1.0-examples"

OPTIONAL = {
    "files_link": ("files.link", ("s", object)),
    "pause": ("pause", ("s",)),
    "resume": ("resume", ("s",)),
    "lifetime_extend": ("lifetime.extend", ("s", 60)),
    "process_write_stdin": ("process.write_stdin", ("s", "p", b"x")),
    "process_close_stdin": ("process.close_stdin", ("s", "p")),
    "process_cancel": ("process.cancel", ("s", "p")),
    "preview_link": ("preview.link", ("s", 3000)),
    "preview_revoke": ("preview.revoke", ("s", "p")),
    "labels_update": ("labels.update", ("s", ())),  # the stub ignores the labels
    "tcp_link": ("tcp.link", ("s", 5432)),
    "files_list": ("files.list", ("s", "/d")),
    "files_mkdir": ("files.mkdir", ("s", "/d")),
    "files_remove": ("files.remove", ("s", "/d")),
    "files_exists": ("files.exists", ("s", "/d")),
    "snapshot_create": (
        "snapshot.create",
        ("s", v1_types.SnapshotRequest(), {"idempotency_key": "idem-key-1"}),
    ),
    "snapshot_get": ("snapshot.get", ("n",)),
    "snapshot_list": ("snapshot.list", ()),
    "snapshot_delete": ("snapshot.delete", ("n",)),
    "snapshot_cost": ("snapshot.cost", ("n",)),
    "image_prepare": (
        "image.prepare",
        (
            v1_types.ImageRequest(v1_types.DockerfileSource("FROM x\n")),
            {"idempotency_key": "idem-key-1"},
        ),
    ),
    "image_get": ("image.get", ("n",)),
    "image_list": ("image.list", ()),
    "image_delete": ("image.delete", ("n",)),
    "cost": ("cost", ("s",)),
    "account_cost": (
        "account.cost",
        (datetime(2026, 11, 13, tzinfo=UTC), datetime(2026, 11, 14, tzinfo=UTC)),
    ),
    "image_cost": ("image.cost", ("i",)),
    "cost_capture": ("cost.capture", ("s", {"idempotency_key": "idem-key-1"})),
    "account_capacity": ("account.capacity", ()),
    "terminal_open": ("terminal.open", ("s", v1_types.TerminalRequest())),
    "terminal_reattach": ("terminal.reattach", ("s", "terminal-id-1")),
    "terminal_end": ("terminal.end", ("s", "terminal-id-1")),
    "network_update": ("network.update", ("s", "open")),
}


def coroutine_methods(cls: type) -> set[str]:
    return {
        name
        for name, member in inspect.getmembers(cls, inspect.iscoroutinefunction)
        if name != "aclose"
    }


def test_operation_ids_equal_provider_methods() -> None:
    ids = {
        item["operationId"]
        for methods in OPENAPI["paths"].values()
        for method, item in methods.items()
        if method in {"get", "put", "post", "delete", "patch"}
    }
    assert ids == coroutine_methods(Provider)
    assert len(ids) == 43


def test_error_table_is_the_openapi_table() -> None:
    table = {
        code: (row["status"], row["x-sps-fault"])
        for code, row in OPENAPI["components"]["x-sps-errors"].items()
    }
    assert dict(ERROR_TABLE) == table
    assert PROVIDER_FAULT == {"unavailable", "timeout", "provider_error"}


def test_sps_error_str_and_validation() -> None:
    error = SpsError("not_found", "No sandbox sbx-17")
    assert str(error) == "not_found: No sandbox sbx-17"
    assert (error.http_status, error.fault, error.outcome) == (404, "caller", "failed")
    assert SpsError("timeout", "slow", outcome="unknown", retry_after_seconds=3).fault == "provider"
    assert SpsError("invalid_request", "short upload", outcome="unknown").outcome == "unknown"
    with pytest.raises(ValueError, match="caller fault"):
        SpsError("not_found", "x", outcome="unknown")
    with pytest.raises(ValueError, match="unknown error code"):
        SpsError("nope", "x")  # type: ignore[arg-type]


def example_names() -> list[str]:
    return sorted(
        name
        for name in (path.stem for path in EXAMPLES.glob("*.json"))
        if any(codec_schema == name for codec_schema in (c.schema for c in wire._CODECS.values()))
    )


def test_every_json_object_type_is_covered() -> None:
    # The examples that are not objects of their own (scalars, maps, bare requests).
    plain = {
        "Decimal", "Timestamp", "Labels", "Env", "FilePath", "Port", "PriceItem", "PriceUnit",
        "EmptyObject", "Error", "ErrorResponse", "SandboxSize", "LifetimeExtendRequest",
        "PreviewRequest", "TcpLinkRequest", "LabelsUpdateRequest", "NetworkUpdateRequest",
        "TerminalId",
        "MkdirRequest", "EntryType", "UserName", "ImageConfig", "ImageDigest", "ImageResources",
        "StartWindow", "Concurrency", "Prepaid", "StoredArtifacts",
    }  # fmt: skip
    every = {path.stem for path in EXAMPLES.glob("*.json")}
    assert set(example_names()) == every - plain


@pytest.mark.parametrize("name", example_names())
def test_example_round_trips_unchanged(name: str) -> None:
    example = json.loads((EXAMPLES / f"{name}.json").read_text(encoding="utf-8"))
    cls = next(cls for cls, codec in wire._CODECS.items() if codec.schema == name)
    value: Any = from_json(cls, example)
    assert isinstance(value, cls)
    assert to_json(value) == example
    # The text form is stable too: the same example read twice gives equal values.
    assert from_json(cls, json.loads(json.dumps(to_json(value)))) == value


def test_error_response_round_trips() -> None:
    example = json.loads((EXAMPLES / "ErrorResponse.json").read_text(encoding="utf-8"))
    error = error_from_json(example)
    assert (error.code, error.message, error.outcome) == (
        "not_found",
        "No sandbox sbx-17",
        "failed",
    )
    assert error_to_json(error) == example


def test_a_bad_error_body_is_a_provider_error_with_unknown_outcome() -> None:
    error = error_from_json("<html>bad gateway</html>")
    assert (error.code, error.outcome) == ("provider_error", "unknown")


def test_decimals_keep_their_digits_and_times_end_in_z() -> None:
    cost = from_json(
        v1_types.Cost,
        {
            "sandbox_id": "s",
            "status": "final",
            "total_usd": "0.0000004500",
            "source": "reported",
            "lines": [],
            "as_of": "2026-11-13T10:05:00.250Z",
        },
    )
    data = to_json(cost)
    assert data["total_usd"] == "0.0000004500"
    assert data["as_of"] == "2026-11-13T10:05:00.250000Z"
    assert "revision" not in data


def test_a_cost_may_have_no_total_yet_and_a_reported_line_no_quantity() -> None:
    document = {
        "sandbox_id": "s",
        "status": "accruing",
        "total_usd": None,
        "source": "reported",
        "lines": [{"item": "cpu", "amount_usd": "1", "start": None, "end": None}],
        "as_of": "2026-11-13T10:05:00Z",
    }
    cost = from_json(v1_types.Cost, document)
    assert cost.total_usd is None
    assert (cost.lines[0].quantity, cost.lines[0].unit) == (None, None)
    assert to_json(cost) == document


def test_a_usage_cost_has_quantities_and_null_amounts() -> None:
    document = {
        "sandbox_id": "s",
        "status": "final",
        "total_usd": None,
        "source": "usage",
        "lines": [
            {
                "item": "cpu",
                "quantity": "240",
                "unit": "vcpu_second",
                "amount_usd": None,
                "start": "2026-11-13T10:00:00Z",
                "end": "2026-11-13T10:02:00Z",
            }
        ],
        "as_of": "2026-11-13T10:05:00Z",
    }
    cost = from_json(v1_types.Cost, document)
    assert cost.source == "usage" and cost.total_usd is None and cost.lines[0].amount_usd is None
    assert to_json(cost) == document


def test_discovery_offers_cost_only_when_it_states_a_final_window() -> None:
    stated = json.loads((EXAMPLES / "Limits.json").read_text(encoding="utf-8"))
    assert from_json(v1_types.Limits, stated).cost_final_within_seconds == 3600
    del stated["cost_final_within_seconds"]
    silent = from_json(v1_types.Limits, stated)
    assert silent.cost_final_within_seconds is None
    assert to_json(silent) == stated


def test_wire_refuses_what_the_schema_refuses() -> None:
    with pytest.raises(WireError):
        from_json(v1_types.Sandbox, {"id": "x"})
    with pytest.raises(WireError):  # a JSON number where a decimal string belongs
        from_json(
            v1_types.CostLine, {"item": "cpu", "quantity": 1, "unit": "gib", "amount_usd": "1"}
        )
    with pytest.raises(WireError):  # naive time
        wire._stamp(v1_types.datetime(2026, 1, 1))  # type: ignore[attr-defined]
    with pytest.raises(WireError):  # lifetime_seconds null with an explicit at_end of paused
        to_json(CreateRequest(lifetime_seconds=None, at_end="paused"))
    with pytest.raises(TypeError):
        to_json(object())


def test_unknown_result_fields_are_ignored() -> None:
    example = json.loads((EXAMPLES / "TcpLink.json").read_text(encoding="utf-8"))
    assert to_json(from_json(v1_types.TcpLink, {**example, "x-example-note": "hi"})) == example


class Stub(Provider, manifest=False):
    """Every required operation, doing nothing."""

    async def discovery(self) -> Any: ...
    async def create(self, request: Any, *, idempotency_key: str) -> Any: ...
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


def test_required_operations_are_abstract() -> None:
    assert sorted(Provider.__abstractmethods__) == [
        "create", "destroy", "discovery", "files_read", "files_write", "get", "list",
        "process_output", "process_start", "run",
    ]  # fmt: skip
    with pytest.raises(TypeError):
        Provider({})  # type: ignore[abstract]
    assert not inspect.isabstract(Stub)


@pytest.mark.parametrize("method", sorted(OPTIONAL))
def test_optional_operation_raises_unsupported(method: str) -> None:
    dotted, args = OPTIONAL[method]
    keywords = args[-1] if args and isinstance(args[-1], dict) else {}
    positional = args[:-1] if keywords else args
    call: tuple[Any, ...] = tuple(
        v1_types.FileLinkRequest("/a", "read", 60) if a is object else a for a in positional
    )
    provider = Stub({})
    with pytest.raises(SpsError) as raised:
        asyncio.run(getattr(provider, method)(*call, **keywords))
    assert raised.value.code == "unsupported"
    assert dotted in raised.value.message
    assert raised.value.outcome == "failed"
    assert set(OPTIONAL) | {"aclose"} == {
        name
        for name, member in inspect.getmembers(Provider, inspect.iscoroutinefunction)
        if not getattr(member, "__isabstractmethod__", False)
    }


def make_package(root: Path, name: str, manifest: object | None) -> None:
    package = root / name
    package.mkdir()
    (package / "__init__.py").write_text(
        textwrap.dedent(
            """
            from sandbox_provider_spec.v1 import Provider

            class Impl(Provider):
                async def discovery(self): ...
                async def create(self, request, *, idempotency_key): ...
                async def get(self, sandbox_id): ...
                async def list(self, *, labels=None, cursor=None, limit=100): ...
                async def destroy(self, sandbox_id): ...
                async def run(self, sandbox_id, request): ...
                async def files_read(self, sandbox_id, path): ...
                async def files_write(self, sandbox_id, path, data, *, size, user=None): ...
                async def process_start(self, sandbox_id, request): ...
                async def process_output(
                    self, sandbox_id, process_id, *, cursor=None, wait_ms=0
                ): ...
                async def cost(self, sandbox_id): ...
            """
        ),
        encoding="utf-8",
    )
    if manifest is not None:
        (package / "sps-provider.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")


GOOD_MANIFEST = {
    "provider_id": "example",
    "name": "Example Cloud",
    "spec_version": "1.0",
    "credential_fields": [
        {"name": "api_key", "description": "API key", "public_prefix": "ex_"},
        {
            "name": "endpoint",
            "secret": False,
            "required": False,
            "default": "https://x.example.test",
        },
    ],
    "api_domains": ["api.example.com", ".example.net"],
}


def import_package(monkeypatch: pytest.MonkeyPatch, root: Path, name: str) -> Any:
    monkeypatch.syspath_prepend(str(root))
    monkeypatch.delitem(sys.modules, name, raising=False)
    return importlib.import_module(name)


def test_subclass_loads_its_manifest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    make_package(tmp_path, "good_provider", GOOD_MANIFEST)
    impl = import_package(monkeypatch, tmp_path, "good_provider").Impl
    assert (impl.provider_id, impl.name, impl.spec_version) == ("example", "Example Cloud", "1.0")
    assert [f.name for f in impl.credential_fields] == ["api_key", "endpoint"]
    assert impl.credential_fields[0].secret is True
    assert [f.public_prefix for f in impl.credential_fields] == ["ex_", None]
    assert impl.credential_fields[1].default == "https://x.example.test"
    assert impl.api_domains == ("api.example.com", ".example.net")

    provider = impl({"api_key": "k"})
    assert dict(provider.credentials) == {"api_key": "k", "endpoint": "https://x.example.test"}
    assert "k" not in repr(provider)
    with pytest.raises(SpsError) as raised:
        impl({"api_key": ""})
    assert raised.value.code == "unauthenticated"
    assert "api_key" in raised.value.message


def test_subclass_without_a_manifest_fails_when_defined(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_package(tmp_path, "bare_provider", None)
    with pytest.raises(ValueError, match="no sps-provider.yaml"):
        import_package(monkeypatch, tmp_path, "bare_provider")


def test_a_class_in_this_test_package_has_no_manifest() -> None:
    with pytest.raises(ValueError, match="sps-provider.yaml"):

        class NoManifest(Stub):
            pass

    with pytest.raises(ValueError, match="sps-provider.yaml"):

        class NoManifestEither(Provider):
            pass


@pytest.mark.parametrize(
    "change",
    [
        {"provider_id": "X"},
        {"spec_version": "2.0"},
        {"credential_fields": []},
        {"credential_fields": [{"name": "k", "default": "v"}]},  # a secret has no default
        {"credential_fields": [{"name": "k", "public_prefix": "Bad"}]},  # a prefix ends in _ or -
        {
            "credential_fields": [{"name": "k", "secret": False, "public_prefix": "ok_"}]
        },  # secret only
        {"api_domains": ["https://api.example.com"]},
        {"api_domains": []},
        {"surprise": 1},
    ],
)
def test_invalid_manifest_fails_when_defined(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: dict[str, Any]
) -> None:
    make_package(tmp_path, "bad_provider", {**GOOD_MANIFEST, **change})
    with pytest.raises(ValueError, match="not valid"):
        import_package(monkeypatch, tmp_path, "bad_provider")


def test_tokens_round_trip_and_refuse_anything_else() -> None:
    token = encode({"a": "1", "b": "2"})
    assert token.startswith("sps1.") and "=" not in token
    assert decode(token, ["b", "a"]) == {"a": "1", "b": "2"}
    for bad in [
        token,  # fields differ
        "plain-token",
        "sps1.!!!",
        encode({"a": "1"}),
        "sps1." + "e30",  # {}
    ]:
        with pytest.raises(SpsError) as raised:
            decode(bad, ["a", "b"] if bad is not token else ["a", "c"])
        assert raised.value.code == "unauthenticated"
        assert bad not in raised.value.message
    with pytest.raises(SpsError):
        decode(encode({"a": "1", "b": "2", "c": "3"}), ["a", "b"])


def test_the_package_names_no_product() -> None:
    root = Path(__file__).resolve().parents[2] / "src" / "sandbox_provider_spec" / "v1"
    for file in root.glob("*.py"):
        assert "boxrouter" not in file.read_text(encoding="utf-8"), file.name


@pytest.mark.parametrize(
    ("item", "unit", "basis"),
    [
        ("snapshot", "gib_month", "used"),
        ("volume", "gib_month", "allocated"),
        ("start", "each", "count"),
        ("request", "each", "count"),
        ("feature", "each", "count"),
    ],
)
def test_every_added_price_item_validates_and_round_trips(item: str, unit: str, basis: str) -> None:
    data = {"item": item, "price_usd": "0.01", "unit": unit, "basis": basis}
    price = from_json(v1_types.Price, data)
    assert price.item == item
    assert to_json(price) == data
    assert item in OPENAPI["components"]["schemas"]["PriceItem"]["enum"]
    assert item in typing.get_args(v1_types.PriceItem)


def test_a_feature_item_priced_per_month_validates_and_round_trips() -> None:
    data = {"item": "feature", "price_usd": "20", "unit": "month", "basis": "count"}
    price = from_json(v1_types.Price, data)
    assert (price.item, price.unit) == ("feature", "month")
    assert to_json(price) == data
    assert "month" in OPENAPI["components"]["schemas"]["PriceUnit"]["enum"]


def test_price_item_enum_equals_the_python_literal() -> None:
    enum = OPENAPI["components"]["schemas"]["PriceItem"]["enum"]
    assert set(enum) == set(typing.get_args(v1_types.PriceItem))
    assert len(enum) == 12


FOUR = ["files.list", "files.mkdir", "files.remove", "files.exists"]


def test_a_class_lists_all_four_directory_operations_or_none() -> None:
    example = json.loads((EXAMPLES / "SandboxClass.json").read_text(encoding="utf-8"))
    assert example["operations"] == FOUR
    value = from_json(v1_types.SandboxClass, example)
    assert tuple(value.operations) == tuple(FOUR)
    assert to_json(value) == example
    # None is the default and is not written.
    bare = {key: item for key, item in example.items() if key != "operations"}
    assert from_json(v1_types.SandboxClass, bare).operations == ()
    assert to_json(from_json(v1_types.SandboxClass, bare)) == bare
    for refused in (FOUR[:1], FOUR[:3], FOUR + FOUR[:1], ["files.list", "files.nope"]):
        with pytest.raises(WireError):
            from_json(v1_types.SandboxClass, {**example, "operations": refused})


@pytest.mark.parametrize(
    ("body", "refused"),
    [
        ({"exists": True, "type": "file"}, False),
        ({"exists": False, "type": None}, False),
        ({"exists": True, "type": None}, True),
        ({"exists": False, "type": "file"}, True),
        ({"exists": True, "type": "socket"}, True),
    ],
)
def test_path_info_pairs_exists_with_type(body: dict[str, Any], refused: bool) -> None:
    if refused:
        with pytest.raises(WireError):
            from_json(v1_types.PathInfo, body)
    else:
        assert to_json(from_json(v1_types.PathInfo, body)) == body


def test_invalid_request_keeps_its_unknown_outcome_over_the_wire() -> None:
    """A streamed upload whose size differs from the declared one may have written bytes."""
    body = error_to_json(SpsError("invalid_request", "size differs", outcome="unknown"))
    assert error_from_json(body).outcome == "unknown"
    plain = error_to_json(SpsError("invalid_request", "bad field"))
    assert error_from_json(plain).outcome == "failed"
    assert error_from_json(error_to_json(SpsError("not_found", "gone"))).outcome == "failed"
