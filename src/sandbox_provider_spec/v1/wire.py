# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The JSON form of every 1.0 type: `to_json` and `from_json`.

Money and quantities are decimal strings, times are RFC 3339 in UTC with a `Z` suffix, and both
directions are checked against the schemas of the OpenAPI file. `to_json(from_json(T, x))`
equals `x` for every valid `x` that the OpenAPI file's examples show.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, TypeVar, cast

from jsonschema.exceptions import ValidationError

from sandbox_provider_spec.v1._spec_files import validator
from sandbox_provider_spec.v1.errors import ERROR_TABLE, Outcome, SpsError
from sandbox_provider_spec.v1.types import (
    AccountCapacity,
    AccountCost,
    Concurrency,
    Cost,
    CostLine,
    CreateRequest,
    DestroyResult,
    DirectoryEntry,
    DirectoryPage,
    Discovery,
    DockerfileSource,
    FileInfo,
    FileLink,
    FileLinkRequest,
    Image,
    ImageConfig,
    ImageDeleteResult,
    ImagePage,
    ImageRequest,
    ImageResources,
    Limits,
    OciSource,
    OutputChunk,
    OutputPage,
    PathInfo,
    Prepaid,
    PreparedImage,
    PreviewLink,
    Price,
    PrivateOciSource,
    Process,
    ProcessStartRequest,
    ProviderInfo,
    ProviderTime,
    RegistryCredentials,
    RunRequest,
    RunResult,
    Sandbox,
    SandboxClass,
    SandboxPage,
    Secret,
    SecretHeader,
    Size,
    Snapshot,
    SnapshotDeleteResult,
    SnapshotPage,
    SnapshotRequest,
    StartWindow,
    TcpLink,
    TerminalLink,
    TerminalRequest,
)

T = TypeVar("T")
Json = dict[str, Any]


class WireError(ValueError):
    """A JSON document does not match the schema of its type."""


# --- scalars -----------------------------------------------------------------------------


def _decimal(value: str) -> Decimal:
    return Decimal(value)


def _dec(value: Decimal) -> str:
    return format(value, "f")


def _time(value: str) -> datetime:
    return datetime.fromisoformat(value).astimezone(UTC)


def _stamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise WireError("a time must have a time zone")
    text = value.astimezone(UTC).replace(tzinfo=None).isoformat()
    return text + "Z"


def timestamp(value: datetime) -> str:
    """A time as the text of a `Timestamp` (RFC 3339 in UTC with a `Z`), for a query parameter."""
    return _stamp(value)


def parse_timestamp(text: str) -> datetime:
    """The time of a `Timestamp` text. Raises `WireError` when it is not one."""
    _check("Timestamp", text)
    return _time(text)


def _opt(value: Any, convert: Callable[[Any], Any]) -> Any:
    return None if value is None else convert(value)


def _number(value: float) -> float | int:
    return int(value) if float(value).is_integer() else value


def _put(out: Json, key: str, value: Any) -> None:
    """Add an optional field only when it has a value."""
    if value is not None:
        out[key] = value


# --- encoders ----------------------------------------------------------------------------


def _enc_size(value: Size) -> Json:
    out: Json = {"cpu": _number(value.cpu), "memory_mib": value.memory_mib}
    _put(out, "disk_mib", value.disk_mib)
    return out


def _enc_provider_time(value: ProviderTime) -> Json:
    return {"kind": value.kind, "at": _stamp(value.at), "source": value.source}


def _enc_secret(value: Secret) -> Json:
    out: Json = {
        "placeholder": value.placeholder,
        "value": value.value,
        "hosts": list(value.hosts),
    }
    if value.headers:
        out["headers"] = [
            {"name": header.name, "prefix": header.prefix, "suffix": header.suffix}
            for header in value.headers
        ]
    return out


def _enc_sandbox(value: Sandbox) -> Json:
    out: Json = {
        "id": value.id,
        "sandbox_class": value.sandbox_class,
        "state": value.state,
        "size": {
            "cpu": _number(value.size.cpu),
            "memory_mib": value.size.memory_mib,
            "disk_mib": value.size.disk_mib,
        },
        "region": value.region,
        "image": value.image,
        "labels": dict(value.labels),
        "created_at": _stamp(value.created_at),
        "ends_at": _opt(value.ends_at, _stamp),
        "at_end": value.at_end,
    }
    if value.times:
        out["times"] = [_enc_provider_time(item) for item in value.times]
    return out


def _enc_create_request(value: CreateRequest) -> Json:
    out: Json = {
        "sandbox_class": value.sandbox_class,
        "resources": dict(value.resources),
        "requirements": dict(value.requirements),
    }
    if value.image is not None:
        out["image"] = value.image if isinstance(value.image, str) else dict(value.image)
    out["lifetime_seconds"] = value.lifetime_seconds
    if value.lifetime_seconds is not None or value.at_end != "destroyed":
        out["at_end"] = value.at_end
    out["env"] = dict(value.env)
    out["labels"] = dict(value.labels)
    _put(out, "snapshot", value.snapshot)
    if value.secrets:
        out["secrets"] = [_enc_secret(item) for item in value.secrets]
    return out


def _enc_price(value: Price) -> Json:
    out: Json = {
        "item": value.item,
        "price_usd": _dec(value.price_usd),
        "unit": value.unit,
        "basis": value.basis,
    }
    if value.included:
        out["included"] = True
    if value.states is not None:
        out["states"] = list(value.states)
    _put(out, "increment_seconds", value.increment_seconds)
    _put(out, "minimum_seconds", value.minimum_seconds)
    _put(out, "minimum_quantity", _opt(value.minimum_quantity, _dec))
    _put(out, "allowance", _opt(value.allowance, dict))
    _put(
        out,
        "size",
        _opt(value.size, lambda size: {"cpu": _number(size.cpu), "memory_mib": size.memory_mib}),
    )
    _put(out, "region", value.region)
    _put(out, "gpu_model", value.gpu_model)
    _put(out, "variant", value.variant)
    return out


def _enc_cost_line(value: CostLine) -> Json:
    out: Json = {"item": value.item}
    _put(out, "quantity", _opt(value.quantity, _dec))
    _put(out, "unit", value.unit)
    out["amount_usd"] = _opt(value.amount_usd, _dec)
    out["start"] = _opt(value.start, _stamp)
    out["end"] = _opt(value.end, _stamp)
    return out


def _enc_snapshot(value: Snapshot) -> Json:
    return {
        "id": value.id,
        "sandbox_id": value.sandbox_id,
        "sandbox_class": value.sandbox_class,
        "state": value.state,
        "keeps": value.keeps,
        "size": {
            "cpu": _number(value.size.cpu),
            "memory_mib": value.size.memory_mib,
            "disk_mib": value.size.disk_mib,
        },
        "stored_bytes": value.stored_bytes,
        "labels": dict(value.labels),
        "created_at": _stamp(value.created_at),
        "expires_at": _opt(value.expires_at, _stamp),
    }


def _enc_cost(value: Cost) -> Json:
    out: Json = {}
    _put(out, "sandbox_id", value.sandbox_id)
    out |= {
        "status": value.status,
        "total_usd": _opt(value.total_usd, _dec),
        "source": value.source,
        "lines": [_enc_cost_line(line) for line in value.lines],
        "as_of": _stamp(value.as_of),
    }
    _put(out, "snapshot_id", value.snapshot_id)
    _put(out, "image_id", value.image_id)
    return out


def _enc_image_resources(value: ImageResources) -> Json:
    out: Json = {}
    _put(out, "cpu", _opt(value.cpu, _number))
    _put(out, "memory_mib", value.memory_mib)
    _put(out, "disk_mib", value.disk_mib)
    _put(out, "region", value.region)
    _put(out, "kernel", value.kernel)
    return out


def _enc_image_config(value: ImageConfig) -> Json:
    out: Json = {
        "env": dict(value.env),
        "workdir": value.workdir,
        "user": value.user,
        "entrypoint": _opt(value.entrypoint, list),
        "cmd": _opt(value.cmd, list),
    }
    _put(out, "init", value.init)
    _put(out, "user_name", value.user_name)
    _put(out, "home", value.home)
    return out


def _enc_image_request(value: ImageRequest) -> Json:
    source = value.source
    body: Json
    if isinstance(source, OciSource):
        body = {
            "oci": source.oci,
            "digest": source.digest,
            "config": _enc_image_config(source.config),
        }
    elif isinstance(source, PrivateOciSource):
        body = {
            "private_oci": source.private_oci,
            "digest": source.digest,
            "config": _enc_image_config(source.config),
            "credentials": {
                "username": source.credentials.username,
                "password": source.credentials.password,
            },
        }
    else:
        body = {"dockerfile": source.dockerfile}
        if source.base is not None:
            body["base"] = {
                "oci": source.base.oci,
                "digest": source.base.digest,
                "config": _enc_image_config(source.base.config),
            }
    return {
        "source": body,
        "resources": _opt(value.resources, _enc_image_resources),
        "labels": dict(value.labels),
    }


def _enc_prepared_image(value: PreparedImage) -> Json:
    return {
        "id": value.id,
        "state": value.state,
        "error": _opt(value.error, _enc_error_body),
        "resources": _opt(value.resources, _enc_image_resources),
        "stored_bytes": value.stored_bytes,
        "labels": dict(value.labels),
        "created_at": _stamp(value.created_at),
    }


def _enc_account_cost(value: AccountCost) -> Json:
    return {
        "start": _stamp(value.start),
        "end": _stamp(value.end),
        "status": value.status,
        "total_usd": _opt(value.total_usd, _dec),
        "source": value.source,
        "lines": [_enc_cost_line(line) for line in value.lines],
        "as_of": _stamp(value.as_of),
    }


def _enc_account_capacity(value: AccountCapacity) -> Json:
    return {
        "as_of": _stamp(value.as_of),
        "starts": [
            {
                "window_seconds": item.window_seconds,
                "used": item.used,
                "limit": item.limit,
                "remaining": item.remaining,
            }
            for item in value.starts
        ],
        "can_start": value.can_start,
        "paid_overage_enabled": value.paid_overage_enabled,
        "concurrency": _opt(
            value.concurrency, lambda item: {"active": item.active, "limit": item.limit}
        ),
        "prepaid": _opt(
            value.prepaid,
            lambda item: {"balance_usd": _dec(item.balance_usd), "past_due": item.past_due},
        ),
    }


def _enc_class(value: SandboxClass) -> Json:
    out: Json = {
        "id": value.id,
        "name": value.name,
        "ready": value.ready,
        "unavailable_regions": list(value.unavailable_regions),
        "resources": dict(value.resources),
        "lifetime_timer": dict(value.lifetime_timer),
    }
    _put(out, "gates", _opt(value.gates, dict))
    if value.lifetime_enforced_by != "provider":
        out["lifetime_enforced_by"] = value.lifetime_enforced_by
    if value.ordered_sessions:
        out["ordered_sessions"] = True
    if value.operations:
        out["operations"] = list(value.operations)
    _put(out, "image_binds", _opt(value.image_binds, list))
    out["images"] = [_enc_image(image) for image in value.images]
    out["prices"] = [_enc_price(price) for price in value.prices]
    return out


def _enc_image(value: Image) -> Json:
    return {"id": value.id, "default": value.default, "description": value.description}


def _enc_discovery(value: Discovery) -> Json:
    return {
        "spec_version": value.spec_version,
        "provider": _enc_provider_info(value.provider),
        "limits": _enc_limits(value.limits),
        "classes": [_enc_class(item) for item in value.classes],
    }


def _enc_provider_info(value: ProviderInfo) -> Json:
    out: Json = {"id": value.id, "name": value.name}
    _put(out, "docs_url", value.docs_url)
    return out


def _enc_limits(value: Limits) -> Json:
    out: Json = {
        "file_bytes": value.file_bytes,
        "run_timeout_ms": value.run_timeout_ms,
        "output_bytes": value.output_bytes,
        "wait_ms": value.wait_ms,
        "process_output_bytes": value.process_output_bytes,
        "process_retention_seconds": value.process_retention_seconds,
        "list_limit": value.list_limit,
    }
    _put(out, "cost_final_within_seconds", value.cost_final_within_seconds)
    _put(out, "image_context_bytes", value.image_context_bytes)
    _put(out, "account_cost_window_seconds", value.account_cost_window_seconds)
    _put(out, "image_layout_bytes", value.image_layout_bytes)
    return out


def _enc_file_link(value: FileLink) -> Json:
    return {
        "method": value.method,
        "url": value.url,
        "headers": dict(value.headers),
        "form_field": value.form_field,
        "expires_at": _stamp(value.expires_at),
        "reusable": value.reusable,
    }


def _enc_file_link_request(value: FileLinkRequest) -> Json:
    out: Json = {
        "path": value.path,
        "operation": value.operation,
        "lifetime_seconds": value.lifetime_seconds,
    }
    _put(out, "size", value.size)
    return out


def _enc_output_page(value: OutputPage) -> Json:
    return {
        "chunks": [{"stream": chunk.stream, "data": chunk.data} for chunk in value.chunks],
        "next_cursor": value.next_cursor,
        "gap": value.gap,
        "stdout_closed": value.stdout_closed,
        "stderr_closed": value.stderr_closed,
        "state": value.state,
        "exit_code": value.exit_code,
    }


# --- decoders ----------------------------------------------------------------------------


def _dec_size(data: Json) -> Size:
    return Size(cpu=data["cpu"], memory_mib=data["memory_mib"], disk_mib=data.get("disk_mib"))


def _dec_provider_time(data: Json) -> ProviderTime:
    return ProviderTime(kind=data["kind"], at=_time(data["at"]), source=data["source"])


def _dec_secret(data: Json) -> Secret:
    return Secret(
        placeholder=data["placeholder"],
        value=data["value"],
        hosts=tuple(data["hosts"]),
        headers=tuple(
            SecretHeader(h["name"], h.get("prefix", ""), h.get("suffix", ""))
            for h in data.get("headers", ())
        ),
    )


def _dec_sandbox(data: Json) -> Sandbox:
    return Sandbox(
        id=data["id"],
        sandbox_class=data["sandbox_class"],
        state=data["state"],
        size=_dec_size(data["size"]),
        region=data["region"],
        image=data["image"],
        labels=dict(data["labels"]),
        created_at=_time(data["created_at"]),
        ends_at=_opt(data["ends_at"], _time),
        at_end=data["at_end"],
        times=tuple(_dec_provider_time(item) for item in data.get("times", ())),
    )


def _dec_create_request(data: Json) -> CreateRequest:
    return CreateRequest(
        sandbox_class=data.get("sandbox_class", "default"),
        resources=dict(data.get("resources", {})),
        requirements=dict(data.get("requirements", {})),
        image=data.get("image"),
        lifetime_seconds=data.get("lifetime_seconds", 300),
        at_end=data.get("at_end", "destroyed"),
        env=dict(data.get("env", {})),
        labels=dict(data.get("labels", {})),
        snapshot=data.get("snapshot"),
        secrets=tuple(_dec_secret(item) for item in data.get("secrets", ())),
    )


def _dec_snapshot(data: Json) -> Snapshot:
    return Snapshot(
        id=data["id"],
        sandbox_id=data["sandbox_id"],
        sandbox_class=data["sandbox_class"],
        state=data["state"],
        keeps=data["keeps"],
        size=_dec_size(data["size"]),
        stored_bytes=data["stored_bytes"],
        labels=dict(data["labels"]),
        created_at=_time(data["created_at"]),
        expires_at=_opt(data["expires_at"], _time),
    )


def _dec_price(data: Json) -> Price:
    return Price(
        item=data["item"],
        price_usd=_decimal(data["price_usd"]),
        unit=data["unit"],
        basis=data["basis"],
        included=data.get("included", False),
        states=_opt(data.get("states"), tuple),
        increment_seconds=data.get("increment_seconds"),
        minimum_seconds=data.get("minimum_seconds"),
        minimum_quantity=_opt(data.get("minimum_quantity"), _decimal),
        allowance=_opt(data.get("allowance"), dict),
        size=_opt(data.get("size"), _dec_size),
        region=data.get("region"),
        gpu_model=data.get("gpu_model"),
        variant=data.get("variant"),
    )


def _dec_cost_line(data: Json) -> CostLine:
    return CostLine(
        item=data["item"],
        amount_usd=_opt(data["amount_usd"], _decimal),
        quantity=_opt(data.get("quantity"), _decimal),
        unit=data.get("unit"),
        start=_opt(data.get("start"), _time),
        end=_opt(data.get("end"), _time),
    )


def _dec_cost(data: Json) -> Cost:
    return Cost(
        sandbox_id=data.get("sandbox_id"),
        status=data["status"],
        total_usd=_opt(data["total_usd"], _decimal),
        source=data["source"],
        lines=tuple(_dec_cost_line(line) for line in data["lines"]),
        as_of=_time(data["as_of"]),
        snapshot_id=data.get("snapshot_id"),
        image_id=data.get("image_id"),
    )


def _dec_image_resources(data: Json) -> ImageResources:
    return ImageResources(
        cpu=data.get("cpu"),
        memory_mib=data.get("memory_mib"),
        disk_mib=data.get("disk_mib"),
        region=data.get("region"),
        kernel=data.get("kernel"),
    )


def _dec_image_config(data: Json) -> ImageConfig:
    return ImageConfig(
        env=dict(data.get("env", {})),
        workdir=data.get("workdir"),
        user=data.get("user"),
        entrypoint=_opt(data.get("entrypoint"), tuple),
        cmd=_opt(data.get("cmd"), tuple),
        init=data.get("init"),
        user_name=data.get("user_name"),
        home=data.get("home"),
    )


def _dec_image_request(data: Json) -> ImageRequest:
    raw = data["source"]
    source: OciSource | PrivateOciSource | DockerfileSource
    if "oci" in raw:
        source = OciSource(raw["oci"], raw["digest"], _dec_image_config(raw["config"]))
    elif "private_oci" in raw:
        credentials = RegistryCredentials(
            raw["credentials"]["username"], raw["credentials"]["password"]
        )
        source = PrivateOciSource(
            raw["private_oci"], raw["digest"], _dec_image_config(raw["config"]), credentials
        )
    else:
        base = raw.get("base")
        source = DockerfileSource(
            raw["dockerfile"],
            None
            if base is None
            else OciSource(base["oci"], base["digest"], _dec_image_config(base["config"])),
        )
    return ImageRequest(
        source=source,
        resources=_opt(data.get("resources"), _dec_image_resources),
        labels=dict(data.get("labels", {})),
    )


def _dec_prepared_image(data: Json) -> PreparedImage:
    return PreparedImage(
        id=data["id"],
        state=data["state"],
        error=_opt(data["error"], _dec_error_body),
        resources=_opt(data["resources"], _dec_image_resources),
        stored_bytes=data["stored_bytes"],
        labels=dict(data["labels"]),
        created_at=_time(data["created_at"]),
    )


def _dec_account_cost(data: Json) -> AccountCost:
    return AccountCost(
        start=_time(data["start"]),
        end=_time(data["end"]),
        status=data["status"],
        total_usd=_opt(data["total_usd"], _decimal),
        source=data["source"],
        lines=tuple(_dec_cost_line(line) for line in data["lines"]),
        as_of=_time(data["as_of"]),
    )


def _dec_account_capacity(data: Json) -> AccountCapacity:
    return AccountCapacity(
        as_of=_time(data["as_of"]),
        starts=tuple(StartWindow(**item) for item in data["starts"]),
        can_start=data["can_start"],
        paid_overage_enabled=data["paid_overage_enabled"],
        concurrency=_opt(data["concurrency"], lambda item: Concurrency(**item)),
        prepaid=_opt(
            data["prepaid"],
            lambda item: Prepaid(_decimal(item["balance_usd"]), item["past_due"]),
        ),
    )


def _dec_class(data: Json) -> SandboxClass:
    return SandboxClass(
        id=data["id"],
        name=data["name"],
        ready=data["ready"],
        resources=dict(data["resources"]),
        lifetime_timer=dict(data["lifetime_timer"]),
        images=tuple(Image(i["id"], i["default"], i["description"]) for i in data["images"]),
        prices=tuple(_dec_price(price) for price in data["prices"]),
        gates=_opt(data.get("gates"), dict),
        unavailable_regions=tuple(data.get("unavailable_regions", ())),
        lifetime_enforced_by=data.get("lifetime_enforced_by", "provider"),
        ordered_sessions=data.get("ordered_sessions", False),
        operations=tuple(data.get("operations", ())),
        image_binds=_opt(data.get("image_binds"), tuple),
    )


def _dec_discovery(data: Json) -> Discovery:
    provider = data["provider"]
    return Discovery(
        spec_version=data["spec_version"],
        provider=ProviderInfo(provider["id"], provider["name"], provider.get("docs_url")),
        limits=Limits(**data["limits"]),
        classes=tuple(_dec_class(item) for item in data["classes"]),
    )


def _dec_output_page(data: Json) -> OutputPage:
    return OutputPage(
        chunks=tuple(OutputChunk(c["stream"], c["data"]) for c in data["chunks"]),
        next_cursor=data["next_cursor"],
        gap=data["gap"],
        stdout_closed=data["stdout_closed"],
        stderr_closed=data["stderr_closed"],
        state=data["state"],
        exit_code=data["exit_code"],
    )


# --- the table ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Codec:
    schema: str
    encode: Callable[[Any], Json]
    decode: Callable[[Json], Any]


_CODECS: dict[type, _Codec] = {
    Size: _Codec("Size", _enc_size, _dec_size),
    Sandbox: _Codec("Sandbox", _enc_sandbox, _dec_sandbox),
    SandboxPage: _Codec(
        "SandboxPage",
        lambda v: {
            "sandboxes": [_enc_sandbox(item) for item in v.sandboxes],
            "next_cursor": v.next_cursor,
        },
        lambda d: SandboxPage(tuple(_dec_sandbox(i) for i in d["sandboxes"]), d["next_cursor"]),
    ),
    CreateRequest: _Codec("CreateRequest", _enc_create_request, _dec_create_request),
    Price: _Codec("Price", _enc_price, _dec_price),
    CostLine: _Codec("CostLine", _enc_cost_line, _dec_cost_line),
    Cost: _Codec("Cost", _enc_cost, _dec_cost),
    AccountCost: _Codec("AccountCost", _enc_account_cost, _dec_account_cost),
    ProviderTime: _Codec("ProviderTime", _enc_provider_time, _dec_provider_time),
    Secret: _Codec("Secret", _enc_secret, _dec_secret),
    AccountCapacity: _Codec("AccountCapacity", _enc_account_capacity, _dec_account_capacity),
    DestroyResult: _Codec(
        "DestroyResult",
        lambda v: {"sandbox_id": v.sandbox_id, "state": v.state},
        lambda d: DestroyResult(d["sandbox_id"], d["state"]),
    ),
    SnapshotRequest: _Codec(
        "SnapshotRequest",
        lambda v: {"keeps": v.keeps, "labels": dict(v.labels)},
        lambda d: SnapshotRequest(keeps=d.get("keeps"), labels=dict(d.get("labels", {}))),
    ),
    Snapshot: _Codec("Snapshot", _enc_snapshot, _dec_snapshot),
    SnapshotPage: _Codec(
        "SnapshotPage",
        lambda v: {
            "snapshots": [_enc_snapshot(item) for item in v.snapshots],
            "next_cursor": v.next_cursor,
        },
        lambda d: SnapshotPage(tuple(_dec_snapshot(i) for i in d["snapshots"]), d["next_cursor"]),
    ),
    SnapshotDeleteResult: _Codec(
        "SnapshotDeleteResult",
        lambda v: {"snapshot_id": v.snapshot_id, "state": v.state},
        lambda d: SnapshotDeleteResult(d["snapshot_id"], d["state"]),
    ),
    ImageRequest: _Codec("ImageRequest", _enc_image_request, _dec_image_request),
    PreparedImage: _Codec("PreparedImage", _enc_prepared_image, _dec_prepared_image),
    ImagePage: _Codec(
        "ImagePage",
        lambda v: {
            "images": [_enc_prepared_image(item) for item in v.images],
            "next_cursor": v.next_cursor,
        },
        lambda d: ImagePage(tuple(_dec_prepared_image(i) for i in d["images"]), d["next_cursor"]),
    ),
    ImageDeleteResult: _Codec(
        "ImageDeleteResult",
        lambda v: {"id": v.id, "state": v.state},
        lambda d: ImageDeleteResult(d["id"], d["state"]),
    ),
    RunRequest: _Codec(
        "RunRequest",
        lambda v: {
            "argv": list(v.argv),
            "cwd": v.cwd,
            "env": dict(v.env),
            "timeout_ms": v.timeout_ms,
            "output_limit_bytes": v.output_limit_bytes,
            **({"user": v.user} if v.user is not None else {}),
            **({"output": v.output} if v.output != "text" else {}),
        },
        lambda d: RunRequest(
            argv=tuple(d["argv"]),
            cwd=d.get("cwd"),
            env=dict(d.get("env", {})),
            timeout_ms=d.get("timeout_ms", 60_000),
            output_limit_bytes=d.get("output_limit_bytes", 16 * 1024 * 1024),
            user=d.get("user"),
            output=d.get("output", "text"),
        ),
    ),
    RunResult: _Codec(
        "RunResult",
        lambda v: {
            "exit_code": v.exit_code,
            "stdout": v.stdout,
            "stderr": v.stderr,
            "stdout_truncated": v.stdout_truncated,
            "stderr_truncated": v.stderr_truncated,
            "timed_out": v.timed_out,
            **(
                {"stdout_base64": v.stdout_base64, "stderr_base64": v.stderr_base64}
                if v.stdout_base64 is not None or v.stderr_base64 is not None
                else {}
            ),
        },
        lambda d: RunResult(**d),
    ),
    FileInfo: _Codec(
        "FileInfo",
        lambda v: {"path": v.path, "size": v.size},
        lambda d: FileInfo(d["path"], d["size"]),
    ),
    ProcessStartRequest: _Codec(
        "ProcessStartRequest",
        lambda v: {
            "argv": list(v.argv),
            "cwd": v.cwd,
            "env": dict(v.env),
            "stdin": v.stdin,
            **({"user": v.user} if v.user is not None else {}),
        },
        lambda d: ProcessStartRequest(
            argv=tuple(d["argv"]),
            cwd=d.get("cwd"),
            env=dict(d.get("env", {})),
            stdin=d.get("stdin", False),
            user=d.get("user"),
        ),
    ),
    Process: _Codec(
        "Process",
        lambda v: {
            "id": v.id,
            "sandbox_id": v.sandbox_id,
            "started_at": _stamp(v.started_at),
        },
        lambda d: Process(d["id"], d["sandbox_id"], _time(d["started_at"])),
    ),
    OutputChunk: _Codec(
        "OutputChunk",
        lambda v: {"stream": v.stream, "data": v.data},
        lambda d: OutputChunk(d["stream"], d["data"]),
    ),
    OutputPage: _Codec("OutputPage", _enc_output_page, _dec_output_page),
    FileLinkRequest: _Codec(
        "FileLinkRequest",
        _enc_file_link_request,
        lambda d: FileLinkRequest(d["path"], d["operation"], d["lifetime_seconds"], d.get("size")),
    ),
    FileLink: _Codec(
        "FileLink",
        _enc_file_link,
        lambda d: FileLink(
            method=d["method"],
            url=d["url"],
            headers=dict(d["headers"]),
            form_field=d.get("form_field"),
            expires_at=_time(d["expires_at"]),
            reusable=d.get("reusable", False),
        ),
    ),
    PreviewLink: _Codec(
        "PreviewLink",
        lambda v: {
            "url": v.url,
            "headers": dict(v.headers),
            "expires_at": _opt(v.expires_at, _stamp),
            "id": v.id,
            "access": v.access,
            "credential": v.credential,
        },
        lambda d: PreviewLink(
            d["url"],
            dict(d["headers"]),
            _opt(d.get("expires_at"), _time),
            id=d.get("id"),
            access=d.get("access", "public"),
            credential=d.get("credential"),
        ),
    ),
    TcpLink: _Codec(
        "TcpLink",
        lambda v: {"host": v.host, "port": v.port},
        lambda d: TcpLink(d["host"], d["port"]),
    ),
    DirectoryEntry: _Codec(
        "DirectoryEntry",
        lambda v: {"name": v.name, "type": v.type, "size": v.size},
        lambda d: DirectoryEntry(d["name"], d["type"], d["size"]),
    ),
    DirectoryPage: _Codec(
        "DirectoryPage",
        lambda v: {
            "entries": [{"name": e.name, "type": e.type, "size": e.size} for e in v.entries],
            "next_cursor": v.next_cursor,
        },
        lambda d: DirectoryPage(
            tuple(DirectoryEntry(e["name"], e["type"], e["size"]) for e in d["entries"]),
            d["next_cursor"],
        ),
    ),
    PathInfo: _Codec(
        "PathInfo",
        lambda v: {"exists": v.exists, "type": v.type},
        lambda d: PathInfo(d["exists"], d["type"]),
    ),
    TerminalLink: _Codec(
        "TerminalLink",
        lambda v: {"url": v.url, "headers": dict(v.headers), "expires_at": _stamp(v.expires_at)},
        lambda d: TerminalLink(d["url"], dict(d["headers"]), _time(d["expires_at"])),
    ),
    TerminalRequest: _Codec(
        "TerminalRequest",
        lambda v: {
            "argv": None if v.argv is None else list(v.argv),
            "cwd": v.cwd,
            "env": dict(v.env),
            "columns": v.columns,
            "rows": v.rows,
            "term": v.term,
        },
        lambda d: TerminalRequest(
            argv=None if d.get("argv") is None else tuple(d["argv"]),
            cwd=d.get("cwd"),
            env=dict(d.get("env", {})),
            columns=d.get("columns", 80),
            rows=d.get("rows", 24),
            term=d.get("term", "xterm-256color"),
        ),
    ),
    Limits: _Codec("Limits", _enc_limits, lambda d: Limits(**d)),
    ProviderInfo: _Codec(
        "ProviderInfo",
        _enc_provider_info,
        lambda d: ProviderInfo(d["id"], d["name"], d.get("docs_url")),
    ),
    Image: _Codec("Image", _enc_image, lambda d: Image(d["id"], d["default"], d["description"])),
    SandboxClass: _Codec("SandboxClass", _enc_class, _dec_class),
    Discovery: _Codec("Discovery", _enc_discovery, _dec_discovery),
}


def _secret_values(data: Any) -> list[str]:
    """The `secrets[].value` strings of a create body (or of one secret), for redaction."""
    items = data.get("secrets") if isinstance(data, dict) else None
    if isinstance(items, list):
        found = [item.get("value") for item in items if isinstance(item, dict)]
    else:
        found = [data.get("value")] if isinstance(data, dict) else []
    return [value for value in found if isinstance(value, str) and value]


def _error_text(schema: str, error: ValidationError, values: Sequence[str]) -> str:
    """One validation error as text that carries no secret value.

    A schema message may quote the offending instance, and a create's secret values must reach
    no error body or log line. An error inside a secret says only which rule failed; any other
    message has every secret value cut out of it, in plain, `repr` and JSON spelling.
    """
    path = list(error.path)
    if schema == "Secret" or (schema == "CreateRequest" and path[:1] == ["secrets"]):
        return f"does not satisfy {error.validator}"
    text = error.message
    for value in values:
        for spelling in (value, repr(value)[1:-1], json.dumps(value)[1:-1]):
            text = text.replace(spelling, "[redacted]")
    return text[:200]


def _check(schema: str, data: Any) -> None:
    errors = sorted(validator(schema).iter_errors(data), key=lambda error: list(error.path))
    if errors:
        values = _secret_values(data) if schema in ("CreateRequest", "Secret") else []
        details = "; ".join(
            f"{'/'.join(map(str, error.path)) or '(root)'}: {_error_text(schema, error, values)}"
            for error in errors[:5]
        )
        raise WireError(f"not a valid {schema}: {details}")


def to_json(value: object) -> Json:
    """The JSON form of a 1.0 value. Raises `WireError` when it does not fit its schema."""
    codec = _CODECS.get(type(value))
    if codec is None:
        raise TypeError(f"{type(value).__name__} has no JSON form")
    data = codec.encode(value)
    _check(codec.schema, data)
    return data


def from_json(cls: type[T], data: object) -> T:
    """The 1.0 value of a JSON document. Raises `WireError` when the document does not fit the
    schema of `cls`; an unknown field of a result is accepted and dropped."""
    codec = _CODECS.get(cls)
    if codec is None:
        raise TypeError(f"{cls.__name__} has no JSON form")
    _check(codec.schema, data)
    assert isinstance(data, dict)
    return cast(T, codec.decode(data))


# --- errors ------------------------------------------------------------------------------


def _enc_error_body(error: SpsError) -> Json:
    body: Json = {
        "code": error.code,
        "message": error.message[:1024],
        "outcome": error.outcome,
        "retry_after_seconds": error.retry_after_seconds,
    }
    _put(body, "failed_step", error.failed_step)
    _put(body, "field", error.field)
    return body


def _dec_error_body(body: Mapping[str, Any]) -> SpsError:
    code = body["code"]
    assert code in ERROR_TABLE
    outcome: Outcome = body["outcome"] if ERROR_TABLE[code][1] == "provider" else "failed"
    return SpsError(
        code,
        body["message"],
        outcome=outcome,
        retry_after_seconds=body.get("retry_after_seconds"),
        failed_step=body.get("failed_step"),
        field=body.get("field"),
    )


def error_to_json(error: SpsError) -> Json:
    """The body of an error response."""
    body = _enc_error_body(error)
    _check("ErrorResponse", {"error": body})
    return {"error": body}


def error_from_json(data: object) -> SpsError:
    """The `SpsError` of an error response body. A body that is not a valid error response
    counts as `provider_error` with outcome `unknown` (the standard's rule for a dropped
    connection or a proxy's page)."""
    try:
        _check("ErrorResponse", data)
    except WireError:
        return SpsError(
            "provider_error", "The response was not a valid error response", outcome="unknown"
        )
    assert isinstance(data, dict)
    return _dec_error_body(cast(Mapping[str, Any], data["error"]))
