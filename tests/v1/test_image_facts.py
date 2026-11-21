# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Image facts, OCI layout, image bindings, image cost, and the error fields (S13 to S17)."""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import io
import json
import tarfile
from collections.abc import Mapping
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any, ClassVar

import httpx
import pytest
import yaml
from test_images import (  # noqa: F401  (the fixture `served`)
    FORM,
    ImageProvider,
    error_code,
    form,
    oci,
    post,
    request_part,
    served_fixture,
    tar_of,
)
from test_tester import with_operations

from sandbox_provider_spec.v1 import (
    Cost,
    CostLine,
    CredentialField,
    Provider,
    SandboxClass,
    SpsError,
    from_json,
    suite_driver_images,
    to_json,
)
from sandbox_provider_spec.v1.errors import ERROR_TABLE
from sandbox_provider_spec.v1.http_client import HttpProvider
from sandbox_provider_spec.v1.oci_layout import LayoutError, build_layout, split_reference
from sandbox_provider_spec.v1.server import create_app
from sandbox_provider_spec.v1.tester import TestOptions, run_tests, select_tests, shared_suite
from sandbox_provider_spec.v1.types import (
    Discovery,
    DockerfileSource,
    ImageConfig,
    ImageRequest,
    OciSource,
)
from sandbox_provider_spec.v1.wire import WireError, error_from_json, error_to_json

SPEC = Path(__file__).resolve().parents[2] / "spec"
EXAMPLES = SPEC / "provider-api-1.0-examples"
BASE = "https://provider.test"
BEARER = "tok-abcdef"
WHEN = datetime(2026, 11, 20, 12, 0, tzinfo=UTC)
IMAGE_OPS = ["image.prepare", "image.get", "image.list", "image.delete"]


def load(name: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((EXAMPLES / f"{name}.json").read_text(encoding="utf-8"))
    return data


def image_cost_body() -> dict[str, Any]:
    return {
        "image_id": "img-1",
        "status": "final",
        "total_usd": "0.002",
        "source": "reported",
        "lines": [{"item": "machine", "amount_usd": "0.002", "start": None, "end": None}],
        "as_of": "2026-11-20T12:00:00Z",
    }


# --- S17: error fields --------------------------------------------------------------------


@pytest.mark.rule("provider-api/error-failed-step")
def test_failed_step_and_field_round_trip_on_an_error_body() -> None:
    error = SpsError("invalid_request", "RUN 3 failed", failed_step=3, field="source")
    body = error_to_json(error)
    assert body["error"]["failed_step"] == 3
    assert body["error"]["field"] == "source"
    back = error_from_json(body)
    assert (back.failed_step, back.field) == (3, "source")
    assert (back.code, back.outcome) == ("invalid_request", "failed")


def test_an_error_without_them_writes_neither_field() -> None:
    body = error_to_json(SpsError("not_found", "no such image"))
    assert "failed_step" not in body["error"]
    assert "field" not in body["error"]
    back = error_from_json(body)
    assert (back.failed_step, back.field) == (None, None)


def test_failed_step_counts_from_one_and_field_is_not_empty() -> None:
    bad_kwargs: tuple[dict[str, Any], ...] = ({"failed_step": 0}, {"field": ""})
    for bad in bad_kwargs:
        with pytest.raises(ValueError):
            SpsError("invalid_request", "x", **bad)
    for bad_body in ({"failed_step": 0}, {"failed_step": "2"}, {"field": ""}):
        error = {**load("Error"), **bad_body}
        assert error_from_json({"error": error}).code == "provider_error"


def test_a_create_that_never_booted_its_image_names_the_image_field() -> None:
    error = SpsError("provider_error", "the image did not boot", outcome="unknown", field="image")
    assert ERROR_TABLE["provider_error"][1] == "provider"
    assert error_from_json(error_to_json(error)).field == "image"


# --- S13: image facts ---------------------------------------------------------------------

DIGEST = "sha256:" + "cd" * 32


def request_body(**config: Any) -> dict[str, Any]:
    body = load("ImageRequest")
    body["source"]["config"] = {**body["source"]["config"], **config}
    return body


def test_image_facts_round_trip_on_an_oci_config() -> None:
    body = request_body(init=True, user_name="app", home="/home/app")
    request = from_json(ImageRequest, body)
    config = request.source.config  # type: ignore[union-attr]
    assert (config.init, config.user_name, config.home) == (True, "app", "/home/app")
    assert to_json(request) == body


def test_image_facts_are_optional_and_absent_ones_are_not_written() -> None:
    body = request_body()
    config = from_json(ImageRequest, body).source.config  # type: ignore[union-attr]
    assert (config.init, config.user_name, config.home) == (None, None, None)
    assert to_json(from_json(ImageRequest, body)) == body
    assert from_json(ImageRequest, request_body(init=None)).source.config.init is None  # type: ignore[union-attr]


@pytest.mark.parametrize(
    "facts", [{"init": "yes"}, {"user_name": 3}, {"home": "relative"}, {"base": {}}], ids=repr
)
def test_image_facts_refuse_what_is_not_a_fact(facts: dict[str, Any]) -> None:
    with pytest.raises(WireError):
        from_json(ImageRequest, request_body(**facts))


def test_a_dockerfile_source_carries_its_resolved_from_image() -> None:
    base = {
        "oci": "docker.io/library/alpine:3.20",
        "digest": DIGEST,
        "config": {"env": {"A": "b"}, "init": False, "user_name": "root", "home": "/root"},
    }
    body = {"source": {"dockerfile": "FROM alpine:3.20\nRUN true\n", "base": base}, "labels": {}}
    request = from_json(ImageRequest, body)
    source = request.source
    assert isinstance(source, DockerfileSource)
    assert isinstance(source.base, OciSource)
    assert (source.base.oci, source.base.digest) == (base["oci"], DIGEST)
    assert source.base.config.home == "/root"
    config = to_json(request)["source"]["base"]["config"]
    assert {key: config[key] for key in ("env", "init", "user_name", "home")} == base["config"]
    assert from_json(ImageRequest, to_json(request)) == request
    plain = from_json(ImageRequest, {"source": {"dockerfile": "FROM scratch\n"}})
    assert plain.source == DockerfileSource("FROM scratch\n")
    assert "base" not in to_json(plain)["source"]


@pytest.mark.parametrize("drop", ["oci", "digest", "config"])
def test_the_resolved_from_image_needs_its_reference_digest_and_config(drop: str) -> None:
    base = {"oci": "alpine:3", "digest": DIGEST, "config": {}}
    del base[drop]
    with pytest.raises(WireError):
        from_json(ImageRequest, {"source": {"dockerfile": "FROM alpine:3", "base": base}})


def test_image_facts_have_defaults_in_python() -> None:
    assert ImageConfig() == ImageConfig(init=None, user_name=None, home=None)


# --- S14: OCI layout, over the reference server -------------------------------------------

LAYOUT = tar_of({"oci-layout": b'{"imageLayoutVersion": "1.0.0"}', "index.json": b"{}"})
LAYOUT_LIMIT = 16384
OPERATIONS_WITH_LAYOUT = (*IMAGE_OPS, "image.prepare.oci_layout")


class LayoutProvider(ImageProvider, manifest=False):
    """An image provider that lists `image.prepare.oci_layout`."""

    async def discovery(self) -> Discovery:
        found = with_operations(OPERATIONS_WITH_LAYOUT)
        limits = dataclasses.replace(found.limits, image_layout_bytes=LAYOUT_LIMIT)
        return dataclasses.replace(found, limits=limits)


@pytest.fixture(name="provider")
def layout_provider_fixture() -> Any:
    ImageProvider.reset()
    yield LayoutProvider()
    ImageProvider.reset()


@pytest.fixture(name="laid")
def laid_fixture() -> Any:
    ImageProvider.reset()
    app = create_app(LayoutProvider)
    transport = httpx.ASGITransport(app=app)
    client = HttpProvider("http://localhost", "token", transport=transport)
    yield client
    asyncio.run(client.aclose())
    ImageProvider.reset()


@pytest.mark.rule("provider-api/image-oci-layout")
def test_oci_layout_reaches_the_provider_as_the_context_of_an_oci_source(
    laid: HttpProvider,
) -> None:
    response = post(laid, form(request_part(oci()), ("context", LAYOUT, "")), **FORM)
    assert response.status_code == 201, response.text
    seen = ImageProvider.seen[0]
    assert seen["bytes"] == LAYOUT
    assert type(seen["request"].source).__name__ == "OciSource"


@pytest.mark.rule("provider-api/image-oci-layout")
def test_oci_layout_is_required_with_every_oci_source_of_a_provider_that_lists_it(
    laid: HttpProvider,
) -> None:
    response = post(laid, form(request_part(oci())), **FORM)
    assert error_code(response) == (400, "invalid_request", "failed")
    assert response.json()["error"]["field"] == "context"
    assert not ImageProvider.images


@pytest.mark.rule("provider-api/image-oci-layout")
def test_oci_layout_is_bounded_by_image_layout_bytes(laid: HttpProvider) -> None:
    big = b"x" * (LAYOUT_LIMIT + 1)
    assert error_code(post(laid, form(request_part(oci()), ("context", big, "")), **FORM)) == (
        413,
        "too_large",
        "failed",
    )
    assert not ImageProvider.images


def test_a_dockerfile_context_is_not_bounded_by_the_layout_limit(laid: HttpProvider) -> None:
    dockerfile = request_part()
    body = form(dockerfile, ("context", b"x" * (LAYOUT_LIMIT + 1), ""))
    assert post(laid, body, **FORM).status_code == 201


def test_without_oci_layout_an_oci_source_takes_no_context(served: HttpProvider) -> None:
    response = post(served, form(request_part(oci()), ("context", LAYOUT, "")), **FORM)
    assert error_code(response) == (400, "invalid_request", "failed")
    assert post(served, form(request_part(oci())), **FORM).status_code == 201


# --- S15: which resources a prepared image is bound to ------------------------------------


def a_class(**changes: Any) -> dict[str, Any]:
    body = {**load("SandboxClass"), **changes}
    if "image_binds" in changes:
        body["operations"] = IMAGE_OPS
    return body


def test_image_binds_round_trips_and_is_absent_by_default() -> None:
    plain = from_json(SandboxClass, a_class())
    assert plain.image_binds is None
    assert "image_binds" not in to_json(plain)
    body = a_class(image_binds=["cpu_min", "region"])
    value = from_json(SandboxClass, body)
    assert tuple(value.image_binds or ()) == ("cpu_min", "region")
    assert to_json(value) == body


def test_an_empty_image_binds_means_any_size_and_is_kept() -> None:
    body = a_class(image_binds=[])
    value = from_json(SandboxClass, body)
    assert value.image_binds == ()
    assert to_json(value) == body


@pytest.mark.parametrize("binds", [["cpu"], ["region", "region"], ["gpu"], "region", [1]], ids=repr)
def test_image_binds_refuses_what_is_not_a_bind(binds: Any) -> None:
    with pytest.raises(WireError):
        from_json(SandboxClass, a_class(image_binds=binds))


def test_every_bind_is_one_of_the_five() -> None:
    items = _schema("SandboxClass")["properties"]["image_binds"]["items"]["enum"]
    assert items == ["cpu_min", "memory_min_mib", "disk_min_mib", "region", "kernel"]


# --- S14: OCI layout ----------------------------------------------------------------------


def discovery_body(**limits: Any) -> dict[str, Any]:
    body = load("Discovery")
    body["limits"] = {**body["limits"], **limits}
    return body


def test_oci_layout_is_an_operation_a_class_may_list() -> None:
    items = _schema("SandboxClass")["properties"]["operations"]["items"]["enum"]
    assert "image.prepare.oci_layout" in items
    assert "image.cost" in items


def test_image_layout_bytes_is_a_limit() -> None:
    body = discovery_body(image_layout_bytes=2**30)
    assert from_json(Discovery, body).limits.image_layout_bytes == 2**30
    assert to_json(from_json(Discovery, body)) == body
    assert from_json(Discovery, discovery_body()).limits.image_layout_bytes is None
    with pytest.raises(WireError):
        from_json(Discovery, discovery_body(image_layout_bytes=0))


def body_with(operations: list[str], **limits: Any) -> dict[str, Any]:
    body = discovery_body(**limits)
    first = body["classes"][0]
    first["operations"] = operations
    first["image_binds"] = []
    return body


def test_oci_layout_needs_the_image_operations_and_a_layout_limit() -> None:
    ok = body_with([*IMAGE_OPS, "image.prepare.oci_layout"], image_layout_bytes=2**30)
    assert from_json(Discovery, ok).classes[0].operations[-1] == "image.prepare.oci_layout"
    for body in (
        body_with([*IMAGE_OPS, "image.prepare.oci_layout"]),  # no limit
        body_with(["image.prepare.oci_layout"], image_layout_bytes=2**30),  # no operations
    ):
        with pytest.raises(WireError):
            from_json(Discovery, body)


def test_image_cost_needs_a_provider_that_offers_cost() -> None:
    offered = body_with([*IMAGE_OPS, "image.cost"], cost_final_within_seconds=60)
    assert from_json(Discovery, offered).classes[0].operations[-1] == "image.cost"
    body = body_with([*IMAGE_OPS, "image.cost"])
    body["limits"].pop("cost_final_within_seconds", None)
    with pytest.raises(WireError):
        from_json(Discovery, body)
    body = body_with(["image.cost"], cost_final_within_seconds=60)
    with pytest.raises(WireError):
        from_json(Discovery, body)


def test_image_binds_only_with_image_prepare() -> None:
    body = body_with(IMAGE_OPS)
    assert from_json(Discovery, body).classes[0].image_binds == ()
    body["classes"][0]["operations"] = []
    with pytest.raises(WireError):
        from_json(Discovery, body)


# --- S16: image cost ----------------------------------------------------------------------


class Imager(Provider, manifest=False):
    provider_id = "imager"
    name = "Imager"
    spec_version = "1.0"
    credential_fields: ClassVar[tuple[CredentialField, ...]] = (CredentialField("api_key"),)
    seen: ClassVar[list[tuple[str, datetime | None]]] = []

    async def discovery(self) -> Discovery:
        raise NotImplementedError

    async def create(self, request: Any, *, idempotency_key: str) -> Any:
        raise NotImplementedError

    async def get(self, sandbox_id: str) -> Any:
        raise NotImplementedError

    async def list(self, **_: Any) -> Any:
        raise NotImplementedError

    async def destroy(self, sandbox_id: str) -> Any:
        raise NotImplementedError

    async def run(self, sandbox_id: str, request: Any) -> Any:
        raise NotImplementedError

    async def files_read(self, sandbox_id: str, path: str) -> Any:
        raise NotImplementedError

    async def files_write(
        self, sandbox_id: str, path: str, data: Any, *, size: int, user: str | None = None
    ) -> Any:
        raise NotImplementedError

    async def process_start(self, sandbox_id: str, request: Any) -> Any:
        raise NotImplementedError

    async def process_output(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError

    async def image_cost(self, image_id: str, *, created_at: datetime | None = None) -> Cost:
        type(self).seen.append((image_id, created_at))
        if image_id == "img-gone":
            raise SpsError("not_found", "no such image")
        return Cost(
            sandbox_id=None,
            image_id=image_id,
            status="final",
            total_usd=Decimal("0.002"),
            source="reported",
            lines=(CostLine("machine", Decimal("0.002")),),
            as_of=WHEN,
        )


class NoCost(Imager, manifest=False):
    image_cost = Provider.image_cost


def client(provider: type[Provider]) -> HttpProvider:
    transport = httpx.ASGITransport(app=create_app(provider))
    return HttpProvider(BASE, BEARER, transport=transport)


def run_image_cost(provider: type[Provider], image_id: str, **kwargs: Any) -> Any:
    async def go() -> Any:
        api = client(provider)
        try:
            return await api.image_cost(image_id, **kwargs)
        finally:
            await api.aclose()

    return asyncio.run(go())


def test_image_cost_is_a_cost_with_an_image_id_and_no_sandbox() -> None:
    Imager.seen = []
    cost = run_image_cost(Imager, "img-1")
    assert (cost.image_id, cost.sandbox_id, cost.status) == ("img-1", None, "final")
    assert cost.total_usd == Decimal("0.002")
    assert to_json(cost) == image_cost_body()
    assert Imager.seen == [("img-1", None)]


def test_image_cost_passes_the_creation_time_hint() -> None:
    Imager.seen = []
    run_image_cost(Imager, "img-1", created_at=WHEN)
    assert Imager.seen == [("img-1", WHEN)]


def test_image_cost_of_an_unknown_image_is_not_found() -> None:
    with pytest.raises(SpsError) as raised:
        run_image_cost(Imager, "img-gone")
    assert raised.value.code == "not_found"


def test_image_cost_is_unsupported_unless_the_provider_offers_it() -> None:
    with pytest.raises(SpsError) as raised:
        run_image_cost(NoCost, "img-1")
    assert raised.value.code == "unsupported"
    assert "image.cost" in raised.value.message


@pytest.mark.parametrize("hint", ["yesterday", "2026-11-20T12:00:00", "2026-11-20"])
def test_image_cost_refuses_a_created_at_that_is_not_an_rfc3339_time(hint: str) -> None:
    async def go() -> Any:
        app = create_app(Imager)
        sent: dict[str, Any] = {}
        scope = {
            "type": "http",
            "method": "GET",
            "path": "/v1/images/img-1/cost",
            "query_string": f"created_at={hint}".encode(),
            "headers": [(b"authorization", f"Bearer {BEARER}".encode())],
        }

        async def receive() -> dict[str, Any]:
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message: Mapping[str, Any]) -> None:
            if message["type"] == "http.response.start":
                sent["status"] = message["status"]

        await app(scope, receive, send)
        return sent["status"]

    assert asyncio.run(go()) == 400


def test_an_image_cost_needs_a_sandbox_or_an_image() -> None:
    assert from_json(Cost, image_cost_body()).image_id == "img-1"
    body = image_cost_body()
    del body["image_id"]
    with pytest.raises(WireError):
        from_json(Cost, body)
    assert from_json(Cost, load("Cost")).image_id is None


# --- helpers ------------------------------------------------------------------------------


def _schema(name: str) -> dict[str, Any]:
    document = yaml.safe_load((SPEC / "provider-api-1.0.openapi.yaml").read_text(encoding="utf-8"))
    schema: dict[str, Any] = document["components"]["schemas"][name]
    return schema


# --- S14: the tester builds the layout it sends ---------------------------------------------


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


class FakeRegistry:
    """A registry that asks for a token, serves a two-platform index, one manifest and its blobs."""

    def __init__(self, *, corrupt: str | None = None) -> None:
        self.layer = b"layer-bytes" * 100
        self.config = json.dumps({"os": "linux", "architecture": "amd64"}).encode()
        self.manifest = json.dumps(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {"digest": _sha(self.config), "size": len(self.config)},
                "layers": [{"digest": _sha(self.layer), "size": len(self.layer)}],
            }
        ).encode()
        self.index = json.dumps(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [
                    {
                        "digest": "sha256:" + "11" * 32,
                        "platform": {"os": "linux", "architecture": "arm64"},
                    },
                    {
                        "digest": _sha(self.manifest),
                        "platform": {"os": "linux", "architecture": "amd64"},
                    },
                ],
            }
        ).encode()
        self.corrupt = corrupt
        self.paths: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.url.host == "auth.test":
            return httpx.Response(200, json={"token": "t0k"})
        self.paths.append(path)
        if request.headers.get("authorization") != "Bearer t0k":
            challenge = 'Bearer realm="https://auth.test/token",service="reg.test",scope="pull"'
            return httpx.Response(401, headers={"www-authenticate": challenge})
        blobs = {
            _sha(self.index): (self.index, "application/vnd.oci.image.index.v1+json"),
            _sha(self.manifest): (self.manifest, "application/vnd.oci.image.manifest.v1+json"),
            _sha(self.config): (self.config, "application/octet-stream"),
            _sha(self.layer): (self.layer, "application/octet-stream"),
        }
        digest = path.rsplit("/", 1)[-1]
        if digest not in blobs:
            return httpx.Response(404)
        data, media = blobs[digest]
        if digest == self.corrupt:
            data = data + b"!"
        return httpx.Response(200, content=data, headers={"content-type": media})


def test_the_tester_builds_an_oci_layout_of_a_public_image_by_digest() -> None:
    registry = FakeRegistry()
    client = httpx.Client(transport=httpx.MockTransport(registry))
    layout = build_layout(
        f"reg.test/team/app@{_sha(registry.index)}", _sha(registry.index), client=client
    )
    with tarfile.open(fileobj=io.BytesIO(layout)) as archive:
        names = sorted(archive.getnames())
        assert json.loads(archive.extractfile("oci-layout").read()) == {  # type: ignore[union-attr]
            "imageLayoutVersion": "1.0.0"
        }
        index = json.loads(archive.extractfile("index.json").read())  # type: ignore[union-attr]
        layer = archive.extractfile(f"blobs/sha256/{_sha(registry.layer)[7:]}").read()  # type: ignore[union-attr]
    assert index["manifests"][0]["digest"] == _sha(registry.index)
    assert layer == registry.layer
    assert len([name for name in names if name.startswith("blobs/sha256/")]) == 4
    assert all("/v2/team/app/" in path for path in registry.paths)
    assert not any("1111" in path for path in registry.paths)  # the other platform is not read


@pytest.mark.parametrize("what", ["index", "layer"])
def test_a_blob_that_does_not_match_its_digest_is_refused(what: str) -> None:
    registry = FakeRegistry()
    registry.corrupt = _sha(getattr(registry, what))
    client = httpx.Client(transport=httpx.MockTransport(registry))
    with pytest.raises(LayoutError, match="came back as"):
        build_layout("reg.test/team/app", _sha(registry.index), client=client)


def test_an_image_the_registry_does_not_have_is_a_layout_error() -> None:
    client = httpx.Client(transport=httpx.MockTransport(FakeRegistry()))
    with pytest.raises(LayoutError, match="404"):
        build_layout("reg.test/team/app", "sha256:" + "22" * 32, client=client)
    with pytest.raises(LayoutError, match="digest"):
        build_layout("reg.test/team/app", "latest", client=client)


@pytest.mark.parametrize(
    ("reference", "expected"),
    [
        ("docker.io/library/alpine@sha256:ab", ("docker.io", "library/alpine")),
        ("alpine:3.20", ("docker.io", "library/alpine")),
        ("org/img:1", ("docker.io", "org/img")),
        ("ghcr.io/org/img:1@sha256:cd", ("ghcr.io", "org/img")),
        ("localhost:5000/x/y:t", ("localhost:5000", "x/y")),
    ],
)
def test_a_reference_splits_into_a_registry_and_a_repository(
    reference: str, expected: tuple[str, str]
) -> None:
    assert split_reference(reference) == expected


# --- the tester: image.cost and the layout ------------------------------------------------


class CostingImages(ImageProvider, manifest=False):
    """An image provider that lists `image.cost` and offers cost."""

    cost_status = "final"
    costs_read: ClassVar[list[str]] = []

    async def discovery(self) -> Discovery:
        found = with_operations((*IMAGE_OPS, "image.cost"))
        limits = dataclasses.replace(found.limits, cost_final_within_seconds=0)
        return dataclasses.replace(found, limits=limits)

    async def image_cost(self, image_id: str, *, created_at: datetime | None = None) -> Cost:
        type(self).costs_read.append(image_id)
        if image_id not in self.images:
            raise SpsError("not_found", "no such image")
        return Cost(
            sandbox_id=None,
            image_id=image_id,
            status=type(self).cost_status,  # type: ignore[arg-type]
            total_usd=Decimal("0.001"),
            source="reported",
            lines=(CostLine("machine", Decimal("0.001")),),
            as_of=WHEN,
        )


@pytest.fixture(name="costing")
def costing_fixture() -> Any:
    ImageProvider.reset()
    CostingImages.cost_status, CostingImages.costs_read = "final", []
    yield CostingImages()
    ImageProvider.reset()


def outcomes(report: Any) -> dict[str, str]:
    return {str(row["id"]): str(row["result"]) for row in report["tests"]}


def test_the_images_cost_test_runs_only_for_a_class_that_lists_image_cost() -> None:
    suite = shared_suite()
    plain = {
        t.id for t in select_tests(suite, with_operations(tuple(IMAGE_OPS)), TestOptions()).tests
    }
    found = asyncio.run(CostingImages().discovery())
    listed = {t.id for t in select_tests(suite, found, TestOptions()).tests}
    assert "images.v1.cost" not in plain
    assert "images.v1.cost" in listed


def test_image_cost_passes_the_images_cost_test_and_reads_the_prepared_image(
    costing: CostingImages,
) -> None:
    report = run_tests(costing, TestOptions(tests=("images.v1.cost",)))
    assert outcomes(report) == {"images.v1.cost": "passed"}, report["tests"]
    assert len(CostingImages.costs_read) == 1
    assert all(image.id in ImageProvider.deleted for image in ImageProvider.images.values())


def test_image_cost_that_names_the_wrong_image_fails_its_test(costing: CostingImages) -> None:
    original = CostingImages.image_cost

    async def wrong(self: CostingImages, image_id: str, **_: Any) -> Cost:
        cost = await original(self, image_id)
        return dataclasses.replace(cost, image_id="img-other")

    CostingImages.image_cost = wrong  # type: ignore[method-assign]
    try:
        report = run_tests(costing, TestOptions(tests=("images.v1.cost",)))
    finally:
        CostingImages.image_cost = original  # type: ignore[method-assign]
    assert outcomes(report) == {"images.v1.cost": "differs"}


def test_a_provider_that_lists_oci_layout_is_sent_the_layout_of_each_oci_image(
    provider: LayoutProvider, monkeypatch: pytest.MonkeyPatch
) -> None:
    built: list[tuple[str, str]] = []

    def build(reference: str, digest: str) -> bytes:
        built.append((reference, digest))
        return LAYOUT

    monkeypatch.setattr(suite_driver_images, "build_layout", build)
    report = run_tests(provider, TestOptions(tests=("images.v1.prepare_oci",)))
    assert outcomes(report) == {"images.v1.prepare_oci": "passed"}, report["tests"]
    assert built and built[0][1].startswith("sha256:")
    assert ImageProvider.seen[0]["bytes"] == LAYOUT
    assert ImageProvider.seen[0]["size"] == len(LAYOUT)


def test_a_provider_that_lists_no_layout_is_sent_no_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ImageProvider.reset()

    def never(reference: str, digest: str) -> bytes:
        raise AssertionError("a layout was built")

    monkeypatch.setattr(suite_driver_images, "build_layout", never)
    report = run_tests(ImageProvider(), TestOptions(tests=("images.v1.prepare_oci",)))
    assert outcomes(report) == {"images.v1.prepare_oci": "passed"}
    assert ImageProvider.seen[0]["bytes"] == b""
    ImageProvider.reset()


def test_an_oci_layout_that_cannot_be_built_is_not_run_rather_than_failed(
    provider: LayoutProvider, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(reference: str, digest: str) -> bytes:
        raise LayoutError("the registry answered 503")

    monkeypatch.setattr(suite_driver_images, "build_layout", broken)
    report = run_tests(provider, TestOptions(tests=("images.v1.prepare_oci",)))
    assert outcomes(report) == {"images.v1.prepare_oci": "not_run"}
    assert not ImageProvider.images
