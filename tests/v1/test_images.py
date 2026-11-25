# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Prepared images (`image.*`): the wire forms, the streaming multipart reader, the reference
server and `HttpProvider` end to end, and the tester's `images` section."""

from __future__ import annotations

import asyncio
import dataclasses
import io
import json
import os
import tarfile
from collections.abc import AsyncIterable, AsyncIterator, Mapping
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from test_openapi import validator
from test_tester import LocalProvider, example, with_gates, with_operations

from sandbox_provider_spec.driver import NotRun
from sandbox_provider_spec.runner import ALPINE_IMAGE
from sandbox_provider_spec.v1 import (
    CreateRequest,
    Discovery,
    DockerfileSource,
    FileStream,
    ImageConfig,
    ImageDeleteResult,
    ImagePage,
    ImageRequest,
    ImageResources,
    OciSource,
    PreparedImage,
    PrivateOciSource,
    RegistryCredentials,
    RunRequest,
    RunResult,
    Sandbox,
    SpsError,
    from_json,
    to_json,
)
from sandbox_provider_spec.v1 import image_upload as image_upload_module
from sandbox_provider_spec.v1.http_client import HttpProvider
from sandbox_provider_spec.v1.multipart import (
    MultipartError,
    MultipartReader,
    boundary_of,
)
from sandbox_provider_spec.v1.server import create_app
from sandbox_provider_spec.v1.suite_driver import ProviderDriver
from sandbox_provider_spec.v1.tester import (
    CLAIMED_TESTS,
    TestOptions,
    claimed_sections,
    run_tests,
    select_tests,
    shared_suite,
    unsupported_operations,
)

DIGEST = "sha256:" + "ab" * 32
IMAGE_OPERATIONS = ("image.prepare", "image.get", "image.list", "image.delete")
MIB = 1024 * 1024
KEY = "image-key-0001"


def oci(**kwargs: Any) -> ImageRequest:
    return ImageRequest(OciSource("docker.io/library/alpine:3.20", DIGEST, ImageConfig()), **kwargs)


async def source_of(data: bytes, step: int) -> AsyncIterator[bytes]:
    for start in range(0, len(data), step):
        yield data[start : start + step]


# --- the wire forms ------------------------------------------------------------------------


def test_every_image_example_is_a_valid_value_and_round_trips() -> None:
    for cls in (ImageRequest, PreparedImage, ImagePage, ImageDeleteResult):
        value = example(cls)
        assert from_json(cls, to_json(value)) == value


def test_an_image_reports_when_it_was_last_used_and_an_older_server_reports_nothing() -> None:
    image = example(PreparedImage)
    assert image.last_used_at == datetime(2026, 11, 24, 16, 33, tzinfo=UTC)
    document = dict(to_json(image))
    assert document["last_used_at"] == "2026-11-24T16:33:00Z"
    del document["last_used_at"]
    assert from_json(PreparedImage, document).last_used_at is None


def test_the_three_sources_round_trip() -> None:
    config = ImageConfig(
        env={"A": "b"}, workdir="/app", user="1000", entrypoint=("/e",), cmd=("c",)
    )
    for source in (
        OciSource("a:1", DIGEST, config),
        PrivateOciSource("p:1", DIGEST, config, RegistryCredentials("user", "pw")),
        DockerfileSource("FROM scratch\n"),
    ):
        request = ImageRequest(source, ImageResources(cpu=1.5, memory_mib=512), {"k": "v"})
        assert from_json(ImageRequest, to_json(request)) == request


def test_a_failed_image_carries_its_error_body() -> None:
    error = SpsError("provider_error", "the build failed", outcome="unknown")
    image = dataclasses.replace(example(PreparedImage), state="failed", error=error)
    back = from_json(PreparedImage, to_json(image))
    assert (back.error.code, back.error.outcome) == ("provider_error", "unknown")  # type: ignore[union-attr]


def test_registry_credentials_never_show_in_a_repr() -> None:
    credentials = RegistryCredentials("alice", "hunter2-secret")
    assert "hunter2" not in repr(credentials) and "alice" not in repr(credentials)
    request = ImageRequest(PrivateOciSource("p:1", DIGEST, ImageConfig(), credentials))
    assert "hunter2" not in repr(request)


def test_an_image_request_has_exactly_one_source_and_no_unknown_field() -> None:
    base = to_json(oci())
    check = validator("ImageRequest")
    assert check.is_valid(base)
    assert not check.is_valid({**base, "no_such_field": 1})
    both = {**base, "source": {**base["source"], "dockerfile": "FROM x"}}
    assert not check.is_valid(both)
    assert not check.is_valid({**base, "source": {"oci": "a:1", "config": {}}})  # no digest
    assert not check.is_valid(
        {**base, "source": {"oci": "a:1", "digest": "sha256:1", "config": {}}}
    )


def test_the_image_operations_are_listed_whole_or_not_at_all() -> None:
    check = validator("SandboxClass")
    cls = example(Discovery).classes[0]
    base = dataclasses.replace(cls, operations=())

    def valid(operations: tuple[str, ...]) -> bool:
        return check.is_valid({**to_json(base), "operations": list(operations)})

    assert valid(()) and valid(IMAGE_OPERATIONS)
    assert not valid(IMAGE_OPERATIONS[:3])
    four = ("files.list", "files.mkdir", "files.remove", "files.exists")
    assert valid(four) and valid(four + IMAGE_OPERATIONS) and not valid(four[:2])


def test_the_context_limit_is_a_discovery_limit_of_at_least_512_mib() -> None:
    check = validator("Limits")
    limits = to_json(example(Discovery).limits)
    assert check.is_valid({**limits, "image_context_bytes": 512 * MIB})
    assert not check.is_valid({**limits, "image_context_bytes": 512 * MIB - 1})


# --- the multipart reader ------------------------------------------------------------------


def form(*parts: tuple[str, bytes, str], boundary: str = "XX", closed: bool = True) -> bytes:
    out = b"a preamble that readers skip\r\n"
    for name, data, extra in parts:
        out += (
            f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n{extra}\r\n'.encode()
        )
        out += data + b"\r\n"
    return out + (f"--{boundary}--\r\n".encode() if closed else b"")


async def read_all(reader: MultipartReader) -> list[tuple[str | None, bytes]]:
    found = []
    while (part := await reader.next_part()) is not None:
        found.append((part.name, b"".join([chunk async for chunk in part.body])))
    return found


@pytest.mark.parametrize("step", [1, 7, 4096, 1 << 20])
def test_the_reader_returns_each_part_however_the_body_is_cut(step: int) -> None:
    payload = os.urandom(20_000) + b"\r\n--X is not it, nor is --XX without a line break\r\n"
    body = form(("request", b'{"a":1}', ""), ("context", payload, "Content-Length: 1\r\n"))
    found = asyncio.run(read_all(MultipartReader("XX", source_of(body, step))))
    assert found == [("request", b'{"a":1}'), ("context", payload)]


def test_the_reader_skips_a_part_that_is_not_read_and_keeps_headers() -> None:
    async def run() -> None:
        body = form(
            ("request", b"{}", "Content-Type: application/json\r\n"), ("context", b"x" * 50_000, "")
        )
        reader = MultipartReader("XX", source_of(body, 100))
        first = await reader.next_part()
        assert first is not None and first.headers["content-type"] == "application/json"
        second = await reader.next_part()  # the first was not read: it is skipped
        assert second is not None and second.name == "context"
        assert await reader.next_part() is None  # the second was not read either
        assert await reader.next_part() is None

    asyncio.run(run())


def test_the_reader_holds_only_a_little_of_a_large_part() -> None:
    async def run() -> int:
        body = form(("context", b"z" * (8 * MIB), ""))
        reader = MultipartReader("XX", source_of(body, 64 * 1024))
        part = await reader.next_part()
        assert part is not None
        biggest = 0
        async for chunk in part.body:
            biggest = max(biggest, len(chunk))
        return biggest

    assert asyncio.run(run()) <= 128 * 1024


@pytest.mark.parametrize(
    "body",
    [
        b"no boundary at all",
        form(("request", b"{}", ""), closed=False),
        form(("request", b"{}", ""))[:-4],
        b"--XX\r\n" + b"Header: " + b"a" * 9000 + b"\r\n\r\nx",
    ],
)
def test_a_malformed_body_is_a_multipart_error(body: bytes) -> None:
    with pytest.raises(MultipartError):
        asyncio.run(read_all(MultipartReader("XX", source_of(body, 50))))


def test_the_boundary_comes_from_the_content_type() -> None:
    assert boundary_of('multipart/form-data; boundary="abc def"') == "abc def"
    assert boundary_of("multipart/form-data; boundary=abc") == "abc"
    assert boundary_of("multipart/mixed; boundary=abc") is None
    assert boundary_of("multipart/form-data") is None
    assert boundary_of("application/json") is None
    assert boundary_of(None) is None


# --- a provider with images, behind the reference server and HttpProvider ------------------


def tar_of(files: Mapping[str, bytes]) -> bytes:
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return out.getvalue()


class ImageProvider(LocalProvider, manifest=False):
    """Prepares images in memory. An image's files are what its source says: an OCI image holds
    an `/etc/os-release`, and a Dockerfile `COPY`s files out of its build context."""

    images: dict[str, PreparedImage] = {}
    files: dict[str, dict[str, bytes]] = {}
    keys: dict[str, tuple[str, str]] = {}
    deleted: set[str] = set()
    seen: list[dict[str, Any]] = []
    box_files: dict[str, dict[str, bytes]] = {}
    create_images: list[dict[str, str]] = []
    polls_until_ready = 0
    claim = True

    @classmethod
    def reset(cls) -> None:
        cls.images, cls.files, cls.keys, cls.deleted = {}, {}, {}, set()
        cls.seen, cls.box_files, cls.create_images = [], {}, []
        cls.polls_until_ready, cls.claim = 0, True

    async def discovery(self) -> Discovery:
        return with_operations(IMAGE_OPERATIONS if self.claim else ())

    async def image_prepare(
        self,
        request: ImageRequest,
        *,
        context: AsyncIterable[bytes] | None = None,
        context_size: int | None = None,
        idempotency_key: str,
    ) -> PreparedImage:
        data = bytearray()
        sizes = []
        if context is not None:
            async for chunk in context:
                sizes.append(len(chunk))
                data += chunk
        body = json.dumps(to_json(request), sort_keys=True) + str(bytes(data))
        known = self.keys.get(idempotency_key)
        if known is not None:
            if known[0] != body:
                raise SpsError("conflict", "the key was used with another request")
            return self.images[known[1]]
        self.seen.append(
            {"request": request, "size": context_size, "chunks": sizes, "bytes": bytes(data)}
        )
        files: dict[str, bytes] = {}
        if isinstance(request.source, DockerfileSource):
            for line in request.source.dockerfile.splitlines():
                if line.startswith("COPY "):
                    _, name, destination = line.split()
                    with tarfile.open(fileobj=io.BytesIO(bytes(data))) as archive:
                        member = archive.extractfile(name)
                        assert member is not None
                        files[destination] = member.read()
        else:
            ubuntu = "ubuntu@" in getattr(request.source, "oci", "")
            files["/etc/os-release"] = b'NAME="Ubuntu"\n' if ubuntu else b'NAME="Alpine Linux"\n'
        image = PreparedImage(
            id=f"img-{len(self.images) + 1}",
            state="preparing" if self.polls_until_ready else "ready",
            error=None,
            resources=request.resources,
            stored_bytes=len(data) or None,
            labels=dict(request.labels),
            created_at=datetime.now(UTC).replace(microsecond=0),
        )
        self.images[image.id], self.files[image.id] = image, files
        self.keys[idempotency_key] = (body, image.id)
        return image

    async def image_get(self, image_id: str) -> PreparedImage:
        if image_id not in self.images or image_id in self.deleted:
            raise SpsError("not_found", "no such image")
        image = self.images[image_id]
        if image.state == "preparing":
            type(self).polls_until_ready -= 1
            if self.polls_until_ready <= 0:
                image = self.images[image_id] = dataclasses.replace(image, state="ready")
        return image

    async def image_list(
        self,
        *,
        labels: Mapping[str, str] | None = None,
        cursor: str | None = None,
        limit: int = 100,
    ) -> ImagePage:
        found = [
            image
            for image in self.images.values()
            if image.id not in self.deleted
            and all(image.labels.get(key) == value for key, value in (labels or {}).items())
        ]
        return ImagePage(found, None)

    async def image_delete(self, image_id: str) -> ImageDeleteResult:
        if image_id not in self.images:
            raise SpsError("not_found", "no such image")
        self.deleted.add(image_id)
        return ImageDeleteResult(image_id, "deleted")

    async def create(self, request: CreateRequest, *, idempotency_key: str) -> Sandbox:
        files: dict[str, bytes] = {}
        if isinstance(request.image, Mapping):
            ImageProvider.create_images.append(dict(request.image))
            image_id = request.image["provider_artifact"]
            if image_id not in self.images or image_id in self.deleted:
                raise SpsError("not_found", "no such image")
            if self.images[image_id].state != "ready":
                raise SpsError("conflict", "the image is not ready")
            files = self.files[image_id]
        box = await super().create(
            CreateRequest(labels=request.labels), idempotency_key=idempotency_key
        )
        self.box_files[box.id] = files
        return box

    async def run(self, sandbox_id: str, request: RunRequest) -> RunResult:
        files = self.box_files.get(sandbox_id)
        if (
            files
            and list(request.argv[:2]) in (["bash", "-c"], ["sh", "-c"])
            and request.argv[2].startswith("cat ")
        ):
            return RunResult(0, files[request.argv[2][4:]].decode(), "")
        return await super().run(sandbox_id, request)

    async def files_read(self, sandbox_id: str, path: str) -> FileStream:
        files = self.box_files.get(sandbox_id, {})
        if path not in files:
            return await super().files_read(sandbox_id, path)

        async def chunks() -> AsyncIterator[bytes]:
            yield files[path]

        return FileStream(len(files[path]), chunks())


@pytest.fixture(name="served")
def served_fixture(monkeypatch: pytest.MonkeyPatch) -> Any:
    """`HttpProvider` over the reference server, in process, serving `ImageProvider`."""
    ImageProvider.reset()
    app = create_app(ImageProvider)
    client = HttpProvider(
        "http://localhost",
        "token",
        transport=httpx.ASGITransport(app=app),
    )
    yield client
    asyncio.run(client.aclose())
    ImageProvider.reset()


def run(coroutine: Any) -> Any:
    return asyncio.run(coroutine)


def test_prepare_get_list_and_delete_over_http(served: HttpProvider) -> None:
    async def scenario() -> None:
        request = oci(labels={"job": "one"}, resources=ImageResources(cpu=2, memory_mib=1024))
        made = await served.image_prepare(request, idempotency_key=KEY)
        assert made.state == "ready" and made.labels == {"job": "one"}
        assert made.resources == ImageResources(cpu=2, memory_mib=1024)
        assert ImageProvider.seen[0]["request"] == request and ImageProvider.seen[0]["size"] is None
        assert await served.image_get(made.id) == made
        assert list((await served.image_list(labels={"job": "one"})).images) == [made]
        assert not (await served.image_list(labels={"job": "two"})).images
        assert (await served.image_delete(made.id)).state == "deleted"
        assert (await served.image_delete(made.id)).state == "deleted"
        with pytest.raises(SpsError) as gone:
            await served.image_get(made.id)
        assert gone.value.code == "not_found"

    run(scenario())


def test_a_repeated_prepare_returns_the_first_image_and_another_request_conflicts(
    served: HttpProvider,
) -> None:
    async def scenario() -> None:
        first = await served.image_prepare(oci(), idempotency_key=KEY)
        assert await served.image_prepare(oci(), idempotency_key=KEY) == first
        with pytest.raises(SpsError) as conflict:
            await served.image_prepare(oci(labels={"a": "b"}), idempotency_key=KEY)
        assert conflict.value.code == "conflict"
        assert len(ImageProvider.images) == 1

    run(scenario())


@pytest.mark.parametrize("known_size", [True, False])
def test_a_large_context_reaches_the_provider_as_a_stream_of_small_chunks(
    served: HttpProvider, known_size: bool
) -> None:
    context = tar_of({"copied.txt": os.urandom(6 * MIB)})

    async def scenario() -> None:
        request = ImageRequest(DockerfileSource("FROM x\nCOPY copied.txt /opt/c\n"))
        await served.image_prepare(
            request,
            context=source_of(context, 3 * MIB),
            context_size=len(context) if known_size else None,
            idempotency_key=KEY,
        )

    run(scenario())
    seen = ImageProvider.seen[0]
    assert seen["bytes"] == context
    assert seen["size"] == (len(context) if known_size else None)
    assert len(seen["chunks"]) >= 6 and max(seen["chunks"]) <= MIB  # never one buffered blob


def post(
    served: HttpProvider, content: bytes | AsyncIterator[bytes], **headers: str
) -> httpx.Response:
    async def send() -> httpx.Response:
        return await served._client.post(  # pylint: disable=protected-access
            "/v1/images",
            content=content,
            headers={"Idempotency-Key": KEY, "Authorization": "Bearer token", **headers},
        )

    response: httpx.Response = run(send())
    return response


def error_code(response: httpx.Response) -> tuple[int, str, str]:
    error = response.json()["error"]
    return response.status_code, error["code"], error["outcome"]


def request_part(request: ImageRequest | None = None) -> tuple[str, bytes, str]:
    body = json.dumps(to_json(request or ImageRequest(DockerfileSource("FROM x\n")))).encode()
    return ("request", body, "Content-Type: application/json\r\n")


FORM = {"Content-Type": "multipart/form-data; boundary=XX"}


@pytest.mark.parametrize(
    ("body", "headers", "expect"),
    [
        (b"{}", {"Content-Type": "application/json"}, (400, "invalid_request", "failed")),
        (form(("context", b"x", "")), FORM, (400, "invalid_request", "failed")),  # no request first
        (form(("request", b"not json", "")), FORM, (400, "invalid_request", "failed")),
        (form(("request", b'{"source": {}}', "")), FORM, (400, "invalid_request", "failed")),
        (form(request_part(), ("other", b"x", "")), FORM, (400, "invalid_request", "failed")),
        (
            form(request_part(), ("context", b"x", ""), ("context", b"x", "")),
            FORM,
            (400, "invalid_request", "unknown"),
        ),
        (
            form(request_part(), ("context", b"x", "Content-Length: 5\r\n")),
            FORM,
            (400, "invalid_request", "unknown"),
        ),
        (
            form(request_part(), ("context", b"x", "Content-Length: nan\r\n")),
            FORM,
            (400, "invalid_request", "failed"),
        ),
        (form(request_part(), ("context", b"x" * 20, "")), FORM, (413, "too_large", "failed")),
        (
            form(request_part(oci()), ("context", b"x", "")),
            FORM,
            (400, "invalid_request", "failed"),
        ),
        (
            form(request_part(), ("context", b"xx", ""), closed=False),
            FORM,
            (400, "invalid_request", "unknown"),
        ),
    ],
)
def test_a_body_that_is_not_what_prepare_takes_is_refused_with_the_right_code(
    served: HttpProvider,
    monkeypatch: pytest.MonkeyPatch,
    body: bytes,
    headers: dict[str, str],
    expect: tuple[int, str, str],
) -> None:
    monkeypatch.setattr(image_upload_module, "DEFAULT_CONTEXT_BYTES", 10)
    assert error_code(post(served, body, **headers)) == expect
    if expect[2] == "failed":
        assert not ImageProvider.images


def test_a_declared_body_over_the_limit_is_refused_before_it_is_read(
    served: HttpProvider, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(image_upload_module, "DEFAULT_CONTEXT_BYTES", 10)
    monkeypatch.setattr(image_upload_module, "FRAMING_BYTES", 0)

    async def never() -> AsyncIterator[bytes]:
        raise AssertionError("the body was read")
        yield b""

    async def send() -> httpx.Response:
        return await served._client.post(  # pylint: disable=protected-access
            "/v1/images",
            content=never(),
            headers={
                "Idempotency-Key": KEY,
                "Authorization": "Bearer token",
                **FORM,
                "Content-Length": "999",
            },
        )

    assert error_code(run(send())) == (413, "too_large", "failed")


def test_a_provider_without_images_answers_unsupported(served: HttpProvider) -> None:
    class Plain(LocalProvider, manifest=False):
        pass

    plain = HttpProvider(
        "http://localhost",
        "token",
        transport=httpx.ASGITransport(app=create_app(Plain)),
    )

    async def scenario() -> None:
        with pytest.raises(SpsError) as refused:
            await plain.image_prepare(oci(), idempotency_key=KEY)
        assert refused.value.code == "unsupported"
        with pytest.raises(SpsError) as listed:
            await plain.image_list()
        assert listed.value.code == "unsupported"
        await plain.aclose()

    run(scenario())


def test_the_client_checks_its_own_inputs(served: HttpProvider) -> None:
    async def scenario() -> None:
        for call in (
            served.image_prepare(oci(), idempotency_key="short"),
            served.image_prepare(oci(), context_size=-1, idempotency_key=KEY),
            served.image_get("../x"),
            served.image_delete("a/b"),
        ):
            with pytest.raises(SpsError) as refused:
                await call
            assert refused.value.code == "invalid_request"
        with pytest.raises(SpsError) as short:
            await served.image_prepare(
                ImageRequest(DockerfileSource("FROM x\n")),
                context=source_of(b"abc", 3),
                context_size=5,
                idempotency_key=KEY,
            )
        assert short.value.code == "invalid_request"

    run(scenario())


# --- the tester's `images` section ---------------------------------------------------------


@pytest.fixture(name="provider")
def provider_fixture() -> Any:
    ImageProvider.reset()
    yield ImageProvider()
    ImageProvider.reset()


def outcome(report: Any) -> dict[str, str]:
    return {str(row["id"]): str(row["result"]) for row in report["tests"]}


def test_the_four_operations_claim_the_images_section_and_nothing_else() -> None:
    suite = shared_suite()
    claimed = {
        t.id for t in select_tests(suite, with_operations(IMAGE_OPERATIONS), TestOptions()).tests
    }
    images = {t.id for t in suite.tests if t.id.startswith("images.") and t.id not in CLAIMED_TESTS}
    images -= {"images.v1.prepare_dockerfile_context"}  # it also needs a dockerfile source claim
    assert images and images <= claimed
    assert not any(
        t.id.startswith("directories.")
        for t in select_tests(suite, with_operations(IMAGE_OPERATIONS), TestOptions()).tests
    )
    assert "images" in claimed_sections(with_operations(IMAGE_OPERATIONS))
    assert "images" not in claimed_sections(with_operations(IMAGE_OPERATIONS[:3]))
    bare = {t.id for t in select_tests(suite, with_operations(()), TestOptions()).tests}
    assert not any(test_id.startswith("images.") for test_id in bare)
    assert (
        unsupported_operations(with_operations(IMAGE_OPERATIONS))
        .keys()
        .isdisjoint(IMAGE_OPERATIONS)
    )
    assert set(unsupported_operations(with_operations(()))) >= set(IMAGE_OPERATIONS)


def test_a_provider_that_prepares_images_passes_the_images_section(provider: ImageProvider) -> None:
    ImageProvider.polls_until_ready = 2  # the tester waits for `ready`
    report = run_tests(provider, TestOptions(tests=("images.",)))
    tests = outcome(report)
    assert tests and set(tests.values()) == {"passed"}, tests
    assert "section images passed" in report.lines
    assert all(image.id in ImageProvider.deleted for image in ImageProvider.images.values())
    assert all(box.state == "destroyed" for box in provider.boxes.values())


def test_the_images_section_passes_over_http_with_the_created_image_naming_its_provider(
    served: HttpProvider,
) -> None:
    """A create from a prepared image crosses the wire form: its `image` is checked against the
    request schema, which requires `provider` beside `provider_artifact`. The tester sent the id
    alone, so every create from a prepared image raised `WireError` over HTTP (the prober's
    route) and passed in process."""
    ImageProvider.polls_until_ready = 2
    report = run_tests(served, TestOptions(tests=("images.",)))
    tests = outcome(report)
    assert tests and set(tests.values()) == {"passed"}, [
        step for row in report["tests"] for step in row["steps"] if step["result"] != "passed"
    ]
    assert ImageProvider.create_images, "no create from a prepared image was sent"
    assert all(
        set(image) == {"provider_artifact", "provider"} for image in ImageProvider.create_images
    ), ImageProvider.create_images


def test_the_dockerfile_test_sends_a_tar_context_with_its_size(provider: ImageProvider) -> None:
    run_tests(provider, TestOptions(tests=("images.v1.prepare_dockerfile_context",)))
    seen = ImageProvider.seen[0]
    assert isinstance(seen["request"].source, DockerfileSource)
    assert seen["size"] == len(seen["bytes"])
    with tarfile.open(fileobj=io.BytesIO(seen["bytes"])) as archive:
        assert archive.getnames() == ["copied.txt"]


def test_a_provider_without_the_claim_has_the_images_tests_unsupported(
    provider: ImageProvider,
) -> None:
    ImageProvider.claim = False
    report = run_tests(provider, TestOptions(tests=("images.",)))
    assert {row["result"] for row in report["tests"]} == {"unsupported"}
    assert not any(line.startswith("section images") for line in report.lines)


def test_a_failed_image_fails_its_test_and_the_run_deletes_what_is_left(
    provider: ImageProvider,
) -> None:
    original = ImageProvider.image_prepare

    async def failing(self: ImageProvider, request: ImageRequest, **kwargs: Any) -> PreparedImage:
        image = await original(self, request, **kwargs)
        failed = dataclasses.replace(
            image, state="failed", error=SpsError("provider_error", "boom")
        )
        ImageProvider.images[image.id] = failed
        return failed

    ImageProvider.image_prepare = failing  # type: ignore[method-assign]
    try:
        report = run_tests(provider, TestOptions(tests=("images.v1.prepare_oci",)))
    finally:
        ImageProvider.image_prepare = original  # type: ignore[method-assign]
    assert outcome(report) == {"images.v1.prepare_oci": "error"}
    assert all(image.id in ImageProvider.deleted for image in ImageProvider.images.values())


def test_the_sweep_deletes_the_runs_images_and_a_provider_without_them_has_none(
    provider: ImageProvider,
) -> None:
    driver = ProviderDriver(provider, run="run-1")
    try:
        assert driver.sweep_images() == []
        keep = dataclasses.replace(
            example(PreparedImage), id="other", labels={"sps.test.run": "someone-else"}
        )
        ImageProvider.images["other"] = keep
        driver.image_prepare(None, {"source": "oci", "image": f"x@{DIGEST}"})
        results = driver.sweep_images()
        assert [row["result"] for row in results] == ["deleted"]
        assert "other" not in ImageProvider.deleted
        assert ProviderDriver(LocalProvider(), run="run-2").sweep_images() == []
    finally:
        driver.close()


def test_a_borrowed_provider_artifact_is_used_but_never_deleted(provider: ImageProvider) -> None:
    driver = ProviderDriver(provider, run="run-1")
    try:
        made = driver.image_prepare(None, {"source": "provider_artifact", "image": "existing-1"})
        assert made["identity"] == "existing-1"
        assert driver.image_delete(made, {}) == {"kind": "image", "result": "already_released"}
    finally:
        driver.close()


def test_the_same_prepare_twice_asks_the_provider_the_same_question(
    provider: ImageProvider,
) -> None:
    driver = ProviderDriver(provider, run="run-1")
    try:
        inputs = {"source": "oci", "image": f"x@{DIGEST}"}
        first = driver.image_prepare(None, inputs)
        second = driver.image_prepare(None, inputs)
        assert (first["identity"], first["key"]) == (second["identity"], second["key"])
        assert len(ImageProvider.images) == 1
        driver.image_delete(first, {})  # after a delete, the same request is a new image
        third = driver.image_prepare(None, inputs)
        assert third["identity"] != first["identity"]
    finally:
        driver.close()


def test_an_oci_reference_without_a_digest_is_not_run(provider: ImageProvider) -> None:
    driver = ProviderDriver(provider, run="run-1")
    try:
        with pytest.raises(NotRun):
            driver.image_prepare(None, {"source": "oci", "image": "alpine:3.20"})
    finally:
        driver.close()


UBUNTU = "docker.io/library/ubuntu@sha256:" + "ab" * 32
IMAGE_TESTS = (
    "images.v1.prepare_oci",
    "images.v1.idempotent_prepare",
    "images.v1.get_and_list",
    "images.v1.cost",
)


def test_the_prepared_image_tests_use_the_runs_oci_image_and_marker(
    provider: ImageProvider,
) -> None:
    ImageProvider.polls_until_ready = 0
    options = TestOptions(
        tests=IMAGE_TESTS, fixtures={"oci_image": UBUNTU, "image_marker": "Ubuntu"}
    )
    tests = outcome(run_tests(provider, options))
    assert set(tests.values()) <= {"passed", "unsupported"} and "passed" in tests.values(), tests
    prepared = {getattr(item["request"].source, "oci", None) for item in ImageProvider.seen}
    assert prepared == {UBUNTU}


def test_the_prepared_image_tests_use_pinned_alpine_without_the_fixture(
    provider: ImageProvider,
) -> None:
    ImageProvider.polls_until_ready = 0
    tests = outcome(run_tests(provider, TestOptions(tests=IMAGE_TESTS)))
    assert "passed" in tests.values(), tests
    prepared = {getattr(item["request"].source, "oci", None) for item in ImageProvider.seen}
    assert prepared == {ALPINE_IMAGE}


def test_an_oci_image_without_its_marker_leaves_the_prepare_test_not_run(
    provider: ImageProvider,
) -> None:
    ImageProvider.polls_until_ready = 0
    options = TestOptions(tests=("images.v1.prepare_oci",), fixtures={"oci_image": UBUNTU})
    report = run_tests(provider, options)
    (row,) = report["tests"]
    assert (row["result"], row["reason"]) == ("not_run", "fixture_missing")


def test_the_dockerfile_test_builds_on_the_runs_image(provider: ImageProvider) -> None:
    ImageProvider.polls_until_ready = 0
    options = TestOptions(
        tests=("images.v1.prepare_dockerfile_context",),
        fixtures={"oci_image": UBUNTU, "image_marker": "Ubuntu"},
    )
    assert set(outcome(run_tests(provider, options)).values()) == {"passed"}
    (item,) = ImageProvider.seen
    assert item["request"].source.dockerfile.splitlines()[0] == f"FROM {UBUNTU}"
    ImageProvider.seen.clear()
    run_tests(provider, TestOptions(tests=("images.v1.prepare_dockerfile_context",)))
    assert ImageProvider.seen[0]["request"].source.dockerfile.startswith(f"FROM {ALPINE_IMAGE}\n")


def test_the_dockerfile_test_runs_only_for_a_class_that_claims_a_dockerfile_source() -> None:
    suite = shared_suite()

    def discovery(sources: list[str]) -> Any:
        found = with_gates({"custom_images": {"source": sources, "prepared": True}})
        first = dataclasses.replace(found.classes[0], operations=IMAGE_OPERATIONS)
        return dataclasses.replace(found, classes=[first, *found.classes[1:]])

    for options in (TestOptions(), TestOptions(tests=["images.v1."])):
        chosen = {t.id for t in select_tests(suite, discovery(["oci"]), options).tests}
        assert "images.v1.prepare_oci" in chosen
        assert "images.v1.prepare_dockerfile_context" not in chosen
        both = {t.id for t in select_tests(suite, discovery(["oci", "dockerfile"]), options).tests}
        assert "images.v1.prepare_dockerfile_context" in both


ARTIFACT_GATES = {"custom_images": {"source": ["provider_artifact"]}}


class ArtifactProvider(ImageProvider, manifest=False):
    """Creates sandboxes from images the account already has, and prepares none: its class claims
    `custom_images` with `source: provider_artifact` and lists no image operation."""

    async def discovery(self) -> Discovery:
        return with_gates(ARTIFACT_GATES)


def test_the_provider_artifact_test_needs_no_image_operation() -> None:
    """The test borrows an artifact that the account already has, without calling the provider,
    so a class that can create from its own artifacts but prepares no image passes it."""
    ImageProvider.reset()
    ImageProvider.images["golden"] = dataclasses.replace(
        example(PreparedImage), id="golden", state="ready", error=None
    )
    ImageProvider.files["golden"] = {"/etc/os-release": b'NAME="Golden"\n'}
    fixtures = {"provider_artifact_image": "golden", "image_marker": "Golden"}
    try:
        report = run_tests(
            ArtifactProvider(),
            TestOptions(tests=("custom_images.provider_artifact",), fixtures=fixtures),
        )
        assert outcome(report) == {"custom_images.provider_artifact": "passed"}, report["tests"]
        assert ImageProvider.seen == []
        assert ImageProvider.create_images == [
            {"provider_artifact": "golden", "provider": "example"}
        ]
        assert ImageProvider.deleted == set()
        chosen = select_tests(
            shared_suite(), with_gates(ARTIFACT_GATES), TestOptions(fixtures=fixtures)
        ).tests
        assert "custom_images.provider_artifact" in {test.id for test in chosen}
    finally:
        ImageProvider.reset()


def test_a_class_without_the_image_operations_still_prepares_no_other_source() -> None:
    ImageProvider.reset()
    try:
        report = run_tests(ArtifactProvider(), TestOptions(tests=("images.v1.prepare_oci",)))
        (row,) = report["tests"]
        assert (row["result"], row["reason"]) == (
            "unsupported",
            "discovery does not claim the section that needs this operation",
        )
        assert ImageProvider.seen == []
    finally:
        ImageProvider.reset()
