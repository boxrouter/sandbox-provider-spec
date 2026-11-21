# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The body of `image_prepare` on the server: the part `request`, then the optional part
`context`, which is handed to the provider as a stream and never held in memory."""

from __future__ import annotations

import json
import re
from collections.abc import AsyncIterator, Callable, Mapping
from dataclasses import dataclass

from sandbox_provider_spec.v1.errors import SpsError
from sandbox_provider_spec.v1.multipart import (
    MultipartError,
    MultipartReader,
    Part,
    boundary_of,
)
from sandbox_provider_spec.v1.provider import Provider
from sandbox_provider_spec.v1.types import DockerfileSource, ImageRequest, PreparedImage
from sandbox_provider_spec.v1.wire import WireError, from_json

MAX_REQUEST_BYTES = 1024 * 1024 + 4096  # the part `request`: a Dockerfile of 1 MiB at most
DEFAULT_CONTEXT_BYTES = 512 * 1024 * 1024  # the floor of `limits.image_context_bytes`
FRAMING_BYTES = MAX_REQUEST_BYTES + 64 * 1024  # what a body may hold beyond its context


@dataclass
class ImageUpload:
    """What a prepare request carries. `context` is None when the request has no context part;
    reading it raises the `SpsError` in `error` when the body is malformed or over the limit."""

    request: ImageRequest
    context: AsyncIterator[bytes] | None
    context_size: int | None
    error: SpsError | None = None
    reader: MultipartReader | None = None

    async def finish(self) -> None:
        """Read what is left of the body and check that it ends as it should. Raises the
        `SpsError` of a malformed body, outcome `unknown` since the provider has already acted."""
        try:
            assert self.reader is not None
            if await self.reader.next_part() is not None:
                raise MultipartError("the body has a part after `context`")
        except MultipartError as error:
            raise self.fail(str(error)) from None
        if self.error is not None:
            raise self.error

    def fail(self, message: str) -> SpsError:
        self.error = SpsError("invalid_request", message, outcome="unknown")
        return self.error


def check_declared_size(declared: str | None, limit: int) -> None:
    """Refuse a body that already says it is over the limit, before reading it."""
    if declared is not None and re.fullmatch(r"[0-9]{1,18}", declared) is None:
        raise SpsError("invalid_request", "Content-Length is not a number")
    if declared is not None and int(declared) > limit + FRAMING_BYTES:
        raise SpsError("too_large", f"The body is over the context limit of {limit} bytes")


async def _read_request(part: Part) -> ImageRequest:
    seen = bytearray()
    async for chunk in part.body:
        seen += chunk
        if len(seen) > MAX_REQUEST_BYTES:
            raise SpsError("too_large", "The part `request` is over 1 MiB")
    media = part.headers.get("content-type", "application/json").split(";", 1)[0].strip().lower()
    if media != "application/json":
        raise SpsError("invalid_request", "The part `request` must be application/json")
    try:
        return from_json(ImageRequest, json.loads(bytes(seen).decode("utf-8")))
    except WireError as error:
        raise SpsError("invalid_request", str(error)[:1000]) from None
    except (UnicodeDecodeError, ValueError):
        raise SpsError("invalid_request", "The part `request` is not valid JSON") from None
    except (TypeError, KeyError):
        raise SpsError("invalid_request", "The part `request` does not fit its schema") from None


async def open_upload(
    content_type: str | None, body: AsyncIterator[bytes], *, limit: int
) -> ImageUpload:
    """Read the part `request` and find the part `context`, if any; the context is not read
    yet. Raises `SpsError` for a body that is not what `image_prepare` takes."""
    boundary = boundary_of(content_type)
    if boundary is None:
        raise SpsError("invalid_request", "The body must be multipart/form-data with a boundary")
    reader = MultipartReader(boundary, body)
    try:
        first = await reader.next_part()
        if first is None or first.name != "request":
            raise SpsError("invalid_request", "The first part must be named `request`")
        request = await _read_request(first)
        second = await reader.next_part()
    except MultipartError as error:
        raise SpsError("invalid_request", str(error)) from None
    if second is None:
        return ImageUpload(request, None, None, reader=reader)
    if second.name != "context":
        raise SpsError("invalid_request", "The only other part is `context`")
    if not isinstance(request.source, DockerfileSource):
        raise SpsError("invalid_request", "Only a Dockerfile source takes a build context")
    declared = second.headers.get("content-length")
    if declared is not None and not re.fullmatch(r"[0-9]{1,18}", declared):
        raise SpsError("invalid_request", "The context's Content-Length is not a number")
    size = None if declared is None else int(declared)
    if size is not None and size > limit:
        raise SpsError("too_large", f"The context is over {limit} bytes")
    upload = ImageUpload(request, None, size, reader=reader)
    upload.context = _context(upload, second, size, limit)
    return upload


async def _context(
    upload: ImageUpload, part: Part, declared: int | None, limit: int
) -> AsyncIterator[bytes]:
    seen = 0
    try:
        async for chunk in part.body:
            seen += len(chunk)
            if seen > limit:
                upload.error = SpsError("too_large", f"The context is over {limit} bytes")
                raise upload.error
            yield chunk
    except MultipartError as error:
        raise upload.fail(str(error)) from None
    if declared is not None and seen != declared:
        raise upload.fail("The context is not as long as its Content-Length says")


async def prepare_image(
    provider: Provider,
    *,
    key: str,
    headers: Mapping[str, str],
    body: AsyncIterator[bytes],
    stream_error: Callable[[], SpsError | None],
) -> PreparedImage:
    """Serve one `image_prepare` request. `stream_error` reports a failure of the body stream
    itself (a dropped connection), which wins over whatever the provider then raised."""
    if type(provider).image_prepare is Provider.image_prepare:
        raise SpsError("unsupported", "The provider does not support image.prepare")
    limit = (await provider.discovery()).limits.image_context_bytes or DEFAULT_CONTEXT_BYTES
    check_declared_size(headers.get("content-length"), limit)
    upload = await open_upload(headers.get("content-type"), body, limit=limit)
    try:
        image = await provider.image_prepare(
            upload.request,
            context=upload.context,
            context_size=upload.context_size,
            idempotency_key=key,
        )
    except Exception:
        failure = stream_error() or upload.error
        if failure is not None:
            raise failure from None
        raise
    await upload.finish()
    return image
