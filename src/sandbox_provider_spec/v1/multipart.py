# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""A streaming reader for `multipart/form-data` (RFC 7578), for `image_prepare`.

The reference server never holds a build context in memory: `MultipartReader` hands out each
part's body as an async iterator of chunks, and keeps only the last few bytes of what it has seen
(enough to recognise the boundary that ends the part). It reads parts in order, one at a time.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass
from email.message import Message
from email.parser import BytesParser

MAX_HEADER_BYTES = 8192
_BOUNDARY_LENGTH = range(1, 71)


class MultipartError(ValueError):
    """The body is not well-formed `multipart/form-data`."""


@dataclass
class Part:
    """One part: its form-field name, its headers (names in lower case) and its body."""

    name: str | None
    headers: dict[str, str]
    body: AsyncIterator[bytes]


def boundary_of(content_type: str | None) -> str | None:
    """The boundary of a `multipart/form-data` content type, or None when it is not one."""
    if not content_type:
        return None
    message = Message()
    message["content-type"] = content_type
    if message.get_content_type() != "multipart/form-data":
        return None
    boundary = message.get_param("boundary")
    if not isinstance(boundary, str) or len(boundary) not in _BOUNDARY_LENGTH:
        return None
    return boundary


class MultipartReader:
    """Read the parts of one multipart body, in order. Each part's body is read to its end, or
    skipped by asking for the next part."""

    def __init__(self, boundary: str, source: AsyncIterator[bytes]) -> None:
        self._delimiter = b"\r\n--" + boundary.encode("ascii")
        self._source = source
        self._buffer = bytearray(b"\r\n")  # the first boundary follows an imagined line break
        self._eof = False
        self._started = False
        self._finished = False
        self._active: AsyncIterator[bytes] | None = None

    async def _more(self) -> bool:
        """Append the next chunk of the source; false when the source has ended."""
        if self._eof:
            return False
        try:
            chunk = await anext(self._source)
        except StopAsyncIteration:
            self._eof = True
            return False
        self._buffer += chunk
        return True

    async def _skip_to_first_boundary(self) -> None:
        keep = len(self._delimiter) - 1
        while True:
            at = self._buffer.find(self._delimiter)
            if at >= 0:
                del self._buffer[: at + len(self._delimiter)]
                return
            del self._buffer[: max(0, len(self._buffer) - keep)]
            if not await self._more():
                raise MultipartError("the body has no multipart boundary")

    async def _need(self, count: int) -> None:
        while len(self._buffer) < count:
            if not await self._more():
                raise MultipartError("the body ended inside a boundary line")

    async def _drain_active(self) -> None:
        if self._active is not None:
            active, self._active = self._active, None
            async for _ in active:
                pass

    async def next_part(self) -> Part | None:
        """The next part, or None after the closing boundary. A part that was not read to its end
        is skipped."""
        await self._drain_active()
        if self._finished:
            return None
        if not self._started:
            self._started = True
            await self._skip_to_first_boundary()
        await self._need(2)
        if self._buffer[:2] == b"--":
            self._finished = True
            return None
        # Transport padding, then the line break that ends the boundary line.
        while True:
            end = self._buffer.find(b"\r\n", 0, 80)
            if end >= 0:
                break
            if len(self._buffer) >= 80 or not await self._more():
                raise MultipartError("a boundary line is not followed by a line break")
        if self._buffer[:end].strip(b" \t"):
            raise MultipartError("a boundary line has unexpected text")
        del self._buffer[: end + 2]
        headers = await self._read_headers()
        name = _field_name(headers)
        self._active = self._body()
        return Part(name, {key.lower(): value for key, value in headers.items()}, self._active)

    async def _read_headers(self) -> Message:
        await self._need(2)
        if self._buffer[:2] == b"\r\n":
            del self._buffer[:2]
            return Message()
        while (end := self._buffer.find(b"\r\n\r\n")) < 0:
            if len(self._buffer) > MAX_HEADER_BYTES:
                raise MultipartError("a part's headers are too long")
            if not await self._more():
                raise MultipartError("the body ended inside a part's headers")
        if end > MAX_HEADER_BYTES:
            raise MultipartError("a part's headers are too long")
        block = bytes(self._buffer[: end + 4])
        del self._buffer[: end + 4]
        return BytesParser().parsebytes(block, headersonly=True)

    async def _body(self) -> AsyncIterator[bytes]:
        keep = len(self._delimiter) - 1
        while True:
            at = self._buffer.find(self._delimiter)
            if at >= 0:
                data = bytes(self._buffer[:at])
                del self._buffer[: at + len(self._delimiter)]
                self._active = None
                if data:
                    yield data
                return
            safe = len(self._buffer) - keep
            if safe > 0:
                data = bytes(self._buffer[:safe])
                del self._buffer[:safe]
                yield data
            if not await self._more():
                raise MultipartError("a part ended without its closing boundary")


def _field_name(headers: Message) -> str | None:
    if headers.get_content_disposition() != "form-data":
        return None
    name = headers.get_param("name", header="content-disposition")
    return name if isinstance(name, str) else None
