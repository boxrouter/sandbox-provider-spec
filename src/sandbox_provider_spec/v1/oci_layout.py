# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""An OCI image layout tar of a public image, which the tester sends as the part `context` of
`image_prepare` to a provider that lists `image.prepare.oci_layout`.

The tester plays the caller here: a provider that takes layouts reaches no registry, so whoever
asks it to prepare an OCI image reads the image first and hands the bytes over. This reads a public
image by digest over the registry HTTP API (anonymous), checks every blob against its digest, and
writes `oci-layout`, `index.json` and `blobs/sha256/*` as one tar archive in a temporary file, so a
large image never sits in memory. The caller bounds the archive's size, which is the provider's
`limits.image_layout_bytes`; an image over it is refused before any blob is downloaded."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import io
import json
import re
import tarfile
import tempfile
from collections.abc import AsyncIterator, Iterable, Iterator, Mapping
from typing import TYPE_CHECKING, Any, BinaryIO

if TYPE_CHECKING:  # `httpx` comes with the `http` extra; the base install never reaches it
    import httpx

MANIFEST_TYPES = (
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.docker.distribution.manifest.v2+json",
)
INDEX_TYPES = frozenset(MANIFEST_TYPES[:1] + MANIFEST_TYPES[2:3])
DOCKER_HUB = "docker.io"
DOCKER_HUB_REGISTRY = "registry-1.docker.io"
MAX_MANIFEST_BYTES = 4 * 1024 * 1024  # the OCI distribution spec's bound on a manifest
_CHUNK = 1024 * 1024
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_CHALLENGE = re.compile(r'(\w+)="([^"]*)"')


class LayoutError(RuntimeError):
    """The image could not be read as a layout; the message is for a person."""


class LayoutTooLarge(LayoutError):
    """The image's layout would be `size` bytes, over the caller's `limit`; no blob was read."""

    def __init__(self, size: int, limit: int) -> None:
        super().__init__(f"the image's layout is {size} bytes, over the limit of {limit} bytes")
        self.size = size
        self.limit = limit


class Layout:
    """An image-layout tar in an anonymous temporary file, `size` bytes long. `close` (or leaving
    the `with` block) deletes the file."""

    def __init__(self, file: BinaryIO, size: int) -> None:
        self._file = file
        self.size = size

    def read(self) -> bytes:
        """The whole archive in memory: for a small image only."""
        self._file.seek(0)
        return self._file.read()

    async def chunks(self, size: int = _CHUNK) -> AsyncIterator[bytes]:
        """The archive, `size` bytes at a time; one stream at a time."""
        self._file.seek(0)
        while chunk := await asyncio.to_thread(self._file.read, size):
            yield chunk

    def close(self) -> None:
        self._file.close()

    def __enter__(self) -> Layout:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def split_reference(reference: str) -> tuple[str, str]:
    """The registry host and repository of an image reference, tag and digest dropped."""
    name = reference.partition("@")[0]
    first, slash, rest = name.partition("/")
    host, path = (first, rest) if slash and _is_host(first) else (DOCKER_HUB, name)
    last = path.rsplit("/", 1)[-1]
    if ":" in last:
        path = path[: len(path) - len(last)] + last.split(":", 1)[0]
    if host in (DOCKER_HUB, "index.docker.io"):
        host = DOCKER_HUB
        if "/" not in path:
            path = f"library/{path}"
    return host, path


def _is_host(first: str) -> bool:
    return "." in first or ":" in first or first == "localhost"


class _Registry:
    def __init__(self, client: httpx.Client, host: str, repository: str) -> None:
        self._client = client
        self._base = (
            f"https://{DOCKER_HUB_REGISTRY if host == DOCKER_HUB else host}/v2/{repository}"
        )
        self._token: str | None = None

    @contextlib.contextmanager
    def open(self, kind: str, digest: str, accept: str | None = None) -> Iterator[httpx.Response]:
        """The streamed response for a manifest or blob by digest."""
        url = f"{self._base}/{kind}/{digest}"
        response = self._request(url, accept)
        try:
            if response.status_code == 401:
                authenticated = self._authenticate(response)
                response.close()
                if authenticated:
                    response = self._request(url, accept)
            if response.status_code != 200:
                raise LayoutError(
                    f"the registry answered {response.status_code} for {kind} {digest}"
                )
            yield response
        finally:
            response.close()

    def manifest(self, digest: str, accept: str) -> tuple[bytes, str]:
        """A manifest by digest, checked against it, with its content type."""
        with self.open("manifests", digest, accept) as response:
            data = bytearray()
            for chunk in response.iter_bytes():
                data.extend(chunk)
                if len(data) > MAX_MANIFEST_BYTES:
                    raise LayoutError(f"manifest {digest} is over {MAX_MANIFEST_BYTES} bytes")
            actual = "sha256:" + hashlib.sha256(data).hexdigest()
            if actual != digest:
                raise LayoutError(f"manifests {digest} came back as {actual}")
            media = response.headers.get("content-type", "").split(";", 1)[0].strip()
            return bytes(data), media

    def _request(self, url: str, accept: str | None) -> httpx.Response:
        headers = {"Accept": accept} if accept else {}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return self._client.send(
            self._client.build_request("GET", url, headers=headers),
            stream=True,
            follow_redirects=True,
        )

    def _authenticate(self, response: httpx.Response) -> bool:
        header = response.headers.get("www-authenticate", "")
        if not header.lower().startswith("bearer "):
            return False
        fields = dict(_CHALLENGE.findall(header))
        realm = fields.pop("realm", None)
        if realm is None or not realm.startswith("https://"):
            return False
        answer = self._client.get(realm, params=fields)
        if answer.status_code != 200:
            return False
        body = answer.json()
        token = body.get("token") or body.get("access_token")
        if not isinstance(token, str):
            return False
        self._token = token
        return True


def _platform_manifest(index: Mapping[str, Any]) -> str:
    for entry in index.get("manifests", ()):
        platform = entry.get("platform") or {}
        if platform.get("os") == "linux" and platform.get("architecture") == "amd64":
            digest = entry.get("digest")
            if isinstance(digest, str) and _DIGEST.fullmatch(digest):
                return digest
    raise LayoutError("the image index has no linux/amd64 manifest")


class _Blob:
    """A blob's response as the file `tarfile` copies from: it hands over exactly the `size` bytes
    the manifest names, hashing every byte the registry sends, and `finish` checks the rest."""

    def __init__(self, chunks: Iterator[bytes], digest: str, size: int) -> None:
        self._chunks = chunks
        self._digest = digest
        self._size = size
        self._hash = hashlib.sha256()
        self._buffer = bytearray()
        self._received = 0
        self._given = 0

    def _pull(self) -> bool:
        chunk = next(self._chunks, None)
        if chunk is None:
            return False
        self._hash.update(chunk)
        self._received += len(chunk)
        self._buffer.extend(chunk)
        return True

    def read(self, count: int) -> bytes:
        count = min(count, self._size - self._given)
        while len(self._buffer) < count:
            if not self._pull():
                raise LayoutError(
                    f"blob {self._digest} ended after {self._received} of {self._size} bytes"
                )
        data = bytes(self._buffer[:count])
        del self._buffer[:count]
        self._given += count
        return data

    def finish(self) -> None:
        while self._pull():
            self._buffer.clear()
        actual = "sha256:" + self._hash.hexdigest()
        if actual != self._digest:
            raise LayoutError(f"blobs {self._digest} came back as {actual}")
        if self._received != self._size:
            raise LayoutError(
                f"blob {self._digest} has {self._received} bytes, its manifest says {self._size}"
            )


def _info(name: str, size: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size, info.mode, info.mtime = size, 0o644, 0
    return info


def _blob_name(digest: str) -> str:
    return f"blobs/sha256/{digest.removeprefix('sha256:')}"


def _tar_size(members: Iterable[tuple[str, int]]) -> int:
    """The exact length of the archive `tarfile` writes for members of these names and sizes."""
    total = 2 * tarfile.BLOCKSIZE  # the end-of-archive blocks
    for name, size in members:
        header = _info(name, size).tobuf(tarfile.DEFAULT_FORMAT, "utf-8", "surrogateescape")
        total += len(header) + -(-size // tarfile.BLOCKSIZE) * tarfile.BLOCKSIZE
    return -(-total // tarfile.RECORDSIZE) * tarfile.RECORDSIZE


def build_layout(
    reference: str, digest: str, *, limit: int, client: httpx.Client | None = None
) -> Layout:
    """The image-layout tar of `reference` at `digest`, from its registry, in a temporary file.
    `limit` bounds the archive's size in bytes (the provider's `limits.image_layout_bytes`); the
    manifests name every blob's size, so an image over it raises `LayoutTooLarge` before a blob is
    downloaded. Raises `LayoutError` when the image cannot be read or a blob does not match its
    digest."""
    if not _DIGEST.fullmatch(digest):
        raise LayoutError("the digest is not sha256:<64 hex digits>")
    host, repository = split_reference(reference)
    import httpx  # noqa: PLC0415  # pylint: disable=import-outside-toplevel,redefined-outer-name

    own = client is None
    http = client or httpx.Client(timeout=60.0)
    file: BinaryIO | None = None
    layout: Layout | None = None
    try:
        registry = _Registry(http, host, repository)
        accept = ", ".join(MANIFEST_TYPES)
        manifests: dict[str, bytes] = {}
        top, media = registry.manifest(digest, accept)
        manifests[digest] = top
        manifest = json.loads(top)
        if media in INDEX_TYPES or "manifests" in manifest:
            child = _platform_manifest(manifest)
            data, _ = registry.manifest(child, accept)
            manifests[child] = data
            manifest = json.loads(data)
        wanted = {
            item["digest"]: int(item["size"])
            for item in (manifest["config"], *manifest.get("layers", ()))
            if item["digest"] not in manifests
        }
        head = {
            "oci-layout": b'{"imageLayoutVersion":"1.0.0"}',
            "index.json": _index(reference, digest, media, len(top)),
            **{_blob_name(name): data for name, data in manifests.items()},
        }
        size = _tar_size(
            [(name, len(data)) for name, data in head.items()]
            + [(_blob_name(name), blob_size) for name, blob_size in wanted.items()]
        )
        if size > limit:
            raise LayoutTooLarge(size, limit)
        file = tempfile.TemporaryFile()  # noqa: SIM115  # the Layout closes it
        with tarfile.open(fileobj=file, mode="w") as archive:
            for name, data in head.items():
                archive.addfile(_info(name, len(data)), io.BytesIO(data))
            for blob_digest, blob_size in wanted.items():
                with registry.open("blobs", blob_digest) as response:
                    blob = _Blob(response.iter_bytes(), blob_digest, blob_size)
                    archive.addfile(_info(_blob_name(blob_digest), blob_size), blob)  # type: ignore[arg-type]
                    blob.finish()
        layout = Layout(file, file.tell())
        return layout
    except (httpx.HTTPError, KeyError, ValueError, TypeError) as error:
        raise LayoutError(f"{type(error).__name__}: {error}") from None
    finally:
        if layout is None and file is not None:
            file.close()
        if own:
            http.close()


def _index(reference: str, digest: str, media: str, size: int) -> bytes:
    index = {
        "schemaVersion": 2,
        "manifests": [
            {
                "mediaType": media,
                "digest": digest,
                "size": size,
                "annotations": {"org.opencontainers.image.ref.name": reference},
            }
        ],
    }
    return json.dumps(index, separators=(",", ":")).encode()
