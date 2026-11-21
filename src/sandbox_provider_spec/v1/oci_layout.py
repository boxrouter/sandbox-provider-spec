# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""An OCI image layout tar of a public image, which the tester sends as the part `context` of
`image_prepare` to a provider that lists `image.prepare.oci_layout`.

The tester plays the caller here: a provider that takes layouts reaches no registry, so whoever
asks it to prepare an OCI image reads the image first and hands the bytes over. This reads a public
image by digest over the registry HTTP API (anonymous), checks every blob against its digest, and
writes `oci-layout`, `index.json` and `blobs/sha256/*` as one tar archive."""

from __future__ import annotations

import hashlib
import io
import json
import re
import tarfile
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

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
MAX_LAYOUT_BYTES = 256 * 1024 * 1024  # a test image is small; refuse to build a huge archive
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_CHALLENGE = re.compile(r'(\w+)="([^"]*)"')


class LayoutError(RuntimeError):
    """The image could not be read as a layout; the message is for a person."""


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
        self._budget = MAX_LAYOUT_BYTES

    def get(self, kind: str, digest: str, accept: str | None = None) -> tuple[bytes, str]:
        """A manifest or blob by digest, checked against it, with its content type."""
        url = f"{self._base}/{kind}/{digest}"
        response = self._request(url, accept)
        if response.status_code == 401 and self._authenticate(response):
            response = self._request(url, accept)
        if response.status_code != 200:
            raise LayoutError(f"the registry answered {response.status_code} for {kind} {digest}")
        data = response.content
        self._budget -= len(data)
        if self._budget < 0:
            raise LayoutError("the image is too large for the tester to build a layout")
        actual = "sha256:" + hashlib.sha256(data).hexdigest()
        if actual != digest:
            raise LayoutError(f"{kind} {digest} came back as {actual}")
        return data, response.headers.get("content-type", "").split(";", 1)[0].strip()

    def _request(self, url: str, accept: str | None) -> httpx.Response:
        headers = {"Accept": accept} if accept else {}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return self._client.get(url, headers=headers, follow_redirects=True)

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


def build_layout(reference: str, digest: str, *, client: httpx.Client | None = None) -> bytes:
    """The image-layout tar of `reference` at `digest`, from its registry. Raises `LayoutError`
    when the image cannot be read or a blob does not match its digest."""
    if not _DIGEST.fullmatch(digest):
        raise LayoutError("the digest is not sha256:<64 hex digits>")
    host, repository = split_reference(reference)
    import httpx  # noqa: PLC0415  # pylint: disable=import-outside-toplevel,redefined-outer-name

    own = client is None
    http = client or httpx.Client(timeout=60.0)
    try:
        registry = _Registry(http, host, repository)
        accept = ", ".join(MANIFEST_TYPES)
        blobs: dict[str, bytes] = {}
        top, media = registry.get("manifests", digest, accept)
        blobs[digest] = top
        manifest = json.loads(top)
        if media in INDEX_TYPES or "manifests" in manifest:
            child = _platform_manifest(manifest)
            data, _ = registry.get("manifests", child, accept)
            blobs[child] = data
            manifest = json.loads(data)
        wanted = [manifest["config"], *manifest.get("layers", ())]
        for item in wanted:
            blob_digest = item["digest"]
            if blob_digest not in blobs:
                blobs[blob_digest] = registry.get("blobs", blob_digest)[0]
    except (httpx.HTTPError, KeyError, ValueError) as error:
        raise LayoutError(f"{type(error).__name__}: {error}") from None
    finally:
        if own:
            http.close()
    return _tar(reference, digest, media, blobs)


def _tar(reference: str, digest: str, media: str, blobs: Mapping[str, bytes]) -> bytes:
    index = {
        "schemaVersion": 2,
        "manifests": [
            {
                "mediaType": media,
                "digest": digest,
                "size": len(blobs[digest]),
                "annotations": {"org.opencontainers.image.ref.name": reference},
            }
        ],
    }
    members: dict[str, bytes] = {
        "oci-layout": b'{"imageLayoutVersion":"1.0.0"}',
        "index.json": json.dumps(index, separators=(",", ":")).encode(),
    }
    for blob_digest, data in blobs.items():
        members[f"blobs/sha256/{blob_digest.removeprefix('sha256:')}"] = data
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as archive:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(data), 0o644, 0
            archive.addfile(info, io.BytesIO(data))
    return out.getvalue()
