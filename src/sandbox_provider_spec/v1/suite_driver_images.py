# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The prepared-image steps of the shared tests (`image.prepare`, `image.state`, `image.list`,
`image.delete`), run through the `image_*` operations of a 1.0 `Provider`."""

from __future__ import annotations

import base64
import builtins
import hashlib
import io
import json
import tarfile
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, TypeVar, cast
from uuid import uuid4

from sandbox_provider_spec import cost_checks
from sandbox_provider_spec.driver import (
    Inputs,
    NativeFailure,
    NotRun,
    Observation,
    Resource,
    Unsupported,
    resource,
    strings,
    text,
)
from sandbox_provider_spec.v1.oci_layout import LayoutError, build_layout
from sandbox_provider_spec.v1.provider import Provider
from sandbox_provider_spec.v1.types import (
    DockerfileSource,
    ImageConfig,
    ImageRequest,
    ImageResources,
    ImageSource,
    OciSource,
    PreparedImage,
    PrivateOciSource,
    RegistryCredentials,
)
from sandbox_provider_spec.v1.wire import to_json

if TYPE_CHECKING:
    from sandbox_provider_spec.v1.suite_driver import ProviderDriver

T = TypeVar("T")

UNKNOWN_IMAGE_ID = "sps-test-no-such-image"
IMAGE_WAIT_SECONDS = 1800  # how long a prepared image may stay in `preparing`
_CONTEXT_CHUNK = 64 * 1024


@dataclass
class ImageHandle:
    """What a prepared-image resource keeps in memory. A borrowed image (a provider artifact that
    the account already had) is never deleted."""

    id: str
    borrowed: bool = False


def image_reference(value: object) -> dict[str, str] | None:
    """The `create` image of a prepared-image binding that a test passes as `image`, or None when
    `value` is not such a binding."""
    if isinstance(value, Mapping) and isinstance(value.get("resource"), Resource):
        native = cast(Resource, value["resource"]).native
        if isinstance(native, ImageHandle):
            return {"provider_artifact": native.id}
    return None


def _resources(inputs: Inputs) -> ImageResources | None:
    raw = inputs.get("resources")
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise ValueError("resources must be a mapping")
    pick = {
        "cpu": raw.get("cpu", raw.get("cpu_min")),
        "memory_mib": raw.get("memory_mib", raw.get("memory_min_mib")),
        "disk_mib": raw.get("disk_mib", raw.get("disk_min_mib")),
    }
    return ImageResources(**pick)


def _config(inputs: Inputs) -> ImageConfig:
    raw = inputs.get("config", {})
    if not isinstance(raw, Mapping):
        raise ValueError("config must be a mapping")
    return ImageConfig(
        env=strings(raw, "env"),
        workdir=cast("str | None", raw.get("workdir")),
        user=cast("str | None", raw.get("user")),
        entrypoint=cast("list[str] | None", raw.get("entrypoint")),
        cmd=cast("list[str] | None", raw.get("cmd")),
    )


def _digest(reference: str) -> str:
    """The digest that an image reference pins; a test names images by digest because the
    provider reaches no registry to find it."""
    _, at, digest = reference.partition("@")
    if not at:
        raise NotRun("oci_reference_has_no_digest")
    return digest


def _source(inputs: Inputs) -> ImageSource:
    kind = inputs.get("source")
    if kind == "dockerfile":
        return DockerfileSource(text(inputs, "dockerfile"))
    reference = text(inputs, "image")
    if kind == "oci":
        return OciSource(reference, _digest(reference), _config(inputs))
    if kind == "private_oci":
        credentials = RegistryCredentials(text(inputs, "username"), text(inputs, "password"))
        return PrivateOciSource(reference, _digest(reference), _config(inputs), credentials)
    raise ValueError("source must be oci, private_oci, dockerfile or provider_artifact")


def _tar(files: object) -> bytes:
    """A tar archive of a test's `context`: a map from a relative path to UTF-8 text or
    `{base64: <text>}`."""
    if not isinstance(files, Mapping):
        raise ValueError("context must map paths to file contents")
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as archive:
        for path in sorted(files):
            value = files[path]
            if isinstance(value, Mapping):
                data = base64.b64decode(str(value["base64"]))
            else:
                data = str(value).encode("utf-8")
            info = tarfile.TarInfo(str(path))
            info.size, info.mode, info.mtime = len(data), 0o644, 0
            archive.addfile(info, io.BytesIO(data))
    return out.getvalue()


async def _chunks(data: bytes) -> AsyncIterator[bytes]:
    for start in range(0, len(data), _CONTEXT_CHUNK):
        yield data[start : start + _CONTEXT_CHUNK]


class ImageSteps:
    """The image steps of `ProviderDriver`, which inherits them."""

    # Whether some class lists `image.prepare.oci_layout`: the tester then reads each OCI image
    # from its registry, as the caller would, and sends it as the part `context`.
    oci_layout = False
    # Whether the provider keeps the labels of its images (discovery's `image_labels_kept_by`).
    image_labels_kept = True

    if TYPE_CHECKING:
        api: Provider
        run_id: str
        _images: dict[str, Resource]
        _image_keys: dict[str, tuple[str, Resource]]

        def wait(self, call: Awaitable[T]) -> T:
            raise NotImplementedError

        def own(self, kind: str, native: object, cleanup: Callable[[], Observation]) -> Resource:
            raise NotImplementedError

        def release(self, owned: Resource) -> Observation:
            raise NotImplementedError

        def _key(self, inputs: Inputs) -> str:
            raise NotImplementedError

    @staticmethod
    def _image_handle(target: object) -> ImageHandle:
        native = resource(target).native
        if not isinstance(native, ImageHandle):
            raise ValueError("operation requires a prepared image")
        return native

    def _own_image(self, image: PreparedImage) -> Resource:
        """The resource of an image, made once: a repeated prepare returns the same image."""
        known = self._images.get(image.id)
        if known is not None:
            return known
        handle = ImageHandle(image.id)
        owned = self.own("image", handle, lambda: self._delete_image(handle.id))
        self._images[image.id] = owned
        return owned

    def _delete_image(self, image_id: str) -> Observation:
        try:
            self.wait(self.api.image_delete(image_id))
        except NativeFailure as error:
            if error.code != "not_found":
                raise
        return {"result": "deleted"}

    def _prepare_key(
        self, inputs: Inputs, request: ImageRequest, context: bytes
    ) -> tuple[str, str]:
        """The request's digest, and the idempotency key to send. A test's named key is used as
        for `create`; without one, a repeat of a request whose image is still held reuses the
        key of the first, so that the provider is asked the same question twice."""
        canonical = json.dumps(to_json(request), sort_keys=True).encode()
        digest = hashlib.sha256(canonical + b"\0" + context).hexdigest()
        if inputs.get("idempotency_key") is not None:
            return digest, self._key(inputs)
        held = self._image_keys.get(digest)
        if held is not None and not held[1].released:
            return digest, held[0]
        return digest, str(uuid4())

    def image_prepare(self, target: object, inputs: Inputs) -> Observation:
        """Prepare an image and wait until it is `ready`. A `provider_artifact` is borrowed: the
        account already has it, and it is never deleted."""
        del target
        if inputs.get("source") == "provider_artifact":
            name = text(inputs, "image")
            borrowed = self.own(
                "image", ImageHandle(name, True), lambda: {"result": "already_released"}
            )
            return {"resource": borrowed, "identity": name, "key": name, "resources": None}
        source = _source(inputs)
        if not isinstance(source, DockerfileSource) and "context" in inputs:
            raise ValueError("only a dockerfile takes a context")
        context = _tar(inputs["context"]) if "context" in inputs else None
        if self.oci_layout and not isinstance(source, DockerfileSource):
            context = self._layout(source)
        request = ImageRequest(
            source=source,
            resources=_resources(inputs),
            labels={**strings(inputs, "labels"), "sps.test.run": self.run_id},
        )
        digest, key = self._prepare_key(inputs, request, context or b"")
        created = self.wait(
            self.api.image_prepare(
                request,
                context=None if context is None else _chunks(context),
                context_size=None if context is None else len(context),
                idempotency_key=key,
            )
        )
        owned = self._own_image(created)  # owned before the wait, so a failed wait cleans up
        self._image_keys[digest] = (key, owned)
        image = created
        deadline = time.monotonic() + IMAGE_WAIT_SECONDS
        while image.state != "ready":
            if image.state == "failed":
                raise NativeFailure("image_failed")
            if time.monotonic() >= deadline:
                raise NotRun("image_not_ready_in_window")
            time.sleep(1)
            image = self.wait(self.api.image_get(created.id))
        return {
            "resource": owned,
            "identity": created.id,
            "key": digest,
            "resources": None if image.resources is None else _resources_json(image.resources),
        }

    @staticmethod
    def _layout(source: OciSource | PrivateOciSource) -> bytes:
        """The image layout that a provider listing `image.prepare.oci_layout` is sent."""
        if isinstance(source, PrivateOciSource):
            raise NotRun("a_private_image_cannot_be_read_without_its_credentials")
        try:
            return build_layout(source.oci, source.digest)
        except LayoutError:
            raise NotRun("oci_layout_could_not_be_built") from None

    def image_cost(self, target: object, inputs: Inputs) -> Observation:
        """Read what preparing an image cost; `final: true` reads until final, up to `timeout_ms`
        (else `cost_final_within_seconds`)."""
        handle = self._image_handle(target)
        cost = cost_checks.read_cost(
            cast("ProviderDriver", self), lambda: self.api.image_cost(handle.id), inputs
        )
        return {
            "status": cost.status,
            "image_matches": cost.image_id == handle.id,
            "has_no_sandbox": cost.sandbox_id is None and cost.snapshot_id is None,
        }

    def image_state(self, target: object, inputs: Inputs) -> Observation:
        """Read one image: `absent` when the provider has no record of it. `unknown: true` reads
        an id that no provider has issued."""
        image_id = (
            UNKNOWN_IMAGE_ID if inputs.get("unknown") is True else self._image_handle(target).id
        )
        try:
            image = self.wait(self.api.image_get(image_id))
        except NativeFailure as error:
            if error.code == "not_found":
                return {"state": "absent"}
            raise
        labels = dict(image.labels)
        if labels.get("sps.test.run") == self.run_id:
            del labels["sps.test.run"]  # the tester's own label
        return {"state": image.state, "labels": labels}

    def image_delete(self, target: object, inputs: Inputs) -> Observation:
        del inputs
        return self.release(resource(target))

    def image_delete_again(self, target: object, inputs: Inputs) -> Observation:
        """Delete an image that an earlier step already deleted, and report the state."""
        del inputs
        return {"state": self.wait(self.api.image_delete(self._image_handle(target).id)).state}

    def sweep_images(self) -> builtins.list[Observation]:
        """Delete every image that still carries this run's label; none when the provider has no
        prepared images."""
        if not self.image_labels_kept:
            return []  # nothing marks the run's images; each one this driver made is released
        try:
            ids = cast("builtins.list[str]", self.image_list(None, {})["ids"])
        except Unsupported:
            return []
        except Exception as error:  # pylint: disable=broad-exception-caught
            return [{"kind": "image", "result": "error", "reason": type(error).__name__}]
        results: builtins.list[Observation] = []
        for image_id in ids:
            try:
                results.append({"kind": "image", **self._delete_image(image_id)})
            except Exception as error:  # pylint: disable=broad-exception-caught
                results.append({"kind": "image", "result": "error", "reason": type(error).__name__})
        return results

    def image_list(self, target: object, inputs: Inputs) -> Observation:
        """The run's images that match the given labels."""
        del target
        # A provider that keeps no image labels is not asked for them: the run's images are the
        # ones this driver made, found among what the provider lists.
        kept = self.image_labels_kept
        wanted = {**strings(inputs, "labels"), "sps.test.run": self.run_id} if kept else None
        ids: builtins.list[str] = []
        cursor: str | None = None
        while True:
            page = self.wait(self.api.image_list(labels=wanted, cursor=cursor))
            ids.extend(item.id for item in page.images if kept or item.id in self._images)
            cursor = page.next_cursor
            if cursor is None:
                return {"count": len(ids), "ids": ids}


def _resources_json(value: ImageResources) -> dict[str, Any]:
    return {
        key: item
        for key, item in (
            ("cpu", value.cpu),
            ("memory_mib", value.memory_mib),
            ("disk_mib", value.disk_mib),
        )
        if item is not None
    }
