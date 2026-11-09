# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Docker SDK create errors after allocation retain the known cleanup name."""

from __future__ import annotations

import socket
import time
from collections.abc import Mapping
from types import SimpleNamespace

import pytest
from docker.errors import NotFound  # type: ignore[import-untyped]
from docker.utils.socket import frames_iter  # type: ignore[import-untyped]

from sandbox_provider_spec.conformance import run_suite
from sandbox_provider_spec.driver import NotRun
from sandbox_provider_spec.drivers.docker_engine import DockerDriver, Exec
from sandbox_provider_spec.runner import Runner
from sandbox_provider_spec.suite import Suite
from sandbox_provider_spec.suite import Test as Scenario


def test_create_readiness_failure_still_removes_the_owned_container() -> None:
    class Containers:
        def __init__(self) -> None:
            self.present = False
            self.identity = ""

        def create(self, image: str, *, name: str, **options: object) -> object:
            del image, options
            self.identity = name
            self.present = True
            raise RuntimeError("native create failed after allocation")

        def get(self, identity: str) -> Containers:
            assert identity == self.identity
            if not self.present:
                raise NotFound("gone")
            return self

        def remove(self, *, force: bool, v: bool) -> None:
            assert force and v
            self.present = False

    class Images:
        @staticmethod
        def get(reference: str) -> object:
            del reference
            return SimpleNamespace(id="existing-fixture")

    driver = DockerDriver({})
    containers = Containers()
    driver._client = SimpleNamespace(containers=containers, images=Images())  # pylint: disable=protected-access
    result: Mapping[str, object] = Runner(driver).run_test(
        Scenario("create", "failure after allocation", ({"op": "create"},), ())
    )
    assert result["result"] == "error"
    assert result["cleanup"] == [{"kind": "sandbox", "result": "deleted"}]
    assert not containers.present


def test_silent_native_sdk_stream_is_bounded_before_poll_can_hang() -> None:
    driver = DockerDriver({})
    # Keep the other endpoint open and silent: SDK frames_iter waits in poll.
    reader, writer = socket.socketpair()
    try:
        transport = reader.makefile("rwb", buffering=0)
        chunks = ((data, None) for _, data in frames_iter(transport, True))
        stream = Exec("native", None, transport, chunks)
        binding = {"resource": driver.own("process", stream, lambda: {"result": "deleted"})}
        started = time.monotonic()
        with pytest.raises(NotRun, match="^native_stream_observation_timed_out$"):
            driver.process_output(binding, {"timeout_ms": 50})
        assert time.monotonic() - started < 2
        transport.close()
    finally:
        reader.close()
        writer.close()


def test_default_image_is_reused_until_the_suite_finishes() -> None:
    class Container:
        def __init__(self, name: str) -> None:
            self.name = name
            self.id = f"id-{name}"

        def start(self) -> None:
            pass

        def remove(self, *, force: bool, v: bool) -> None:
            assert force and v
            containers.pop(self.name, None)

    containers: dict[str, Container] = {}
    images: dict[str, str] = {}
    pulls: list[str] = []

    class NativeContainers:
        @staticmethod
        def create(image: str, *, name: str, **options: object) -> Container:
            assert image == "sha256:python"
            del options
            native = Container(name)
            containers[name] = native
            return native

        @staticmethod
        def get(identity: str) -> Container:
            if identity not in containers:
                raise NotFound("gone")
            return containers[identity]

    class NativeImages:
        @staticmethod
        def get(reference: str) -> SimpleNamespace:
            if reference not in images and reference != "sha256:python":
                raise NotFound("absent")
            if reference == "sha256:python" and "python:3.12-slim" not in images:
                raise NotFound("absent")
            return SimpleNamespace(id="sha256:python")

        @staticmethod
        def pull(reference: str, **options: object) -> SimpleNamespace:
            assert not options
            pulls.append(reference)
            images[reference] = "sha256:python"
            return SimpleNamespace(id="sha256:python")

        @staticmethod
        def remove(identity: str, *, force: bool) -> None:
            assert identity == "sha256:python" and not force
            images.clear()

    driver = DockerDriver({})
    driver._client = SimpleNamespace(  # pylint: disable=protected-access
        containers=NativeContainers(), images=NativeImages()
    )
    suite = [
        Scenario("first", "first create", ({"op": "create"},), ()),
        Scenario("second", "second create", ({"op": "create"},), ()),
    ]

    results = run_suite(driver, Suite("test", tuple(suite)))

    assert pulls == ["python:3.12-slim"]
    assert results[0]["cleanup"] == [{"kind": "sandbox", "result": "deleted"}]
    assert results[1]["cleanup"] == [
        {"kind": "sandbox", "result": "deleted"},
        {"kind": "pulled_image", "result": "deleted"},
    ]
    assert images == {}


def test_build_cleanup_defers_tagged_base_image_to_suite_finish() -> None:
    class Image:
        def __init__(self, identity: str, tags: list[str]) -> None:
            self.id = identity
            self.tags = tags

    images = {
        "sha256:base": Image("sha256:base", ["python:3.12-slim"]),
        "sha256:built": Image("sha256:built", []),
    }

    class NativeImages:
        @staticmethod
        def list(*, all: bool) -> list[Image]:  # pylint: disable=redefined-builtin
            del all
            return list(images.values())

        @staticmethod
        def get(reference: str) -> Image:
            if reference == "python:3.12-slim":
                reference = "sha256:base"
            if reference not in images:
                raise NotFound("gone")
            return images[reference]

        @staticmethod
        def remove(identity: str, *, force: bool) -> None:
            assert not force
            images.pop(identity)

    driver = DockerDriver({})
    driver._client = SimpleNamespace(images=NativeImages())  # pylint: disable=protected-access

    assert driver._delete_build_images(set()) == {"result": "deleted"}  # pylint: disable=protected-access
    assert set(images) == {"sha256:base"}
    assert driver.finish() == [{"kind": "pulled_image", "result": "deleted"}]
    assert images == {}


def test_failed_default_image_pull_is_not_retried_for_each_test() -> None:
    pulls = 0

    class NativeImages:
        @staticmethod
        def get(reference: str) -> object:
            del reference
            raise NotFound("absent")

        @staticmethod
        def pull(reference: str, **options: object) -> object:
            nonlocal pulls
            assert reference == "python:3.12-slim" and not options
            pulls += 1
            raise RuntimeError("registry unavailable")

    driver = DockerDriver({})
    driver._client = SimpleNamespace(images=NativeImages())  # pylint: disable=protected-access

    with pytest.raises(RuntimeError, match="registry unavailable"):
        driver._image("python:3.12-slim")  # pylint: disable=protected-access
    with pytest.raises(NotRun, match="^suite_image_pull_failed$"):
        driver._image("python:3.12-slim")  # pylint: disable=protected-access

    assert pulls == 1
    assert driver.finish() == [{"kind": "pulled_image", "result": "deleted"}]
