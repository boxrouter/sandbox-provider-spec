# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""A class may state that the router keeps the labels of its images and snapshots
(`image_labels_kept_by`, `snapshot_labels_kept_by`): the tester then leaves out the label
assertions and still checks everything else."""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from typing import Any

import pytest
from test_images import IMAGE_OPERATIONS, ImageProvider, outcome
from test_tester import SnapshotProvider, example

from sandbox_provider_spec.v1 import (
    Discovery,
    ImagePage,
    ImageRequest,
    PreparedImage,
    Snapshot,
    SnapshotPage,
    SnapshotRequest,
    from_json,
    to_json,
)
from sandbox_provider_spec.v1.suite_driver import ProviderDriver
from sandbox_provider_spec.v1.tester import (
    TestOptions,
    labels_kept,
    run_tests,
    select_tests,
    shared_suite,
    unsupported_operations,
)


def stating(discovery: Discovery, **fields: str) -> Discovery:
    first = dataclasses.replace(discovery.classes[0], **fields)
    return dataclasses.replace(discovery, classes=[first, *discovery.classes[1:]])


class UnlabelledImageProvider(ImageProvider, manifest=False):
    """Prepares images and keeps no labels: `get` and `list` return `{}` and ignore the filter."""

    router = True

    async def discovery(self) -> Discovery:
        found = await super().discovery()
        return stating(found, image_labels_kept_by="router") if self.router else found

    async def image_prepare(self, request: ImageRequest, **kwargs: Any) -> PreparedImage:
        image = await super().image_prepare(request, **kwargs)
        return dataclasses.replace(image, labels={})

    async def image_get(self, image_id: str) -> PreparedImage:
        return dataclasses.replace(await super().image_get(image_id), labels={})

    async def image_list(
        self, *, labels: Mapping[str, str] | None = None, **kwargs: Any
    ) -> ImagePage:
        page = await super().image_list(**kwargs)
        return ImagePage([dataclasses.replace(item, labels={}) for item in page.images], None)


@pytest.fixture(name="provider")
def provider_fixture() -> Any:
    UnlabelledImageProvider.reset()
    UnlabelledImageProvider.router = True
    yield UnlabelledImageProvider()
    UnlabelledImageProvider.reset()


@pytest.mark.rule("provider-api/image-labels-router-kept")
def test_a_router_kept_image_section_passes_without_label_assertions(
    provider: UnlabelledImageProvider,
) -> None:
    report = run_tests(provider, TestOptions(tests=("images.",)))
    tests = outcome(report)
    assert tests and set(tests.values()) == {"passed"}, tests
    assert all(image.id in ImageProvider.deleted for image in ImageProvider.images.values())


def test_a_provider_that_states_nothing_is_still_held_to_its_image_labels(
    provider: UnlabelledImageProvider,
) -> None:
    UnlabelledImageProvider.router = False
    tests = outcome(run_tests(provider, TestOptions(tests=("images.v1.get_and_list",))))
    assert tests == {"images.v1.get_and_list": "differs"}


def test_the_label_assertions_alone_are_left_out_of_a_router_kept_class() -> None:
    suite = shared_suite()
    discovery = stating(
        example(Discovery),
        operations=IMAGE_OPERATIONS,
        image_labels_kept_by="router",
        snapshot_labels_kept_by="router",
    )
    chosen = {
        test.id: test
        for test in select_tests(
            suite, discovery, TestOptions(tests=("images.v1.get_and_list", "snapshots.v1."))
        ).tests
    }
    state = [s for s in chosen["images.v1.get_and_list"].steps if s["op"] == "image.state"][0]
    assert state["expect"] == {"equals": {"state": "ready"}}
    assert any(s["op"] == "image.list" for s in chosen["images.v1.get_and_list"].steps)
    lists = [s for s in chosen["snapshots.v1.get_and_list"].steps if s["op"] == "snapshot.list"]
    assert [list(s["in"]) for s in lists] == [["sandbox_id"]]
    original = {t.id: t for t in suite.tests}["snapshots.v1.get_and_list"]
    assert len([s for s in original.steps if s["op"] == "snapshot.list"]) == 2
    assert not any(
        s["op"] == "snapshot.list" for s in chosen["snapshots.v1.idempotent_create"].steps
    )
    # a class that states nothing keeps every step
    plain = select_tests(suite, example(Discovery), TestOptions(tests=("snapshots.v1.",)))
    assert [t.steps for t in plain.tests if t.id == "snapshots.v1.get_and_list"] == [original.steps]


def test_the_wire_carries_the_two_fields_and_omits_the_default() -> None:
    discovery = example(Discovery)
    assert labels_kept(discovery) == {"image": True, "snapshot": True}
    assert "image_labels_kept_by" not in to_json(discovery)["classes"][0]
    assert "snapshot_labels_kept_by" not in to_json(discovery)["classes"][0]
    routed = stating(discovery, snapshot_labels_kept_by="router")
    wire = to_json(routed)
    assert wire["classes"][0]["snapshot_labels_kept_by"] == "router"
    assert "image_labels_kept_by" not in wire["classes"][0]
    again = from_json(Discovery, wire)
    assert labels_kept(again) == {"image": True, "snapshot": False}


class UnlabelledSnapshotProvider(SnapshotProvider, manifest=False):
    """Keeps snapshots and no labels; its list needs a source sandbox and ignores labels."""

    async def snapshot_create(
        self, sandbox_id: str, request: SnapshotRequest, *, idempotency_key: str
    ) -> Snapshot:
        return await super().snapshot_create(
            sandbox_id, dataclasses.replace(request, labels={}), idempotency_key=idempotency_key
        )

    async def snapshot_list(
        self,
        *,
        labels: Mapping[str, str] | None = None,
        sandbox_id: str | None = None,
        cursor: str | None = None,
        limit: int = 100,
    ) -> SnapshotPage:
        assert not labels, "the tester must not ask a router-kept class for labels"
        return await super().snapshot_list(sandbox_id=sandbox_id, cursor=cursor, limit=limit)


@pytest.mark.rule("provider-api/snapshot-labels-router-kept")
def test_a_router_kept_snapshot_list_is_asked_by_sandbox_and_counts_only_the_runs_snapshots() -> (
    None
):
    provider = UnlabelledSnapshotProvider()
    provider.states = ["ready", "ready"]  # each snapshot reads back ready
    driver = ProviderDriver(provider, run="run-1")
    driver.snapshot_labels_kept = False
    try:
        box = driver.call("create", None, {})
        other = driver.call("create", None, {})
        snap = driver.call("snapshot.take", box, {"keeps": "files_only", "labels": {"a": "b"}})
        driver.call("snapshot.take", other, {"keeps": "files_only"})
        listed = driver.call("snapshot.list", None, {"sandbox_id": box["identity"]})
        assert listed == {"count": 1, "ids": [snap["identity"]]}
        # nothing marks the run's snapshots, so the sweep leaves them to their owners' release
        assert driver.snapshot_leftovers() == []
    finally:
        driver.close()


@pytest.mark.rule("provider-api/snapshot-cost-unavailable")
def test_a_class_that_cannot_report_a_snapshots_cost_has_that_test_left_out() -> None:
    suite = shared_suite()
    gates = {"snapshots": [{"keeps": "files_only", "original_after": "any"}]}
    offered = stating(example(Discovery), gates=gates)
    ids = {t.id for t in select_tests(suite, offered, TestOptions()).tests}
    assert "snapshots.v1.cost" in ids and "snapshots.v1.get_and_list" in ids
    discovery = stating(example(Discovery), gates=gates, snapshot_cost="unavailable")
    ids = {t.id for t in select_tests(suite, discovery, TestOptions()).tests}
    assert "snapshots.v1.cost" not in ids and "snapshots.v1.get_and_list" in ids
    assert unsupported_operations(discovery)["snapshot.cost"] == (
        "the class states snapshot_cost unavailable"
    )
    wire = to_json(discovery)
    assert wire["classes"][0]["snapshot_cost"] == "unavailable"
    assert from_json(Discovery, wire).classes[0].snapshot_cost == "unavailable"
    assert "snapshot_cost" not in to_json(example(Discovery))["classes"][0]
