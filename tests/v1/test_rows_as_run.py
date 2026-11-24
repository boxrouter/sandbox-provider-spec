# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The row AS THE TESTER RUNS IT for a provider comes from one function, `rows_as_run`.

The tester rewrites some rows for what a provider's discovery states before it runs and digests
them (a router that keeps labels has the label assertions left out; images that cannot be deleted
while a sandbox runs from them have the sandbox destroyed first). Whoever judges a report must
digest the same rows, or every rewritten row reads stale on every rerun."""

from __future__ import annotations

import dataclasses
from typing import Any

from test_images import IMAGE_OPERATIONS
from test_tester import example

from sandbox_provider_spec.check_digests import check_digests
from sandbox_provider_spec.v1 import Discovery
from sandbox_provider_spec.v1.tester import (
    TestOptions,
    labels_kept,
    rows_as_run,
    run_discovery,
    select_tests,
    shared_suite,
)

#: What t5nf's reproduction found the committed reports recorded: the rows a rewrite changes.
LABEL_ROWS = {
    "images.v1.get_and_list",
    "snapshots.v1.get_and_list",
    "snapshots.v1.idempotent_create",
}
CONFLICT_ROWS = {"images.v1.prepare_oci"}


def stating(discovery: Discovery, index: int = 0, **fields: Any) -> Discovery:
    classes = list(discovery.classes)
    classes[index] = dataclasses.replace(classes[index], **fields)
    return dataclasses.replace(discovery, classes=classes)


def plain() -> Discovery:
    return stating(example(Discovery), operations=IMAGE_OPERATIONS)


def routers() -> Discovery:
    return stating(plain(), image_labels_kept_by="router", snapshot_labels_kept_by="router")


def conflicting() -> Discovery:
    return stating(plain(), image_delete_in_use="conflict")


def changed(discovery: Discovery) -> set[str]:
    rows = shared_suite().tests
    return {
        before.id
        for before, after in zip(rows, rows_as_run(rows, discovery), strict=True)
        if before != after
    }


def test_a_provider_that_states_nothing_that_rewrites_gets_its_rows_unchanged() -> None:
    rows = shared_suite().tests
    assert rows_as_run(rows, plain()) == tuple(rows)
    assert rows_as_run(rows, None) == tuple(rows)
    assert check_digests(rows_as_run(rows, plain())) == check_digests(tuple(rows))  # 0 digests move


def test_a_router_that_keeps_labels_rewrites_exactly_the_rows_that_assert_them() -> None:
    assert LABEL_ROWS <= changed(routers())
    assert not changed(routers()) & CONFLICT_ROWS
    moved = {
        id_
        for id_, digest in check_digests(rows_as_run(shared_suite().tests, routers())).items()
        if digest != check_digests(tuple(shared_suite().tests))[id_]
    }
    assert moved == changed(routers())  # a digest moves for a rewritten row, and for no other


def test_a_blocking_image_delete_rewrites_exactly_the_rows_that_delete_images() -> None:
    assert changed(conflicting()) >= CONFLICT_ROWS
    assert not changed(conflicting()) & {"snapshots.v1.get_and_list", "baseline.get"}


def test_the_tester_selects_the_rows_it_runs_through_the_same_function() -> None:
    for discovery in (routers(), conflicting(), plain()):
        run = select_tests(shared_suite(), discovery, TestOptions())
        unrewritten = select_tests(shared_suite(), plain(), TestOptions())
        assert run.tests == rows_as_run(unrewritten.tests, discovery)


def test_a_run_pinned_to_one_class_is_judged_by_that_class_alone() -> None:
    first = example(Discovery)
    second = dataclasses.replace(first.classes[0], id="other", image_labels_kept_by="router")
    both = dataclasses.replace(first, classes=[first.classes[0], second])
    assert labels_kept(both)["image"] is False  # a whole-provider run: any class says router
    assert labels_kept(run_discovery(both, first.classes[0].id))["image"] is True
    assert labels_kept(run_discovery(both, "other"))["image"] is False
    assert run_discovery(both, None) is both
    assert run_discovery(both, "no-such-class") is both
