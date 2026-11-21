# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The typed views of a class's gates, operations and lifetime timer (`SandboxClass.claims`,
`.lists` and `.timer`)."""

from __future__ import annotations

import dataclasses

from sandbox_provider_spec.v1 import LifetimeTimerView, SandboxClass


def make(**fields: object) -> SandboxClass:
    base: dict[str, object] = {
        "id": "default",
        "name": "Default",
        "ready": True,
        "resources": {},
        "lifetime_timer": {"enforced_by": "provider"},
        "images": [],
        "prices": [],
    }
    return dataclasses.replace(SandboxClass(**base), **fields)  # type: ignore[arg-type]


def test_class_views_claims_an_unclaimed_gate_is_empty() -> None:
    assert make().claims("processes") == ()
    assert make(gates={"files": [{"a": 1}]}).claims("processes") == ()


def test_class_views_claims_returns_every_variant_in_order() -> None:
    item = make(gates={"previews": [{"access": "public"}, {"access": "private"}]})
    assert item.claims("previews") == ({"access": "public"}, {"access": "private"})


def test_class_views_claims_takes_one_mapping_as_one_variant_and_drops_the_rest() -> None:
    assert make(gates={"processes": {"cancel": True}}).claims("processes") == ({"cancel": True},)
    assert make(gates={"processes": [{"cancel": True}, "x", 3]}).claims("processes") == (
        {"cancel": True},
    )


def test_class_views_lists_needs_every_named_operation() -> None:
    item = make(operations=("files.list", "labels.update"))
    assert item.lists("labels.update") and item.lists("files.list", "labels.update")
    assert not item.lists("files.list", "files.mkdir")
    assert not make(operations=()).lists("labels.update")  # an empty `operations` lists nothing


def test_class_views_timer_reads_the_declared_timer() -> None:
    item = make(
        lifetime_timer={
            "enforced_by": "router",
            "counts_paused_time": True,
            "at_end": ["paused", "destroyed"],
        }
    )
    assert item.timer() == LifetimeTimerView("router", True, ("paused", "destroyed"))


def test_class_views_timer_defaults_missing_fields() -> None:
    assert make(lifetime_timer={}).timer() == LifetimeTimerView("none", False, ("destroyed",))


def test_class_views_timer_is_none_for_a_value_the_spec_does_not_define() -> None:
    assert make(lifetime_timer={"enforced_by": "client"}).timer() is None
    assert make(lifetime_timer={"at_end": "frozen"}).timer() is None
    assert make(lifetime_timer={"at_end": []}).timer() is None
    assert make(lifetime_timer={"counts_paused_time": "yes"}).timer() is None


def test_class_views_labels_kept_by_names_the_keeper_of_each_kind() -> None:
    assert make().labels_kept_by("image") == "provider"
    item = make(image_labels_kept_by="router", snapshot_labels_kept_by="provider")
    assert (item.labels_kept_by("image"), item.labels_kept_by("snapshot")) == ("router", "provider")
