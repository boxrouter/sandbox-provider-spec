# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""`Provider.static_discovery()`, `within(discovery, ceiling)` and `installed()`."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from sandbox_provider_spec.v1 import (
    Discovery,
    Provider,
    discovery_digest,
    from_json,
    installed,
    package_digest,
    report_subject,
    within,
)

EXAMPLES = Path(__file__).resolve().parents[2] / "spec" / "provider-api-1.0-examples"


def example() -> Discovery:
    return from_json(Discovery, json.loads((EXAMPLES / "Discovery.json").read_text("utf-8")))


def with_resources(base: Discovery, **resources: object) -> Discovery:
    first = base.classes[0]
    changed = dataclasses.replace(first, resources={**first.resources, **resources})
    return dataclasses.replace(base, classes=[changed, *base.classes[1:]])


@pytest.mark.rule("provider-api/discovery-within-static")
def test_within_equal_documents_are_within() -> None:
    assert within(example(), example()) == []


@pytest.mark.rule("provider-api/discovery-within-static")
def test_within_a_narrower_region_list_is_within_and_a_wider_one_names_the_path() -> None:
    base = with_resources(example(), regions=["us", "eu"])
    narrower = with_resources(example(), regions=["us"])
    assert within(narrower, base) == []
    wider = with_resources(example(), regions=["us", "eu", "asia"])
    name = base.classes[0].id
    assert within(wider, base) == [f"classes.{name}.resources.regions: +asia"]


@pytest.mark.rule("provider-api/discovery-within-static")
def test_within_an_extra_class_is_refused() -> None:
    base = example()
    extra = dataclasses.replace(base.classes[0], id="extra")
    assert within(dataclasses.replace(base, classes=[*base.classes, extra]), base) == [
        "classes.extra: +class"
    ]
    both = dataclasses.replace(base, classes=[*base.classes, extra])
    assert within(base, both) == []  # fewer classes are narrower


@pytest.mark.rule("provider-api/discovery-within-static")
def test_within_a_larger_limit_is_refused_and_a_smaller_one_is_within() -> None:
    base = example()
    larger = dataclasses.replace(
        base, limits=dataclasses.replace(base.limits, file_bytes=base.limits.file_bytes + 1)
    )
    assert within(larger, base) == [
        f"limits.file_bytes: {base.limits.file_bytes + 1} (ceiling {base.limits.file_bytes})"
    ]
    smaller = dataclasses.replace(
        base, limits=dataclasses.replace(base.limits, file_bytes=base.limits.file_bytes - 1)
    )
    assert within(smaller, base) == []


@pytest.mark.rule("provider-api/discovery-within-static")
def test_within_ready_true_is_outside_a_ceiling_that_is_not_ready() -> None:
    base = example()
    first = dataclasses.replace(base.classes[0], ready=False)
    ceiling = dataclasses.replace(base, classes=[first, *base.classes[1:]])
    assert within(base, ceiling) == [f"classes.{first.id}.ready: +ready"]
    assert within(ceiling, base) == []


def test_static_discovery_is_unimplemented_by_default() -> None:
    class Plain(Provider, manifest=False):
        pass

    with pytest.raises(NotImplementedError):
        Plain.static_discovery()


def test_static_discovery_installed_lists_the_providers_by_id() -> None:
    found = installed()
    assert all(isinstance(cls, type) and issubclass(cls, Provider) for cls in found.values())
    assert all(cls.provider_id == name for name, cls in found.items())


def test_report_subject_binds_a_report_to_the_package_and_its_discovery() -> None:
    cls = installed()["example"] if "example" in installed() else next(iter(installed().values()))
    subject = report_subject(cls, example())
    assert subject is not None
    assert subject["package_digest"] == package_digest(cls)
    assert subject["package_digest"].startswith("sha256:") and len(subject["package_digest"]) == 71
    assert subject["discovery_digest"] == discovery_digest(example())
    # availability flips do not move the digest; a real change does
    base = example()
    flipped = dataclasses.replace(
        base, classes=[dataclasses.replace(base.classes[0], ready=not base.classes[0].ready)]
    )
    assert discovery_digest(flipped) == discovery_digest(
        dataclasses.replace(base, classes=[flipped.classes[0]])
    )
    renamed = dataclasses.replace(
        base, classes=[dataclasses.replace(base.classes[0], name="Another name")]
    )
    assert discovery_digest(renamed) != discovery_digest(
        dataclasses.replace(base, classes=[base.classes[0]])
    )
