# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Direct OCI qualification does not invent a prepared image or delete the source."""

from __future__ import annotations

from typing import Any

import pytest
from test_tester import LocalProvider, with_gates

from sandbox_provider_spec.v1 import CreateRequest, Discovery, Sandbox
from sandbox_provider_spec.v1.tester import (
    TestOptions,
    not_claimed_tests,
    run_tests,
    select_tests,
    shared_suite,
)

REFERENCE = "docker.io/library/alpine@sha256:" + "a" * 64
DIRECT = "coverage.custom_images.direct.oci"


class DirectOciProvider(LocalProvider, manifest=False):
    def __init__(self) -> None:
        super().__init__()
        self.requests: list[CreateRequest] = []

    async def discovery(self) -> Discovery:
        return with_gates({"custom_images": [{"source": "oci", "prepared": False}]})

    async def create(self, request: CreateRequest, *, idempotency_key: str) -> Sandbox:
        self.requests.append(request)
        return await super().create(request, idempotency_key=idempotency_key)


def test_direct_oci_boots_the_reference_without_preparing_or_deleting_an_image() -> None:
    provider = DirectOciProvider()
    report = run_tests(
        provider,
        TestOptions(
            tests=(DIRECT, "custom_images.oci"),
            fixtures={"oci_image": REFERENCE, "image_marker": "ID="},
        ),
    )
    outcomes = {row["id"]: row for row in report["tests"]}
    assert outcomes[DIRECT]["result"] == "passed", report["tests"]
    assert outcomes["custom_images.oci"]["reason"] == "direct_oci_uses_separate_check"
    assert report.all_passed
    assert "section custom_images passed" in report.lines
    assert report["clean"] is True
    image_requests = [request for request in provider.requests if request.image is not None]
    assert len(image_requests) == 1
    assert image_requests[0].image == REFERENCE
    assert image_requests[0].requirements == {"custom_images": {"prepared": False}}
    assert all(box.state == "destroyed" for box in provider.boxes.values())


@pytest.mark.parametrize(
    ("variants", "omitted"),
    [
        ([{"source": "oci"}], True),
        ([{"source": "oci", "prepared": False}], True),
        ([{"source": "oci", "prepared": True}], False),
        ([{"source": "oci"}, {"source": "oci", "prepared": True}], False),
        ([{"source": "dockerfile", "prepared": True}], False),
        ([{"source": "oci", "prepared": "unknown"}], False),
    ],
)
def test_only_direct_oci_skips_the_legacy_check_that_prepares_an_image(
    variants: list[dict[str, Any]], omitted: bool
) -> None:
    found = not_claimed_tests(with_gates({"custom_images": variants}))
    assert ("custom_images.oci" in found) is omitted


def test_direct_check_is_selected_only_for_a_direct_variant() -> None:
    suite = shared_suite()
    direct = with_gates({"custom_images": [{"source": "oci"}]})
    prepared = with_gates({"custom_images": [{"source": "oci", "prepared": True}]})
    assert DIRECT in {row.id for row in select_tests(suite, direct, TestOptions()).tests}
    assert DIRECT not in {row.id for row in select_tests(suite, prepared, TestOptions()).tests}
