# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""HTTP 0.3 admissions retain the matcher's selected resource facts."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest

from sandbox_provider_spec.http_binding_validation import (
    SCHEMA,
    BindingValidationError,
    validate_message,
    validate_new_create_03,
)


def discovery() -> dict[str, Any]:
    return deepcopy(SCHEMA["$defs"]["Discovery"]["examples"][-1])


def create() -> dict[str, Any]:
    return deepcopy(SCHEMA["$defs"]["CreateRequest03"]["examples"][0])


def test_finite_size_admission_is_valid_and_preserves_selected_values() -> None:
    current = discovery()
    declaration = current["offerings"][0]["declaration"]
    declaration["resources"]["disk_in_memory"] = False
    declaration["resources"]["sizes"] = [{"cpu": 4, "memory_mib": 8192, "disk_mib": 10240}]
    request = create()
    request["request"]["resources"] = {
        "cpu_min": 4,
        "memory_min_mib": 8192,
        "disk_min_mib": 10240,
    }

    admission = validate_new_create_03(request, current)

    assert admission["resources"] == {"size": {"cpu": 4, "memory_mib": 8192, "disk_mib": 10240}}
    validate_message("Admission", admission)


@pytest.mark.parametrize(
    ("resource_ask", "declared_resources", "expected"),
    [
        (
            {"region": "modal:us-east"},
            {"regions": ["modal:us-east"]},
            {"region": "modal:us-east"},
        ),
        (
            {"gpu_model": "nvidia:a10", "gpu_count": 1},
            {"gpus": ["nvidia:a10"], "max_gpus": 1},
            {"gpu": {"model": "nvidia:a10", "count": 1}},
        ),
    ],
)
def test_known_region_and_gpu_fit_use_spec_registries(
    resource_ask: dict[str, Any],
    declared_resources: dict[str, Any],
    expected: dict[str, Any],
) -> None:
    current = discovery()
    current["offerings"][0]["declaration"]["resources"].update(declared_resources)
    request = create()
    request["request"]["resources"] = resource_ask

    admission = validate_new_create_03(request, current)

    assert admission["resources"] == expected
    validate_message("Admission", admission)


def test_unknown_or_mismatched_region_and_gpu_refuse_before_admission() -> None:
    current = discovery()
    current["offerings"][0]["declaration"]["resources"].update(
        {"regions": ["modal:us-east"], "gpus": ["nvidia:a10"], "max_gpus": 1}
    )
    for ask in (
        {"region": "not-a-region"},
        {"region": "modal:us-central"},
        {"gpu_model": "not-a-gpu", "gpu_count": 1},
        {"gpu_model": "nvidia:h100", "gpu_count": 1},
    ):
        request = create()
        request["request"]["resources"] = ask
        with pytest.raises(BindingValidationError):
            validate_new_create_03(request, current)


@pytest.mark.parametrize(
    "resources",
    [
        {"size": {"cpu": True}},
        {"size": {"disk_min_mib": 10240}},
        {"size": {"cpu": 4, "future": 1}},
        {"gpu": {"model": "nvidia:a10", "count": True}},
        {"region": 12},
        {"future": True},
    ],
)
def test_admission_rejects_malformed_or_request_only_resource_facts(
    resources: dict[str, Any],
) -> None:
    value = validate_new_create_03(create(), discovery())
    validate_message("Admission", value)
    value["resources"] = resources
    with pytest.raises(BindingValidationError):
        validate_message("Admission", value)


def test_partial_disk_size_and_located_region_null_are_admitted() -> None:
    current = discovery()
    declaration_resources = current["offerings"][0]["declaration"]["resources"]
    declaration_resources.update({"disk_mib": 12288, "located_in": ["US"]})
    request = create()
    request["request"]["resources"] = {"disk_min_mib": 10240, "region": "US"}

    admission = validate_new_create_03(request, current)

    assert admission["resources"] == {"size": {"disk_mib": 12288}, "region": None}
    validate_message("Admission", admission)


def test_every_current_matcher_selected_resource_shape_is_retained() -> None:
    current = discovery()
    declaration_resources = current["offerings"][0]["declaration"]["resources"]
    declaration_resources.update(
        {
            "disk_in_memory": False,
            "sizes": [{"cpu": 4, "memory_mib": 8192, "disk_mib": 10240}],
            "regions": ["modal:us-east"],
            "gpus": ["nvidia:a10"],
            "max_gpus": 1,
            "root": ["sudo", "per_command"],
            "arch": ["arm64"],
            "egress_ips": ["dedicated"],
            "kernel_features": ["fuse"],
            "outbound_traffic": ["http"],
        }
    )
    request = create()
    request["request"]["resources"] = {
        "cpu_min": 4,
        "memory_min_mib": 8192,
        "disk_min_mib": 10240,
        "region": "modal:us-east",
        "gpu_model": "nvidia:a10",
        "gpu_count": 1,
        "root": ["sudo"],
        "arch": "arm64",
        "egress_ips": "dedicated",
        "kernel_features": ["fuse"],
        "outbound_traffic": ["http"],
    }

    admission = validate_new_create_03(request, current)

    assert admission["resources"] == {
        "size": {"cpu": 4, "memory_mib": 8192, "disk_mib": 10240},
        "region": "modal:us-east",
        "gpu": {"model": "nvidia:a10", "count": 1},
        "root": ["sudo"],
        "arch": "arm64",
        "egress_ips": "dedicated",
        "kernel_features": ["fuse"],
        "outbound_traffic": ["http"],
    }
    validate_message("Admission", admission)
