# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Focused offline checks for the first HTTP binding 0.3 contract unit."""

from __future__ import annotations

import json
from copy import deepcopy
from typing import Any

import pytest

from sandbox_provider_spec.http_binding_validation import (
    BOOTSTRAP_CONTROL_RESPONSE_BYTES,
    SCHEMA,
    BindingValidationError,
    body_bytes,
    request_digest,
    validate_discovery,
    validate_exchange,
    validate_new_create_03,
    validate_request,
)
from sandbox_provider_spec.matcher import declared_fit, match


def _discovery() -> dict[str, Any]:
    return deepcopy(SCHEMA["$defs"]["Discovery"]["examples"][-1])


def _create() -> dict[str, Any]:
    return deepcopy(SCHEMA["$defs"]["CreateRequest03"]["examples"][0])


def test_declared_fit_is_compatible_without_proof_while_strict_match_stays_proof_gated() -> None:
    discovery = _discovery()
    declaration = discovery["offerings"][0]["declaration"]
    strict = match({}, [declaration])
    compatibility = declared_fit({}, [declaration])
    name = next(iter(strict["results"]))

    assert strict["eligible"] == []
    assert strict["results"][name]["failed"][0]["reason"] == "baseline_failed"
    assert compatibility["compatible"] == [name]
    assert compatibility["results"][name]["resources"] == {}


def test_http03_new_create_calls_declared_fit_and_returns_exact_admission() -> None:
    discovery = _discovery()
    request = _create()
    admission = validate_new_create_03(request, discovery)

    assert admission["selection"]["binding"] == discovery["binding"]
    assert admission["selection"]["offering"] == discovery["offerings"][0]
    assert admission["requirements"] == request["request"].get("requirements", {})
    assert admission["lifetime_seconds"] == request["request"].get("lifetime_seconds")
    assert admission["at_end"] == request["request"].get("at_end")
    assert "env" not in admission


def test_http03_admission_is_a_deep_snapshot_of_discovery() -> None:
    discovery = _discovery()
    admission = validate_new_create_03(_create(), discovery)
    expected = deepcopy(admission)

    discovery["offerings"][0]["declaration"]["provider"] = "mutated-provider"
    assert admission == expected
    admission["selection"]["offering"]["declaration"]["provider"] = "caller-mutation"
    assert discovery["offerings"][0]["declaration"]["provider"] == "mutated-provider"


def test_http03_new_create_refuses_incompatible_requirements_before_reservation() -> None:
    discovery = _discovery()
    request = _create()
    request["request"] = {"resources": {"cpu_min": 2}}

    with pytest.raises(BindingValidationError, match="incompatible"):
        validate_new_create_03(request, discovery)


def test_http03_labels_are_required_bounded_and_never_used_as_grants() -> None:
    discovery = _discovery()
    request = _create()
    request["labels"] = {"administrator-grant": "all"}
    validate_request(request, discovery)
    admission = validate_new_create_03(request, discovery)
    assert admission["requirements"] == {}

    malformed = _create()
    malformed.pop("labels")
    with pytest.raises(BindingValidationError):
        validate_request(malformed, discovery)

    too_many = _create()
    too_many["labels"] = {f"k{index}": "v" for index in range(33)}
    with pytest.raises(BindingValidationError):
        validate_request(too_many, discovery)


def test_http03_labels_use_utf8_byte_bounds_and_reject_nul() -> None:
    discovery = _discovery()
    request = _create()
    request["labels"] = {"é" * 31 + "a": "漢" * 85}
    validate_request(request, discovery)
    validate_new_create_03(request, discovery)

    for labels in (
        {"é" * 32: "ok"},
        {"ok": "漢" * 86},
        {"bad\x00key": "value"},
        {"key": "bad\x00value"},
    ):
        malformed = _create()
        malformed["labels"] = labels
        with pytest.raises(BindingValidationError):
            validate_request(malformed, discovery)


def test_http03_maximum_escaped_public_labels_fit_validator() -> None:
    discovery = _discovery()
    labels = {"\x01" * 60 + f"{index:03d}": "\x01" * 255 for index in range(32)}
    escaped_wire = json.dumps(labels, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    assert len(escaped_wire) <= 64 * 1024
    assert len(escaped_wire) > 16 * 1024
    request = _create()
    request["labels"] = labels
    validate_request(request, discovery)
    admission = validate_new_create_03(request, discovery)
    assert admission["selection"]["binding"] == discovery["binding"]


def test_http03_admission_overflow_is_refused_before_dispatch() -> None:
    discovery = _discovery()
    discovery["offerings"][0]["declaration"].setdefault("x-example", {})["payload"] = "x" * (
        BOOTSTRAP_CONTROL_RESPONSE_BYTES + 1
    )
    request = _create()

    with pytest.raises(BindingValidationError) as error:
        validate_new_create_03(request, discovery)
    assert error.value.code == "limit_exceeded"
    assert "admission" in str(error.value)


def test_http03_bootstrap_get_uses_control_cap_independent_of_workload_cap() -> None:
    discovery = _discovery()
    discovery["limits"]["response_bytes"] = 1_000_000
    # The original selection has disappeared from today's offer list and workload cap.
    discovery["offerings"][0]["offering_id"] = "replacement-offer"
    discovery["offerings"][0]["declaration_id"] = "replacement-selection"
    validate_discovery(discovery)
    request = deepcopy(SCHEMA["$defs"]["GetRequest"]["examples"][0])
    request["account_id"] = discovery["account_id"]
    response = deepcopy(SCHEMA["$defs"]["GetResult03"]["examples"][0])
    response["account_id"] = request["account_id"]
    response["request_id"] = request["request_id"]
    response["admission"]["selection"]["offering"]["declaration"]["x-example"] = {
        "payload": "x" * 1_100_000
    }
    raw_response = body_bytes(response)
    assert len(raw_response) > discovery["limits"]["response_bytes"]
    assert len(raw_response) < BOOTSTRAP_CONTROL_RESPONSE_BYTES

    validate_exchange(
        request,
        response,
        discovery,
        request_body=body_bytes(request),
        response_body=raw_response,
        control_response_cap=BOOTSTRAP_CONTROL_RESPONSE_BYTES,
    )
    with pytest.raises(BindingValidationError) as error:
        validate_exchange(
            request,
            response,
            discovery,
            request_body=body_bytes(request),
            response_body=raw_response,
            control_response_cap=1_000_000,
        )
    assert error.value.code == "limit_exceeded"


def test_http03_bootstrap_get_request_uses_protocol_cap_not_shrunk_workload_cap() -> None:
    discovery = _discovery()
    discovery["limits"]["request_bytes"] = 1024
    request = deepcopy(SCHEMA["$defs"]["GetRequest"]["examples"][0])
    request["account_id"] = discovery["account_id"]
    response = deepcopy(SCHEMA["$defs"]["GetResult03"]["examples"][0])
    response["request_id"] = request["request_id"]
    response["account_id"] = request["account_id"]

    raw_request = body_bytes(request) + b" " * 1100
    validate_exchange(request, response, discovery, request_body=raw_request)


def test_http03_absent_get_may_return_null_admission_and_observations() -> None:
    discovery = _discovery()
    request = deepcopy(SCHEMA["$defs"]["GetRequest"]["examples"][0])
    request["account_id"] = discovery["account_id"]
    response = deepcopy(SCHEMA["$defs"]["GetResult03"]["examples"][0])
    response["request_id"] = request["request_id"]
    response["account_id"] = request["account_id"]
    response["state"] = "absent"
    response["admission"] = None
    response["labels"] = None
    response["lifetime"] = None
    validate_exchange(request, response, discovery)


def test_http03_get_rejects_wrong_incarnation_even_with_valid_admission() -> None:
    discovery = _discovery()
    request = deepcopy(SCHEMA["$defs"]["GetRequest"]["examples"][0])
    request["account_id"] = discovery["account_id"]
    response = deepcopy(SCHEMA["$defs"]["GetResult03"]["examples"][0])
    response["request_id"] = request["request_id"]
    response["account_id"] = request["account_id"]
    response["sandbox"]["incarnation"] = "replacement-incarnation"
    with pytest.raises(BindingValidationError, match="incarnation"):
        validate_exchange(request, response, discovery)


def test_http03_get_rejects_retained_selection_from_another_provider() -> None:
    discovery = _discovery()
    request = deepcopy(SCHEMA["$defs"]["GetRequest"]["examples"][0])
    request["account_id"] = discovery["account_id"]
    response = deepcopy(SCHEMA["$defs"]["GetResult03"]["examples"][0])
    response["request_id"] = request["request_id"]
    response["account_id"] = request["account_id"]
    response["admission"]["selection"]["offering"]["declaration"]["provider"] = "different-provider"

    with pytest.raises(BindingValidationError, match="provider mismatch"):
        validate_exchange(request, response, discovery)


def test_http03_get_rejects_retained_selection_with_incoherent_workload_caps() -> None:
    discovery = _discovery()
    request = deepcopy(SCHEMA["$defs"]["GetRequest"]["examples"][0])
    request["account_id"] = discovery["account_id"]
    response = deepcopy(SCHEMA["$defs"]["GetResult03"]["examples"][0])
    response["request_id"] = request["request_id"]
    response["account_id"] = request["account_id"]
    response["admission"]["selection"]["limits"]["response_bytes"] = 1

    with pytest.raises(BindingValidationError, match="cannot serve"):
        validate_exchange(request, response, discovery)


def test_http03_get_rejects_unsupported_retained_process_addressability() -> None:
    discovery = _discovery()
    request = deepcopy(SCHEMA["$defs"]["GetRequest"]["examples"][0])
    request["account_id"] = discovery["account_id"]
    response = deepcopy(SCHEMA["$defs"]["GetResult03"]["examples"][0])
    response["request_id"] = request["request_id"]
    response["account_id"] = request["account_id"]
    response["admission"]["selection"]["process_addressability"] = "made_up"

    with pytest.raises(BindingValidationError, match="process addressability"):
        validate_exchange(request, response, discovery)


def test_http03_bootstrap_get_recovers_after_last_current_offering_disappears() -> None:
    discovery = _discovery()
    discovery["offerings"] = []
    validate_discovery(discovery)
    request = deepcopy(SCHEMA["$defs"]["GetRequest"]["examples"][0])
    request["account_id"] = discovery["account_id"]
    response = deepcopy(SCHEMA["$defs"]["GetResult03"]["examples"][0])
    response["request_id"] = request["request_id"]
    response["account_id"] = request["account_id"]

    validate_exchange(request, response, discovery)


@pytest.mark.parametrize("binding", ["sandbox-provider-http/0.1", "sandbox-provider-http/0.2"])
def test_legacy_discovery_still_requires_an_offering(binding: str) -> None:
    discovery = _discovery()
    discovery["binding"] = binding
    discovery["offerings"] = []

    with pytest.raises(BindingValidationError, match="Discovery"):
        validate_discovery(discovery)


def test_http03_new_create_rejects_stale_selection_as_conflict() -> None:
    discovery = _discovery()
    request = _create()
    request["declaration_id"] = "stale-selection"

    with pytest.raises(BindingValidationError) as error:
        validate_new_create_03(request, discovery)
    assert error.value.code == "conflict"


def test_http03_new_create_with_no_current_offerings_is_conflict() -> None:
    discovery = _discovery()
    discovery["offerings"] = []

    with pytest.raises(BindingValidationError) as error:
        validate_new_create_03(_create(), discovery)
    assert error.value.code == "conflict"


def test_http03_create_get_and_list_observations_round_trip_the_versioned_shapes() -> None:
    discovery = _discovery()
    create = _create()
    admission = validate_new_create_03(create, discovery)
    create_raw = body_bytes(create)
    created = deepcopy(SCHEMA["$defs"]["CreateResult03"]["examples"][0])
    created["request_id"] = create["request_id"]
    created["account_id"] = create["account_id"]
    created["allocation_key"] = create["allocation_key"]
    created["request_digest"] = request_digest(create_raw)
    created["key_expires_at"] = int(create["allocation_key"][:10]) + 86400
    created["admission"] = admission
    created["labels"] = create["labels"]
    validate_exchange(
        create,
        created,
        discovery,
        request_body=create_raw,
        response_body=body_bytes(created),
        digest=request_digest(create_raw),
    )

    get_request = deepcopy(SCHEMA["$defs"]["GetRequest"]["examples"][0])
    get_request["account_id"] = discovery["account_id"]
    get_response = deepcopy(SCHEMA["$defs"]["GetResult03"]["examples"][0])
    get_response["request_id"] = get_request["request_id"]
    get_response["account_id"] = get_request["account_id"]
    get_response["admission"] = admission
    validate_exchange(get_request, get_response, discovery)

    list_request = deepcopy(SCHEMA["$defs"]["ListRequest"]["examples"][0])
    list_request["account_id"] = discovery["account_id"]
    list_response = deepcopy(SCHEMA["$defs"]["ListResult03"]["examples"][0])
    list_response["request_id"] = list_request["request_id"]
    list_response["account_id"] = list_request["account_id"]
    validate_exchange(list_request, list_response, discovery)


@pytest.mark.parametrize("state", ["pending", "unknown"])
def test_http03_create_without_native_identity_may_have_null_admission(state: str) -> None:
    discovery = _discovery()
    request = _create()
    raw_request = body_bytes(request)
    response = deepcopy(SCHEMA["$defs"]["CreateResult03"]["examples"][0])
    response.update(
        {
            "request_id": request["request_id"],
            "account_id": request["account_id"],
            "allocation_key": request["allocation_key"],
            "request_digest": request_digest(raw_request),
            "key_expires_at": int(request["allocation_key"][:10]) + 86400,
            "state": state,
            "sandbox": None,
            "admission": None,
            "labels": None,
            "lifetime": None,
        }
    )

    validate_exchange(
        request,
        response,
        discovery,
        request_body=raw_request,
        digest=request_digest(raw_request),
    )


def test_http03_ready_lifetime_timestamps_must_match_the_accepted_policy() -> None:
    discovery = _discovery()
    request = _create()
    request["request"]["lifetime_seconds"] = 300
    discovery["offerings"][0]["declaration"]["resources"]["max_lifetime_seconds"] = 600
    admission = validate_new_create_03(request, discovery)
    result = deepcopy(SCHEMA["$defs"]["CreateResult03"]["examples"][0])
    result["admission"] = admission
    result["labels"] = request["labels"]
    result["request_id"] = request["request_id"]
    result["account_id"] = request["account_id"]
    result["allocation_key"] = request["allocation_key"]
    raw = body_bytes(request)
    result["request_digest"] = request_digest(raw)
    result["key_expires_at"] = int(request["allocation_key"][:10]) + 86400
    result["lifetime"]["ends_at"] = "2026-10-22T12:06:00Z"
    with pytest.raises(BindingValidationError, match="accepted duration"):
        validate_exchange(request, result, discovery, request_body=raw, digest=request_digest(raw))


def test_http03_lifetime_timestamp_overflow_is_a_typed_validation_error() -> None:
    discovery = _discovery()
    request = _create()
    request["request"]["lifetime_seconds"] = 10**30
    discovery["offerings"][0]["declaration"]["resources"]["max_lifetime_seconds"] = "unlimited"
    admission = validate_new_create_03(request, discovery)
    result = deepcopy(SCHEMA["$defs"]["CreateResult03"]["examples"][0])
    result["admission"] = admission
    result["labels"] = request["labels"]
    result["request_id"] = request["request_id"]
    result["account_id"] = request["account_id"]
    result["allocation_key"] = request["allocation_key"]
    raw = body_bytes(request)
    result["request_digest"] = request_digest(raw)
    result["key_expires_at"] = int(request["allocation_key"][:10]) + 86400

    with pytest.raises(BindingValidationError, match="timestamp arithmetic"):
        validate_exchange(request, result, discovery, request_body=raw, digest=request_digest(raw))


def test_http03_exact_create_replay_uses_retained_selection_before_current_bounds() -> None:
    discovery = _discovery()
    request = _create()
    admission = validate_new_create_03(request, discovery)
    raw_request = body_bytes(request)
    result = deepcopy(SCHEMA["$defs"]["CreateResult03"]["examples"][0])
    result["request_id"] = request["request_id"]
    result["account_id"] = request["account_id"]
    result["allocation_key"] = request["allocation_key"]
    result["request_digest"] = request_digest(raw_request)
    result["key_expires_at"] = int(request["allocation_key"][:10]) + 86400
    result["admission"] = admission
    result["labels"] = request["labels"]
    raw_result = body_bytes(result)

    current = deepcopy(discovery)
    current["limits"]["request_bytes"] = 1
    current["offerings"][0]["offering_id"] = "replacement-offer"
    current["offerings"][0]["declaration_id"] = "replacement-selection"
    validate_exchange(
        request,
        result,
        current,
        request_body=raw_request,
        response_body=raw_result,
        digest=request_digest(raw_request),
        replay_admission=admission,
    )
    with pytest.raises(BindingValidationError) as error:
        validate_exchange(
            request,
            result,
            current,
            request_body=raw_request,
            response_body=raw_result,
            digest=request_digest(raw_request),
        )
    assert error.value.code == "limit_exceeded"


def test_http03_admission_normalizes_only_accepted_requirements_without_image_body() -> None:
    discovery = _discovery()
    discovery["offerings"][0]["declaration"]["gates"]["custom_images"] = [
        {"source": ["oci"], "prepared": False}
    ]
    request = _create()
    request["request"] = {
        "image": "registry.example/team/image:stable",
        "requirements": {"custom_images": {}},
    }

    admission = validate_new_create_03(request, discovery)

    assert admission["requirements"] == {"custom_images": {"source": ["oci"], "prepared": [False]}}
    assert "image" not in admission["requirements"]
    assert "env" not in admission
