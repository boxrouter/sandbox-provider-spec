# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Offline contract examples, explicitly separate from native conformance proof."""

from __future__ import annotations

import copy
import json
import runpy
from typing import Any

import pytest

from sandbox_provider_spec import http_binding_validation
from sandbox_provider_spec.check import spec_dir

ROOT = spec_dir().parent
CHECK_CASE = runpy.run_path(str(ROOT / "tooling/http_binding/validate.py"))["check_case"]
CASES = json.loads((ROOT / "examples/http-binding/semantics.json").read_text())


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_semantic_fixture(case: dict[str, Any]) -> None:
    if case["valid"]:
        CHECK_CASE(case)
    else:
        with pytest.raises(ValueError):
            CHECK_CASE(case)


@pytest.mark.parametrize("raw", [b"\xff", b'{"x":1} trailing', b'{"x":Infinity}'])
def test_reject_invalid_raw_json(raw: bytes) -> None:
    with pytest.raises(ValueError):
        http_binding_validation.decode_json(raw, 100)


def test_raw_body_limit_includes_whitespace() -> None:
    with pytest.raises(ValueError, match="limit"):
        http_binding_validation.decode_json(b'{"x":1}' + b" " * 20, 10)


def test_new_create_key_is_not_a_claim_of_atomic_implementation() -> None:
    """The pure oracle makes the storage proof boundary explicit."""
    case = next(case for case in CASES if case["name"] == "fresh-key")
    assert http_binding_validation.key_disposition(**case["input"]) == "reserve"
    assert http_binding_validation.key_disposition(**case["input"]) == "reserve"


@pytest.mark.parametrize(
    ("operation", "field", "bound"),
    [
        ("list", "page_size", "page_size"),
        ("process.output", "max_frames", "output_frames"),
        ("process.output", "observation_timeout_ms", "observation_ms"),
        ("process.output", "limit_bytes", "command_output_bytes"),
        ("files.read_bytes", "limit_bytes", "file_bytes"),
        ("files.write", "byte_count", "file_bytes"),
    ],
)
def test_request_limit_errors_have_machine_readable_status(
    operation: str, field: str, bound: str
) -> None:
    case = copy.deepcopy(next(case for case in CASES if case["name"] == "valid-" + operation))
    case["discovery"]["limits"][bound] = 1
    assert case["request"][field] > 1
    with pytest.raises(http_binding_validation.BindingValidationError) as captured:
        http_binding_validation.validate_request(case["request"], case["discovery"])
    assert captured.value.code == "limit_exceeded"
    assert http_binding_validation.STATUS[captured.value.code] == 413


@pytest.mark.parametrize("raw,code", [(b"{} ", "limit_exceeded"), (b"{", "invalid_request")])
def test_decoder_errors_remain_value_errors_with_codes(raw: bytes, code: str) -> None:
    with pytest.raises(ValueError) as captured:
        http_binding_validation.decode_json(raw, 2)
    assert captured.value.code == code  # type: ignore[attr-defined]


def test_malformed_request_ids_can_be_null_in_route_derived_error() -> None:
    case = next(case for case in CASES if case["name"] == "valid-get")
    response = {
        "operation": "get",
        "request_id": None,
        "account_id": None,
        "error": {
            "code": "invalid_request",
            "outcome": "not_dispatched",
            "message": "Malformed body",
            "exit_code": None,
        },
    }
    http_binding_validation.validate_exchange(
        {"operation": "get"}, response, case["discovery"], status=422
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("mode", "buffered_commands_v1"),
        ("encoding", "base64"),
        ("execution_limit_ms", 10),
        ("output_limit_bytes", 10),
    ],
)
def test_v01_rejects_every_buffered_command_control_before_dispatch(field: str, value: Any) -> None:
    case = copy.deepcopy(next(case for case in CASES if case["name"] == "valid-run"))
    case["request"][field] = value
    if field == "mode":
        case["request"].update(encoding="base64", execution_limit_ms=10, output_limit_bytes=10)
    with pytest.raises(http_binding_validation.BindingValidationError) as captured:
        http_binding_validation.validate_request(case["request"], case["discovery"])
    if field == "mode":
        assert captured.value.code == "unsupported_mode"
    else:
        assert captured.value.code == "invalid_request"


def test_buffered_mode_limits_are_independent_and_discovery_capacity_is_coherent() -> None:
    case = copy.deepcopy(
        next(case for case in CASES if case["name"] == "buffered-binary-two-streams")
    )
    case["request"]["observation_timeout_ms"] = 1
    case["request"]["execution_limit_ms"] = 30000
    http_binding_validation.validate_request(case["request"], case["discovery"])
    incoherent = copy.deepcopy(case["discovery"])
    incoherent["limits"]["response_bytes"] = 33554432
    with pytest.raises(http_binding_validation.BindingValidationError, match="Response cap"):
        http_binding_validation.validate_discovery(incoherent)


@pytest.mark.parametrize(
    "case_name",
    ["buffered-binary-two-streams", "buffered-existing-identity-after-offering-removal"],
)
def test_buffered_response_mode_downgrades_are_typed_validation_errors(case_name: str) -> None:
    case = copy.deepcopy(next(case for case in CASES if case["name"] == case_name))
    legacy_response = copy.deepcopy(
        next(case for case in CASES if case["name"] == "valid-run")["response"]
    )
    with pytest.raises(http_binding_validation.BindingValidationError):
        http_binding_validation.validate_exchange(
            case["request"], legacy_response, case["discovery"]
        )

    legacy_request = copy.deepcopy(
        next(case for case in CASES if case["name"] == "valid-run")["request"]
    )
    with pytest.raises(http_binding_validation.BindingValidationError):
        http_binding_validation.validate_exchange(
            legacy_request, case["response"], case["discovery"]
        )


@pytest.mark.parametrize("sandbox", [None, False, "invalid"])
def test_invalid_buffered_sandbox_shape_fails_before_mode_field_access(sandbox: Any) -> None:
    case = copy.deepcopy(
        next(case for case in CASES if case["name"] == "buffered-binary-two-streams")
    )
    case["request"]["sandbox"] = sandbox
    with pytest.raises(http_binding_validation.BindingValidationError, match="RunRequest"):
        http_binding_validation.validate_request(case["request"], case["discovery"])
