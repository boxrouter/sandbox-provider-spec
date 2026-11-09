# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Reusable HTTP binding validation; this checks messages, not native truth."""

from __future__ import annotations

import base64
import hashlib
import json
import math
from copy import deepcopy
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from sandbox_provider_spec.check import check_request, spec_dir
from sandbox_provider_spec.matcher import declared_fit
from sandbox_provider_spec.matcher.registry import Registry as MatcherRegistry
from sandbox_provider_spec.matcher.request import Request
from sandbox_provider_spec.matcher.request import validate_request as validate_sps_request

SCHEMA: dict[str, Any] = json.loads((spec_dir() / "http-binding.schema.json").read_text())
DOCUMENTS: list[dict[str, Any]] = [SCHEMA] + [
    json.loads((spec_dir() / f"{name}-schema.json").read_text())
    for name in ("request", "declaration")
]
REGISTRY: Registry[Any] = Registry().with_resources(
    (document["$id"], Resource.from_contents(document)) for document in DOCUMENTS
)
MATCHER_REGISTRY = MatcherRegistry.from_documents(
    json.loads((spec_dir() / "registries/regions.json").read_text()),
    json.loads((spec_dir() / "registries/gpu-models.json").read_text()),
)


STATUS: dict[str, int] = {
    "unauthenticated": 401,
    "forbidden": 403,
    "conflict": 409,
    "expired_key": 410,
    "limit_exceeded": 413,
    "invalid_request": 422,
    "unsupported_mode": 422,
    "provider_error": 502,
    "output_unavailable": 502,
    "timeout": 504,
}

BUFFERED_COMMANDS = "buffered_commands_v1"
HTTP_BINDING_02 = "sandbox-provider-http/0.2"
HTTP_BINDING_03 = "sandbox-provider-http/0.3"
BOOTSTRAP_CONTROL_RESPONSE_BYTES = 4 * 1024 * 1024
LABELS_BYTES = 64 * 1024
MAX_PROTOCOL_REQUEST_BYTES = 32 * 1024 * 1024


def _base64_size(byte_count: int) -> int:
    return 4 * ((byte_count + 2) // 3)


def _bootstrap_response_size(admission: dict[str, Any]) -> int:
    """Worst-case 0.3 GET envelope with this retained descriptor and bounded observations."""
    envelope = {
        "operation": "get",
        "request_id": "x" * 128,
        "account_id": "x" * 128,
        "sandbox": {
            field: "x" * 128
            for field in (
                "provider_id",
                "account_id",
                "offering_id",
                "sandbox_id",
                "incarnation",
            )
        },
        "state": "destroyed",
        "admission": admission,
        "labels": {},
        "lifetime": {"ready_at": "x" * 64, "ends_at": "x" * 64},
    }
    return len(body_bytes(envelope)) - 2 + LABELS_BYTES


def _buffered_result_capacity(output_limit: int) -> int:
    """Conservative wire size for both streams and the full identity envelope."""
    identity = {
        "provider_id": "x" * 128,
        "account_id": "x" * 128,
        "offering_id": "x" * 128,
        "sandbox_id": "x" * 128,
        "incarnation": "x" * 128,
    }
    result = {
        "operation": "run",
        "request_id": "x" * 128,
        "account_id": "x" * 128,
        "sandbox": identity,
        "mode": BUFFERED_COMMANDS,
        "encoding": "base64",
        "stdout_base64": "",
        "stderr_base64": "",
        "stdout_bytes": output_limit,
        "stderr_bytes": output_limit,
        "stdout_truncated": False,
        "stderr_truncated": False,
        "exit_code": -2147483648,
        "output_complete": True,
    }
    maximum_error = {
        "operation": "run",
        "request_id": "x" * 128,
        "account_id": "x" * 128,
        "error": {
            "code": "output_unavailable",
            "outcome": "unknown",
            "message": "\x00" * 1024,
            "exit_code": None,
        },
    }
    return max(
        len(body_bytes(result)) + 2 * _base64_size(output_limit),
        len(body_bytes(maximum_error)),
    )


class BindingValidationError(ValueError):
    """Wire rejection category; never evidence of a native operation's outcome.

    A pre-dispatch caller can map code through STATUS. After dispatch, a validation
    failure is a bad provider reply; the caller must retain the native uncertainty.
    """

    code: str

    def __init__(self, reason: str, *, code: str = "invalid_request") -> None:
        super().__init__(reason)
        self.code = code


def require(condition: bool, reason: str, *, code: str = "invalid_request") -> None:
    if not condition:
        raise BindingValidationError(reason, code=code)


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON key")
        result[key] = value
    return result


def _scalars(value: Any) -> None:
    if isinstance(value, str):
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeError as error:
            raise BindingValidationError("Invalid Unicode scalar") from error
    elif isinstance(value, float):
        require(math.isfinite(value), "Non-finite JSON number")
    elif isinstance(value, list):
        for item in value:
            _scalars(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            _scalars(key)
            _scalars(item)


def decode_json(raw: bytes, limit: int) -> Any:
    """Decode bounded strict JSON; callers must also bound IO before buffering it."""
    require(len(raw) <= limit, "JSON body limit exceeded", code="limit_exceeded")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
        _scalars(value)
    except (UnicodeError, RecursionError, json.JSONDecodeError) as error:
        raise BindingValidationError("Invalid UTF-8 JSON") from error
    return value


def body_bytes(value: Any) -> bytes:
    """Fixture serialization only; live callers must retain their actual wire bytes."""
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def _labels_wire_bytes(value: dict[str, str]) -> bytes:
    """Use JSON's ASCII escapes so control characters count at their wire worst case."""
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode(
        "ascii"
    )


def request_digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def validate_message(name: str, value: Any) -> None:
    """Validate one named wire shape plus scalar/base64 invariants."""
    require(name in SCHEMA["$defs"], "Unknown message type")
    validator = Draft202012Validator(
        {"$ref": SCHEMA["$id"] + "#/$defs/" + name},
        registry=REGISTRY,
        format_checker=FormatChecker(),
    )
    require(validator.is_valid(value), "Message does not match " + name)
    _scalars(value)
    if name == "Labels":
        for key, item in value.items():
            require(
                len(key.encode("utf-8")) <= 63 and len(item.encode("utf-8")) <= 255,
                "Label key or value exceeds its UTF-8 byte bound",
            )
        require(
            len(_labels_wire_bytes(value)) <= LABELS_BYTES,
            "Serialized labels exceed the 64 KiB bound",
            code="limit_exceeded",
        )
    if isinstance(value, dict):
        for field, count_field in (
            ("data_base64", "byte_count"),
            ("stdout_base64", "stdout_bytes"),
            ("stderr_base64", "stderr_bytes"),
        ):
            if field not in value:
                continue
            try:
                decoded = base64.b64decode(value[field], validate=True)
            except ValueError as error:
                raise BindingValidationError("Invalid base64") from error
            require(base64.b64encode(decoded).decode() == value[field], "Noncanonical base64")
            require(len(decoded) == value[count_field], "Decoded byte count mismatch")


def validate_discovery(discovery: dict[str, Any]) -> None:
    """Check wire discovery; this does not admit its origin or prove declarations."""
    validate_message("Discovery", discovery)
    origin = urlsplit(discovery["endpoint_origin"])
    require(
        origin.scheme == "https"
        and bool(origin.hostname)
        and not origin.path
        and not origin.query
        and not origin.fragment
        and origin.username is None
        and origin.password is None
        and not any(c.isspace() for c in origin.netloc),
        "Invalid endpoint origin",
    )
    try:
        require(origin.port is None or 1 <= origin.port <= 65535, "Invalid origin port")
    except ValueError as error:
        raise BindingValidationError("Invalid origin port") from error
    offerings = discovery["offerings"]
    require(
        discovery["binding"] == HTTP_BINDING_03 or bool(offerings),
        "Discovery must advertise at least one offering",
    )
    require(len({o["offering_id"] for o in offerings}) == len(offerings), "Duplicate offering")
    for offering in offerings:
        require(
            offering["declaration"]["provider"] == discovery["provider_id"],
            "Declaration provider mismatch",
        )
    limits = discovery["limits"]
    if discovery["binding"] == HTTP_BINDING_03:
        require(
            BUFFERED_COMMANDS in discovery["core_modes"],
            "Binding 0.3 requires buffered_commands_v1",
            code="unsupported_mode",
        )
    _validate_buffered_bounds(discovery["core_modes"], limits)


def _validate_buffered_bounds(core_modes: list[str], limits: dict[str, Any]) -> None:
    """Apply the same advertised-capacity invariant to discovery and retained selection."""
    if BUFFERED_COMMANDS not in core_modes:
        return
    capacity = limits.get("buffered_command_output_bytes")
    require(
        isinstance(capacity, int) and not isinstance(capacity, bool),
        "Buffered mode lacks its output bound",
    )
    assert isinstance(capacity, int) and not isinstance(capacity, bool)
    response_limit = limits.get("response_bytes")
    require(
        isinstance(response_limit, int) and not isinstance(response_limit, bool),
        "Buffered mode lacks its response bound",
    )
    assert isinstance(response_limit, int) and not isinstance(response_limit, bool)
    require(
        _buffered_result_capacity(capacity) <= response_limit,
        "Response cap cannot serve the advertised buffered output bounds",
    )


def _validate_retained_selection(selection: dict[str, Any], provider_id: str) -> None:
    """Validate a retained snapshot with the same semantic rules as 0.3 discovery."""
    validate_message("AdmissionSelection", selection)
    require(
        selection["core_modes"] == [BUFFERED_COMMANDS],
        "Retained 0.3 selection must advertise buffered_commands_v1 only",
        code="unsupported_mode",
    )
    require(
        selection["process_addressability"] == "endpoint_lifetime",
        "Unsupported retained process addressability",
    )
    retention = selection["process_retention_seconds"]
    require(
        isinstance(retention, int) and not isinstance(retention, bool) and 1 <= retention <= 604800,
        "Invalid retained process retention",
    )
    _validate_buffered_bounds(selection["core_modes"], selection["limits"])
    offering = selection["offering"]
    require(
        offering["declaration"]["provider"] == provider_id,
        "Retained declaration provider mismatch",
    )


def _identity(sandbox: dict[str, Any], discovery: dict[str, Any]) -> None:
    for field in ("provider_id", "account_id"):
        require(sandbox[field] == discovery[field], "Sandbox authority mismatch")
    # An existing allocation can outlive an offering's current availability.


def validate_request(
    request: dict[str, Any],
    discovery: dict[str, Any],
    *,
    request_body: bytes | None = None,
    replay_admission: dict[str, Any] | None = None,
) -> None:
    """Pure pre-dispatch checks; create replay precedes mutable offering admission.

    BindingValidationError.code distinguishes malformed input (invalid_request)
    from otherwise well-formed input exceeding advertised bounds (limit_exceeded).

    An endpoint must additionally authenticate, match a NEW create to its current
    declaration, check the digest/key, and validate native handles/cursors. This
    function does not call native providers, reserve keys or match capabilities.
    """
    validate_discovery(discovery)
    require(isinstance(request, dict), "Request must be an object")
    request_context = discovery
    if replay_admission is not None:
        require(
            discovery.get("binding") == HTTP_BINDING_03 and request.get("operation") == "create",
            "Retained admission applies only to a 0.3 create replay",
        )
        validate_message("Admission", replay_admission)
        selection = replay_admission["selection"]
        request_context = _discovery_with_selection(discovery, selection)
        require(
            selection["offering"]["offering_id"] == request.get("offering_id")
            and selection["offering"]["declaration_id"] == request.get("declaration_id"),
            "Create replay differs from its retained selection",
        )
        validate_discovery(request_context)
    operation = request.get("operation")
    require(isinstance(operation, str) and operation in SCHEMA["x-operations"], "Unknown operation")
    assert isinstance(operation, str)
    request_shape = _shape_for(request_context["binding"], operation, "request")
    validate_message(request_shape, request)
    if operation == "run":
        mode = request.get("mode")
        if mode is not None and mode != BUFFERED_COMMANDS:
            raise BindingValidationError("Unsupported run mode", code="unsupported_mode")
        if mode is not None:
            require(
                request_context["binding"] in (HTTP_BINDING_02, HTTP_BINDING_03)
                and BUFFERED_COMMANDS in request_context["core_modes"],
                "Buffered command mode is not advertised",
                code="unsupported_mode",
            )
    require(request["account_id"] == request_context["account_id"], "Request account mismatch")
    limits = request_context["limits"]
    request_limit = (
        MAX_PROTOCOL_REQUEST_BYTES
        if request_context["binding"] == HTTP_BINDING_03 and operation == "get"
        else limits["request_bytes"]
    )
    if request_body is not None:
        decoded_request = decode_json(request_body, request_limit)
        require(decoded_request == request, "Request body differs from validated request")
    else:
        require(
            len(body_bytes(request)) <= request_limit,
            "Request body limit exceeded",
            code="limit_exceeded",
        )
    sandbox = request.get("sandbox") or request.get("process", {}).get("sandbox")
    if sandbox:
        _identity(sandbox, request_context)
    for field, bound in (
        ("page_size", "page_size"),
        ("max_frames", "output_frames"),
        ("observation_timeout_ms", "observation_ms"),
    ):
        if field in request:
            require(
                request[field] <= limits[bound],
                "Request exceeds advertised " + bound,
                code="limit_exceeded",
            )
    if "limit_bytes" in request:
        bound = "file_bytes" if operation == "files.read_bytes" else "command_output_bytes"
        require(
            request["limit_bytes"] <= limits[bound],
            "Request byte limit exceeds discovery",
            code="limit_exceeded",
        )
    if operation == "run" and request.get("mode") == BUFFERED_COMMANDS:
        require(
            request["execution_limit_ms"] <= limits["execution_ms"],
            "Execution limit exceeds discovery",
            code="limit_exceeded",
        )
        require(
            request["output_limit_bytes"] <= limits["buffered_command_output_bytes"],
            "Per-stream output limit exceeds discovery",
            code="limit_exceeded",
        )
    if operation == "files.write":
        require(
            request["byte_count"] <= limits["file_bytes"],
            "File limit exceeded",
            code="limit_exceeded",
        )
    if operation == "create":
        require(not check_request(request["request"]), "Invalid SPS create request")
        if request_context["binding"] == HTTP_BINDING_03:
            validate_message("Labels", request["labels"])
            require(
                len(_labels_wire_bytes(request["labels"])) <= LABELS_BYTES,
                "Create labels exceed the 64 KiB serialized bound",
                code="limit_exceeded",
            )


def _shape_for(binding: str, operation: str, direction: str) -> str:
    """Resolve a named wire shape for one advertised binding version."""
    versions = SCHEMA.get("x-binding-versions", {})
    if binding in versions and operation in versions[binding]:
        return str(versions[binding][operation][direction])
    return str(SCHEMA["x-operations"][operation][direction])


def message_shape(binding: str, operation: str, direction: str) -> str:
    """Return the authoritative versioned schema name for one wire direction."""
    return _shape_for(binding, operation, direction)


def _discovery_with_selection(
    discovery: dict[str, Any], selection: dict[str, Any]
) -> dict[str, Any]:
    context = dict(discovery)
    for field in (
        "binding",
        "core_modes",
        "limits",
        "process_retention_seconds",
        "process_addressability",
    ):
        context[field] = selection[field]
    context["offerings"] = [selection["offering"]]
    return context


def validate_new_create_03(
    request: dict[str, Any],
    discovery: dict[str, Any],
    *,
    request_body: bytes | None = None,
) -> dict[str, Any]:
    """Return original admission for a NEW 0.3 create, before reservation/dispatch.

    A producer checks its account/key/exact-body replay first and uses retained admission
    for a replay. Only a genuinely new key reaches this mutable-current-discovery fit.
    The descriptor is bounded before allocation; a later bootstrap GET uses the fixed
    4 MiB control envelope independently of workload response limits.
    """
    require(discovery.get("binding") == HTTP_BINDING_03, "Expected binding 0.3")
    validate_request(request, discovery, request_body=request_body)
    require(request["operation"] == "create", "Expected create request")
    accepted_request = validate_sps_request(request["request"], registry=MATCHER_REGISTRY)
    offering = next(
        (
            item
            for item in discovery["offerings"]
            if item["offering_id"] == request["offering_id"]
            and item["declaration_id"] == request["declaration_id"]
        ),
        None,
    )
    require(
        offering is not None,
        "Create selection is not in current discovery",
        code="conflict",
    )
    assert offering is not None
    result = declared_fit(request["request"], [offering["declaration"]], registry=MATCHER_REGISTRY)
    compatible = result["compatible"]
    if not compatible:
        provider_result = next(iter(result["results"].values()), None)
        failures = provider_result["failed"] if provider_result is not None else []
        detail = "; ".join(
            str(item.get("reason", "incompatible")) + ": " + str(item.get("detail", ""))
            for item in failures[:4]
        )[:700]
        raise BindingValidationError(
            (
                "Create request is incompatible with the selected declaration"
                + (": " + detail if detail else "")
            )[:900]
        )
    fitted = result["results"][compatible[0]]
    selection = {
        "binding": HTTP_BINDING_03,
        "core_modes": list(discovery["core_modes"]),
        "limits": dict(discovery["limits"]),
        "process_retention_seconds": discovery["process_retention_seconds"],
        "process_addressability": discovery["process_addressability"],
        "offering": deepcopy(offering),
    }
    admission = {
        "selection": selection,
        "requirements": _normalized_requirements(accepted_request),
        "resources": fitted["resources"],
        "lifetime_seconds": request["request"].get("lifetime_seconds"),
        "at_end": request["request"].get("at_end"),
    }
    validate_message("Admission", admission)
    require(
        _bootstrap_response_size(admission) <= BOOTSTRAP_CONTROL_RESPONSE_BYTES,
        "Retained admission and observations exceed the 4 MiB bootstrap control-response bound",
        code="limit_exceeded",
    )
    return deepcopy(admission)


def _normalized_requirements(request: Request) -> dict[str, Any]:
    """Serialize accepted matcher requirements, omitting the private image body."""
    requirements: dict[str, Any] = {}
    for gate, ask in request.gates.items():
        values = dict(ask.settings)
        # custom_images.settings carries the original image value; the admitted source
        # knob is sufficient and avoids persisting image credentials or body text.
        values.pop("image", None)
        values.update(ask.knobs)
        requirements[gate] = values
    requirements.update({f"x-{provider}": value for provider, value in request.extras.items()})
    return requirements


def key_disposition(
    *, key: str, digest: str, now: int, expiry_floor: int, stored_digest: str | None
) -> str:
    """Fixture oracle, NOT an atomic/durable key store. Inputs are account-scoped.

    Before emitting expired_key, durably latch expiry even for a never-seen key:
    persist a floor at least its expiry or permanent per-key rejection state.
    Consult that state on every later call; this pure function cannot persist it.
    No implementation proof follows from this function.
    """
    validate_message("AllocationKey", key)
    validate_message("Digest", digest)
    issued = int(key.split(":", 1)[0])
    effective_now = max(now, expiry_floor)
    if effective_now >= issued + 86400:
        return "expired_key"
    if issued > effective_now + 60:
        return "invalid_request"
    if stored_digest is None:
        return "reserve"
    return "replay" if digest == stored_digest else "conflict"


def _validate_03_metadata(
    response: dict[str, Any],
    *,
    sandbox: dict[str, Any] | None,
    request: dict[str, Any] | None = None,
    discovery: dict[str, Any],
) -> None:
    """Check immutable admission and separate observations for binding 0.3."""
    admission = response["admission"]
    labels = response["labels"]
    lifetime = response["lifetime"]
    known_present = sandbox is not None and (
        request is not None or response.get("state") not in ("absent", "unknown")
    )
    if known_present:
        require(admission is not None, "Present allocation lacks retained admission")
        require(
            labels is not None and lifetime is not None, "Present allocation lacks observations"
        )
    if admission is None:
        return
    validate_message("Admission", admission)
    require(
        admission["selection"]["binding"] == HTTP_BINDING_03,
        "Retained selection binding mismatch",
    )
    selection = admission["selection"]
    selected_offering = selection["offering"]
    _validate_retained_selection(selection, discovery["provider_id"])
    if sandbox is not None:
        _identity(sandbox, discovery)
        require(
            selected_offering["offering_id"] == sandbox["offering_id"],
            "Retained admission offering mismatch",
        )
        require(
            selected_offering["declaration"]["provider"] == sandbox["provider_id"],
            "Retained admission provider mismatch",
        )
    if labels is not None:
        validate_message("Labels", labels)
        require(
            len(_labels_wire_bytes(labels)) <= LABELS_BYTES,
            "Observed labels exceed the 64 KiB serialized bound",
            code="limit_exceeded",
        )
    if lifetime is not None:
        validate_message("LifetimeObservation", lifetime)
    if response.get("state") == "ready" and admission is not None:
        seconds = admission["lifetime_seconds"]
        if seconds is not None:
            require(
                lifetime is not None
                and lifetime["ready_at"] is not None
                and lifetime["ends_at"] is not None,
                "Ready response lacks established requested lifetime timestamps",
            )
            assert lifetime is not None
            try:
                ready_at = datetime.fromisoformat(lifetime["ready_at"].replace("Z", "+00:00"))
                ends_at = datetime.fromisoformat(lifetime["ends_at"].replace("Z", "+00:00"))
                expected_end = ready_at + timedelta(seconds=seconds)
            except (OverflowError, ValueError) as error:
                raise BindingValidationError("Invalid lifetime timestamp arithmetic") from error
            require(
                ends_at == expected_end,
                "Ready response lifetime does not match the accepted duration",
            )
    if request is not None:
        create = request["request"]
        accepted = validate_sps_request(create, registry=MATCHER_REGISTRY)
        require(
            admission["requirements"] == _normalized_requirements(accepted),
            "Retained requirements broaden or differ from accepted requirements",
        )
        require(
            admission["lifetime_seconds"] == create.get("lifetime_seconds")
            and admission["at_end"] == create.get("at_end"),
            "Retained lifetime policy differs from the accepted request",
        )
        require(labels == request["labels"], "Returned labels differ from the create labels")
        require(
            selected_offering["offering_id"] == request["offering_id"]
            and selected_offering["declaration_id"] == request["declaration_id"],
            "Retained admission differs from the selected create offering",
        )


# pylint: disable=too-many-arguments
def validate_exchange(
    request: dict[str, Any],
    response: dict[str, Any],
    discovery: dict[str, Any],
    *,
    status: int = 200,
    request_body: bytes | None = None,
    response_body: bytes | None = None,
    digest: str | None = None,
    control_response_cap: int = BOOTSTRAP_CONTROL_RESPONSE_BYTES,
    replay_admission: dict[str, Any] | None = None,
) -> None:
    """Check a structurally valid request/reply pair; never infer native truth.

    Error exchanges may reject invalid requests; validate only their envelope.
    Raw input/response size must ALSO be checked at the transport boundary.
    """
    validate_discovery(discovery)
    require(isinstance(request, dict), "Request must be an object")
    operation = request.get("operation")
    require(isinstance(operation, str) and operation in SCHEMA["x-operations"], "Unknown operation")
    assert isinstance(operation, str)
    request_context = discovery
    if status == 200:
        validate_request(
            request,
            discovery,
            request_body=request_body,
            replay_admission=replay_admission,
        )
        if replay_admission is not None:
            request_context = _discovery_with_selection(discovery, replay_admission["selection"])
        validate_message(_shape_for(discovery["binding"], operation, "result"), response)
    else:
        validate_message("Error", response)
        failure = response["error"]
        require(STATUS[failure["code"]] == status, "Error HTTP status mismatch")
    require(response["operation"] == operation, "Response operation mismatch")
    for field in ("request_id", "account_id"):
        if status in (401, 403) and response[field] is None:
            continue
        expected = request.get(field)
        if status != 200:
            try:
                validate_message("Identifier", expected)
            except ValueError:
                expected = None
        require(response[field] == expected, "Response correlation mismatch")
    response_cap = request_context["limits"]["response_bytes"]
    if discovery["binding"] == HTTP_BINDING_03 and operation == "get":
        require(
            isinstance(control_response_cap, int)
            and not isinstance(control_response_cap, bool)
            and control_response_cap > 0,
            "Control response cap must be a positive integer",
        )
        response_cap = min(BOOTSTRAP_CONTROL_RESPONSE_BYTES, control_response_cap)
    if response_body is not None:
        decoded_response = decode_json(response_body, response_cap)
        require(decoded_response == response, "Response body differs from validated response")
    else:
        require(
            len(body_bytes(response)) <= response_cap,
            "Response body limit exceeded",
        )
    if status != 200:
        return
    for field in ("sandbox", "process"):
        if field in request and field in response:
            require(response[field] == request[field], "Response incarnation mismatch")
    sandbox = response.get("sandbox") or response.get("process", {}).get("sandbox")
    if sandbox:
        _identity(sandbox, discovery)
    if operation == "create":
        require(
            request_body is not None and digest is not None, "Create requires exact body digest"
        )
        assert request_body is not None
        require(
            request_digest(request_body) == digest == response["request_digest"],
            "Create digest mismatch",
        )
        require(response["allocation_key"] == request["allocation_key"], "Allocation key mismatch")
        require(
            response["key_expires_at"] == int(request["allocation_key"][:10]) + 86400,
            "Key expiry mismatch",
        )
        if sandbox:
            require(
                sandbox["offering_id"] == request["offering_id"], "Allocation offering mismatch"
            )
        if discovery["binding"] == HTTP_BINDING_03:
            _validate_03_metadata(response, sandbox=sandbox, request=request, discovery=discovery)
            if replay_admission is not None:
                require(
                    response["admission"] == replay_admission,
                    "Create replay did not return its retained admission",
                )
            elif response["admission"] is not None or not (
                sandbox is None and response["state"] in ("pending", "unknown")
            ):
                require(
                    response["admission"] == validate_new_create_03(request, discovery),
                    "Successful create admission differs from current selected discovery and fit",
                )
    elif operation == "get" and discovery["binding"] == HTTP_BINDING_03:
        _validate_03_metadata(response, sandbox=response["sandbox"], discovery=discovery)
    elif operation == "list":
        require(len(response["items"]) <= request["page_size"], "Inventory page exceeds limit")
        seen = set()
        for item in response["items"]:
            _identity(item["sandbox"], discovery)
            if discovery["binding"] == HTTP_BINDING_03:
                if item["state"] in ("active", "paused"):
                    require(
                        item["labels"] is not None and item["lifetime"] is not None,
                        "Present inventory item lacks observations",
                    )
                if item["labels"] is not None:
                    require(
                        len(_labels_wire_bytes(item["labels"])) <= LABELS_BYTES,
                        "Observed labels exceed the 64 KiB serialized bound",
                        code="limit_exceeded",
                    )
            if request["offering_id"] is not None:
                require(
                    item["sandbox"]["offering_id"] == request["offering_id"],
                    "Inventory filter mismatch",
                )
            identity = tuple(item["sandbox"][key] for key in sorted(item["sandbox"]))
            require(identity not in seen, "Duplicate inventory identity")
            seen.add(identity)
    elif operation == "run":
        if request.get("mode") == BUFFERED_COMMANDS:
            require(
                response.get("mode") == BUFFERED_COMMANDS and response.get("encoding") == "base64",
                "Buffered command response downgraded its mode or encoding",
            )
            for stream in ("stdout", "stderr"):
                count = response[stream + "_bytes"]
                require(
                    count <= request["output_limit_bytes"],
                    "Buffered command stream exceeds the requested limit",
                    code="limit_exceeded",
                )
                require(
                    count <= discovery["limits"]["buffered_command_output_bytes"],
                    "Buffered command stream exceeds discovery",
                    code="limit_exceeded",
                )
                # Output over the limit is not an error: the stream is its first L bytes,
                # marked truncated. A truncated stream is therefore exactly L bytes long, and
                # a stream shorter than L was never truncated.
                require(
                    not response[stream + "_truncated"] or count == request["output_limit_bytes"],
                    "Truncated buffered command stream is not exactly the requested limit",
                )
        else:
            require(
                response.get("mode") is None and "stdout" in response and "stderr" in response,
                "Baseline run response upgraded or downgraded its encoding",
            )
            size = len(response["stdout"].encode()) + len(response["stderr"].encode())
            require(
                size <= discovery["limits"]["command_output_bytes"],
                "Command output limit exceeded",
            )
    elif operation == "files.read_bytes":
        require(response["byte_count"] <= request["limit_bytes"], "Read limit exceeded")
    elif operation == "files.write":
        require(response["written_bytes"] == request["byte_count"], "Partial write success")
    elif operation == "process.start":
        require(response["process"]["sandbox"] == request["sandbox"], "Process sandbox mismatch")
    elif operation == "process.output":
        frames = response["frames"]
        first = response["first_available_cursor"]
        start = max(request["cursor"], first)
        require(response["gap"] == (first > request["cursor"]), "Hidden or invented output gap")
        require(len(frames) <= request["max_frames"], "Output frame limit exceeded")
        require(
            [frame["sequence"] for frame in frames] == list(range(start, start + len(frames))),
            "Noncontiguous output sequences",
        )
        require(response["next_cursor"] == start + len(frames), "Wrong next output cursor")
        require(
            sum(len(frame["text"].encode()) for frame in frames) <= request["limit_bytes"],
            "Output byte limit exceeded",
        )
