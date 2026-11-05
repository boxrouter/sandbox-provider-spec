# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Authored HTTP binding semantic examples, generated against schema examples."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from typing import Any


def cases(source: dict[str, Any]) -> list[dict[str, Any]]:
    definitions = source["$defs"]
    discovery = copy.deepcopy(definitions["Discovery"]["examples"][0])
    result: list[dict[str, Any]] = []

    def exchange(operation: str, name: str, valid: bool = True) -> dict[str, Any]:
        entry = source["x-operations"][operation]
        case = {
            "name": name,
            "kind": "exchange",
            "valid": valid,
            "discovery": copy.deepcopy(discovery),
            "request": copy.deepcopy(definitions[entry["request"]]["examples"][0]),
            "response": copy.deepcopy(definitions[entry["result"]]["examples"][0]),
        }
        if operation == "create":
            raw = json.dumps(case["request"], separators=(",", ":"), ensure_ascii=False)
            case["request_body"] = raw
            case["digest"] = "sha256:" + hashlib.sha256(raw.encode()).hexdigest()
            case["response"]["request_digest"] = case["digest"]
        result.append(case)
        return case

    for operation in source["x-operations"]:
        exchange(operation, "valid-" + operation)
        case = exchange(operation, "wrong-account-" + operation, False)
        case["response"]["account_id"] = "other-account"

    def buffered(name: str, valid: bool = True) -> dict[str, Any]:
        request = copy.deepcopy(definitions["RunRequest"]["examples"][1])
        response = copy.deepcopy(definitions["RunResult"]["examples"][1])
        mode_discovery = copy.deepcopy(definitions["Discovery"]["examples"][2])
        case = {
            "name": name,
            "kind": "exchange",
            "valid": valid,
            "discovery": mode_discovery,
            "request": request,
            "response": response,
        }
        result.append(case)
        return case

    buffered("buffered-binary-two-streams")
    case = buffered("buffered-per-stream-not-aggregate")
    case["discovery"]["limits"]["command_output_bytes"] = 10
    case = buffered("buffered-stream-content-order", False)
    case.update(
        kind="buffered_content", expected_stdout=b"ready".hex(), expected_stderr=b"diagnostic".hex()
    )
    case["response"]["stdout_base64"], case["response"]["stderr_base64"] = (
        case["response"]["stderr_base64"],
        case["response"]["stdout_base64"],
    )
    case["response"]["stdout_bytes"], case["response"]["stderr_bytes"] = 10, 5
    case = buffered("buffered-byte-fidelity-nul-invalid-utf8")
    case["response"].update(
        stdout_base64=base64.b64encode(b"a\x00\xff").decode(),
        stdout_bytes=3,
        stderr_base64="",
        stderr_bytes=0,
    )
    for field, value in (("encoding", "utf8"), ("mode", "other")):
        buffered("buffered-response-downgrade-" + field, False)["response"][field] = value
    case = buffered("buffered-swapped-streams", False)
    case["response"]["stdout_base64"], case["response"]["stderr_base64"] = (
        case["response"]["stderr_base64"],
        case["response"]["stdout_base64"],
    )
    case = buffered("buffered-count-mismatch", False)
    case["response"]["stdout_bytes"] += 1
    case = buffered("buffered-correlation-mismatch", False)
    case["response"]["request_id"] = "other-request"
    case = buffered("buffered-identity-mismatch", False)
    case["response"]["sandbox"]["incarnation"] = "other-incarnation"
    for stream in ("stdout", "stderr"):
        case = buffered("buffered-exact-limit-" + stream)
        encoded = base64.b64encode(b"x" * case["request"]["output_limit_bytes"]).decode()
        case["request"]["output_limit_bytes"] = len(base64.b64decode(encoded))
        case["response"][stream + "_base64"] = encoded
        case["response"][stream + "_bytes"] = len(base64.b64decode(encoded))
        case = buffered("buffered-truncated-prefix-" + stream)
        case["response"][stream + "_base64"] = encoded
        case["response"][stream + "_bytes"] = len(base64.b64decode(encoded))
        case["response"][stream + "_truncated"] = True
        case = buffered("buffered-truncated-short-" + stream, False)
        case["response"][stream + "_truncated"] = True
        case = buffered("buffered-limit-plus-one-" + stream, False)
        case["response"][stream + "_base64"] = base64.b64encode(b"x" * 1048577).decode()
        case["response"][stream + "_bytes"] = 1048577
    for stream in ("stdout", "stderr"):
        case = buffered("buffered-missing-truncated-flag-" + stream, False)
        del case["response"][stream + "_truncated"]
    case = buffered("buffered-execution-limit-independent-of-observation")
    case["request"]["observation_timeout_ms"] = 1
    case["request"]["execution_limit_ms"] = 30000
    case = buffered("buffered-existing-identity-after-offering-removal")
    case["discovery"]["offerings"][0]["offering_id"] = "current-offering"
    case["discovery"]["offerings"][0]["declaration_id"] = "current-token"
    case = buffered("buffered-response-cap-too-small", False)
    case["request"].update(output_limit_bytes=0, execution_limit_ms=1)
    case["response"].update(stdout_base64="", stderr_base64="", stdout_bytes=0, stderr_bytes=0)
    case["discovery"]["limits"].update(
        buffered_command_output_bytes=1, execution_ms=1, response_bytes=16384
    )
    case["response_body"] = json.dumps(case["response"], separators=(",", ":")) + " " * 32768
    case = buffered("buffered-request-cap-overflow", False)
    raw_request = json.dumps(case["request"], separators=(",", ":"))
    case["discovery"]["limits"]["request_bytes"] = len(raw_request.encode()) + 8
    case["request_body"] = raw_request + " " * 16

    for name, request_change, _response_change, discovery_change, valid in (
        ("buffered-absent-mode-controls", {"mode": None}, {}, {}, False),
        ("buffered-unknown-mode", {"mode": "future"}, {}, {}, False),
        ("buffered-zero-execution", {"execution_limit_ms": 0}, {}, {}, False),
        ("buffered-boolean-execution", {"execution_limit_ms": True}, {}, {}, False),
        ("buffered-zero-observation", {"observation_timeout_ms": 0}, {}, {}, False),
        ("buffered-boolean-observation", {"observation_timeout_ms": True}, {}, {}, False),
        ("buffered-missing-execution", {"execution_limit_ms": None}, {}, {}, False),
        ("buffered-boolean-output-limit", {"output_limit_bytes": True}, {}, {}, False),
        (
            "buffered-unsupported-on-v01",
            {},
            {},
            {"binding": "sandbox-provider-http/0.1", "core_modes": []},
            False,
        ),
    ):
        case = buffered(name, valid)
        if request_change.get("mode") is None:
            case["request"].pop("mode")
        else:
            case["request"].update(request_change)
        case["discovery"].update(discovery_change)
        if not valid:
            if name == "buffered-unsupported-on-v01":
                case["discovery"]["limits"].pop("buffered_command_output_bytes")
                case["discovery"]["limits"].pop("execution_ms")

    for name, events, expected, valid in (
        (
            "term-resistance-after-leader-exit",
            ["dispatch", "term_at_e", "leader_exit", "kill_before_five", "group_running"],
            "invalid",
            False,
        ),
        (
            "term-resistance-escalates-at-five",
            ["dispatch", "term_at_e", "leader_exit", "kill_at_e_plus_five", "settled"],
            "completed",
            True,
        ),
        (
            "observer-loss-does-not-terminate",
            ["dispatch", "observer_lost", "command_running"],
            "unknown",
            True,
        ),
        (
            "observation-timeout-does-not-terminate",
            ["dispatch", "observation_timeout", "command_running"],
            "unknown",
            True,
        ),
        (
            "ordinary-background-does-not-delay-output",
            ["dispatch", "foreground_exit", "finalize", "receipt", "background_write"],
            "completed",
            True,
        ),
        (
            "execution-timeout-uncertain-is-unknown",
            ["dispatch", "term_at_e", "termination_unobserved"],
            "unknown",
            True,
        ),
        (
            "buffered-no-replay-after-observer-loss",
            ["dispatch", "observer_lost", "no_replay"],
            "unknown",
            True,
        ),
    ):
        result.append(
            {
                "name": name,
                "kind": "buffered_trace",
                "events": events,
                "expected": expected,
                "valid": valid,
                "normative": True,
            }
        )
    for name, events, expected, valid, details in (
        (
            "new-create-stale-selection-conflicts-before-allocation",
            ["new_key", "compare_current_token", "conflict"],
            "not_dispatched",
            True,
            {
                "requested_token": "old-token",
                "current_token": "new-token",
                "native_submissions": 0,
                "bound_inputs": ["declaration", "binding", "core_modes", "limits"],
            },
        ),
        (
            "existing-key-replay-precedes-current-selection-admission",
            ["key_lookup", "digest_match", "return_saved_selection", "current_listing_changed"],
            "replay",
            True,
            {
                "saved_modes": ["buffered_commands_v1"],
                "saved_capacity_bytes": 1048576,
                "native_submissions": 0,
                "saved_selection_token": "old-token",
                "retained_through_lifetime": True,
            },
        ),
        (
            "removed-offering-keeps-original-selection-for-old-identity",
            ["created_with_selection_token", "offering_removed", "run_exact_incarnation"],
            "original_selection",
            True,
            {"admitted_mode": "buffered_commands_v1", "native_submissions": 0},
        ),
    ):
        result.append(
            {
                "name": name,
                "kind": "selection_trace",
                "events": events,
                "expected": expected,
                "valid": valid,
                "normative": True,
                **details,
            }
        )
    for field, value in (
        ("request_digest", "sha256:" + "f" * 64),
        ("key_expires_at", 1),
        ("allocation_key", "1792670400:" + "b" * 32),
    ):
        exchange("create", "wrong-create-" + field, False)["response"][field] = value
    for state in ("pending", "unknown", "unavailable"):
        exchange("create", "create-" + state)["response"]["state"] = state
    case = exchange("create", "unavailable-needs-identity", False)
    case["response"].update(state="unavailable", sandbox=None)
    exchange("create", "body-digest-mismatch", False)["request_body"] += " "
    case = exchange("get", "wrong-incarnation", False)
    case["response"]["sandbox"]["incarnation"] = "replacement"
    exchange("run", "nonzero-observed-exit")["response"]["exit_code"] = 17
    exchange("run", "truncated-run-is-not-success", False)["response"]["output_complete"] = False
    case = exchange("run", "utf8-bytes-not-characters", False)
    case["response"].update(stdout="\U0001f642", stderr="")
    case["discovery"]["limits"]["command_output_bytes"] = 1
    for operation, field in (("files.read_bytes", "response"), ("files.write", "request")):
        exchange(operation, operation + "-count-mismatch", False)[field]["byte_count"] = 1
        exchange(operation, operation + "-noncanonical-padding", False)[field]["data_base64"] = (
            "AP9="
        )
        case = exchange(operation, operation + "-empty-file")
        case[field].update(data_base64="", byte_count=0)
        if operation == "files.write":
            case["response"]["written_bytes"] = 0
    exchange("files.read_bytes", "partial-read-success", False)["response"]["complete"] = False
    exchange("files.read_bytes", "read-request-limit", False)["request"]["limit_bytes"] = 1
    exchange("files.write", "partial-write-success", False)["response"]["written_bytes"] = 1
    case = exchange("process.start", "start-wrong-sandbox", False)
    case["response"]["process"]["sandbox"]["incarnation"] = "replacement"
    for field in ("gap", "next_cursor"):
        case = exchange("process.output", "output-wrong-" + field, False)
        case["response"][field] = True if field == "gap" else 99
    case = exchange("process.output", "output-noncontiguous", False)
    case["response"]["frames"][0]["sequence"] = 4
    case = exchange("process.output", "gap-with-data")
    case["response"].update(first_available_cursor=5, next_cursor=6, gap=True)
    case["response"]["frames"][0]["sequence"] = 5
    case = exchange("process.output", "gap-with-empty-page")
    case["response"].update(first_available_cursor=5, next_cursor=5, gap=True, frames=[])
    case = exchange("process.output", "empty-gap-cannot-keep-old-cursor", False)
    case["response"].update(first_available_cursor=5, next_cursor=0, gap=True, frames=[])
    case = exchange("process.output", "eof-without-exit")
    case["response"].update(stdout_eof=True, stderr_eof=True, observation_end="stream_end")
    case = exchange("process.output", "exit-before-output-drained")
    case["response"].update(execution_state="exited", exit_code=7, observation_end="process_exit")
    case = exchange("process.output", "exit-without-status", False)
    case["response"].update(execution_state="exited", exit_code=None)
    case = exchange("process.output", "stream-end-without-eof", False)
    case["response"]["observation_end"] = "stream_end"
    case = exchange("process.output", "wait-timeout-is-running")
    case["response"].update(frames=[], next_cursor=0, observation_end="wait_timeout")
    case = exchange("process.output", "observation-lost-not-exit")
    case["response"].update(
        frames=[], next_cursor=0, observation_end="unavailable", execution_state="unknown"
    )
    case = exchange("process.output", "four-byte-scalar-cannot-fit-one", False)
    case["request"]["limit_bytes"] = 1
    case["response"]["frames"][0]["text"] = "\U0001f642"
    case = exchange("list", "duplicate-inventory-identity", False)
    case["response"]["items"] *= 2
    case = exchange("list", "foreign-inventory-identity", False)
    case["response"]["items"][0]["sandbox"]["account_id"] = "other-account"
    case = exchange("create", "new-required-mode-rejected", False)
    case["request"]["request"]["requirements"] = {"invented_mode": {}}

    for operation in ("run", "process.start", "files.write", "destroy"):
        case = exchange(operation, "unknown-mutation-" + operation)
        case["status"] = 504
        case["response"] = {
            key: case["request"][key] for key in ("operation", "request_id", "account_id")
        }
        case["response"]["error"] = {
            "code": "timeout",
            "outcome": "unknown",
            "message": "Observation expired",
            "exit_code": None,
        }
    case = copy.deepcopy(result[-1])
    case.update(name="error-status-mismatch", status=200, valid=False)
    result.append(case)
    case = copy.deepcopy(result[-2])
    case.update(name="timeout-cannot-invent-exit", valid=False)
    case["response"]["error"]["exit_code"] = 0
    result.append(case)

    key = definitions["CreateRequest"]["examples"][0]["allocation_key"]
    issued = int(key[:10])
    digest = "sha256:" + "a" * 64
    for name, now, floor, stored, expected in (
        ("fresh-key", issued, 0, None, "reserve"),
        ("identical-replay", issued + 1, 0, digest, "replay"),
        ("changed-payload-conflicts", issued + 1, 0, "sha256:" + "b" * 64, "conflict"),
        ("expired-key-with-record", issued + 86400, 0, digest, "expired_key"),
        ("expired-key-without-record", issued + 86400, 0, None, "expired_key"),
        (
            "crash-clock-rollback-after-record-deletion",
            issued + 10,
            issued + 86400,
            None,
            "expired_key",
        ),
        ("future-key", issued - 61, 0, None, "invalid_request"),
    ):
        result.append(
            {
                "name": name,
                "kind": "key",
                "valid": True,
                "input": {
                    "key": key,
                    "digest": digest,
                    "now": now,
                    "expiry_floor": floor,
                    "stored_digest": stored,
                },
                "expected": expected,
            }
        )
    for stored, label in ((digest, "retained-reservation"), (None, "never-seen-key")):
        for latched in (True, False):
            result.append(
                {
                    "name": label + "-expiry-latched-" + str(latched),
                    "kind": "key_expiry_trace",
                    "valid": latched,
                    "key": key,
                    "digest": digest,
                    "steps": [
                        {
                            "now": issued + 86400,
                            "expiry_floor": issued + 86400 if latched else 0,
                            "stored_digest": stored,
                            "expected": "expired_key",
                        },
                        {
                            "now": issued + 10,
                            "expiry_floor": issued + 86400 if latched else 0,
                            "stored_digest": stored,
                            "expected": "expired_key",
                        },
                    ],
                }
            )
    identity = definitions["CreateResult"]["examples"][0]["sandbox"]
    for name, submissions, new_key, valid in (
        ("concurrent-create-same-identity", 1, False, True),
        ("concurrent-create-double-dispatch", 2, False, False),
        ("lost-create-reply-stays-unknown", 1, False, True),
        ("lost-create-reply-new-key-unsafe", 2, True, False),
    ):
        result.append(
            {
                "name": name,
                "kind": "create_trace",
                "valid": valid,
                "identities": [identity, identity],
                "native_submissions": submissions,
                "lost_response": True,
                "automatic_new_key": new_key,
            }
        )
    for event in ("lookup_failed", "disconnect", "deadline"):
        for response, valid in (
            ({"state": "unknown", "execution_state": "unknown"}, True),
            ({"state": "absent"}, False),
            ({"execution_state": "exited"}, False),
        ):
            result.append(
                {
                    "name": event + "-" + next(iter(response.values())),
                    "kind": "observation_trace",
                    "native_event": event,
                    "response": response,
                    "valid": valid,
                }
            )
    for oversized_response, valid in (
        ({"error": {"code": "limit_exceeded"}}, True),
        ({"frames": []}, False),
    ):
        result.append(
            {
                "name": "oversized-frame-" + str(valid),
                "kind": "observation_trace",
                "native_event": "oversized_next_frame",
                "response": oversized_response,
                "valid": valid,
            }
        )
    frame = {"sequence": 0, "stream": "stdout", "text": "hello"}
    for name, page, valid in (
        ("stable-sequence", {"first": 0, "high": 1, "frames": [frame]}, True),
        ("resplit-sequence", {"first": 0, "high": 1, "frames": [{**frame, "text": "he"}]}, False),
        ("first-after-issued", {"first": 2, "high": 1, "frames": []}, False),
        ("issued-regressed", {"first": 0, "high": 0, "frames": []}, False),
    ):
        result.append(
            {
                "name": name,
                "kind": "output_trace",
                "valid": valid,
                "pages": [{"first": 0, "high": 1, "frames": [frame]}, page],
            }
        )
    for name, raw, valid in (
        ("duplicate-json-key", '{"a":1,"a":2}', False),
        ("nonfinite-json", '{"a":NaN}', False),
        ("overflow-json-number", '{"a":1e999}', False),
        ("unpaired-surrogate", '{"a":"\\ud800"}', False),
        ("valid-unicode", '{"a":"hello"}', True),
    ):
        result.append({"name": name, "kind": "json", "raw": raw, "limit": 100, "valid": valid})
    return result
