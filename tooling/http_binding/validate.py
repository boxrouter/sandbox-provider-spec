# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Run committed HTTP binding semantic fixtures against the packaged validator."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from sandbox_provider_spec.http_binding_validation import (
    body_bytes,
    decode_json,
    key_disposition,
    require,
    validate_exchange,
    validate_request,
)

ROOT = Path(__file__).resolve().parents[2]


def validate_trace(case: dict[str, Any]) -> None:
    """Check supplied observations; fake native facts do not become runtime proof."""
    kind = case["kind"]
    if kind == "create_trace":
        identities = {body_bytes(identity) for identity in case["identities"]}
        require(
            len(identities) <= 1 and case["native_submissions"] <= 1,
            "Create key allocated more than once",
        )
        require(
            not case["lost_response"] or case["automatic_new_key"] is False,
            "Unknown create retried with a new key",
        )
    elif kind == "key_expiry_trace":
        # This fixture exercises the floor alternative, not a storage implementation.
        previous_floor = 0
        expiry = int(case["key"][:10]) + 86400
        for step in case["steps"]:
            floor = step["expiry_floor"]
            require(floor >= previous_floor, "Durable expiry floor regressed")
            previous_floor = floor
            disposition = key_disposition(
                key=case["key"],
                digest=case["digest"],
                now=step["now"],
                expiry_floor=floor,
                stored_digest=step["stored_digest"],
            )
            require(disposition == step["expected"], "Wrong expiry trace disposition")
            if disposition == "expired_key":
                require(floor >= expiry, "Expiry must be durably latched before reply")
    elif kind == "observation_trace":
        event = case["native_event"]
        response = case["response"]
        if event in ("lookup_failed", "disconnect", "deadline"):
            require(response.get("state") not in ("absent", "destroyed"), "Failure became absence")
            require(response.get("execution_state") != "exited", "Observation loss became exit")
        if event == "oversized_next_frame":
            require(
                response.get("error", {}).get("code") == "limit_exceeded",
                "Oversized retained frame cannot make progress",
            )
    elif kind == "output_trace":
        previous_first = previous_high = 0
        frames: dict[int, tuple[str, str]] = {}
        for page in case["pages"]:
            require(previous_first <= page["first"] <= page["high"], "First cursor regressed")
            require(previous_high <= page["high"], "Issued cursor regressed")
            previous_first, previous_high = page["first"], page["high"]
            for frame in page["frames"]:
                sequence = frame["sequence"]
                require(sequence < page["high"], "Frame beyond issued cursor")
                value = (frame["stream"], frame["text"])
                require(
                    sequence not in frames or frames[sequence] == value, "Retained frame changed"
                )
                frames[sequence] = value
    elif kind == "buffered_trace":
        events = case["events"]
        require(events[0] == "dispatch", "Buffered trace must begin at dispatch")
        require(
            "no_replay" not in events or events.count("dispatch") == 1, "Buffered command replayed"
        )
        if "kill_before_five" in events:
            require(False, "KILL cannot precede the five-second TERM grace period")
        if "kill_at_e_plus_five" in events:
            require(
                "term_at_e" in events
                and events.index("kill_at_e_plus_five") > events.index("term_at_e"),
                "KILL requires the TERM escalation deadline",
            )
        if "leader_exit" in events and "group_running" in events:
            require(
                events.index("kill_at_e_plus_five") < events.index("group_running"),
                "TERM resistance obligation survives leader exit",
            )
        if "observer_lost" in events and "command_running" in events:
            require(
                case["expected"] == "unknown", "Observer loss cannot terminate or complete work"
            )
        if "background_write" in events:
            require(
                events.index("receipt") < events.index("background_write"),
                "Completion does not wait for later inherited descriptor writes",
            )
        if "finalize" in events:
            require(
                events.index("foreground_exit")
                < events.index("finalize")
                < events.index("receipt"),
                "Streams finalize after foreground completion and before the receipt",
            )
        if "observation_timeout" in events and "command_running" in events:
            require(
                case["expected"] == "unknown", "Observation timeout cannot stop command execution"
            )
    elif kind == "buffered_content":
        require(
            base64.b64decode(case["response"]["stdout_base64"]).hex() == case["expected_stdout"],
            "Buffered stdout content or stream identity changed",
        )
        require(
            base64.b64decode(case["response"]["stderr_base64"]).hex() == case["expected_stderr"],
            "Buffered stderr content or stream identity changed",
        )
    elif kind == "selection_trace":
        events = case["events"]
        require(case.get("normative") is True, "Selection trace must be labeled normative")
        if case["expected"] == "not_dispatched":
            require(
                case["requested_token"] != case["current_token"]
                and case["bound_inputs"] == ["declaration", "binding", "core_modes", "limits"]
                and events[-1] == "conflict"
                and "dispatch" not in events
                and case["native_submissions"] == 0,
                "A stale new-create token conflicts before allocation",
            )
        elif case["expected"] == "replay":
            require(
                events.index("key_lookup") < events.index("return_saved_selection")
                and events.index("digest_match") < events.index("return_saved_selection")
                and events.index("return_saved_selection") < events.index("current_listing_changed")
                and case["saved_selection_token"]
                and "buffered_commands_v1" in case["saved_modes"]
                and case["saved_capacity_bytes"] > 0
                and case["retained_through_lifetime"] is True
                and case["native_submissions"] == 0,
                "Existing key replay retains the originally selected modes and capacities",
            )
        elif case["expected"] == "original_selection":
            require(
                events.index("created_with_selection_token") < events.index("offering_removed")
                and events.index("offering_removed") < events.index("run_exact_incarnation")
                and case["admitted_mode"] == "buffered_commands_v1",
                "An old exact identity keeps its originally admitted mode after listing changes",
            )
    else:
        raise ValueError("Unknown trace fixture")


def check_case(case: dict[str, Any]) -> None:
    kind = case["kind"]
    if kind == "exchange":
        body = case.get("request_body")
        validate_exchange(
            case["request"],
            case["response"],
            case["discovery"],
            status=case.get("status", 200),
            request_body=body.encode() if body is not None else None,
            response_body=case.get("response_body", "").encode()
            if "response_body" in case
            else None,
            digest=case.get("digest"),
        )
    elif kind == "request":
        validate_request(case["request"], case["discovery"])
    elif kind == "json":
        decode_json(case["raw"].encode(), case["limit"])
    elif kind == "key":
        require(key_disposition(**case["input"]) == case["expected"], "Wrong key disposition")
    else:
        validate_trace(case)


def main() -> None:
    cases = json.loads((ROOT / "examples/http-binding/semantics.json").read_text())
    for case in cases:
        try:
            check_case(case)
        except ValueError:
            require(not case["valid"], "Rejected valid fixture: " + case["name"])
        else:
            require(case["valid"], "Accepted invalid fixture: " + case["name"])
    print(f"{len(cases)} HTTP binding semantic fixtures passed (offline only)")


if __name__ == "__main__":
    main()
