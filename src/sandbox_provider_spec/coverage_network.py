# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Native egress policy observations with healthy unrestricted controls."""

from __future__ import annotations

import base64
import json
import subprocess
import sys
import time
import urllib.parse
import uuid
from collections.abc import Mapping
from typing import cast

from sandbox_provider_spec import coverage_network_probe as network_probe
from sandbox_provider_spec.driver import Driver, NativeFailure, NotRun, Unsupported
from sandbox_provider_spec.suite import suite_path


def urls(value: object) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > 128:
        raise ValueError("invalid HTTP fixture URLs")
    result: list[str] = []
    for entry in value:
        if isinstance(entry, list):
            result.extend(urls(entry))
        elif isinstance(entry, str):
            parsed = urllib.parse.urlsplit(entry)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username:
                raise ValueError("invalid HTTP fixture URL")
            result.append(entry)
        else:
            raise ValueError("invalid HTTP fixture URL")
    if len(result) > 128 or len(set(result)) != len(result):
        raise ValueError("invalid HTTP fixture URLs")
    return result


def parse(payload: object, count: int) -> list[bool]:
    if not isinstance(payload, (bytes, str)) or len(payload) > 32768:
        raise NativeFailure("network_fixture_response_invalid")
    value = json.loads(payload)
    rows = value.get("results") if isinstance(value, dict) else None
    if not isinstance(rows, list) or len(rows) != count:
        raise NativeFailure("network_fixture_response_invalid")
    for row in rows:
        if (
            not isinstance(row, dict)
            or set(row) != {"reached", "ambiguous"}
            or any(not isinstance(item, bool) for item in row.values())
        ):
            raise NativeFailure("network_fixture_response_invalid")
        if row["ambiguous"]:
            raise NotRun("network_tls_observation_ambiguous")
    return [row["reached"] for row in rows]


def outside(targets: list[str]) -> list[bool]:
    try:
        result = subprocess.run(
            [sys.executable, "-I", str(suite_path().parent / "fixtures/coverage_http.py")],
            input=json.dumps({"urls": targets}).encode(),
            capture_output=True,
            timeout=len(targets) * 8 + 5,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise NativeFailure("network_control_observer_timeout") from None
    if result.returncode != 0:
        raise NativeFailure("network_control_observer_failed")
    return parse(result.stdout, len(targets))


def healthy(targets: list[str]) -> None:
    if not all(outside(targets)):
        raise NotRun("network_unrestricted_control_unavailable")


def checked_probe(
    driver: Driver,
    box: object,
    requests: list[Mapping[str, object]],
) -> list[Mapping[str, object]]:
    """Probe runner endpoints with unique tokens and verify each recorder result."""
    targets: list[str] = []
    methods: list[str] = []
    recorder_modes: list[str] = []
    for request in requests:
        target = urls([request.get("url")])[0]
        method = request.get("method", "GET")
        recorder = request.get("recorder", "required")
        if (
            not isinstance(method, str)
            or method.upper() not in {"GET", "POST", "PUT", "PATCH"}
            or not isinstance(recorder, str)
            or recorder not in {"required", "absent", "none"}
        ):
            raise ValueError("invalid network recorder probe")
        targets.append(target)
        methods.append(method.upper())
        recorder_modes.append(recorder)
    if not requests:
        raise ValueError("network recorder probe cannot be empty")

    indexed = [i for i, mode in enumerate(recorder_modes) if mode != "none"]
    for i, mode in enumerate(recorder_modes):
        if mode == "none" and not outside([targets[i]])[0]:
            raise NotRun("network_unrestricted_control_unavailable")
    if indexed:
        network_probe.runner_controls([targets[i] for i in indexed], [methods[i] for i in indexed])

    guest_observations, tokens = network_probe.guest_http_observations(
        driver, box, list(zip(targets, methods, strict=True))
    )
    observations: list[Mapping[str, object]] = []
    for target, method, token, mode, guest_observation in zip(
        targets, methods, tokens, recorder_modes, guest_observations, strict=True
    ):
        succeeded = guest_observation["succeeded"]
        ambiguous = guest_observation["ambiguous"]
        recorded: bool | None = None
        if ambiguous and mode == "none":
            raise NotRun("network_tls_observation_ambiguous")
        if mode != "none" or ambiguous:
            try:
                records = network_probe.records(target, token)
            except NotRun as error:
                if ambiguous and str(error) == "network_receiver_observer_unavailable":
                    raise NotRun("network_tls_observation_ambiguous", detail=error.detail) from None
                raise
            except NativeFailure as error:
                if ambiguous and error.code == "network_receiver_response_invalid":
                    raise NotRun("network_tls_observation_ambiguous", detail=error.code) from None
                raise
            if ambiguous:
                if records not in ([], [(method, network_probe.path(target))]):
                    raise NotRun("network_receiver_observation_mismatch")
                succeeded = bool(records)
            else:
                expected = [(method, network_probe.path(target))] if succeeded else []
                if records != expected:
                    raise NotRun("network_receiver_observation_mismatch")
            recorded = bool(records)
        observations.append({"reached": succeeded, "recorded": recorded})
    return observations


def network_checks(
    driver: Driver, box: object, inputs: Mapping[str, object]
) -> Mapping[str, object]:
    requests = inputs.get("requests", [])
    if not isinstance(requests, list) or any(not isinstance(row, Mapping) for row in requests):
        raise ValueError("invalid network check requests")
    requests = list(requests)
    for key, reachable, recorder in (
        ("allowed_urls", True, "required"),
        ("blocked_urls", False, "absent"),
    ):
        if key in inputs:
            supplied = inputs[key]
            targets = urls([supplied]) if isinstance(supplied, str) else urls(supplied)
            requests.extend(
                {"url": target, "reachable": reachable, "recorder": recorder} for target in targets
            )
    if not requests:
        raise ValueError("network checks require at least one request")
    expected: list[Mapping[str, object]] = []
    for row in requests:
        reached = row.get("reachable")
        recorder = row.get("recorder", "required")
        if not isinstance(reached, bool) or recorder not in {"required", "absent", "none"}:
            raise ValueError("invalid network check expectation")
        expected.append(
            {
                "reached": reached,
                "recorded": None
                if recorder == "none"
                else (reached if recorder == "required" else False),
            }
        )
    excluded_hosts = inputs.get("excluded_hosts")
    if excluded_hosts is not None:
        if not isinstance(excluded_hosts, list) or any(
            not isinstance(host, str) or not host for host in excluded_hosts
        ):
            raise ValueError("invalid network exclusion list")
        excluded = {host.lower() for host in cast(list[str], excluded_hosts)}
        for row in cast(list[Mapping[str, object]], requests):
            if row.get("reachable") is False and row.get("recorder", "required") == "absent":
                hostname = urllib.parse.urlsplit(urls([row.get("url")])[0]).hostname
                if hostname is None or hostname.lower() in excluded:
                    raise ValueError("blocked fixture must be outside the selected allowlist")
    observed = checked_probe(driver, box, cast(list[Mapping[str, object]], requests))
    passed = all(
        got["reached"] == want["reached"]
        and (want["recorded"] is None or got["recorded"] == want["recorded"])
        for got, want in zip(observed, expected, strict=True)
    )
    return {"passed": passed, "observations": observed}


def write(driver: Driver, box: object, path: str, data: bytes) -> None:
    driver.call("files.write", box, {"path": path, "data": base64.b64encode(data).decode()})


def http(driver: Driver, box: object, targets: list[str]) -> list[bool]:
    observations = checked_probe(
        driver,
        box,
        [{"url": target, "recorder": "required"} for target in targets],
    )
    return [bool(row["reached"]) for row in observations]


def denylist(driver: Driver, box: object, inputs: Mapping[str, object]) -> Mapping[str, object]:
    blocked, allowed = urls(inputs["blocked_urls"]), urls(inputs["allowed_urls"])
    if set(blocked) & set(allowed):
        raise ValueError("denylist fixtures overlap")
    blocked_results = http(driver, box, blocked)
    allowed_results = http(driver, box, allowed)
    if not any(allowed_results):
        raise NotRun("network_unlisted_control_unavailable")
    return {"listed_blocked": not any(blocked_results), "unlisted_allowed": all(allowed_results)}


def ticker(driver: Driver, box: object, path: str) -> Mapping[str, object]:
    result = driver.call("files.read_bytes", box, {"path": path})
    payload = result.get("data")
    if not isinstance(payload, (bytes, str)):
        raise NativeFailure("network_process_probe_invalid")
    value = json.loads(payload)
    if not isinstance(value, dict) or not isinstance(value.get("count"), int):
        raise NativeFailure("network_process_probe_invalid")
    return cast(Mapping[str, object], value)


def policy_change(
    driver: Driver, box: object, inputs: Mapping[str, object]
) -> Mapping[str, object]:
    targets = urls([inputs["allowed_url"]])
    reachable_before = inputs.get("reachable_before", True)
    reachable_after = inputs.get("reachable_after")
    if not isinstance(reachable_before, bool) or (
        reachable_after is not None and not isinstance(reachable_after, bool)
    ):
        raise ValueError("network policy transition reachability must be boolean")
    before_result = checked_probe(driver, box, [{"url": targets[0], "recorder": "required"}])[0]
    initial_state_observed = (
        before_result["reached"] == reachable_before
        and before_result["recorded"] == reachable_before
    )
    write(driver, box, "/tmp/sps-network-retained", b"sps-retained")
    write(
        driver,
        box,
        "/tmp/sps-idle-activity.py",
        (suite_path().parent / "fixtures/idle_activity.py").read_bytes(),
    )
    # Each call's heartbeat writes its own file: a heartbeat an earlier call left running on this
    # sandbox would otherwise overwrite the file this call reads, under its own pid.
    heartbeat = f"/tmp/sps-idle-activity-{uuid.uuid4().hex}.json"
    started = driver.call(
        "run",
        box,
        {
            "bash_script": "nohup python3 /tmp/sps-idle-activity.py "
            f"{heartbeat} </dev/null >/dev/null 2>&1 &"
        },
    )
    if started.get("exit_code") != 0:
        raise NativeFailure("network_process_probe_failed")
    time.sleep(1)
    before = ticker(driver, box, heartbeat)
    try:
        new_policy = inputs.get("new_policy")
        if not isinstance(new_policy, Mapping):
            raise ValueError("native network policy required")
        driver.call("network.update", box, new_policy)
    except Unsupported:
        pass
    after_observed = checked_probe(driver, box, [{"url": targets[0], "recorder": "required"}])[0]
    actual_after = bool(after_observed["reached"])
    recorder_observed = after_observed["recorded"] is actual_after
    changed = initial_state_observed and recorder_observed and actual_after != reachable_before
    time.sleep(0.3)
    after = ticker(driver, box, heartbeat)
    retained = driver.call("files.read_bytes", box, {"path": "/tmp/sps-network-retained"})
    preserved = (
        before.get("pid") == after.get("pid")
        and cast(int, after["count"]) > cast(int, before["count"])
        and retained.get("data") in {b"sps-retained", "sps-retained"}
    )
    return {"policy_changed": changed, "source_preserved": preserved}
