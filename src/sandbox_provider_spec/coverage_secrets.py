# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Observe native hidden credentials through an independently authenticated receiver."""

from __future__ import annotations

import base64
import gzip
import json
import shlex
import subprocess
import sys
import time
import zlib
from collections.abc import Callable, Mapping
from typing import cast
from uuid import uuid4

from sandbox_provider_spec.driver import Driver, NativeFailure, NotRun, Unsupported
from sandbox_provider_spec.suite import suite_path

Receiver = Callable[[str, str | None], Mapping[str, object]]


def write(driver: Driver, target: object, path: str, data: bytes) -> None:
    driver.call("files.write", target, {"path": path, "data": base64.b64encode(data).decode()})


def outside(inputs: Mapping[str, object]) -> Mapping[str, object]:
    try:
        result = subprocess.run(
            [sys.executable, "-I", str(suite_path().parent / "fixtures/external_observer.py")],
            input=json.dumps(dict(inputs)).encode(),
            capture_output=True,
            timeout=12,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise NativeFailure("secret_outside_observer_timeout") from None
    if result.returncode != 0 or len(result.stdout) > 4096:
        raise NativeFailure("secret_outside_observer_failed")
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise NativeFailure("secret_outside_observer_invalid")
    return cast(Mapping[str, object], value)


def counts(receiver: Mapping[str, object]) -> list[int]:
    value = outside(
        {
            "probe": "counts",
            "url": receiver["observations_url"],
            "headers": receiver["observer_headers"],
        }
    ).get("counts")
    if (
        not isinstance(value, list)
        or not 1 <= len(value) <= 2
        or any(not isinstance(item, int) or isinstance(item, bool) or item < 0 for item in value)
    ):
        raise NativeFailure("secret_receiver_observation_invalid")
    return value


def response(
    driver: Driver, box: object, *, url: str, placeholder: bool, ignore_proxy: bool = False
) -> Mapping[str, object]:
    write(
        driver,
        box,
        "/tmp/sps-secret-request.json",
        json.dumps(
            {
                "url": url,
                "use_placeholder": placeholder,
                "ignore_proxy": ignore_proxy,
            }
        ).encode(),
    )
    code = (
        "import json,subprocess,sys\n"
        "try:\n"
        " result=subprocess.run(['python3','/tmp/sps-secret-request.py'],"
        "capture_output=True,timeout=10)\n"
        "except subprocess.TimeoutExpired:\n"
        + (
            " print(json.dumps({'status':0,'headers':{},'body':''}))\n sys.exit(0)\n"
            if ignore_proxy
            else " raise\n"
        )
        + "sys.stdout.buffer.write(result.stdout); sys.exit(result.returncode)"
    )
    result = driver.call(
        "run", box, {"bash_script": "python3 -c " + shlex.quote(code), "timeout_ms": 15000}
    )
    if result.get("exit_code") != 0:
        raise NativeFailure("secret_fixture_request_failed")
    payload = result.get("stdout")
    if not isinstance(payload, (bytes, str)) or len(payload) > 131072:
        raise NativeFailure("secret_fixture_response_invalid")
    value = json.loads(payload)
    if not isinstance(value, dict) or set(value) != {"status", "headers", "body"}:
        raise NativeFailure("secret_fixture_response_invalid")
    return cast(Mapping[str, object], value)


def received(
    driver: Driver, box: object, receiver: Mapping[str, object], *, placeholder: bool
) -> bool:
    before = counts(receiver)[0]
    reply = response(driver, box, url=str(receiver["coverage_url"]), placeholder=placeholder)
    after = counts(receiver)[0]
    if reply.get("status") not in {200, 403}:
        raise NativeFailure("secret_fixture_request_failed")
    return after > before and reply.get("status") == 200


def wait_file(driver: Driver, box: object, path: str) -> Mapping[str, object]:
    deadline = time.monotonic() + 30
    while not driver.call("files.exists", box, {"path": path}).get("exists"):
        if time.monotonic() >= deadline:
            raise NativeFailure("secret_running_client_not_ready")
        time.sleep(0.2)
    value = driver.call("files.read_bytes", box, {"path": path}).get("data")
    if not isinstance(value, (bytes, str)):
        raise NativeFailure("secret_running_client_result_invalid")
    return cast(Mapping[str, object], json.loads(value))


def rotation(
    driver: Driver, box: object, secret: object, receiver: Mapping[str, object], replacement: str
) -> Mapping[str, object]:
    script = (suite_path().parent / "fixtures/secret_running_client.py").read_bytes()
    write(driver, box, "/tmp/sps-secret-running-client.py", script)
    process = driver.call(
        "process.start",
        box,
        {
            "bash_script": "python3 /tmp/sps-secret-running-client.py",
            "timeout_ms": 150000,
        },
    )
    driver.call("process.disconnect", process, {})
    before = wait_file(driver, box, "/tmp/sps-secret-phase0.json")
    if before.get("status") != 200 or counts(receiver)[0] == 0:
        raise NativeFailure("secret_initial_generation_not_received")
    available = True
    try:
        driver.call(
            "secret.rotate",
            secret,
            {
                "value": replacement,
                "sandbox": box,
                "hosts": receiver["hosts"],
            },
        )
    except Unsupported:
        available = False
    write(driver, box, "/tmp/sps-secret-continue", b"continue")
    after = wait_file(driver, box, "/tmp/sps-secret-phase1.json")
    if (
        after.get("pid") != before.get("pid")
        or after.get("instance") != before.get("instance")
        or after.get("status") != 200
    ):
        raise NativeFailure("secret_running_client_changed_or_failed")
    if not available:
        return {"rotates": False}
    deadline = time.monotonic() + 45
    while counts(receiver)[1] == 0:
        if time.monotonic() >= deadline:
            raise NotRun("native_secret_rotation_observation_ambiguous")
        time.sleep(0.2)
    final = wait_file(driver, box, "/tmp/sps-secret-phase1.json")
    if final.get("instance") != before.get("instance") or final.get("pid") != before.get("pid"):
        raise NativeFailure("secret_running_client_changed_or_failed")
    return {"rotates": True}


def certificate(url: str) -> Mapping[str, object]:
    value = outside({"probe": "certificate", "url": url})
    if set(value) != {"digest", "issuer"} or any(not isinstance(v, str) for v in value.values()):
        raise NativeFailure("secret_tls_certificate_invalid")
    return value


def intercepted(control: Mapping[str, object], inside: Mapping[str, object]) -> bool:
    if set(inside) != {"digest", "issuer"} or any(not isinstance(v, str) for v in inside.values()):
        raise NativeFailure("secret_tls_certificate_invalid")
    if control["digest"] == inside["digest"]:
        return False
    if control["issuer"] == inside["issuer"]:
        # Different CDN leaf certificates signed by the same CA do not prove a proxy.
        raise NotRun("native_tls_interception_unobservable")
    return True


def tls(
    driver: Driver, box: object, receiver: Mapping[str, object], other: Mapping[str, object]
) -> Mapping[str, object]:
    script = (suite_path().parent / "fixtures/secret_certificate.py").read_bytes()
    write(driver, box, "/tmp/sps-secret-certificate.py", script)
    observations = []
    for endpoint in (receiver, other):
        url = str(endpoint["health_url"])
        before = certificate(url)
        write(driver, box, "/tmp/sps-secret-certificate.json", json.dumps({"url": url}).encode())
        code = (
            "import subprocess,sys; "
            "result=subprocess.run(['python3','/tmp/sps-secret-certificate.py'],"
            "capture_output=True,timeout=10); "
            "sys.stdout.buffer.write(result.stdout); sys.exit(result.returncode)"
        )
        result = driver.call(
            "run", box, {"bash_script": "python3 -c " + shlex.quote(code), "timeout_ms": 15000}
        )
        payload = result.get("stdout")
        if (
            result.get("exit_code") != 0
            or not isinstance(payload, (bytes, str))
            or len(payload) > 4096
        ):
            raise NativeFailure("secret_tls_observation_failed")
        if certificate(url) != before:
            raise NotRun("secret_tls_control_changed")
        observations.append(intercepted(before, json.loads(payload)))
    if not observations[0]:
        raise NotRun("native_tls_interception_unobservable")
    return {"intercepts": "all_https" if observations[1] else "injected_hosts"}


def observe(
    driver: Driver, inputs: Mapping[str, object], factory: Receiver
) -> Mapping[str, object]:
    probe = inputs["probe"]
    if probe not in {"rotates", "scrubs_responses", "injection", "intercepts", "transparent"}:
        raise ValueError("invalid hidden-secret probe")
    value, replacement = uuid4().hex + uuid4().hex, uuid4().hex + uuid4().hex
    secret = driver.call("secret.create", None, {"value": value, "hosts": []})
    receiver = factory(value, replacement if probe == "rotates" else None)
    box = driver.call(
        "create",
        None,
        {
            "secret": secret,
            "lifetime_seconds": 300,
            "requirements": {
                "hidden_secrets": {"inject_into": receiver["hosts"], str(probe): inputs["value"]}
            },
        },
    )
    script = (suite_path().parent / "fixtures/secret_request.py").read_bytes()
    write(driver, box, "/tmp/sps-secret-request.py", script)
    exposed = driver.call(
        "run",
        box,
        {
            "bash_script": "printf '%s' \"$SPS_SECRET_PLACEHOLDER\"",
        },
    ).get("stdout")
    if exposed is not None and not isinstance(exposed, (bytes, str)):
        raise NativeFailure("secret_fixture_environment_invalid")
    if exposed in {value, value.encode()}:
        raise NativeFailure("secret_plaintext_guest_readable")
    placeholder = exposed not in {b"", "", None}
    if probe == "transparent":
        if not received(driver, box, receiver, placeholder=placeholder):
            raise NativeFailure("secret_initial_generation_not_received")
        before = counts(receiver)[0]
        reply = response(
            driver,
            box,
            url=str(receiver["coverage_url"]),
            placeholder=placeholder,
            ignore_proxy=True,
        )
        after = counts(receiver)[0]
        if reply.get("status") not in {0, 200, 403}:
            raise NativeFailure("secret_fixture_request_failed")
        # The ordinary request is a positive control. Only the receiver's
        # authenticated credential receipt establishes direct injection.
        return {"transparent": after > before}
    if probe == "injection":
        automatic = received(driver, box, receiver, placeholder=False)
        substituted = received(driver, box, receiver, placeholder=True) if placeholder else False
        if not automatic and not substituted:
            raise NativeFailure("secret_injection_not_observed")
        return {"injection": "sets_header" if automatic else "replaces_placeholder"}
    if probe == "rotates":
        # The running client reads this same request config and opaque placeholder.
        write(
            driver,
            box,
            "/tmp/sps-secret-request.json",
            json.dumps(
                {
                    "url": receiver["coverage_url"],
                    "use_placeholder": placeholder,
                }
            ).encode(),
        )
        return rotation(driver, box, secret, receiver, replacement)
    if probe == "scrubs_responses":
        before = counts(receiver)[0]
        reply = response(driver, box, url=str(receiver["echo_url"]), placeholder=placeholder)
        if reply.get("status") != 200 or counts(receiver)[0] <= before:
            raise NativeFailure("secret_echo_not_received")
        body, headers = reply.get("body"), reply.get("headers")
        if not isinstance(body, str) or not isinstance(headers, Mapping):
            raise NativeFailure("secret_fixture_response_invalid")
        decoded = base64.b64decode(body, validate=True)
        encoding = next(
            (v for k, v in headers.items() if str(k).lower() == "content-encoding"), "identity"
        )
        if encoding == "gzip":
            decoded = gzip.decompress(decoded)
        elif encoding == "deflate":
            decoded = zlib.decompress(decoded)
        elif encoding != "identity":
            raise NativeFailure("secret_echo_encoding_unobservable")
        scrubbed = value.encode() not in decoded and all(
            isinstance(header, str) and value not in header for header in headers.values()
        )
        return {"scrubs_responses": scrubbed}
    if not received(driver, box, receiver, placeholder=placeholder):
        raise NativeFailure("secret_initial_generation_not_received")
    return tls(driver, box, receiver, factory(uuid4().hex, None))
