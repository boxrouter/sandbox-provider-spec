# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Evaluate shared tests and record only explicit, safe observations."""

from __future__ import annotations

import base64
import copy
import json
import math
import shlex
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Generator, Mapping
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any, cast
from uuid import uuid4

from sandbox_provider_spec import (
    coverage_desktop,
    coverage_docker,
    coverage_lifecycle,
    coverage_network,
    coverage_ports,
    coverage_probe,
    coverage_secrets,
    coverage_ssh,
    coverage_v2,
    coverage_v3,
    coverage_v4,
    coverage_v5,
    coverage_v6,
    process_eof,
    protocol_probe,
    snapshot_ticker,
)
from sandbox_provider_spec.driver import (
    Differs,
    Driver,
    NativeFailure,
    NotRun,
    Unsupported,
    resource,
    strings,
)
from sandbox_provider_spec.fuse_mount_identity import default_proof_errors
from sandbox_provider_spec.proofs import proof_fixtures, proof_targets
from sandbox_provider_spec.suite import Suite, Test, suite_path
from sandbox_provider_spec.volume_visibility import observe as volume_visibility


def _url_credentials_present(parts: urllib.parse.SplitResult) -> bool:
    """Reject either credential field, checking username before password."""
    return parts.username is not None or parts.password is not None


def https_fixture(value: object) -> str:
    """The baseline outbound probe is HTTPS. Plain HTTP is a separate fixture."""
    if not isinstance(value, str):
        raise NotRun("proof_fixture_invalid")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise NotRun("proof_fixture_invalid")
    try:
        parts = urllib.parse.urlsplit(value)
        invalid_port = parts.port is not None and not 1 <= parts.port <= 65535
    except ValueError:
        raise NotRun("proof_fixture_invalid") from None
    if (
        parts.scheme != "https"
        or not parts.hostname
        or any(character.isspace() for character in parts.netloc)
        or _url_credentials_present(parts)
        or invalid_port
    ):
        raise NotRun("proof_fixture_invalid")
    return value


def resolve(value: Any, bindings: Mapping[str, object], fixtures: Mapping[str, object]) -> Any:
    if isinstance(value, str) and value.startswith("$"):
        name, _, field = value[1:].partition(".")
        if name == "runner":
            if field not in fixtures:
                raise NotRun("fixture_missing")
            found = fixtures[field]
            if field == "reachable_url":
                return https_fixture(found)
            return found
        bound = bindings[name]
        if not field:
            return bound
        if not isinstance(bound, Mapping) or field not in bound:
            raise NotRun("observation_unmapped")
        return bound[field]
    if isinstance(value, dict):
        expanded: dict[str, Any] = {}
        if "<<" in value:
            base = resolve(value["<<"], bindings, fixtures)
            if not isinstance(base, Mapping):
                raise NotRun("proof_fixture_invalid")
            expanded.update(base)
        expanded.update({k: resolve(v, bindings, fixtures) for k, v in value.items() if k != "<<"})
        return expanded
    if isinstance(value, list):
        return [resolve(v, bindings, fixtures) for v in value]
    return value


def validate_runner_fixtures(value: Any, fixtures: Mapping[str, object]) -> None:
    """Resolve runner fixtures before a scenario can allocate provider resources."""
    if isinstance(value, str) and value.startswith("$runner."):
        resolve(value, {}, fixtures)
    elif isinstance(value, dict):
        for nested in value.values():
            validate_runner_fixtures(nested, fixtures)
    elif isinstance(value, list):
        for nested in value:
            validate_runner_fixtures(nested, fixtures)


def matches(actual: object, expected: object) -> bool:
    if isinstance(expected, dict) and len(expected) == 1:
        kind, wanted = next(iter(expected.items()))
        if kind in {"utf8", "b64", "utf8_contains", "utf8_absent"}:
            data = actual.encode() if isinstance(actual, str) else actual
            if not isinstance(data, (bytes, bytearray, memoryview)):
                return False
            data = bytes(data)
            payload = base64.b64decode(wanted) if kind == "b64" else wanted.encode()
            if kind == "utf8_contains":
                return payload in data
            if kind == "utf8_absent":
                return payload not in data
            return data == payload
        if kind == "one_of":
            return actual in wanted
    return actual == expected


def bounded(value: object) -> object:
    """Controlled assertion fields only: bounded text/bytes, never native handles."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        payload = bytes(value)
        return {"b64": base64.b64encode(payload[:768]).decode(), "truncated": len(payload) > 768}
    if isinstance(value, str):
        return {"utf8": value[:1024], "truncated": len(value) > 1024}
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    if (
        isinstance(value, list)
        and len(value) <= 20
        and all(isinstance(v, str) and len(v) <= 255 for v in value)
    ):
        return value
    return {"unrecorded": True}


def asserted(result: Mapping[str, object], expected: Mapping[str, Any]) -> dict[str, object]:
    """Return only fields explicitly asserted; no handles, URLs, tokens or native errors."""
    observations: dict[str, object] = {}
    for field in expected.get("record", []):
        if field == "ceiling_evidence":
            value = result.get(field)
            if not isinstance(value, str) or len(value) > 16384:
                raise ValueError("ceiling evidence is not bounded text")
            observations[field] = value
            continue
        if field == "fuse_mount_default":
            value = result.get(field)
            if not isinstance(value, Mapping) or default_proof_errors(value):
                raise ValueError("default mount diagnostic observation is invalid")
            observations[field] = dict(value)
            continue
        if field not in {
            "default_user",
            "default_cwd",
            "stdout",
            "stderr",
            "state",
            "exit_code",
            "exists",
            "served",
            "status",
            "retention_seconds",
            "longest_gap_ms",
            "baseline_gap_ms",
            "capture",
            "observed_cpu",
            "observed_memory_mib",
        }:
            raise ValueError("record field is not permitted")
        value = result.get(field)
        if field in {"exists", "served"} and not isinstance(value, bool):
            raise ValueError("record value must be boolean")
        if field in {
            "status",
            "exit_code",
            "retention_seconds",
            "longest_gap_ms",
            "baseline_gap_ms",
            "observed_memory_mib",
        } and (not isinstance(value, int) or isinstance(value, bool)):
            raise ValueError("record value must be an integer")
        if field == "observed_cpu" and (
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not math.isfinite(value)
        ):
            raise ValueError("record value must be a finite number")
        if isinstance(value, (bytes, bytearray, memoryview)):
            value = bytes(value).decode("utf-8")
        primitives = (str, int, float, bool) if field == "observed_cpu" else (str, int, bool)
        if not isinstance(value, primitives) or len(str(value)) > 1024:
            raise ValueError("record value is not a bounded primitive")
        observations[field] = value
    for field, wanted in expected.get("equals", {}).items():
        if field not in result:
            raise NotRun("observation_unmapped")
        actual = result[field]
        # Report a controlled assertion outcome, not arbitrary upstream payloads.
        observations[field] = {"matches": matches(actual, wanted)}
        if field in {
            "stdout",
            "stderr",
            "terminal",
            "data",
            "state",
            "exit_code",
            "exists",
            "names",
            "left_reads_right",
            "right_reads_left",
            "original_after",
            "advancing",
        }:
            controlled = not isinstance(wanted, dict) or any(k in wanted for k in ("utf8", "b64"))
            actual_value = (
                bounded(actual)
                if controlled
                else {
                    "type": type(actual).__name__,
                    "length": len(actual)
                    if isinstance(actual, (str, bytes, bytearray, memoryview))
                    else None,
                }
            )
            observations[field] = {"matches": matches(actual, wanted), "actual": actual_value}
        if not matches(actual, wanted):
            error = Differs(field)
            error.observation = observations
            raise error
    for field, unwanted in expected.get("not_equals", {}).items():
        if field not in result:
            raise NotRun("observation_unmapped")
        if result[field] is None:
            raise NotRun("observation_unmapped")
        observations[field] = {
            "matches": not matches(result[field], unwanted),
            "actual": bounded(result[field])
            if field in {"exit_code", "exists"}
            else {"type": type(result[field]).__name__},
        }
        if matches(result[field], unwanted):
            error = Differs(field)
            error.observation = observations
            raise error
    for field, wanted in expected.get("contains", {}).items():
        values = result.get(field)
        if not isinstance(values, list):
            raise NotRun("observation_unmapped")
        if not any(
            isinstance(v, Mapping) and all(v.get(k) == x for k, x in wanted.items()) for v in values
        ):
            raise Differs(field)
        observations[field] = {"contains": True}
    return observations


def http(inputs: Mapping[str, object]) -> Mapping[str, object]:
    """No redirect: a sign-in page is not a successful authorized preview."""

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args: Any, **kwargs: Any) -> None:
            del args, kwargs

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)
    url = str(inputs["url"])
    if query := strings(inputs, "query"):
        parts = urllib.parse.urlsplit(url)
        encoded = urllib.parse.urlencode(query)
        url = urllib.parse.urlunsplit(
            parts._replace(query=parts.query + "&" + encoded if parts.query else encoded)
        )
    request = urllib.request.Request(url, headers=strings(inputs, "headers"))
    try:
        with opener.open(request, timeout=10) as response:
            return {
                "status": response.status,
                "reachable": True,
                "served": 200 <= response.status < 300,
                "body": response.read(65536),
            }
    except urllib.error.HTTPError as error:
        return {
            "status": error.code,
            "served": False,
            "reachable": True,
            "body": error.read(65536),
        }
    except urllib.error.URLError:
        raise NativeFailure("probe_connection_failed") from None


class Runner:
    """Each test owns and cleans its resources, even after an unsupported step."""

    def __init__(self, driver: Driver, fixtures: Mapping[str, object] | None = None) -> None:
        self.driver = driver
        self.fixtures = {**(fixtures or {}), "run_nonce": uuid4().hex}

    def _idle_budget(self, test: Test) -> int | None:
        """An idle observation must finish before either unrelated deadline."""
        if not any(
            isinstance(step.get("in", {}), Mapping)
            and step.get("in", {}).get("lifetime_seconds") == "$runner.idle_lifetime_seconds"
            for step in test.steps
        ):
            return None
        delays = [
            resolve(step["wait_ms"], {}, self.fixtures) for step in test.steps if "wait_ms" in step
        ]
        lifetime = resolve("$runner.idle_lifetime_seconds", {}, self.fixtures)
        process = (
            resolve("$runner.idle_process_timeout_ms", {}, self.fixtures)
            if any(step.get("op") == "process.start" for step in test.steps)
            else lifetime * 1000
            if isinstance(lifetime, int)
            else lifetime
        )
        if any(
            not isinstance(v, int) or isinstance(v, bool) or v <= 0
            for v in [*delays, lifetime, process]
        ):
            raise NotRun("idle_fixture_window_invalid")
        required = sum(delays) + 30000
        budget = min(lifetime * 1000, process)
        if budget <= required:
            raise NotRun("idle_fixture_window_invalid")
        return cast(int, budget)

    def _secret_receiver(
        self,
        value: str,
        replacement: str | None = None,
        header: str = "X-SPS-Secret",
        expected_value: str | None = None,
    ) -> Mapping[str, object]:
        """An owned guest fixture observes native injection, never supplies it."""
        nonce, observer = self.fixtures["run_nonce"], uuid4().hex
        receiver = self.driver.call(
            "create",
            None,
            {
                "lifetime_seconds": 300,
                "requirements": {"previews": {"access": "public", "ports": [7777]}},
            },
        )
        files = {
            "/tmp/sps-receiver.py": (
                suite_path().parent / "fixtures/secret_receiver.py"
            ).read_bytes(),
            "/tmp/sps-receiver-config": json.dumps(
                {
                    "nonce": nonce,
                    "observer": observer,
                    "value": value,
                    "values": [value] + ([replacement] if replacement else []),
                    "header": header,
                    "expected_value": expected_value or value,
                }
            ).encode(),
        }
        for path, data in files.items():
            self.driver.call(
                "files.write", receiver, {"path": path, "data": base64.b64encode(data).decode()}
            )
        self.driver.call(
            "process.start",
            receiver,
            {"bash_script": "python3 /tmp/sps-receiver.py", "timeout_ms": 270000},
        )
        deadline = time.monotonic() + 30
        while not self.driver.call(
            "files.exists", receiver, {"path": "/tmp/sps-receiver-ready"}
        ).get("exists"):
            if time.monotonic() >= deadline:
                raise NativeFailure("receiver_not_ready")
            time.sleep(0.2)
        link = self.driver.call("preview.link", receiver, {"port": 7777, "access": "public"})
        url = str(link["url"]).rstrip("/")
        host = urllib.parse.urlsplit(url).hostname
        if not host:
            raise NativeFailure("receiver_link_invalid")
        return {
            "hosts": [host],
            "health_url": url + "/health/" + str(nonce),
            "url": url + "/inject/" + str(nonce),
            "receipt_url": url + "/receipt/" + str(nonce),
            "coverage_url": url + "/inject/" + str(nonce) + "?sps_run=" + str(nonce),
            "observations_url": url + "/observations/" + str(nonce),
            "echo_url": url + "/echo/" + str(nonce) + "?sps_run=" + str(nonce),
            "observer_headers": {"X-SPS-Observer": observer},
        }

    def _test_operation(
        self, operation: str, target: object, inputs: Mapping[str, Any]
    ) -> Mapping[str, object]:
        """Repeated native test actions; no lifecycle or capability emulation."""
        if operation == "fixture.process_eof":
            return process_eof.observe(self.driver, target, inputs)
        if operation == "fixture.coverage_docker_create":
            return coverage_docker.create(self.driver, inputs)
        if operation == "fixture.coverage_docker":
            return coverage_docker.observe(self.driver, target, inputs)
        if operation == "fixture.coverage_desktop":
            return coverage_desktop.observe(self.driver, target)
        if operation == "probe.desktop_browser":
            return coverage_desktop.browser(inputs)
        if operation == "fixture.coverage_denylist":
            return coverage_network.denylist(self.driver, target, inputs)
        if operation == "fixture.coverage_network_checks":
            return coverage_network.network_checks(self.driver, target, inputs)
        if operation == "fixture.coverage_kernel_feature":
            return coverage_v6.kernel_feature(self.driver, target, inputs)
        if operation == "fixture.coverage_outbound_traffic":
            return coverage_v6.outbound_traffic(self.driver, target, inputs)
        if operation == "fixture.coverage_private_network":
            return coverage_v6.private_network(self.driver, inputs)
        if operation == "fixture.coverage_allowlist":
            return coverage_v2.allowlist(self.driver, target, inputs)
        if operation == "fixture.coverage_deny_wins":
            return coverage_v2.deny_wins(self.driver, target, inputs)
        if operation == "fixture.coverage_http_rules":
            return coverage_v2.http_rules(self.driver, target, inputs)
        if operation == "fixture.coverage_http_rule_deny":
            return coverage_v2.http_rule_deny(self.driver, target, inputs)
        if operation == "fixture.coverage_harness_health":
            return coverage_v2.harness_health(self.driver, target, inputs)
        if operation == "fixture.coverage_domain_traffic":
            return coverage_v2.domain_traffic(self.driver, target, inputs)
        if operation == "fixture.coverage_policy_change":
            return coverage_network.policy_change(self.driver, target, inputs)
        if operation == "fixture.coverage_open_connection":
            return coverage_v3.open_connection(self.driver, target, inputs)
        if operation == "fixture.coverage_connection_update":
            return coverage_v3.connection_update(self.driver, target, inputs)
        if operation == "fixture.coverage_connection_closed":
            return coverage_v3.connection_closed(self.driver, target, inputs)
        if operation == "fixture.coverage_reserved_ports":
            return coverage_ports.observe(self.driver, inputs)
        if operation == "fixture.coverage_secret":
            return coverage_secrets.observe(self.driver, inputs, self._secret_receiver)
        if operation == "fixture.coverage_identity_token":
            return coverage_v5.identity_token(self.driver, inputs, self.fixtures)
        if operation == "fixture.coverage_egress_proxy":
            return coverage_v5.egress_proxy(self.driver, inputs, self.fixtures)
        if operation == "fixture.coverage_secret_header":
            return coverage_v4.secret_header(self.driver, inputs, str(self.fixtures["run_nonce"]))
        if operation == "fixture.coverage_secret_body":
            return coverage_v4.secret_body(self.driver, inputs, str(self.fixtures["run_nonce"]))
        if operation == "fixture.coverage_secret_hosts":
            return coverage_v4.secret_hosts(
                self.driver, target, inputs, str(self.fixtures["run_nonce"])
            )
        if operation == "fixture.coverage_secret_wildcard":
            return coverage_v4.secret_wildcard(
                self.driver, target, inputs, str(self.fixtures["run_nonce"])
            )
        if operation == "fixture.coverage_active_lifetime":
            return coverage_lifecycle.active_lifetime(self.driver, target, inputs)
        if operation == "probe.websocket":
            return protocol_probe.websocket(inputs)
        if operation == "probe.tcp":
            return protocol_probe.tcp(inputs)
        if operation == "probe.ssh":
            return coverage_ssh.observe(self.driver, inputs)
        if operation == "fixture.coverage_server":
            return coverage_probe.server(self.driver, target, inputs)
        if operation == "fixture.coverage_fact":
            return coverage_probe.guest(self.driver, target, inputs)
        if operation == "native.operation_absent":
            name = str(inputs["operation"])
            if name in self.driver.unsupported:
                return {"absent": True}
            if callable(getattr(self.driver, name.replace(".", "_"), None)):
                return {"absent": False}
            raise NotRun("operation_unmapped")
        if operation == "fixture.process_state":
            process_code = (suite_path().parent / "fixtures/process_state.py").read_text()
            result = self.driver.call(
                "run",
                target,
                {
                    "bash_script": "python3 -c " + shlex.quote(process_code),
                    "environment": {"SPS_EXPECTED_PROCESS": json.dumps(inputs.get("identity"))},
                },
            )
            if result.get("exit_code") != 0:
                raise NativeFailure("controlled_process_observation_failed")
            observation = json.loads(cast(str | bytes, result["stdout"]))
            if not isinstance(observation, dict) or not isinstance(
                observation.get("stopped"), bool
            ):
                raise NativeFailure("controlled_process_observation_invalid")
            return cast(Mapping[str, object], observation)
        if operation == "environment.observe":
            fact = inputs["fact"]
            if fact not in {"default_user", "default_cwd"}:
                raise ValueError("unknown default environment fact")
            result = self.driver.call(
                "run", target, {"bash_script": "id -un" if fact == "default_user" else "pwd"}
            )
            if result.get("exit_code") != 0:
                raise NativeFailure("default_environment_command_failed")
            observed = result.get("stdout")
            if isinstance(observed, bytes):
                observed = observed.decode("utf-8")
            if not isinstance(observed, str):
                raise NotRun("observation_unmapped")
            observed = observed.removesuffix("\n")
            if (
                not observed
                or len(observed) > 1024
                or any(unicodedata.category(char).startswith("C") for char in observed)
                or (fact == "default_cwd" and not observed.startswith("/"))
            ):
                raise NativeFailure("default_environment_observation_invalid")
            return {str(fact): observed}
        if operation == "clock.start":
            return {"started": time.monotonic()}
        if operation == "clock.observe":
            return {
                "within_window": (time.monotonic() - inputs["started"]) * 1000 < inputs["limit_ms"]
            }
        if operation == "fixture.root_attack":
            code = (suite_path().parent / "fixtures/root_attack.py").read_bytes()
            self.driver.call(
                "files.write",
                target,
                {"path": "/tmp/sps-root-attack.py", "data": base64.b64encode(code).decode()},
            )
            result = self.driver.call(
                "run",
                target,
                {
                    "bash_script": 'if [ "$(id -u)" = 0 ]; then '
                    "python3 /tmp/sps-root-attack.py; else "
                    "sudo -n true 2>/dev/null || exit 77; "
                    "sudo -n python3 /tmp/sps-root-attack.py; fi",
                    "timeout_ms": 30000,
                },
            )
            if result.get("exit_code") == 77:
                raise NotRun("account_guest_root_unavailable")
            return result
        if operation == "fixture.secret_receiver":
            return self._secret_receiver(
                str(inputs["value"]),
                header=str(inputs.get("header", "X-SPS-Secret")),
                expected_value=str(inputs["expected_value"])
                if "expected_value" in inputs
                else None,
            )
        if operation == "fixture.volume_visibility":
            return volume_visibility(self.driver, inputs)
        if operation == "fixture.snapshot_ticker_start":
            return snapshot_ticker.start(self.driver, target)
        if operation == "fixture.snapshot_ticker_observe":
            return snapshot_ticker.observe(self.driver, target, inputs["ticker"])
        if operation == "volume.create_many":
            mounts = []
            for index in range(inputs["count"]):
                volume = self.driver.call("volume.create", None, {"kind": inputs["kind"]})
                resource(volume)
                mounts.append({"volume": volume, "path": f"/sps-mount-{index}"})
            return {"mounts": mounts}
        if operation == "volume.observe_mounts":
            observed_mounts = cast(list[Mapping[str, Any]], inputs["mounts"])
            for index, mount in enumerate(observed_mounts):
                self.driver.call(
                    "files.write",
                    target,
                    {
                        "path": mount["path"] + "/sps-proof",
                        "data": base64.b64encode(f"sps-mounted-{index}".encode()).decode(),
                    },
                )
            self.driver.call("destroy", target, {})
            again = self.driver.call(
                "create",
                None,
                {
                    "volumes": observed_mounts,
                    "requirements": {"volumes": {"kind": self.fixtures["volume_kind"]}},
                },
            )
            for index, mount in enumerate(observed_mounts):
                data = self.driver.call(
                    "files.read_bytes", again, {"path": mount["path"] + "/sps-proof"}
                )
                if data.get("data") != f"sps-mounted-{index}".encode():
                    return {"all_writable": False}
            return {"all_writable": True}
        if operation == "run.each_url":
            for url in inputs["urls"]:
                result = self.driver.call(
                    "run",
                    target,
                    {
                        "bash_script": inputs["bash_script"],
                        "timeout_ms": inputs["timeout_ms"],
                        "environment": {"TARGET": url},
                    },
                )
                if result.get("exit_code") != 0:
                    return result
            return {"exit_code": 0}
        return self.driver.call(operation, target, inputs)

    def _step(self, step: dict[str, Any], bindings: dict[str, object]) -> dict[str, object]:
        operation = step["op"]
        inputs = resolve(step.get("in", {}), bindings, self.fixtures)
        target = bindings.get(step.get("target", ""))
        expected = resolve(step.get("expect", {}), bindings, self.fixtures)
        deadline = time.monotonic() + expected.get("eventually_ms", 0) / 1000
        while True:
            try:
                result = (
                    {"equal": inputs["left"] == inputs["right"]}
                    if operation == "bindings.compare"
                    else http(inputs)
                    if operation == "probe.http"
                    else self._test_operation(operation, target, inputs)
                )
                if name := step.get("as"):
                    bindings[name] = result
                if expected.get("unsupported"):
                    raise Differs("expected_unsupported")
                if expected.get("error"):
                    raise Differs("expected_error")
                if skip := expected.get("not_run_if"):
                    if all(k in result and matches(result[k], v) for k, v in skip.items()):
                        raise NotRun("guest_fixture_unavailable")
                observation = asserted(result, expected)
                return {"operation": operation, "result": "passed", "observations": observation}
            except Unsupported:
                if expected.get("unsupported") is True:
                    return {"operation": operation, "result": "passed", "native_absence": True}
                raise
            except NativeFailure as error:
                if expected.get("error") in {True, error.code}:
                    return {"operation": operation, "result": "passed", "native_code": error.code}
                raise
            except Differs as error:
                error.observation = {
                    "operation": operation,
                    "result": "differs",
                    "observations": error.observation or {str(error): {"matches": False}},
                }
                if time.monotonic() >= deadline:
                    raise
                time.sleep(min(0.2, max(0, deadline - time.monotonic())))

    def _case(
        self, test: Test, capacity: int | None = None
    ) -> Generator[float, None, dict[str, object]]:
        start = time.monotonic()
        owned_resources = []
        outcome: dict[str, object] = {
            "id": test.id,
            "result": "passed",
            "steps": [],
            "rules": list(test.rules),
            "proves": [],
        }
        steps: list[dict[str, object]] = []
        bindings: dict[str, object] = {}
        operation = "prepare"
        try:
            self.fixtures.update(proof_fixtures(test, self.fixtures))
            for step in test.steps:
                operation = step.get("op", "wait")
                validate_runner_fixtures(step, self.fixtures)
            outcome["proves"] = proof_targets(test, self.fixtures)
            for step in test.steps:
                operation = step.get("op", "wait")
                if operation in self.driver.unsupported and not step.get("expect", {}).get(
                    "unsupported"
                ):
                    raise Unsupported(self.driver.unsupported[operation])
            operation = "prepare"
            idle_budget = self._idle_budget(test)
            for step in test.steps:
                if (
                    idle_budget is not None
                    and (time.monotonic() - start) * 1000 + 10000 >= idle_budget
                ):
                    raise NotRun("idle_observation_deadline_near")
                operation = step.get("op", "wait")
                if (
                    capacity is not None
                    and operation == "create"
                    and sum(
                        not owned.released and owned.kind == "sandbox"
                        for owned in self.driver.resources
                    )
                    >= capacity
                ):
                    raise NotRun("runner_sandbox_capacity_unavailable")
                if "wait_ms" in step:
                    delay = resolve(step["wait_ms"], bindings, self.fixtures)
                    if not isinstance(delay, int) or isinstance(delay, bool) or delay < 0:
                        raise ValueError("wait_ms must be a nonnegative integer")
                    yield time.monotonic() + delay / 1000
                    steps.append({"operation": "wait", "result": "passed"})
                else:
                    offset = len(self.driver.resources)
                    try:
                        steps.append(self._step(step, bindings))
                    finally:
                        owned_resources.extend(self.driver.resources[offset:])
            environment = bindings.get("environment", {})
            outcome["proves"] = proof_targets(
                test, self.fixtures, environment if isinstance(environment, Mapping) else {}
            )
        except Unsupported as error:
            steps.append({"operation": operation, "result": "unsupported", "reason": str(error)})
            outcome.update(result="unsupported", reason=str(error))
        except NotRun as error:
            step = {"operation": operation, "result": "not_run", "reason": str(error)}
            if error.detail is not None:
                step["detail"] = error.detail
            steps.append(step)
            outcome.update(result="not_run", reason=str(error))
        except NativeFailure as error:
            steps.append({"operation": operation, "result": "error", "reason": error.code})
            outcome.update(result="error", reason=error.code)
        except Differs as error:
            steps.append(error.observation)
            outcome.update(result="differs", reason=str(error))
        except Exception as error:  # pylint: disable=broad-exception-caught
            steps.append(
                {"operation": operation, "result": "error", "reason": type(error).__name__}
            )
            outcome.update(result="error", reason=type(error).__name__)
        finally:
            cleanup: list[dict[str, object]] = []
            for owned in reversed(owned_resources):
                try:
                    self.driver.settle_create(owned)
                    cleanup.append(dict(self.driver.release(owned)))
                except Exception as error:  # pylint: disable=broad-exception-caught
                    cleanup.append(
                        {"kind": owned.kind, "result": "error", "reason": type(error).__name__}
                    )
            finished = time.monotonic()
            outcome.update(
                cleanup=cleanup,
                steps=steps,
                duration_ms=round((finished - start) * 1000),
                _started=start,
                _finished=finished,
            )
        return outcome

    def _schedule(self, tests: list[Test]) -> list[dict[str, object]]:
        limit = self.fixtures.get("max_live_sandboxes", 1)
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
            raise ValueError("max_live_sandboxes must be a positive integer")
        results: dict[int, dict[str, object]] = {}
        pending: dict[int, tuple[Generator[float, None, dict[str, object]], float]] = {}

        def advance(index: int, case: Generator[float, None, dict[str, object]]) -> None:
            try:
                pending[index] = (case, next(case))
            except StopIteration as done:
                results[index] = done.value
                pending.pop(index, None)

        def start(index: int, capacity: int | None = None) -> None:
            failed = next(
                (
                    row
                    for row in results.values()
                    if row["id"] == tests[index].id and row["result"] != "passed"
                ),
                None,
            )
            if failed is not None:
                results[index] = {**failed, "steps": [], "cleanup": [], "duration_ms": 0}
                return
            runner = copy.copy(self)
            runner.fixtures = self.fixtures.copy()
            advance(index, runner._case(tests[index], capacity))  # pylint: disable=protected-access

        def resume() -> None:
            index = min(pending, key=lambda index: pending[index][1])
            case, deadline = pending[index]
            time.sleep(max(0, deadline - time.monotonic()))
            advance(index, case)

        # Only these explicit single-sandbox programs may overlap. Fixture operations
        # can allocate additional resources internally and stay serial.
        overlap_operations = {
            "create",
            "get",
            "destroy",
            "run",
            "pause",
            "resume",
            "lifetime.extend",
            "lifetime.observe_paused_countdown",
        }
        timed, serial = [], []
        for index, test in enumerate(tests):
            operations = [step["op"] for step in test.steps if "op" in step]
            if (
                not any(
                    step.get("op") in self.driver.unsupported
                    and not step.get("expect", {}).get("unsupported")
                    for step in test.steps
                )
                and any("wait_ms" in step for step in test.steps)
                and operations.count("create") == 1
                and set(operations) <= overlap_operations
            ):
                timed.append(index)
            elif any("wait_ms" in step for step in test.steps) and not any(
                step.get("op") in self.driver.unsupported for step in test.steps
            ):
                serial.append(index)
            else:
                start(index)
                while pending:
                    resume()
        for index in serial:
            start(index)
            while pending:
                resume()
        for index in timed:
            while (
                pending
                and sum(
                    not resource.released and resource.kind == "sandbox"
                    for resource in self.driver.resources
                )
                >= limit
            ):
                resume()
            start(index, limit)
        while pending:
            resume()
        return [results[index] for index in range(len(tests))]

    def run_test(self, test: Test) -> dict[str, object]:
        return self.run(Suite("", (test,)))[0]

    def run(self, suite: Suite) -> list[dict[str, object]]:
        cases: list[Test] = []
        groups: list[list[int]] = []
        for test in suite.tests:
            lanes = {step.get("lane") for step in test.steps}
            unsupported = any(
                step.get("op") in self.driver.unsupported
                and not step.get("expect", {}).get("unsupported")
                for step in test.steps
            )
            if not lanes or lanes == {None} or unsupported:
                branches = [test]
            else:
                if None in lanes or any(not isinstance(lane, str) or not lane for lane in lanes):
                    raise ValueError("every step of a lane check must name its lane")
                branches = [
                    replace(test, steps=tuple(step for step in test.steps if step["lane"] == lane))
                    for lane in dict.fromkeys(step["lane"] for step in test.steps)
                ]
            groups.append(list(range(len(cases), len(cases) + len(branches))))
            cases.extend(branches)
        rows = self._schedule(cases)
        outcomes = []
        for group in groups:
            completed = [rows[index] for index in group]
            outcome = next(
                (row.copy() for row in completed if row["result"] != "passed"), completed[0].copy()
            )
            for field in ("steps", "cleanup"):
                outcome[field] = [
                    item for row in completed for item in cast(list[object], row[field])
                ]
            outcome["duration_ms"] = round(
                (
                    max(cast(float, row["_finished"]) for row in completed)
                    - min(cast(float, row["_started"]) for row in completed)
                )
                * 1000
            )
            outcome.pop("_started")
            outcome.pop("_finished")
            outcomes.append(outcome)
        return outcomes


def now() -> str:
    return datetime.now(UTC).isoformat()
