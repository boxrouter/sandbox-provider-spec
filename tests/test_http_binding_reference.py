# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Second-side HTTP proof with an explicitly non-executing test backend."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, cast

import httpx
import pytest

from sandbox_provider_spec import http_binding_validation as CONTRACT
from sandbox_provider_spec.check import check_declaration
from sandbox_provider_spec.http_reference import Endpoint, EndpointSettings, Failure
from sandbox_provider_spec.http_reference.test_backend import TestBackend as ScriptedBackend

NOW = 1792692000


class LostReplyTransport(httpx.BaseTransport):
    """Deliver a request, then inject a read failure after the endpoint committed it."""

    def __init__(self, endpoint: Any) -> None:
        self.inner = httpx.WSGITransport(app=endpoint)
        self.server_reply: dict[str, Any] | None = None

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        reply = self.inner.handle_request(request)
        reply.read()
        self.server_reply = reply.json()
        reply.close()
        raise httpx.ReadError("Injected loss after server dispatch", request=request)

    def close(self) -> None:
        self.inner.close()


class Harness:
    """In-process HTTP only. Validates replies using the separately owned PP1 oracle."""

    def __init__(self, tmp_path: Path, backend: Any = None) -> None:
        self.backend: Any = backend or ScriptedBackend()
        self.database = tmp_path / "allocations.sqlite3"
        self.now = NOW
        self.origin = "https://reference.invalid"
        self.tokens = {"test-token-a": "account-a", "test-token-b": "account-b"}
        self.endpoint = Endpoint(
            self.backend,
            self.database,
            self.tokens,
            settings=EndpointSettings(self.origin, clock=lambda: self.now),
        )
        self.client = httpx.Client(
            transport=httpx.WSGITransport(app=self.endpoint), base_url="https://reference.invalid"
        )
        self.counter = 0

    def restart(self) -> None:
        self.client.close()
        self.endpoint.close()
        self.endpoint = Endpoint(
            self.backend,
            self.database,
            self.tokens,
            settings=EndpointSettings(self.origin, clock=lambda: self.now),
        )
        self.client = httpx.Client(
            transport=httpx.WSGITransport(app=self.endpoint), base_url="https://reference.invalid"
        )

    def request(self, operation: str, **values: Any) -> dict[str, Any]:
        self.counter += 1
        return {
            "operation": operation,
            "request_id": f"request-{self.counter}",
            "account_id": "account-a",
            **values,
        }

    def create_request(self, **values: Any) -> dict[str, Any]:
        return self.request(
            "create",
            allocation_key=f"{NOW}:{self.counter:032x}",
            offering_id="container",
            declaration_id=self.endpoint.discovery("account-a")["offerings"][0]["declaration_id"],
            request={},
            env={},
            **values,
        )

    def send(
        self,
        request: dict[str, Any],
        *,
        status: int = 200,
        token: str = "test-token-a",
        raw: bytes | None = None,
        validate: bool = True,
    ) -> dict[str, Any]:
        body = raw if raw is not None else CONTRACT.body_bytes(request)
        digest = "sha256:" + hashlib.sha256(body).hexdigest()
        response = self.client.post(
            "/sps/v1/" + request["operation"],
            content=body,
            headers={
                "Authorization": "Bearer " + token,
                "Content-Type": "application/json",
                "SPS-Request-Digest": digest,
            },
        )
        assert response.status_code == status, response.text
        result = response.json()
        if validate:
            CONTRACT.validate_exchange(
                request,
                result,
                self.endpoint.discovery(request["account_id"]),
                status=status,
                request_body=body,
                digest=digest,
            )
        return cast(dict[str, Any], result)

    def create(self) -> dict[str, Any]:
        return cast(dict[str, Any], self.send(self.create_request())["sandbox"])

    def start(
        self, sandbox: dict[str, Any], *, observation_timeout_ms: int = 100
    ) -> dict[str, Any]:
        result = self.send(
            self.request(
                "process.start",
                sandbox=sandbox,
                argv=["fixed-test"],
                cwd=None,
                env={},
                observation_timeout_ms=observation_timeout_ms,
            )
        )["process"]
        return cast(dict[str, Any], result)

    def output_request(self, process: dict[str, Any], **values: Any) -> dict[str, Any]:
        return self.request(
            "process.output",
            process=process,
            **{
                "cursor": 0,
                "max_frames": 10,
                "limit_bytes": 65536,
                "observation_timeout_ms": 100,
                **values,
            },
        )


@pytest.fixture
def harness(tmp_path: Path) -> Any:
    value = Harness(tmp_path)
    yield value
    value.client.close()
    value.endpoint.close()


def test_discovery_and_all_nine_operations(harness: Harness) -> None:
    discovery = harness.client.get(
        "/.well-known/sandbox-provider-spec.json", headers={"Authorization": "Bearer test-token-a"}
    ).json()
    CONTRACT.validate_discovery(discovery)
    assert discovery["endpoint_origin"] == harness.origin
    assert discovery["account_id"] == "account-a"
    other_account = harness.endpoint.discovery("account-b")
    assert other_account["endpoint_origin"] == harness.origin
    assert other_account["account_id"] == "account-b"
    assert discovery["core_modes"] == []
    assert discovery["offerings"][0]["declaration"]["gates"] == {}
    sandbox = harness.create()
    assert harness.send(harness.request("get", sandbox=sandbox))["state"] == "active"
    listed = harness.send(harness.request("list", offering_id=None, cursor=None, page_size=1))
    assert listed["items"] == [{"sandbox": sandbox, "state": "active"}]
    run = harness.send(
        harness.request(
            "run",
            sandbox=sandbox,
            argv=["fixed-test", "hello\n"],
            cwd="/tmp",
            env={},
            observation_timeout_ms=100,
            encoding="utf8",
        )
    )
    assert (run["stdout"], run["stderr"], run["exit_code"]) == (
        "hello\n",
        "scripted diagnostic\n",
        7,
    )
    data = bytes(range(256)) + b"\x00\xff\r\n"
    write = harness.request(
        "files.write",
        sandbox=sandbox,
        path="/tmp/input",
        data_base64=base64.b64encode(data).decode(),
        byte_count=len(data),
    )
    assert harness.send(write)["written_bytes"] == len(data)
    read = harness.send(
        harness.request("files.read_bytes", sandbox=sandbox, path="/tmp/input", limit_bytes=65536)
    )
    assert base64.b64decode(read["data_base64"]) == data
    process = harness.start(sandbox)
    output = harness.send(harness.output_request(process))
    assert output["frames"][0]["text"] == "ready\n"
    assert output["execution_state"] == "running" and output["exit_code"] is None
    assert harness.send(harness.request("destroy", sandbox=sandbox))["state"] == "destroyed"
    assert harness.send(harness.request("get", sandbox=sandbox))["state"] == "absent"


@pytest.mark.parametrize("origin", ["http://127.0.0.1", "https://host/path", "https://host:70000"])
def test_endpoint_rejects_invalid_configured_origin(tmp_path: Path, origin: str) -> None:
    with pytest.raises(ValueError):
        Endpoint(
            ScriptedBackend(),
            tmp_path / "invalid-origin.sqlite3",
            {},
            settings=EndpointSettings(origin),
        )


def test_lost_create_reply_restart_exact_retry_conflict_and_expiry(harness: Harness) -> None:
    request = harness.create_request()
    transport = LostReplyTransport(harness.endpoint)
    raw = CONTRACT.body_bytes(request)
    with httpx.Client(transport=transport, base_url="https://reference.invalid") as client:
        with pytest.raises(httpx.ReadError, match="Injected loss after server dispatch"):
            client.post(
                "/sps/v1/create",
                content=raw,
                headers={
                    "Authorization": "Bearer test-token-a",
                    "Content-Type": "application/json",
                    "SPS-Request-Digest": CONTRACT.request_digest(raw),
                },
            )
    harness.restart()
    assert harness.send(request) == transport.server_reply
    assert harness.backend.calls["create"] == 1
    changed = {**request, "env": {"CHANGED": "yes"}}
    assert harness.send(changed, status=409)["error"]["code"] == "conflict"
    # Even whitespace changes the digest. The retry must use saved exact bytes.
    assert (
        harness.send(request, raw=json.dumps(request, indent=2).encode(), status=409)["error"][
            "code"
        ]
        == "conflict"
    )
    harness.now = NOW + 86400
    assert harness.send(request, status=410)["error"]["code"] == "expired_key"
    with harness.endpoint.connect() as db:
        assert db.execute("SELECT count(*) FROM allocations").fetchone()[0] == 1
    harness.now = NOW
    harness.restart()
    assert harness.send(request, status=410)["error"]["code"] == "expired_key"
    assert harness.backend.calls["create"] == 1


@pytest.mark.parametrize(
    ("code", "outcome", "status"),
    [
        ("forbidden", "not_dispatched", 403),
        ("provider_error", "failed", 502),
        ("provider_error", "completed", 502),
    ],
)
def test_definitive_create_refusal_is_retained_across_restart(
    harness: Harness, monkeypatch: pytest.MonkeyPatch, code: str, outcome: str, status: int
) -> None:
    request = harness.create_request()

    def refused(identity: dict[str, Any], env: dict[str, str]) -> None:
        del identity, env
        harness.backend.calls["create"] += 1
        raise Failure(code, outcome)

    monkeypatch.setattr(harness.backend, "create", refused)
    first = harness.send(request, status=status)
    assert first["error"] == {
        "code": code,
        "outcome": outcome,
        "message": "Reference operation could not satisfy the requested contract",
        "exit_code": None,
    }
    assert harness.backend.calls["create"] == 1

    harness.restart()
    assert (
        harness.send(request, status=401, token="invalid-token", validate=False)["error"]["code"]
        == "unauthenticated"
    )
    replay = harness.send(request, status=status)
    assert replay == first
    assert harness.backend.calls["create"] == 1

    changed = {**request, "env": {"CHANGED": "yes"}}
    assert harness.send(changed, status=409)["error"]["code"] == "conflict"
    assert harness.backend.calls["create"] == 1


def test_late_definitive_create_failure_replay_survives_restart(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = harness.create_request()
    harness.endpoint.settings.operation_timeout_ms = 500
    entered, release, settled = threading.Event(), threading.Event(), threading.Event()

    def refused(identity: dict[str, Any], env: dict[str, str]) -> None:
        del identity, env
        harness.backend.calls["create"] += 1
        entered.set()
        try:
            assert release.wait(3)
            raise Failure("forbidden", "not_dispatched")
        finally:
            settled.set()

    monkeypatch.setattr(harness.backend, "create", refused)
    with ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(harness.send, request, status=504)
        assert entered.wait(1), "create must enter the fake backend before observer timeout"
        initial = first.result(timeout=2)
        assert initial["error"]["code"] == "timeout"
        assert initial["error"]["outcome"] == "unknown"

        release.set()
        assert settled.wait(1), "fake backend must settle before replay"
        with harness.endpoint._runtime.observations:
            assert harness.endpoint._runtime.observations.wait_for(
                lambda: harness.endpoint._runtime.pending == 0, 1
            )

    harness.restart()
    replay = harness.send(request, status=403)
    assert replay["operation"] == "create"
    assert replay["request_id"] == initial["request_id"]
    assert replay["account_id"] == initial["account_id"]
    assert replay["error"]["code"] == "forbidden"
    assert replay["error"]["outcome"] == "not_dispatched"
    assert harness.backend.calls["create"] == 1


def test_late_unknown_create_failure_stays_unknown_after_restart(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = harness.create_request()
    harness.endpoint.settings.operation_timeout_ms = 500
    entered, release, settled = threading.Event(), threading.Event(), threading.Event()

    def uncertain(identity: dict[str, Any], env: dict[str, str]) -> None:
        del identity, env
        harness.backend.calls["create"] += 1
        entered.set()
        try:
            assert release.wait(3)
            raise OSError("native outcome remains uncertain")
        finally:
            settled.set()

    monkeypatch.setattr(harness.backend, "create", uncertain)
    with ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(harness.send, request, status=504)
        assert entered.wait(1), "create must enter the fake backend before observer timeout"
        initial = first.result(timeout=2)
        assert initial["error"]["code"] == "timeout"
        assert initial["error"]["outcome"] == "unknown"

        release.set()
        assert settled.wait(1), "fake backend must settle before replay"
        with harness.endpoint._runtime.observations:
            assert harness.endpoint._runtime.observations.wait_for(
                lambda: harness.endpoint._runtime.pending == 0, 1
            )

    harness.restart()
    replay = harness.send(request)
    assert replay["state"] == "unknown" and replay["sandbox"] is None
    assert harness.backend.calls["create"] == 1


def test_concurrent_create_reservation_survives_uncertain_dispatch(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = harness.create_request()
    raw = CONTRACT.body_bytes(request)
    digest = CONTRACT.request_digest(raw)
    entered, release = threading.Event(), threading.Event()
    original = harness.backend.create

    def blocked(identity: dict[str, Any], env: dict[str, str]) -> None:
        entered.set()
        assert release.wait(5)
        original(identity, env)

    monkeypatch.setattr(harness.backend, "create", blocked)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(
            harness.endpoint.handle,
            "POST",
            "/sps/v1/create",
            "Bearer test-token-a",
            raw,
            headers={"digest": digest},
        )
        try:
            assert entered.wait(5)
            replay = harness.send(request)
            assert replay["state"] == "unknown" and replay["sandbox"] is None
        finally:
            release.set()
        status, body = first.result(timeout=5)
    assert status == 200
    assert harness.send(request)["sandbox"] == json.loads(body)["sandbox"]
    assert harness.backend.calls["create"] == 1


def test_native_create_failure_leaves_durable_unknown_not_a_new_attempt(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = harness.backend.create

    def accepted_then_lost(identity: dict[str, Any], env: dict[str, str]) -> None:
        original(identity, env)
        raise OSError("Response lost after native allocation")

    monkeypatch.setattr(harness.backend, "create", accepted_then_lost)
    request = harness.create_request()
    failure = harness.send(request, status=502)
    assert failure["error"]["outcome"] == "unknown"
    monkeypatch.setattr(harness.backend, "create", original)
    harness.restart()
    assert harness.send(request)["state"] == "unknown"
    assert harness.backend.calls["create"] == 1


def test_replay_after_destroy_preserves_unavailable_identity(harness: Harness) -> None:
    request = harness.create_request()
    identity = harness.send(request)["sandbox"]
    harness.send(harness.request("destroy", sandbox=identity))
    replay = harness.send(request)
    assert replay["state"] == "unavailable" and replay["sandbox"] == identity
    assert harness.backend.calls["create"] == 1


@pytest.mark.parametrize(
    "mutation",
    [
        "unknown_field",
        "wrong_count",
        "noncanonical",
        "unsupported_request",
        "bad_account",
        "bad_incarnation",
    ],
)
def test_reject_before_native_mutation(harness: Harness, mutation: str) -> None:
    sandbox = harness.create()
    request = harness.request(
        "files.write", sandbox=sandbox, path="/tmp/input", data_base64="AA==", byte_count=1
    )
    status = 422
    if mutation == "unknown_field":
        request["atomic"] = True
    elif mutation == "wrong_count":
        request["byte_count"] = 2
    elif mutation == "noncanonical":
        request["data_base64"] = "AB=="
    elif mutation == "unsupported_request":
        request = harness.create_request()
        request["request"] = {"spec": "sandbox-provider-spec/0.1", "resources": {"cpu_min": 2}}
    elif mutation == "bad_account":
        request["account_id"] = "account-b"
        status = 403
    elif mutation == "bad_incarnation":
        request["sandbox"] = {**sandbox, "incarnation": "stale"}
    before = dict(harness.backend.calls)
    result = harness.send(request, status=status, validate=False)
    CONTRACT.validate_message("Error", result)
    assert result["error"]["outcome"] == "not_dispatched"
    assert dict(harness.backend.calls) == before


@pytest.mark.parametrize(
    "body",
    [
        b'{"operation":"run","operation":"create"}',
        b'{"number":NaN}',
        b'{"s":"\\ud800"}',
        b"\xff",
        b"[]",
    ],
)
def test_malformed_json_never_dispatches(harness: Harness, body: bytes) -> None:
    response = harness.client.post(
        "/sps/v1/create",
        content=body,
        headers={"Authorization": "Bearer test-token-a", "Content-Type": "application/json"},
    )
    assert response.status_code in (403, 422)
    CONTRACT.validate_message("Error", response.json())
    assert not harness.backend.calls


def test_unauthenticated_discovery_and_operations_reveal_nothing(harness: Harness) -> None:
    assert harness.client.get("/.well-known/sandbox-provider-spec.json").content == b""
    request = harness.create_request()
    error = harness.send(request, token="wrong", status=401, validate=False)
    assert error["request_id"] is None and error["account_id"] is None
    assert not harness.backend.calls


def test_output_replay_eof_before_exit_gap_and_state_loss(harness: Harness) -> None:
    harness.endpoint.settings.operation_timeout_ms = 10000
    process = harness.start(harness.create(), observation_timeout_ms=10000)
    request = harness.output_request(process)
    first = harness.send(request)
    assert harness.send(request) == first
    harness.backend.finish(process["process_id"], eof_only=True)
    eof = harness.send(harness.output_request(process, cursor=first["next_cursor"]))
    assert eof["stdout_eof"] and eof["stderr_eof"]
    assert eof["execution_state"] == "running" and eof["exit_code"] is None
    harness.backend.finish(process["process_id"])
    exited = harness.send(harness.output_request(process, cursor=first["next_cursor"]))
    assert exited["execution_state"] == "exited" and exited["exit_code"] == 0
    harness.restart()
    assert harness.send(request, status=502)["error"]["code"] == "output_unavailable"


def test_bounded_retention_never_silently_loses_output(harness: Harness) -> None:
    process = harness.start(harness.create())
    retained = harness.backend.processes[process["process_id"]]["output"]
    retained.capacity = 8
    retained.feed("stderr", "later\n")
    page = harness.send(harness.output_request(process))
    assert page["gap"] and page["first_available_cursor"] == 1
    assert page["frames"] == [{"sequence": 1, "stream": "stderr", "text": "later\n"}]
    # Old frames expire; empty page advances across the visibly lost prefix.
    retained.clock = lambda: 10**12
    empty = harness.send(harness.output_request(process))
    assert empty["gap"] and empty["next_cursor"] == 2 and empty["frames"] == []
    assert (
        harness.send(harness.output_request(process, cursor=3), status=422)["error"]["code"]
        == "invalid_request"
    )


def test_small_output_limit_does_not_mutate_frame_or_cursor(harness: Harness) -> None:
    process = harness.start(harness.create())
    assert (
        harness.send(harness.output_request(process, limit_bytes=1), status=413)["error"]["code"]
        == "limit_exceeded"
    )
    assert harness.send(harness.output_request(process))["frames"][0]["text"] == "ready\n"


def test_failed_lookup_is_not_absence(harness: Harness) -> None:
    sandbox = harness.create()
    harness.backend.fail = "get"
    failed = harness.send(harness.request("get", sandbox=sandbox), status=502)
    assert failed["error"]["outcome"] == "unknown"
    assert "Private diagnostic" not in json.dumps(failed)


def test_list_cursor_account_filter_scope_and_unique_identity(harness: Harness) -> None:
    identities = [harness.create(), harness.create()]
    first = harness.send(harness.request("list", offering_id=None, cursor=None, page_size=1))
    second = harness.send(
        harness.request("list", offering_id=None, cursor=first["next_cursor"], page_size=1)
    )
    assert [first["items"][0]["sandbox"], second["items"][0]["sandbox"]] == identities
    bad = harness.request("list", offering_id="container", cursor=first["next_cursor"], page_size=1)
    assert harness.send(bad, status=422)["error"]["code"] == "invalid_request"
    bad.update(account_id="account-b", offering_id=None)
    assert harness.send(bad, token="test-token-b", status=422)["error"]["code"] == "invalid_request"


@pytest.mark.parametrize(
    "operation,call",
    [("run", "run"), ("process.start", "start"), ("files.write", "write"), ("destroy", "destroy")],
)
def test_lost_mutation_response_has_no_automatic_retry(
    harness: Harness, operation: str, call: str
) -> None:
    sandbox = harness.create()
    fields: dict[str, Any] = {"sandbox": sandbox}
    if operation in ("run", "process.start"):
        fields.update(argv=["fixed-test"], cwd=None, env={}, observation_timeout_ms=100)
    if operation == "run":
        fields["encoding"] = "utf8"
    if operation == "files.write":
        fields.update(path="/tmp/input", data_base64="AA==", byte_count=1)
    request = harness.request(operation, **fields)
    # Inject an actual HTTPX read error after dispatch; transport never retries the mutation.
    with httpx.Client(
        transport=LostReplyTransport(harness.endpoint), base_url="https://reference.invalid"
    ) as client:
        with pytest.raises(httpx.ReadError, match="Injected loss after server dispatch"):
            client.post(
                "/sps/v1/" + operation,
                json=request,
                headers={"Authorization": "Bearer test-token-a"},
            )
    assert harness.backend.calls[call] == 1
    # Correlation is not a deduplication key: explicit redispatch really calls the backend.
    harness.send(request)
    assert harness.backend.calls[call] == 2


@pytest.mark.parametrize("corruption", ["identity", "request_id", "byte_count", "missing_field"])
def test_pp1_validator_rejects_corrupted_or_replayed_replies(
    harness: Harness, corruption: str
) -> None:
    sandbox = harness.create()
    harness.send(
        harness.request(
            "files.write", sandbox=sandbox, path="/tmp/input", data_base64="AP8=", byte_count=2
        )
    )
    request = harness.request(
        "files.read_bytes", sandbox=sandbox, path="/tmp/input", limit_bytes=65536
    )
    response = copy.deepcopy(harness.send(request))
    if corruption == "identity":
        response["sandbox"]["incarnation"] = "other"
    elif corruption == "request_id":
        response["request_id"] = "replayed-other-request"
    elif corruption == "byte_count":
        response["byte_count"] = 1
    else:
        del response["complete"]
    with pytest.raises(ValueError):
        CONTRACT.validate_exchange(request, response, harness.endpoint.discovery("account-a"))


@pytest.fixture
def native(tmp_path: Path) -> Any:
    if os.environ.get("SPS_HTTP_DOCKER") != "1":
        pytest.skip("opt in with SPS_HTTP_DOCKER=1; requires Docker and cached python:3.12-slim")
    from sandbox_provider_spec.http_reference.docker_backend import DockerBackend  # noqa: PLC0415

    backend_type = DockerBackend
    backend = backend_type("python:3.12-slim", owner=uuid.uuid4().hex[:12])
    proof = Harness(tmp_path, backend)
    try:
        yield proof
    finally:
        proof.client.close()
        proof.endpoint.close()
        proof.backend.close()  # Asserts exact owned-label absence and stopped drain threads.


@pytest.mark.live
def test_native_docker_all_nine_operations(native: Harness) -> None:
    create = native.create_request()
    create["env"] = {"INITIAL": "inherited", "OVERRIDE": "initial"}
    sandbox = native.send(create)["sandbox"]
    owner = native.backend.run_id
    wrong = type(native.backend)("python:3.12-slim", owner=uuid.uuid4().hex[:12])
    try:
        with pytest.raises(
            ValueError, match="Native authority does not match the allocation store"
        ):
            Endpoint(
                wrong,
                native.database,
                native.tokens,
                settings=EndpointSettings(native.origin),
            )
        assert native.backend.get(sandbox) == "active"
    finally:
        wrong.close()
    native.backend.client.close()
    native.backend = type(native.backend)("python:3.12-slim", owner=owner)
    native.restart()  # Reopen both key store and backend under the same authority.
    assert native.send(create)["sandbox"] == sandbox
    assert native.send(native.request("get", sandbox=sandbox))["state"] == "active"
    assert native.send(native.request("list", offering_id=None, cursor=None, page_size=10))[
        "items"
    ] == [{"sandbox": sandbox, "state": "active"}]
    argument = "space ' quote ; $HOME \n unicode=λ"
    script = (
        "import os,sys,json; "
        "print(json.dumps([sys.argv[1],os.getcwd(),os.getenv('INITIAL'),"
        "os.getenv('OVERRIDE')],ensure_ascii=False)); "
        "sys.stderr.write('diagnostic\\n'); sys.exit(7)"
    )
    run = native.send(
        native.request(
            "run",
            sandbox=sandbox,
            argv=["python3", "-c", script, argument],
            cwd="/tmp",
            env={"OVERRIDE": "overlay"},
            observation_timeout_ms=5000,
            encoding="utf8",
        )
    )
    assert json.loads(run["stdout"]) == [argument, "/tmp", "inherited", "overlay"]
    assert run["stderr"] == "diagnostic\n" and run["exit_code"] == 7
    data = bytes(range(256)) * 4 + b"\x00\r\n\xff"
    for payload in (data, b""):
        native.send(
            native.request(
                "files.write",
                sandbox=sandbox,
                path="/tmp/proof.bin",
                data_base64=base64.b64encode(payload).decode(),
                byte_count=len(payload),
            )
        )
        read = native.send(
            native.request(
                "files.read_bytes", sandbox=sandbox, path="/tmp/proof.bin", limit_bytes=65536
            )
        )
        assert base64.b64decode(read["data_base64"]) == payload
    started = native.send(
        native.request(
            "process.start",
            sandbox=sandbox,
            argv=[
                "python3",
                "-u",
                "-c",
                "import time,sys; print('ready',flush=True); "
                "time.sleep(2); sys.stderr.write('done\\n')",
            ],
            cwd="/tmp",
            env={},
            observation_timeout_ms=1000,
        )
    )
    process = started["process"]
    first = native.send(native.output_request(process, observation_timeout_ms=1000))
    assert "ready\n" == "".join(frame["text"] for frame in first["frames"])
    assert first["execution_state"] == "running" and first["exit_code"] is None
    # Direct native control-plane metadata independently establishes the early observation.
    assert native.backend.client.api.exec_inspect(process["process_id"])["Running"] is True
    replay = native.send(native.output_request(process, observation_timeout_ms=1))
    assert replay["frames"] == first["frames"]
    deadline = time.monotonic() + 5
    cursor = first["next_cursor"]
    final: dict[str, Any] = {}
    remaining = []
    while time.monotonic() < deadline:
        final = native.send(
            native.output_request(process, cursor=cursor, observation_timeout_ms=200)
        )
        remaining.extend(final["frames"])
        cursor = final["next_cursor"]
        if final["execution_state"] == "exited" and final["stdout_eof"] and final["stderr_eof"]:
            break
        time.sleep(0.01)
    assert final["execution_state"] == "exited" and final["exit_code"] == 0
    assert final["stdout_eof"] and final["stderr_eof"]
    assert "done\n" == "".join(frame["text"] for frame in remaining if frame["stream"] == "stderr")
    assert native.send(native.request("destroy", sandbox=sandbox))["state"] == "destroyed"
    assert native.send(native.request("get", sandbox=sandbox))["state"] == "absent"
    assert native.send(create)["state"] == "unavailable"


@pytest.mark.live
def test_native_docker_observation_timeout_is_not_exit_or_cancel(native: Harness) -> None:
    sandbox = native.create()
    request = native.request(
        "run",
        sandbox=sandbox,
        argv=["python3", "-c", "import time; time.sleep(2)"],
        cwd=None,
        env={},
        observation_timeout_ms=20,
        encoding="utf8",
    )
    response = native.send(request, status=504)
    assert response["error"]["outcome"] == "unknown"
    assert response["error"]["exit_code"] is None
    assert native.send(native.request("get", sandbox=sandbox))["state"] == "active"


@pytest.mark.live
def test_native_docker_incremental_utf8_and_read_limit(native: Harness) -> None:
    sandbox = native.create()
    run = native.send(
        native.request(
            "run",
            sandbox=sandbox,
            argv=[
                "python3",
                "-u",
                "-c",
                "import os,time; os.write(1,b'\\xe2'); time.sleep(.02); "
                "os.write(1,b'\\x82\\xac\\xff'); os.write(2,b'error\\r\\n')",
            ],
            cwd=None,
            env={},
            observation_timeout_ms=1000,
            encoding="utf8",
        )
    )
    assert run["stdout"] == "€�" and run["stderr"] == "error\r\n"
    native.send(
        native.request(
            "files.write", sandbox=sandbox, path="/tmp/limit.bin", data_base64="AP8=", byte_count=2
        )
    )
    error = native.send(
        native.request("files.read_bytes", sandbox=sandbox, path="/tmp/limit.bin", limit_bytes=1),
        status=413,
    )
    assert error["error"]["code"] == "limit_exceeded"


def test_declared_limits_and_digest_are_checked_before_dispatch(harness: Harness) -> None:
    request = harness.create_request()
    raw = CONTRACT.body_bytes(request)
    response = harness.client.post(
        "/sps/v1/create",
        content=raw,
        headers={
            "Authorization": "Bearer test-token-a",
            "Content-Type": "application/json",
            "SPS-Request-Digest": "sha256:" + "0" * 64,
        },
    )
    assert response.status_code == 422 and not harness.backend.calls
    sandbox = harness.create()
    oversized = harness.request(
        "files.read_bytes", sandbox=sandbox, path="/tmp/input", limit_bytes=65537
    )
    assert (
        harness.send(oversized, status=413, validate=False)["error"]["outcome"] == "not_dispatched"
    )
    assert harness.backend.calls["read"] == 0


def test_changed_declaration_does_not_strand_create_replay(harness: Harness) -> None:
    original = harness.create_request()
    identity = harness.send(original)["sandbox"]
    harness.backend.sdks = {"reference-test-backend": "changed"}
    assert (
        harness.endpoint.discovery("account-a")["offerings"][0]["declaration_id"]
        != original["declaration_id"]
    )
    assert harness.send(original)["sandbox"] == identity
    new = harness.create_request()
    new["declaration_id"] = original["declaration_id"]
    assert harness.send(new, status=409)["error"]["code"] == "conflict"
    assert harness.backend.calls["create"] == 1


def test_same_key_is_separate_across_authenticated_accounts(harness: Harness) -> None:
    request = harness.create_request()
    first = harness.send(request)["sandbox"]
    request["account_id"] = "account-b"
    second = harness.send(request, token="test-token-b")["sandbox"]
    assert second["account_id"] == "account-b" and second["sandbox_id"] != first["sandbox_id"]
    assert harness.backend.calls["create"] == 2


@pytest.mark.parametrize("operation", [None, [], "not-an-operation"])
def test_invalid_operation_uses_known_path_in_error(harness: Harness, operation: Any) -> None:
    response = harness.client.post(
        "/sps/v1/create",
        json={"operation": operation, "account_id": "account-a"},
        headers={"Authorization": "Bearer test-token-a"},
    )
    assert response.status_code == 422
    CONTRACT.validate_message("Error", response.json())
    assert response.json()["operation"] == "create" and not harness.backend.calls


def test_invalid_backend_reply_is_an_unknown_contract_failure(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    sandbox = harness.create()
    original = harness.backend.run

    def malformed(request: dict[str, Any], *, deadline: float) -> dict[str, Any]:
        result = original(request, deadline=deadline)
        result["exit_code"] = None
        return cast(dict[str, Any], result)

    monkeypatch.setattr(harness.backend, "run", malformed)
    result = harness.send(
        harness.request(
            "run",
            sandbox=sandbox,
            argv=["fixed-test"],
            cwd=None,
            env={},
            observation_timeout_ms=100,
            encoding="utf8",
        ),
        status=502,
    )
    assert result["error"]["outcome"] == "unknown" and harness.backend.calls["run"] == 1


def test_semantic_probes_detect_corruption_beyond_json_shape(harness: Harness) -> None:
    sandbox = harness.create()
    request = harness.request(
        "run",
        sandbox=sandbox,
        argv=["fixed-test", "out"],
        cwd=None,
        env={},
        observation_timeout_ms=100,
        encoding="utf8",
    )
    result = harness.send(request)
    merged = {**result, "stdout": result["stdout"] + result["stderr"], "stderr": ""}
    CONTRACT.validate_exchange(request, merged, harness.endpoint.discovery("account-a"))
    assert (merged["stdout"], merged["stderr"]) != ("out", "scripted diagnostic\n")
    # Count-consistent corruption passes shape validation but fails the payload oracle.
    write = harness.request(
        "files.write", sandbox=sandbox, path="/tmp/input", data_base64="AP8=", byte_count=2
    )
    harness.send(write)
    read = harness.request("files.read_bytes", sandbox=sandbox, path="/tmp/input", limit_bytes=2)
    corrupt = {**harness.send(read), "data_base64": "AAA="}
    CONTRACT.validate_exchange(read, corrupt, harness.endpoint.discovery("account-a"))
    assert base64.b64decode(corrupt["data_base64"]) != b"\x00\xff"
    process = harness.start(sandbox)
    harness.backend.processes[process["process_id"]]["output"].frames.clear()
    missing = harness.send(harness.output_request(process))
    assert missing["frames"] == [] and missing["gap"]
    unsupported = harness.endpoint.discovery("account-a")
    unsupported["core_modes"] = ["exact-command-bytes"]
    with pytest.raises(ValueError):
        CONTRACT.validate_discovery(unsupported)


def test_unproven_optional_gate_cannot_pass_existing_sps_evidence_check(harness: Harness) -> None:
    declaration = harness.endpoint.discovery("account-a")["offerings"][0]["declaration"]
    assert check_declaration(declaration).errors == []
    declaration["gates"]["terminal"] = [{}]
    CONTRACT.validate_message(
        "Offering",
        {
            "offering_id": "container",
            "declaration_id": "unverified-test",
            "declaration": declaration,
        },
    )
    assert check_declaration(declaration).errors == [
        "evidence is missing a citation for gates.terminal.0"
    ]


def test_full_ring_and_scalar_limit_report_loss_without_empty_success(harness: Harness) -> None:
    process = harness.start(harness.create())
    output = harness.backend.processes[process["process_id"]]["output"]
    output.feed("stdout", "x" * (65536 + 1024))
    assert output.size <= 65536
    page = harness.send(harness.output_request(process))
    assert page["gap"] and page["frames"]
    output.capacity = 4
    output.feed("stderr", "😀")
    next_sequence = output.high - 1
    request = harness.output_request(process, cursor=next_sequence, limit_bytes=1)
    assert harness.send(request, status=413)["error"]["code"] == "limit_exceeded"
    request["limit_bytes"] = 4
    accepted = harness.send(request)
    assert accepted["frames"] == [{"sequence": next_sequence, "stream": "stderr", "text": "😀"}]
    assert accepted["next_cursor"] == next_sequence + 1


def test_serialized_response_cap_does_not_advance_output(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = harness.endpoint._selection

    def bounded(account: str, discovery: dict[str, Any] | None = None) -> dict[str, Any]:
        selection = original(account, discovery)
        selection["limits"]["response_bytes"] = 800
        return selection

    monkeypatch.setattr(harness.endpoint, "_selection", bounded)
    process = harness.start(harness.create())
    retained = harness.endpoint._runtime.processes[process["process_id"]][1]
    retained.feed("stdout", "x" * 1024)
    request = harness.output_request(process)
    response = harness.send(request, status=413)
    assert response["error"]["code"] == "limit_exceeded"
    frames = list(retained.frames)
    assert harness.send(request, status=413)["error"]["code"] == "limit_exceeded"
    assert list(retained.frames) == frames


def test_wrong_native_authority_fails_before_any_lookup(harness: Harness) -> None:
    harness.create()
    before = dict(harness.backend.calls)
    harness.backend.authority = "different-native-namespace"
    with pytest.raises(ValueError, match="Native authority does not match the allocation store"):
        Endpoint(
            harness.backend,
            harness.database,
            harness.tokens,
            settings=EndpointSettings(harness.origin),
        )
    assert dict(harness.backend.calls) == before


@pytest.mark.parametrize("observation_ms", [1, 100])
def test_stalled_native_dispatch_has_a_hard_observation_deadline(
    harness: Harness, observation_ms: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    sandbox = harness.create()
    entered, release, completed = threading.Event(), threading.Event(), threading.Event()
    original = harness.backend.run

    def stalled(request: dict[str, Any], *, deadline: float) -> dict[str, Any]:
        entered.set()
        assert release.wait(2)
        return cast(dict[str, Any], original(request, deadline=deadline))

    monkeypatch.setattr(harness.backend, "run", stalled)
    request = harness.request(
        "run",
        sandbox=sandbox,
        argv=["fixed-test"],
        cwd=None,
        env={},
        observation_timeout_ms=observation_ms,
        encoding="utf8",
    )

    def call() -> None:
        try:
            result = harness.send(request, status=504)
            assert result["error"]["code"] == "timeout"
            assert result["error"]["outcome"] in ("unknown", "not_dispatched")
            if entered.is_set():
                assert result["error"]["outcome"] == "unknown"
        finally:
            completed.set()

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(call)
        try:
            # A 1ms budget may expire before scheduling; this is a truthful refusal.
            # The 100ms case separately proves an admitted native call stays blocked.
            assert completed.wait(observation_ms / 1000 + 5), "Observation wait exceeded budget"
            if observation_ms == 100:
                assert entered.is_set() and not release.is_set()
        finally:
            release.set()
            future.result(timeout=2)


def test_never_seen_expired_key_stays_expired_after_restart_rollback(harness: Harness) -> None:
    request = harness.create_request()
    harness.now = NOW + 86400
    assert harness.send(request, status=410)["error"]["code"] == "expired_key"
    with harness.endpoint.connect() as db:
        assert db.execute("SELECT count(*) FROM allocations").fetchone()[0] == 0
    harness.now = NOW
    harness.restart()
    assert harness.send(request, status=410)["error"]["code"] == "expired_key"
    assert harness.backend.calls["create"] == 0


def test_observation_slots_stay_owned_until_late_completion(harness: Harness) -> None:
    release = threading.Event()
    entered = [threading.Event() for _ in range(8)]

    def blocked(index: int) -> None:
        entered[index].set()
        assert release.wait(20)
        if index % 2:
            raise OSError("Late native failure")

    try:
        for index in range(8):
            with pytest.raises(Failure) as failure:

                def observe_one(index: int = index) -> None:
                    blocked(index)

                harness.endpoint.observe(observe_one, time.monotonic() + 0.25)
            assert failure.value.code == "timeout" and failure.value.outcome == "unknown"
            assert entered[index].is_set()
        assert harness.endpoint._runtime.pending == 8
        with pytest.raises(Failure) as failure:
            harness.endpoint.observe(
                lambda: pytest.fail("Saturated call dispatched"), time.monotonic() + 1
            )
        assert failure.value.code == "provider_error"
        assert failure.value.outcome == "not_dispatched"
    finally:
        release.set()
        with harness.endpoint._runtime.observations:
            assert harness.endpoint._runtime.observations.wait_for(
                lambda: harness.endpoint._runtime.pending == 0, 20
            )
    for _ in range(12):
        assert harness.endpoint.observe(lambda: "complete", time.monotonic() + 1) == "complete"
    with pytest.raises(OSError, match="Native failure"):
        harness.endpoint.observe(
            lambda: (_ for _ in ()).throw(OSError("Native failure")), time.monotonic() + 1
        )
    with harness.endpoint._runtime.observations:
        assert harness.endpoint._runtime.observations.wait_for(
            lambda: harness.endpoint._runtime.pending == 0, 1
        )
    with pytest.raises(Failure) as failure:
        harness.endpoint.observe(
            lambda: pytest.fail("Expired call dispatched"), time.monotonic() - 1
        )
    assert failure.value.code == "timeout" and failure.value.outcome == "not_dispatched"


def test_output_uses_remaining_deadline_and_late_inspect_does_not_consume(harness: Harness) -> None:
    process = harness.start(harness.create())
    retained = harness.endpoint._runtime.processes[process["process_id"]]
    release, entered = threading.Event(), threading.Event()

    def blocked() -> tuple[str, int | None]:
        entered.set()
        assert release.wait(2)
        return "exited", 42

    harness.endpoint._runtime.processes[process["process_id"]] = (*retained[:2], blocked)
    try:
        result = harness.send(harness.output_request(process, observation_timeout_ms=250))
        assert entered.wait(2) and not release.is_set()
        assert result["execution_state"] == "unknown" and result["exit_code"] is None
        assert result["frames"][0]["sequence"] == 0
        assert not result["stdout_eof"] and not result["stderr_eof"]
    finally:
        release.set()
        with harness.endpoint._runtime.observations:
            assert harness.endpoint._runtime.observations.wait_for(
                lambda: harness.endpoint._runtime.pending == 0, 2
            )
        harness.endpoint._runtime.processes[process["process_id"]] = retained
    repeated = harness.send(harness.output_request(process, observation_timeout_ms=100))
    assert repeated["frames"] == result["frames"]
    assert repeated["execution_state"] == "running"


@pytest.mark.live
def test_native_docker_stalled_start_deadline_preserves_actual_process(native: Harness) -> None:
    sandbox = native.create()
    api = native.backend.client.api
    original = api.exec_start
    entered, release = threading.Event(), threading.Event()
    ids: list[str] = []

    def stalled(identity: str, **kwargs: Any) -> Any:
        stream = original(identity, **kwargs)
        ids.append(identity)
        entered.set()
        assert release.wait(3)
        return stream

    api.exec_start = stalled
    request = native.request(
        "run",
        sandbox=sandbox,
        argv=[
            "python3",
            "-c",
            "import time; time.sleep(.4); open('/tmp/completed','wb').write(b'once')",
        ],
        cwd=None,
        env={},
        observation_timeout_ms=100,
        encoding="utf8",
    )
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(native.send, request, status=504)
        try:
            assert entered.wait(2)
            result = future.result(timeout=5)
            assert result["error"]["code"] == "timeout"
            assert result["error"]["outcome"] == "unknown"
            assert len(ids) == 1 and api.exec_inspect(ids[0])["Running"]
            assert (
                native.endpoint._runtime.pending == 1
            )  # Timed-out caller did not abandon ownership.
        finally:
            release.set()
            api.exec_start = original
            future.result(timeout=3)
            with native.endpoint._runtime.observations:
                assert native.endpoint._runtime.observations.wait_for(
                    lambda: native.endpoint._runtime.pending == 0, 3
                )
    deadline = time.monotonic() + 3
    while api.exec_inspect(ids[0])["Running"] and time.monotonic() < deadline:
        time.sleep(0.01)
    assert api.exec_inspect(ids[0])["ExitCode"] == 0
    result = native.send(
        native.request("files.read_bytes", sandbox=sandbox, path="/tmp/completed", limit_bytes=10)
    )
    assert base64.b64decode(result["data_base64"]) == b"once"
    assert len(ids) == 1


@pytest.mark.live
def test_native_docker_stalled_inspect_does_not_advance_cursor(native: Harness) -> None:
    sandbox = native.create()
    process = native.send(
        native.request(
            "process.start",
            sandbox=sandbox,
            argv=[
                "python3",
                "-u",
                "-c",
                "import time; print('ready'); time.sleep(.5); print('done')",
            ],
            cwd=None,
            env={},
            observation_timeout_ms=1000,
        )
    )["process"]
    api = native.backend.client.api
    original = api.exec_inspect
    release, entered = threading.Event(), threading.Event()

    def stalled(identity: str) -> Any:
        entered.set()
        assert release.wait(3)
        return original(identity)

    api.exec_inspect = stalled
    try:
        result = native.send(native.output_request(process, observation_timeout_ms=5))
        assert entered.is_set() and not release.is_set()
        assert result["execution_state"] == "unknown" and result["exit_code"] is None
        assert original(process["process_id"])["Running"]
    finally:
        release.set()
        api.exec_inspect = original
        with native.endpoint._runtime.observations:
            assert native.endpoint._runtime.observations.wait_for(
                lambda: native.endpoint._runtime.pending == 0, 3
            )
    # Always repeat the original cursor: the late read never owns a caller cursor.
    cursor, text = 0, ""
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        page = native.send(
            native.output_request(process, cursor=cursor, observation_timeout_ms=100)
        )
        assert not page["gap"]
        text += "".join(frame["text"] for frame in page["frames"])
        cursor = page["next_cursor"]
        if page["execution_state"] == "exited" and page["stdout_eof"] and page["stderr_eof"]:
            assert page["exit_code"] == 0
            break
    else:
        pytest.fail("Native process did not reach observed exit and EOF")
    assert text == "ready\ndone\n"


def test_output_wait_spends_only_budget_remaining_after_inspect(harness: Harness) -> None:
    harness.endpoint.settings.operation_timeout_ms = 20000
    process = harness.start(harness.create())
    retained = harness.endpoint._runtime.processes[process["process_id"]]
    entered, release, completed = threading.Event(), threading.Event(), threading.Event()

    def inspect() -> tuple[str, int | None]:
        entered.set()
        assert release.wait(20)
        return "running", None

    harness.endpoint._runtime.processes[process["process_id"]] = (*retained[:2], inspect)
    request = harness.output_request(process, cursor=1, observation_timeout_ms=20000)

    def call() -> dict[str, Any]:
        try:
            return harness.send(request)
        finally:
            completed.set()

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(call)
        try:
            assert entered.wait(10)
            # Spend most of the one request budget inside native metadata inspection.
            assert not completed.wait(10)
            release.set()
            assert completed.wait(18), "Output wait incorrectly started a fresh 20s budget"
            result = future.result(timeout=10)
            assert result["frames"] == [] and result["observation_end"] == "wait_timeout"
            assert result["execution_state"] == "running" and result["exit_code"] is None
        finally:
            release.set()
            future.result(timeout=30)


def test_late_scheduled_call_does_not_dispatch(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    tasks: list[Any] = []

    class DeferredThread:
        def __init__(self, *, target: Any, daemon: bool) -> None:
            tasks.append(target)

        def start(self) -> None:
            pass

    monkeypatch.setitem(Endpoint.observe.__globals__, "Thread", DeferredThread)
    with pytest.raises(Failure) as failure:
        harness.endpoint.observe(
            lambda: pytest.fail("Late scheduled native call dispatched"), time.monotonic() + 0.005
        )
    assert failure.value.code == "timeout" and harness.endpoint._runtime.pending == 1
    tasks[0]()
    assert harness.endpoint._runtime.pending == 0


def test_locked_identity_store_times_out_without_later_native_dispatch(harness: Harness) -> None:
    sandbox = harness.create()
    before = dict(harness.backend.calls)
    request = harness.request(
        "run",
        sandbox=sandbox,
        argv=["fixed-test"],
        cwd=None,
        env={},
        observation_timeout_ms=50,
        encoding="utf8",
    )
    with harness.endpoint.connect() as lock, ThreadPoolExecutor(max_workers=1) as pool:
        lock.execute("BEGIN EXCLUSIVE")
        future = pool.submit(harness.send, request, status=504)
        try:
            result = future.result(timeout=0.3)
            assert result["error"]["code"] == "timeout"
            assert result["error"]["outcome"] == "not_dispatched"
            assert harness.endpoint._runtime.pending == 1
            assert dict(harness.backend.calls) == before
        finally:
            lock.rollback()
            future.result(timeout=2)
    with harness.endpoint._runtime.observations:
        assert harness.endpoint._runtime.observations.wait_for(
            lambda: harness.endpoint._runtime.pending == 0, 2
        )
    assert dict(harness.backend.calls) == before


def test_locked_create_store_keeps_slots_and_reservations_without_late_dispatch(
    harness: Harness,
) -> None:
    harness.endpoint.settings.operation_timeout_ms = 50
    requests = [harness.create_request() for _ in range(8)]
    with harness.endpoint.connect() as lock, ThreadPoolExecutor(max_workers=1) as pool:
        lock.execute("BEGIN EXCLUSIVE")
        try:
            for request in requests:
                result = pool.submit(harness.send, request, status=504).result(timeout=10)
                assert result["error"]["code"] == "timeout"
                assert result["error"]["outcome"] in ("unknown", "not_dispatched")
            assert harness.endpoint._runtime.pending == 8
            saturated = pool.submit(harness.send, harness.create_request(), status=502).result(
                timeout=10
            )
            assert saturated["error"]["code"] == "provider_error"
            assert saturated["error"]["outcome"] == "not_dispatched"
            assert harness.backend.calls["create"] == 0
        finally:
            lock.rollback()
    with harness.endpoint._runtime.observations:
        assert harness.endpoint._runtime.observations.wait_for(
            lambda: harness.endpoint._runtime.pending == 0, 3
        )
    assert harness.backend.calls["create"] == 0
    with harness.endpoint.connect() as db:
        records = db.execute("SELECT result FROM allocations").fetchall()
    assert len(records) == 8
    assert all(json.loads(row[0])["state"] == "unknown" for row in records)
    # Late scheduling proves native create was not dispatched; replay retains that refusal.
    harness.endpoint.settings.operation_timeout_ms = 1000
    harness.restart()
    refused = harness.send(requests[0], status=504)
    assert refused["error"]["code"] == "timeout"
    assert refused["error"]["outcome"] == "not_dispatched"
    assert harness.backend.calls["create"] == 0


def test_late_create_result_store_completion_preserves_one_native_identity(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = harness.create_request()
    harness.endpoint.settings.operation_timeout_ms = 500
    original = harness.backend.create
    accepted, release = threading.Event(), threading.Event()

    def create(identity: dict[str, Any], env: dict[str, str]) -> None:
        original(identity, env)
        accepted.set()
        assert release.wait(10)

    monkeypatch.setattr(harness.backend, "create", create)
    with harness.endpoint.connect() as lock, ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(harness.send, request, status=504)
        try:
            assert accepted.wait(10)
            # Native acceptance already happened. Block only persistence of its known result.
            lock.execute("BEGIN EXCLUSIVE")
            release.set()
            result = future.result(timeout=5)
            assert result["error"]["code"] == "timeout"
            assert result["error"]["outcome"] == "unknown"
            assert harness.endpoint._runtime.pending == 1
        finally:
            release.set()
            lock.rollback()
            future.result(timeout=2)
    with harness.endpoint._runtime.observations:
        assert harness.endpoint._runtime.observations.wait_for(
            lambda: harness.endpoint._runtime.pending == 0, 2
        )
    harness.restart()
    replay = harness.send(request)
    assert replay["state"] == "ready"
    assert replay["sandbox"]["sandbox_id"] in harness.backend.sandboxes
    assert harness.backend.calls["create"] == 1
