# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""In-process WSGI tests for the HTTP 0.3 reference control plane."""

from __future__ import annotations

import copy
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import httpx
import pytest

from sandbox_provider_spec import http_binding_validation as validation
from sandbox_provider_spec.http_reference import Endpoint, EndpointSettings, Failure
from sandbox_provider_spec.http_reference.test_backend import TestBackend as DeterministicBackend

NOW = 1792692000


class AdmittedFakeBackend(DeterministicBackend):
    """Native-looking state machine with no process, host, Docker or network access."""

    kind = "fake-native-03"
    authority = "fake-native-authority-03"

    def __init__(self) -> None:
        super().__init__()
        self.offerings_enabled = True
        self.offering_calls = 0
        self.output_cap = 1024
        self.admitted_calls: list[dict[str, Any]] = []
        self.observations: dict[str, dict[str, Any]] = {}
        self.now = NOW
        self.create_entered: threading.Event | None = None
        self.create_release: threading.Event | None = None
        self.create_failure: BaseException | None = None
        self.create_settled: threading.Event | None = None
        self.observation_failure = False
        self.mutate_admission_argument = False
        self.invalid_lifetime_observation = False

    def offerings(self, account: str) -> list[dict[str, Any]]:
        self.offering_calls += 1
        del account
        if not self.offerings_enabled:
            return []
        declaration = copy.deepcopy(
            validation.SCHEMA["$defs"]["Discovery"]["examples"][-1]["offerings"][0]["declaration"]
        )
        declaration["provider"] = self.kind
        declaration["gates"]["pause_resume"] = [{"keeps": "files_only"}]
        declaration["resources"]["max_lifetime_seconds"] = 3600
        declaration["lifetime_timer"] = {
            "enforced_by": "provider",
            "counts_paused_time": False,
            "at_end": ["destroyed"],
        }
        return [
            {
                "offering_id": "container",
                "declaration_id": "selection-v3-one",
                "declaration": declaration,
            }
        ]

    def create_admitted(
        self,
        identity: dict[str, Any],
        request: dict[str, Any],
        env: dict[str, str],
        labels: dict[str, Any],
        admission: dict[str, Any],
    ) -> dict[str, Any]:
        self.calls["create_admitted"] += 1
        self.admitted_calls.append(
            {
                "identity": copy.deepcopy(identity),
                "request": copy.deepcopy(request),
                "env": copy.deepcopy(env),
                "labels": copy.deepcopy(labels),
                "admission": copy.deepcopy(admission),
            }
        )
        if self.create_entered is not None:
            self.create_entered.set()
        if self.create_release is not None and not self.create_release.wait(2):
            raise OSError("fake create did not settle")
        if self.create_failure is not None:
            if self.create_settled is not None:
                self.create_settled.set()
            raise self.create_failure
        if self.mutate_admission_argument:
            admission["selection"]["offering"]["declaration"]["provider"] = "mutated-provider"
        ready = datetime.fromtimestamp(self.now, UTC)
        duration = admission["lifetime_seconds"]
        ends = None if duration is None else ready + timedelta(seconds=duration)
        if ends is not None and self.invalid_lifetime_observation:
            ends -= timedelta(seconds=1)
        observation = {
            "state": "active",
            "labels": copy.deepcopy(labels),
            "lifetime": {
                "ready_at": ready.isoformat().replace("+00:00", "Z"),
                "ends_at": None if ends is None else ends.isoformat().replace("+00:00", "Z"),
            },
            "provider_metadata": {
                "owner": "internal-owner-secret",
                "identity": copy.deepcopy(identity),
                "grant": "internal-grant-secret",
            },
        }
        self.sandboxes[identity["sandbox_id"]] = {"state": "active"}
        self.observations[identity["sandbox_id"]] = observation
        return copy.deepcopy(observation)

    def observe_admitted(self, identity: dict[str, Any]) -> dict[str, Any]:
        self.calls["observe_admitted"] += 1
        if self.observation_failure:
            raise Failure("provider_error", "unknown")
        observation = self.observations.get(identity["sandbox_id"])
        if observation is None:
            return {"state": "absent", "labels": None, "lifetime": None}
        return copy.deepcopy(observation)

    def run_buffered(self, request: dict[str, Any], *, execution_limit_ms: int) -> dict[str, Any]:
        self.calls["run_buffered"] += 1
        del request, execution_limit_ms
        return {
            "mode": "buffered_commands_v1",
            "encoding": "base64",
            "stdout_base64": "",
            "stderr_base64": "",
            "stdout_bytes": 0,
            "stderr_bytes": 0,
            "stdout_truncated": False,
            "stderr_truncated": False,
            "exit_code": 0,
            "output_complete": True,
        }


class Reference03:
    def __init__(
        self,
        tmp_path: Path,
        *,
        backend: AdmittedFakeBackend | None = None,
        database: Path | None = None,
        clock: list[int] | None = None,
        output_cap: int = 1024,
        control_response_cap: int = 4 * 1024 * 1024,
        operation_timeout_ms: int = 5000,
    ) -> None:
        self.backend = backend or AdmittedFakeBackend()
        self.backend.output_cap = output_cap
        self.database = database or tmp_path / "allocations.sqlite3"
        self.clock_value = clock or [NOW]
        self.tokens = {"test-token": "account-a"}
        self.endpoint = Endpoint(
            self.backend,
            self.database,
            self.tokens,
            settings=EndpointSettings(
                "https://reference.invalid",
                clock=lambda: self.clock_value[0],
                buffered_command_output_bytes=output_cap,
                execution_ms=30000,
                operation_timeout_ms=operation_timeout_ms,
                binding_version="0.3",
                control_response_cap=control_response_cap,
            ),
        )
        self.client = httpx.Client(
            transport=httpx.WSGITransport(app=self.endpoint),
            base_url="https://reference.invalid",
        )
        self.sequence = 0

    def close(self) -> None:
        self.client.close()
        self.endpoint.close()

    def request(self, operation: str, **fields: Any) -> dict[str, Any]:
        self.sequence += 1
        value = {
            "operation": operation,
            "request_id": f"request-{self.sequence}",
            "account_id": "account-a",
            **fields,
        }
        if operation == "create":
            value.setdefault("allocation_key", f"{self.clock_value[0]}:{self.sequence:032x}")
            discovery = self.endpoint.discovery("account-a")
            value.setdefault("offering_id", "container")
            value.setdefault("declaration_id", discovery["offerings"][0]["declaration_id"])
            value.setdefault(
                "request",
                {
                    "requirements": {"pause_resume": {"keeps": "files_only"}},
                    "lifetime_seconds": 300,
                    "at_end": "destroyed",
                },
            )
            value.setdefault("labels", {"run": "test"})
            value.setdefault("env", {"PRIVATE": "value"})
        return value

    def send(
        self,
        request: dict[str, Any],
        *,
        status: int = 200,
        raw: bytes | None = None,
        validate: bool = True,
        replay_admission: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        body = raw if raw is not None else validation.body_bytes(request)
        digest = validation.request_digest(body)
        response = self.client.post(
            "/sps/v1/" + request["operation"],
            content=body,
            headers={
                "Authorization": "Bearer test-token",
                "Content-Type": "application/json",
                "SPS-Request-Digest": digest,
            },
        )
        assert response.status_code == status, response.text
        result = response.json()
        if validate:
            validation.validate_exchange(
                request,
                result,
                self.endpoint.discovery(request["account_id"]),
                status=status,
                request_body=body,
                digest=digest,
                control_response_cap=self.endpoint.settings.control_response_cap,
                replay_admission=replay_admission,
            )
        return cast(dict[str, Any], result)


@pytest.fixture
def reference03(tmp_path: Path) -> Any:
    value = Reference03(tmp_path)
    yield value
    value.close()


def test_03_discovery_and_requestful_create_fit_before_one_native_dispatch(
    reference03: Reference03,
) -> None:
    discovery_response = reference03.client.get(
        "/.well-known/sandbox-provider-spec.json",
        headers={"Authorization": "Bearer test-token"},
    )
    assert discovery_response.status_code == 200
    discovery = discovery_response.json()
    assert discovery["binding"] == "sandbox-provider-http/0.3"
    assert discovery["offerings"] == reference03.backend.offerings("account-a")

    request = reference03.request("create")
    reference03.backend.mutate_admission_argument = True
    created = reference03.send(request)
    assert created["state"] == "ready"
    assert created["sandbox"]["offering_id"] == "container"
    assert created["admission"]["requirements"] == {"pause_resume": {"keeps": ["files_only"]}}
    assert created["labels"] == request["labels"]
    assert "provider_metadata" not in created
    assert "internal-owner-secret" not in json.dumps(created)
    assert "internal-grant-secret" not in json.dumps(created)
    assert created["lifetime"]["ends_at"] is not None
    assert reference03.backend.calls["create_admitted"] == 1
    call = reference03.backend.admitted_calls[0]
    assert call["identity"] == created["sandbox"]
    assert call["request"] == request["request"]
    assert call["labels"] == request["labels"]
    assert call["admission"]["resources"] == created["admission"]["resources"]
    assert created["admission"]["selection"]["offering"]["declaration"]["provider"] == (
        reference03.backend.kind
    )
    assert "PRIVATE" not in json.dumps(created["admission"])


@pytest.mark.parametrize(
    ("mutate", "status"),
    [
        (lambda request: request.update(request={"resources": {"cpu_min": 3}}), 422),
        (lambda request: request.update(declaration_id="stale-token"), 409),
        (lambda request: request.update(labels={f"k{i}": "x" for i in range(33)}), 422),
    ],
)
def test_03_refusal_before_native_allocation(
    reference03: Reference03, mutate: Any, status: int
) -> None:
    request = reference03.request("create")
    mutate(request)
    reference03.send(request, status=status)
    assert reference03.backend.calls["create_admitted"] == 0


def test_03_selected_size_region_gpu_roundtrip_create_get_and_replay(
    reference03: Reference03, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_offerings = reference03.backend.offerings

    def selected_offerings(account: str) -> list[dict[str, Any]]:
        offerings = original_offerings(account)
        offerings[0]["declaration"]["resources"].update(
            {
                "disk_in_memory": False,
                "sizes": [{"cpu": 4, "memory_mib": 8192, "disk_mib": 10240}],
                "regions": ["modal:us-east"],
                "gpus": ["nvidia:a10"],
                "max_gpus": 1,
            }
        )
        return offerings

    monkeypatch.setattr(reference03.backend, "offerings", selected_offerings)
    create = reference03.request(
        "create",
        env={},
        request={
            "requirements": {"pause_resume": {"keeps": "files_only"}},
            "resources": {
                "cpu_min": 4,
                "memory_min_mib": 8192,
                "disk_min_mib": 10240,
                "region": "modal:us-east",
                "gpu_model": "nvidia:a10",
                "gpu_count": 1,
            },
            "lifetime_seconds": 300,
            "at_end": "destroyed",
        },
    )

    created = reference03.send(create)
    expected_resources = {
        "size": {"cpu": 4, "memory_mib": 8192, "disk_mib": 10240},
        "region": "modal:us-east",
        "gpu": {"model": "nvidia:a10", "count": 1},
    }
    assert created["admission"]["resources"] == expected_resources
    replay = reference03.send(create)
    assert replay["admission"] == created["admission"]
    observed = reference03.send(reference03.request("get", sandbox=created["sandbox"]))
    assert observed["admission"] == created["admission"]
    assert observed["admission"]["resources"] == expected_resources
    assert reference03.backend.calls["create_admitted"] == 1


def test_03_old_backend_fails_closed_before_advertisement(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="requestful admission"):
        Endpoint(
            DeterministicBackend(),
            tmp_path / "old-backend.sqlite3",
            {"token": "account-a"},
            settings=EndpointSettings(
                "https://reference.invalid",
                buffered_command_output_bytes=1024,
                execution_ms=30000,
                binding_version="0.3",
            ),
        )


def test_03_endpoint_construction_does_not_probe_native_offerings(tmp_path: Path) -> None:
    backend = AdmittedFakeBackend()
    endpoint = Endpoint(
        backend,
        tmp_path / "no-construction-probe.sqlite3",
        {"token": "account-a"},
        settings=EndpointSettings(
            "https://reference.invalid",
            buffered_command_output_bytes=1024,
            execution_ms=30000,
            binding_version="0.3",
        ),
    )
    try:
        assert backend.offering_calls == 0
        assert endpoint.discovery("account-a")["offerings"]
        assert backend.offering_calls == 1
    finally:
        endpoint.close()


def test_03_get_recovers_original_admission_after_restart_expiry_and_offering_removal(
    tmp_path: Path,
) -> None:
    backend = AdmittedFakeBackend()
    clock = [NOW]
    first = Reference03(tmp_path, backend=backend, clock=clock)
    create = first.request("create", labels={"run": "original"})
    created = first.send(create)
    original_admission = copy.deepcopy(created["admission"])
    original_lifetime = copy.deepcopy(created["lifetime"])
    identity = created["sandbox"]
    first.close()

    backend.offerings_enabled = False
    second = Reference03(
        tmp_path,
        backend=backend,
        database=first.database,
        clock=clock,
        output_cap=512,
    )
    try:
        discovery = second.endpoint.discovery("account-a")
        assert discovery["offerings"] == []
        offering_calls = backend.offering_calls
        replay = second.send(create, validate=False)
        assert backend.offering_calls == offering_calls
        raw = validation.body_bytes(create)
        digest = validation.request_digest(raw)
        validation.validate_exchange(
            create,
            replay,
            second.endpoint.discovery("account-a", include_offerings=False),
            request_body=raw,
            digest=digest,
            replay_admission=original_admission,
            control_response_cap=second.endpoint.settings.control_response_cap,
        )
        assert replay["admission"] == original_admission
        assert backend.calls["create_admitted"] == 1
        backend.observations[identity["sandbox_id"]]["labels"] = {"run": "observed-later"}
        clock[0] += 86400
        assert second.send(create, status=410)["error"]["code"] == "expired_key"
        get = second.request("get", sandbox=identity)
        observed = second.send(get)
        assert observed["admission"] == original_admission
        assert observed["labels"] == {"run": "observed-later"}
        assert "provider_metadata" not in observed
        assert "internal-owner-secret" not in json.dumps(observed)
        assert "internal-grant-secret" not in json.dumps(observed)
        assert observed["lifetime"] == original_lifetime
        assert backend.calls["create_admitted"] == 1
    finally:
        second.close()


def test_03_inventory_pages_are_complete_for_the_managed_account_namespace(
    reference03: Reference03,
) -> None:
    created = [reference03.send(reference03.request("create")) for _ in range(3)]
    request = reference03.request("list", offering_id=None, cursor=None, page_size=1)
    page = reference03.send(request)
    items = list(page["items"])
    while page["next_cursor"] is not None:
        request = reference03.request(
            "list", offering_id=None, cursor=page["next_cursor"], page_size=1
        )
        page = reference03.send(request)
        items.extend(page["items"])
    assert {item["sandbox"]["sandbox_id"] for item in items} == {
        item["sandbox"]["sandbox_id"] for item in created
    }
    assert all(item["labels"] is not None and item["lifetime"] is not None for item in items)
    assert all("provider_metadata" not in item for item in items)
    assert "internal-owner-secret" not in json.dumps(items)
    assert "internal-grant-secret" not in json.dumps(items)


def test_03_inventory_observation_failure_fails_page(reference03: Reference03) -> None:
    reference03.send(reference03.request("create"))
    reference03.backend.observation_failure = True
    request = reference03.request("list", offering_id=None, cursor=None, page_size=1)
    response = reference03.send(request, status=502)
    assert response["error"]["code"] == "provider_error"


def test_03_full_identity_mismatch_is_refused_before_native_observation(
    reference03: Reference03,
) -> None:
    sandbox = reference03.send(reference03.request("create"))["sandbox"]
    before = reference03.backend.calls["observe_admitted"]
    wrong = {**sandbox, "incarnation": "different-incarnation"}
    request = reference03.request("get", sandbox=wrong)
    response = reference03.send(request, status=422)
    assert response["error"]["code"] == "invalid_request"
    assert reference03.backend.calls["observe_admitted"] == before


def test_03_existing_workload_keeps_original_selected_command_cap(
    reference03: Reference03,
) -> None:
    created = reference03.send(reference03.request("create"))
    reference03.endpoint.settings.buffered_command_output_bytes = 512
    request = {
        "operation": "run",
        "request_id": "run-after-cap-shrink",
        "account_id": "account-a",
        "sandbox": created["sandbox"],
        "argv": ["fake", "argument"],
        "cwd": None,
        "env": {},
        "observation_timeout_ms": 1000,
        "encoding": "base64",
        "mode": "buffered_commands_v1",
        "execution_limit_ms": 20000,
        "output_limit_bytes": 1024,
    }
    response = reference03.send(request, validate=False)
    selected = reference03.endpoint._discovery_for_selection(
        "account-a", created["admission"]["selection"]
    )
    validation.validate_exchange(request, response, selected)
    assert response["mode"] == "buffered_commands_v1"
    assert reference03.backend.calls["run_buffered"] == 1


def test_03_concurrent_exact_create_dispatches_once(reference03: Reference03) -> None:
    request = reference03.request("create")
    reference03.backend.create_entered = threading.Event()
    reference03.backend.create_release = threading.Event()
    with ThreadPoolExecutor(max_workers=2) as workers:
        first = workers.submit(reference03.send, request)
        assert reference03.backend.create_entered.wait(1)
        replay = workers.submit(reference03.send, request).result(timeout=2)
        reference03.backend.create_release.set()
        created = first.result(timeout=3)

    assert replay["state"] == "unknown" and replay["sandbox"] is None
    assert created["state"] == "ready"
    assert reference03.backend.calls["create_admitted"] == 1


@pytest.mark.parametrize(
    ("late_error", "replay_status", "expected_code"),
    [
        (Failure("forbidden", "not_dispatched"), 403, "forbidden"),
        (RuntimeError("unclassified fake-native error"), 200, None),
    ],
)
def test_03_late_native_settlement_preserves_definitive_or_unknown_outcome(
    tmp_path: Path,
    late_error: BaseException,
    replay_status: int,
    expected_code: str | None,
) -> None:
    backend = AdmittedFakeBackend()
    backend.create_entered = threading.Event()
    backend.create_release = threading.Event()
    backend.create_settled = threading.Event()
    backend.create_failure = late_error
    reference = Reference03(tmp_path, backend=backend, operation_timeout_ms=250)
    request = reference.request("create")
    try:
        first = reference.send(request, status=504)
        assert first["error"]["code"] == "timeout"
        assert first["error"]["outcome"] == "unknown"
        assert backend.create_entered.wait(2)
        backend.create_release.set()
        assert backend.create_settled.wait(1)
        with reference.endpoint._runtime.observations:
            assert reference.endpoint._runtime.observations.wait_for(
                lambda: reference.endpoint._runtime.pending == 0, timeout=1
            )

        replay = reference.send(request, status=replay_status)
        if expected_code is None:
            assert replay["state"] == "unknown" and replay["sandbox"] is None
        else:
            assert replay["error"]["code"] == expected_code
        assert backend.calls["create_admitted"] == 1
    finally:
        backend.create_release.set()
        reference.close()


def test_03_create_key_conflict_does_not_replay_native_create(reference03: Reference03) -> None:
    request = reference03.request("create")
    reference03.send(request)
    conflict = copy.deepcopy(request)
    conflict["labels"] = {"run": "changed"}
    response = reference03.send(conflict, status=409)
    assert response["error"]["code"] == "conflict"
    assert reference03.backend.calls["create_admitted"] == 1


def test_03_false_native_lifetime_is_never_published_as_ready(reference03: Reference03) -> None:
    reference03.backend.invalid_lifetime_observation = True
    request = reference03.request("create")
    first = reference03.send(request, status=502)
    assert first["error"]["code"] == "provider_error"
    with reference03.endpoint.connect() as db:
        raw = db.execute("SELECT result FROM allocations").fetchone()[0]
    retained, _selection = reference03.endpoint._stored_allocation(raw)
    assert retained["state"] == "unknown"
    assert retained["sandbox"] is not None

    replay = reference03.send(request, status=502)
    assert replay["error"]["code"] == "provider_error"
    assert reference03.backend.calls["create_admitted"] == 1
