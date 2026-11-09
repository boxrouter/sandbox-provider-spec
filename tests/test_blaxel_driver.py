# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The Blaxel driver's own logic: name reservation, cleanup, timeouts and entitlements."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import httpx
import pytest
from blaxel.core.client import errors
from blaxel.core.sandbox.default.sandbox import SandboxAPIError
from blaxel.core.sandbox.sync import SyncSandboxInstance
from blaxel.core.sandbox.types import ResponseError

from sandbox_provider_spec.driver import NativeFailure, NotRun, Reserved, Unsupported
from sandbox_provider_spec.drivers import blaxel as native
from sandbox_provider_spec.runner import Runner
from sandbox_provider_spec.suite import Test as Scenario


class Instances:
    """What the SDK's class-level calls see: names that exist, and their statuses."""

    def __init__(self) -> None:
        self.status: dict[str, str] = {}
        self.calls: list[str] = []

    def create(self, sandbox: dict[str, Any]) -> Any:
        self.status[sandbox["name"]] = "DEPLOYING"
        raise RuntimeError("deployment failed after the name was taken")

    def delete(self, name: str) -> None:
        self.calls.append(f"delete:{name}")
        self.status[name] = "TERMINATED"

    def get(self, name: str) -> Any:
        if name not in self.status:
            raise SandboxAPIError("not found", status_code=404)
        return SimpleNamespace(status=self.status[name])


def test_a_failed_create_cleans_the_reserved_name(monkeypatch: pytest.MonkeyPatch) -> None:
    instances = Instances()
    monkeypatch.setattr(native, "SyncSandboxInstance", instances)
    monkeypatch.setattr(native, "INSTANCE", instances)
    result = Runner(native.BlaxelDriver()).run_test(
        Scenario("example.create", "", ({"op": "create", "as": "box"},), (), ())
    )
    assert result["result"] == "error"
    assert result["cleanup"] == [{"kind": "sandbox", "result": "deleted"}]
    assert instances.calls == [f"delete:{name}" for name in instances.status]


class FlakyDeployments(Instances):
    """Blaxel answers DEPLOYMENT_FAILED for the first attempts, then deploys."""

    def __init__(self, failures: int) -> None:
        super().__init__()
        self.failures = failures

    def create(self, sandbox: dict[str, Any]) -> Any:
        self.status[sandbox["name"]] = "FAILED"
        if self.failures:
            self.failures -= 1
            raise SandboxAPIError(
                "Sandbox deployment failed. Please try again.",
                status_code=500,
                code="DEPLOYMENT_FAILED",
            )
        self.status[sandbox["name"]] = "DEPLOYED"
        return SimpleNamespace(metadata=SimpleNamespace(name=sandbox["name"]))


@pytest.mark.parametrize("failures", [1, 2])
def test_a_failed_deployment_is_deleted_and_deployed_again_under_a_new_name(
    monkeypatch: pytest.MonkeyPatch, failures: int
) -> None:
    instances = FlakyDeployments(failures)
    monkeypatch.setattr(native, "SyncSandboxInstance", instances)
    monkeypatch.setattr(native, "INSTANCE", instances)
    driver = native.BlaxelDriver()
    created = driver.create(None, {})
    names = list(instances.status)
    assert len(names) == failures + 1 and created["identity"] == names[-1]
    # Each failed attempt was deleted, with its deletion confirmed, before the next.
    assert instances.calls == [f"delete:{name}" for name in names[:-1]]
    assert [owned.released for owned in driver.resources] == [True] * failures + [False]
    assert [owned.kind for owned in driver.resources] == ["failed_deployment"] * failures + [
        "sandbox"
    ]


def test_each_failed_deployment_is_a_cleanup_entry_in_the_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    instances = FlakyDeployments(2)
    monkeypatch.setattr(native, "SyncSandboxInstance", instances)
    monkeypatch.setattr(native, "INSTANCE", instances)
    result = Runner(native.BlaxelDriver()).run_test(
        Scenario("example.create", "", ({"op": "create", "as": "box"},), (), ())
    )
    assert result["result"] == "passed"
    assert [entry["kind"] for entry in cast(list[dict[str, str]], result["cleanup"])] == [
        "sandbox",
        "failed_deployment",
        "failed_deployment",
    ]


def test_deployment_failures_beyond_the_attempts_are_raised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    instances = FlakyDeployments(native.DEPLOYMENT_ATTEMPTS)
    monkeypatch.setattr(native, "SyncSandboxInstance", instances)
    monkeypatch.setattr(native, "INSTANCE", instances)
    with pytest.raises(SandboxAPIError):
        native.BlaxelDriver().create(None, {})
    assert len(instances.status) == native.DEPLOYMENT_ATTEMPTS


def test_a_run_waits_through_the_sdks_streaming_endpoint() -> None:
    sent: list[dict[str, Any]] = []

    def exec_(process: dict[str, Any]) -> Any:
        sent.append(process)
        return SimpleNamespace(stdout="a\nb", stderr="e", exit_code=3)

    sandbox = SimpleNamespace(process=SimpleNamespace(exec=exec_))
    owned = native.BlaxelDriver().own("sandbox", Reserved("box"), lambda: {"result": "deleted"})
    cast(Any, owned.native).native = sandbox
    result = native.BlaxelDriver().run(
        {"resource": owned}, {"bash_script": "true", "timeout_ms": 0}
    )
    assert result == {"stdout": "a\nb", "stderr": "e", "exit_code": 3}
    assert sent[0]["timeout"] == 0 and sent[0]["wait_for_completion"] is True
    assert callable(sent[0]["on_stdout"])


def test_a_terminated_record_counts_as_deleted(monkeypatch: pytest.MonkeyPatch) -> None:
    instances = Instances()
    instances.status["sps-example"] = "DEPLOYED"
    monkeypatch.setattr(native, "SyncSandboxInstance", instances)
    monkeypatch.setattr(native, "INSTANCE", instances)
    assert native.BlaxelDriver._delete("sps-example") == {"result": "deleted"}  # pylint: disable=protected-access


def test_cleanup_refuses_a_sandbox_that_stays_deployed(monkeypatch: pytest.MonkeyPatch) -> None:
    instances = Instances()
    instances.status["sps-example"] = "DEPLOYED"
    instances.delete = lambda name: None  # type: ignore[method-assign]
    monkeypatch.setattr(native, "SyncSandboxInstance", instances)
    monkeypatch.setattr(native, "INSTANCE", instances)
    times = iter([0.0, 91.0])
    monkeypatch.setattr("sandbox_provider_spec.driver.time.monotonic", lambda: next(times))
    with pytest.raises(NativeFailure, match="^cleanup_not_confirmed$"):
        native.BlaxelDriver._delete("sps-example")  # pylint: disable=protected-access


def _response(status: int, error: str) -> ResponseError:
    request = httpx.Request("POST", "https://sandbox.blaxel.ai/process")
    return ResponseError(httpx.Response(status, json={"error": error}, request=request))


def test_the_native_timeout_is_classified() -> None:
    assert native._timed_out(_response(422, "process timed out after 1 seconds"))  # pylint: disable=protected-access
    assert not native._timed_out(_response(422, "invalid working directory"))  # pylint: disable=protected-access
    assert not native._timed_out(_response(500, "process timed out"))  # pylint: disable=protected-access


def test_a_zero_timeout_asks_blaxel_for_none() -> None:
    timeout = native._native_timeout  # pylint: disable=protected-access
    assert timeout({"timeout_ms": 0}) == 0
    assert timeout({"timeout_ms": 1}) == 1
    assert timeout({"timeout_ms": 60001}) == 61
    assert timeout({}) == 15


def test_a_missing_entitlement_is_not_run() -> None:
    def refused() -> None:
        raise SandboxAPIError("forbidden", status_code=403)

    with pytest.raises(NotRun, match="^account_entitlement_missing$"):
        native._entitled(refused)  # pylint: disable=protected-access
    with pytest.raises(SandboxAPIError):
        native._entitled(lambda: (_ for _ in ()).throw(SandboxAPIError("boom", status_code=500)))  # pylint: disable=protected-access


def _config(inputs: dict[str, Any]) -> dict[str, object]:
    return native.BlaxelDriver._config(inputs)  # pylint: disable=protected-access


def test_egress_is_forced_through_the_filtering_proxy() -> None:
    config = _config({"requirements": {"network_lockdown": {"policy": "deny_all"}}})
    assert config["network"] == {
        "proxy": {"forbidden_domains": ["*"]},
        "firewall": {"rulesets": ["proxy"]},
    }
    with pytest.raises(Unsupported):
        _config({"requirements": {"network_lockdown": {"policy": "allowlist_ips"}}})


def test_idle_deletion_is_a_lifecycle_policy_and_standby_is_fixed() -> None:
    idle = {"on_idle": "destroyed", "custom_idle_time": True, "idle_seconds": 60}
    config = _config({"requirements": {"idle_shutdown": idle}})
    assert config["lifecycle"] == {
        "expiration_policies": [{"type": "ttl-idle", "action": "delete", "value": "60s"}]
    }
    with pytest.raises(Unsupported):
        _config(
            {"requirements": {"idle_shutdown": {"on_idle": "paused", "custom_idle_time": True}}}
        )
    assert "lifecycle" not in _config({"requirements": {"idle_shutdown": {"on_idle": "paused"}}})


def test_a_sandbox_is_sized_by_memory_only() -> None:
    assert _config({"resources": {"memory_min_mib": 4096}})["memory"] == 4096
    with pytest.raises(Unsupported):
        _config({"resources": {"cpu_min": 2}})


def test_a_refusal_outside_the_sdk_contract_is_classified_too() -> None:
    def refused() -> None:
        raise errors.UnexpectedStatus(403, b"")

    with pytest.raises(NotRun, match="^account_entitlement_missing$"):
        native._entitled(refused)  # pylint: disable=protected-access


def test_long_running_is_unsupported_because_standby_is_fixed() -> None:
    with pytest.raises(Unsupported):
        _config({"resources": {"long_running": True}})


def test_a_dockerfile_image_build_is_not_run() -> None:
    with pytest.raises(NotRun, match="^image_build_mapping_pending$"):
        native.BlaxelDriver().image_create(None, {"source": "dockerfile", "dockerfile": "FROM x"})


def test_idle_deletion_without_a_duration_is_not_run() -> None:
    with pytest.raises(NotRun, match="^native_idle_duration_required$"):
        _config({"requirements": {"idle_shutdown": {"on_idle": "destroyed"}}})


def test_a_custom_idle_time_selects_deletion_and_standby_cannot_skip_waking() -> None:
    config = _config(
        {"requirements": {"idle_shutdown": {"custom_idle_time": True, "idle_seconds": 60}}}
    )
    assert "lifecycle" in config
    assert "lifecycle" not in _config({"requirements": {"idle_shutdown": {"auto_wake": True}}})
    with pytest.raises(Unsupported):
        _config({"requirements": {"idle_shutdown": {"auto_wake": False}}})


def test_standby_is_read_from_the_runtime_state(monkeypatch: pytest.MonkeyPatch) -> None:
    standby = SimpleNamespace(status="DEPLOYED", sandbox=SimpleNamespace(state="STANDBY"))
    monkeypatch.setattr(SyncSandboxInstance, "get", lambda name: standby)
    driver = native.BlaxelDriver()
    owned = driver.own("sandbox", Reserved("sps-example"), lambda: {"result": "deleted"})
    assert driver.get({"resource": owned}, {}) == {"state": "paused"}


def test_a_domain_denylist_is_the_proxys_forbidden_list() -> None:
    config = _config(
        {
            "requirements": {
                "network_lockdown": {"policy": "denylist_domains", "deny": ["example.com"]}
            }
        }
    )
    assert config["network"] == {
        "proxy": {"forbidden_domains": ["example.com"]},
        "firewall": {"rulesets": ["proxy"]},
    }


def test_an_interpreter_result_reports_output_status_and_png() -> None:
    execution = SimpleNamespace(
        logs=SimpleNamespace(stdout=["73421\n"], stderr=[]),
        results=[SimpleNamespace(png="iVBOR"), SimpleNamespace(text="x")],
        error=None,
    )
    interpreter = SimpleNamespace(run_code=lambda code, context, timeout: execution)
    driver = native.BlaxelDriver()
    owned = driver.own(
        "interpreter_context",
        native.InterpreterContext(interpreter, SimpleNamespace(id="c1")),  # type: ignore[arg-type]
        lambda: {"result": "deleted"},
    )
    observed = driver.interpreter_run({"resource": owned}, {"code": "print(73421)"})
    assert observed == {"stdout": "73421\n", "stderr": "", "exit_code": 0, "image_data": ["iVBOR"]}


@pytest.mark.parametrize(
    "order", [("network_lockdown", "hidden_secrets"), ("hidden_secrets", "network_lockdown")]
)
def test_a_secret_route_and_a_lockdown_compose_in_either_order(order: tuple[str, str]) -> None:
    driver = native.BlaxelDriver()
    secret = driver.own("secret_value", "s3cret", lambda: {"result": "already_released"})
    gates = {
        "network_lockdown": {"policy": "allowlist_domains", "allow": ["pypi.org"]},
        "hidden_secrets": {"inject_into": ["receiver.example"]},
    }
    config = _config({"secret": {"resource": secret}, "requirements": {g: gates[g] for g in order}})
    network = cast(dict[str, Any], config["network"])
    assert network["firewall"] == {"rulesets": ["proxy"]}
    assert network["proxy"]["allowed_domains"] == ["pypi.org"]
    (route,) = network["proxy"]["routing"]
    assert route["destinations"] == ["receiver.example"]
    assert route["secrets"] == {"sps-secret": "s3cret"}
