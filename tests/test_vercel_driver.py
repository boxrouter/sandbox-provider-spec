# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The Vercel driver's own logic: name reservation, concurrency waits, cleanup, pause."""

from __future__ import annotations

from typing import Any, cast

import httpx2
import pytest
from vercel.sandbox.sync import NetworkPolicy, SandboxApiError

from sandbox_provider_spec.driver import NativeFailure, NotRun, Reserved, Unsupported
from sandbox_provider_spec.drivers import vercel as native
from sandbox_provider_spec.runner import Runner
from sandbox_provider_spec.suite import Test as Scenario


@pytest.fixture(autouse=True)
def _no_snapshots(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(native, "query_snapshots", lambda *, name: iter(()))


def _error(status: int) -> SandboxApiError:
    request = httpx2.Request("POST", "https://api.vercel.com/")
    return SandboxApiError(httpx2.Response(status, request=request), f"HTTP {status}")


class Sandbox:
    def __init__(self, calls: list[str], *, persistent: bool = False) -> None:
        self.calls = calls
        self.persistent = persistent

    def destroy(self, *, delete_orphan_snapshots: bool) -> None:
        self.calls.append(f"destroy:{delete_orphan_snapshots}")


def _lookup(calls: list[str], existing: set[str]) -> Any:
    def get_sandbox(*, name: str) -> Sandbox:
        calls.append(f"get:{name}")
        if name not in existing:
            raise _error(404)
        existing.discard(name)
        return Sandbox(calls)

    return get_sandbox


def test_a_failed_create_cleans_the_reserved_name(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    existing: set[str] = set()

    def create_sandbox(*, name: str, **options: object) -> Sandbox:
        del options
        existing.add(name)
        raise RuntimeError("readiness failed after allocation")

    monkeypatch.setattr(native, "create_sandbox", create_sandbox)
    monkeypatch.setattr(native, "get_sandbox", _lookup(calls, existing))
    driver = native.VercelDriver()
    result = Runner(driver).run_test(
        Scenario("example.create", "", ({"op": "create", "as": "box"},), (), ())
    )
    assert result["result"] == "error"
    assert result["cleanup"] == [{"kind": "sandbox", "result": "deleted"}]
    assert calls[1] == "destroy:True"


def test_a_create_waits_out_the_concurrency_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    answers: list[object] = [_error(429), _error(429), Sandbox([])]

    def create_sandbox(**options: object) -> object:
        del options
        answer = answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(native, "create_sandbox", create_sandbox)
    monkeypatch.setattr("sandbox_provider_spec.drivers.vercel.time.sleep", lambda seconds: None)
    observed = native.VercelDriver().create(None, {})
    assert str(observed["identity"]).startswith("sps-")
    assert answers == []


def test_any_other_refusal_is_not_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    def create_sandbox(**options: object) -> object:
        del options
        raise _error(400)

    monkeypatch.setattr(native, "create_sandbox", create_sandbox)
    with pytest.raises(SandboxApiError):
        native.VercelDriver().create(None, {})


def test_cleanup_refuses_an_unconfirmed_deletion(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(native, "get_sandbox", lambda *, name: Sandbox([]))
    times = iter([0.0, 121.0])
    monkeypatch.setattr("sandbox_provider_spec.driver.time.monotonic", lambda: next(times))
    with pytest.raises(NativeFailure, match="^cleanup_not_confirmed$"):
        native.VercelDriver._delete("sps-example")  # pylint: disable=protected-access


def test_a_sandbox_created_without_pause_resume_is_not_paused() -> None:
    driver = native.VercelDriver()
    holder = Reserved("sps-example", Sandbox([], persistent=False))
    owned = driver.own("sandbox", holder, lambda: {"result": "deleted"})
    with pytest.raises(NotRun, match="^pause_resume_not_requested$"):
        driver.pause({"resource": owned}, {})


def test_the_lifetime_ends_in_stopped_or_destroyed_only() -> None:
    with pytest.raises(Unsupported):
        native.VercelDriver().create(None, {"at_end": "paused"})


def test_a_stopped_sandbox_that_was_not_persistent_is_destroyed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Stopped:
        status = "stopped"

        def __init__(self, persistent: bool) -> None:
            self.persistent = persistent

    driver = native.VercelDriver()
    owned = driver.own("sandbox", Reserved("sps-example"), lambda: {"result": "deleted"})
    monkeypatch.setattr(native, "get_sandbox", lambda *, name: Stopped(False))
    assert driver.get({"resource": owned}, {}) == {"state": "destroyed"}
    monkeypatch.setattr(native, "get_sandbox", lambda *, name: Stopped(True))
    assert driver.get({"resource": owned}, {}) == {"state": "stopped"}


def test_a_plan_usage_limit_is_not_run(monkeypatch: pytest.MonkeyPatch) -> None:
    def create_sandbox(**options: object) -> object:
        del options
        raise _error(402)

    monkeypatch.setattr(native, "create_sandbox", create_sandbox)
    with pytest.raises(NotRun, match="^account_quota_exhausted$"):
        native.VercelDriver().create(None, {})


def test_gates_are_chosen_at_creation() -> None:
    options = native.VercelDriver._options(  # pylint: disable=protected-access
        {
            "requirements": {
                "network_lockdown": {"policy": "allowlist_domains", "allow": ["example.com"]},
                "previews": {"access": "public", "ports": [3000]},
                "pause_resume": {"keeps": "files_only"},
            },
            "resources": {"cpu_min": 2, "memory_min_mib": 4096},
        }
    )
    assert options["persistent"] is True
    assert options["ports"] == [3000]
    assert options["resources"].vcpus == 2
    with pytest.raises(Unsupported):
        native.VercelDriver._options(  # pylint: disable=protected-access
            {"requirements": {"previews": {"access": "private", "ports": [3000]}}}
        )


def test_deletion_waits_for_the_drive_to_be_released(monkeypatch: pytest.MonkeyPatch) -> None:
    class Drive:
        def __init__(self, holder: str | None) -> None:
            self.current_sandbox_name = holder

    monkeypatch.setattr(native, "get_sandbox", _lookup([], set()))
    answers = [[Drive("sps-example")], [Drive(None)]]
    monkeypatch.setattr(native, "query_drives", lambda: answers.pop(0))
    monkeypatch.setattr("sandbox_provider_spec.driver.time.sleep", lambda seconds: None)
    deleted = native.VercelDriver._delete("sps-example", mounted=True)  # pylint: disable=protected-access
    assert deleted == {"result": "deleted"}
    assert answers == []


def test_a_drive_held_by_another_sandbox_is_in_use(monkeypatch: pytest.MonkeyPatch) -> None:
    def create_sandbox(**options: object) -> object:
        del options
        request = httpx2.Request("POST", "https://api.vercel.com/")
        response = httpx2.Response(409, request=request)
        raise SandboxApiError(response, "HTTP 409", data={"error": {"code": "drive_attached"}})

    monkeypatch.setattr(native, "create_sandbox", create_sandbox)
    with pytest.raises(NativeFailure, match="^volume_in_use$"):
        native.VercelDriver().create(None, {})


def test_a_process_that_has_exited_or_stopped_is_cleaned() -> None:
    class Ended:
        returncode = None

        def __init__(self, status: int, code: str) -> None:
            self.status, self.code = status, code

        def refresh(self) -> Ended:
            return self

        def kill(self) -> None:
            request = httpx2.Request("POST", "https://api.vercel.com/")
            response = httpx2.Response(self.status, request=request)
            raise SandboxApiError(response, "refused", data={"error": {"code": self.code}})

    kill = native.VercelDriver._kill  # pylint: disable=protected-access
    assert kill(Ended(404, "command_not_found_or_exited")) == {"result": "deleted"}  # type: ignore[arg-type]
    assert kill(Ended(410, "sandbox_stopped")) == {"result": "deleted"}  # type: ignore[arg-type]
    with pytest.raises(SandboxApiError):
        kill(Ended(500, "internal"))  # type: ignore[arg-type]


def test_an_automatic_snapshot_left_by_a_stop_is_deleted(monkeypatch: pytest.MonkeyPatch) -> None:
    class Snapshot:
        def __init__(self, status: str) -> None:
            self.id = "snap_example"
            self.status = status

        def delete(self) -> None:
            statuses.append("deleted")

    statuses = ["created"]
    monkeypatch.setattr(native, "query_snapshots", lambda *, name: iter([Snapshot("created")]))
    monkeypatch.setattr(native, "get_sandbox", _lookup([], {"sps-example"}))
    monkeypatch.setattr(native, "get_snapshot", lambda *, snapshot_id: Snapshot(statuses[-1]))
    deleted = native.VercelDriver._delete("sps-example")  # pylint: disable=protected-access
    assert deleted == {"result": "deleted"}
    assert statuses == ["created", "deleted"]


def test_an_ip_denylist_keeps_every_domain_and_denies_the_ranges() -> None:
    policy = native._policy({"policy": "denylist_ips", "deny": ["10.0.0.0/8"]})  # pylint: disable=protected-access
    assert policy.mode == "custom"
    assert "*" in policy.allow
    with pytest.raises(Unsupported):
        native._policy({"policy": "denylist_domains", "deny": ["example.com"]})  # pylint: disable=protected-access


def test_root_runs_through_the_sdk_selector_and_policy_updates_live(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: dict[str, object] = {}

    class Box:
        def run_process(self, *args: object, **kwargs: object) -> object:
            calls["sudo"] = kwargs["sudo"]
            return type("Done", (), {"stdout": "0\n", "stderr": "", "returncode": 0})()

        def update_network_policy(self, policy: object) -> None:
            calls["policy"] = policy

    driver = native.VercelDriver()
    owned = driver.own("sandbox", Reserved("sps-example", Box()), lambda: {"result": "deleted"})
    target = {"resource": owned}
    assert driver.run_as_root(target, {"bash_script": "id -u"})["exit_code"] == 0
    assert calls["sudo"] is True
    assert driver.network_update(target, {"policy": "deny_all"}) == {}
    assert cast(NetworkPolicy, calls["policy"]).mode == "deny-all"


def test_a_secret_is_a_header_on_its_hosts_within_the_requested_lockdown() -> None:
    open_policy = native._with_secret("s3cret", ["receiver.example"], None)  # pylint: disable=protected-access
    assert set(open_policy.allow) == {"*", "receiver.example"}
    locked = native._with_secret(  # pylint: disable=protected-access
        "s3cret", ["receiver.example"], {"policy": "allowlist_domains", "allow": ["pypi.org"]}
    )
    assert set(locked.allow) == {"pypi.org", "receiver.example"}
    (rule,) = locked.allow["receiver.example"]
    assert rule.transform[0].headers == {"X-SPS-Secret": "s3cret"}
    with pytest.raises(Unsupported):
        native._with_secret("s3cret", ["h"], {"policy": "allowlist_ips", "allow": ["1.1.1.1/32"]})  # pylint: disable=protected-access


def test_a_rotation_replaces_the_running_policy_with_the_new_value() -> None:
    updates: list[NetworkPolicy] = []

    class Box:
        def update_network_policy(self, policy: NetworkPolicy) -> None:
            updates.append(policy)

    driver = native.VercelDriver()
    secret = driver.own(
        "secret_value",
        native.SecretValue("old", {"policy": "allowlist_domains", "allow": ["pypi.org"]}),
        lambda: {"result": "already_released"},
    )
    box = driver.own("sandbox", Reserved("sps-example", Box()), lambda: {"result": "deleted"})
    driver.secret_rotate(
        {"resource": secret},
        {"value": "new", "sandbox": {"resource": box}, "hosts": ["receiver.example"]},
    )
    (policy,) = updates
    assert set(policy.allow) == {"pypi.org", "receiver.example"}
    assert policy.allow["receiver.example"][0].transform[0].headers == {"X-SPS-Secret": "new"}


def test_a_zero_timeout_sets_no_command_deadline() -> None:
    kill_after = native._kill_after  # pylint: disable=protected-access
    assert kill_after({"timeout_ms": 0}) is None
    assert kill_after({"timeout_ms": 1500}) == 1.5
    assert kill_after({}) == 15.0


def test_bare_ipv4_entries_are_single_address_ranges() -> None:
    cidrs = native._cidrs  # pylint: disable=protected-access
    assert cidrs(["1.1.1.1", "1.0.0.0/24", "192.0.2.7/32"]) == [
        "1.1.1.1/32",
        "1.0.0.0/24",
        "192.0.2.7/32",
    ]
