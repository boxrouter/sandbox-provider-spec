# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""V11's §5.2 Blaxel operation and input mappings against the pinned SDK."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import pytest
from blaxel.core.client.models import SandboxLifecycle
from blaxel.core.sandbox.types import SandboxUpdateNetwork

from sandbox_provider_spec.driver import Reserved, Resource, Unsupported
from sandbox_provider_spec.drivers import blaxel as native
from sandbox_provider_spec.runner import Runner
from sandbox_provider_spec.suite import Test as Scenario


def _binding(
    sandbox: object,
    cleanup: Any = None,
) -> tuple[native.BlaxelDriver, dict[str, Resource]]:
    driver = native.BlaxelDriver()
    owned = driver.own(
        "sandbox", Reserved("sps-v11-test", sandbox), cleanup or (lambda: {"result": "deleted"})
    )
    return driver, {"resource": owned}


def test_unimplemented_rotation_cannot_prove_a_negative_capability() -> None:
    result = Runner(native.BlaxelDriver()).run_test(
        Scenario(
            "rotation",
            "Rotation needs a native mapping",
            ({"op": "secret.rotate"},),
            ({"gate": "hidden_secrets", "knob": "rotates", "value": False},),
        )
    )
    assert result["result"] == "not_run"
    assert result["reason"] == "native_secret_rotation_unimplemented"
    assert result["cleanup"] == []


def test_create_calls_the_pinned_sandbox_sdk(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, object]] = []
    instance = SimpleNamespace(metadata=SimpleNamespace(name="sps-v11-test"))

    def create(config: dict[str, object]) -> object:
        calls.append(config)
        return instance

    monkeypatch.setattr(native, "SyncSandboxInstance", SimpleNamespace(create=create))
    result = native.BlaxelDriver().call("create", None, {"resources": {"memory_min_mib": 2048}})
    assert len(calls) == 1 and calls[0]["memory"] == 2048
    owned = cast(Resource, result["resource"])
    assert cast(Reserved[Any], owned.native).native is instance


def test_allocation_observe_reads_the_sdk_runtime_memory(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    instance = SimpleNamespace(spec=SimpleNamespace(runtime=SimpleNamespace(memory=4096)))

    def get(name: str) -> object:
        calls.append(name)
        return instance

    monkeypatch.setattr(
        native,
        "SyncSandboxInstance",
        SimpleNamespace(get=get),
    )
    driver, target = _binding(None)
    cast(Reserved[object], target["resource"].native).name = "sps-v11-test"
    assert driver.call("allocation.observe", target, {}) == {"allocation": {"memory_min_mib": 4096}}
    assert calls == ["sps-v11-test"]


def test_destroy_calls_the_sdk_and_confirms_termination(monkeypatch: pytest.MonkeyPatch) -> None:
    deleted: list[str] = []
    monkeypatch.setattr(native, "INSTANCE", SimpleNamespace(delete=deleted.append))
    monkeypatch.setattr(
        native,
        "SyncSandboxInstance",
        SimpleNamespace(get=lambda name: SimpleNamespace(status="TERMINATED")),
    )
    driver, target = _binding(None, lambda: native.BlaxelDriver._delete("sps-v11-test"))  # pylint: disable=protected-access
    assert driver.call("destroy", target, {})["result"] == "deleted"
    assert deleted == ["sps-v11-test"]


def test_files_exists_uses_the_sdk_file_read() -> None:
    sandbox = SimpleNamespace(fs=SimpleNamespace(read_binary=lambda path: b"file"))
    _, target = _binding(sandbox)
    assert native.BlaxelDriver().call("files.exists", target, {"path": "/tmp/file"}) == {
        "exists": True
    }


def test_files_read_bytes_uses_the_sdk_file_read() -> None:
    sandbox = SimpleNamespace(fs=SimpleNamespace(read_binary=lambda path: b"\x00\xff"))
    _, target = _binding(sandbox)
    assert native.BlaxelDriver().call("files.read_bytes", target, {"path": "/tmp/file"}) == {
        "data": b"\x00\xff"
    }


def test_files_write_uses_the_sdk_binary_write() -> None:
    calls: list[tuple[str, bytes]] = []
    sandbox = SimpleNamespace(
        fs=SimpleNamespace(write_binary=lambda path, data: calls.append((path, data)))
    )
    _, target = _binding(sandbox)
    assert (
        native.BlaxelDriver().call("files.write", target, {"path": "/tmp/file", "data": "AP8="})
        == {}
    )
    assert calls == [("/tmp/file", b"\x00\xff")]


def test_idle_select_duration_calls_the_sdk_lifecycle_update(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, object]] = []
    instance = SimpleNamespace(
        update_lifecycle=lambda name, lifecycle: calls.append((name, lifecycle))
    )
    monkeypatch.setattr(native, "INSTANCE", instance)
    driver, target = _binding(None)
    assert driver.call("idle.select_duration", target, {"idle_seconds": 90}) == {}
    assert calls[0][0] == "sps-v11-test"
    assert cast(SandboxLifecycle, calls[0][1]).to_dict()["expirationPolicies"][0]["value"] == "90s"


def test_provider_artifact_image_prepare_borrows_an_image_reference() -> None:
    observed = native.BlaxelDriver().call(
        "image.prepare", None, {"source": "provider_artifact", "image": "blaxel/base:latest"}
    )
    assert cast(Resource, observed["resource"]).kind == "image_reference"


@pytest.mark.parametrize(
    ("policy", "settings", "expected"),
    [
        ("allowlist", {"allow": ["ok.example"]}, {"allowed_domains": ["ok.example"]}),
        ("allowlist", {"allow": []}, {"forbidden_domains": ["*"]}),
        ("deny_all", {}, {"forbidden_domains": ["*"]}),
        ("denylist", {"deny": ["bad.example"]}, {"forbidden_domains": ["bad.example"]}),
    ],
)
def test_create_maps_domain_policy_values(
    policy: str, settings: dict[str, object], expected: dict[str, object]
) -> None:
    network = native.BlaxelDriver._config(  # pylint: disable=protected-access
        {"requirements": {"network_lockdown": {"policy": policy, **settings}}}
    )["network"]
    assert network["proxy"] == expected  # type: ignore[index]


def test_create_open_policy_is_unsupported_because_the_firewall_cannot_be_removed() -> None:
    with pytest.raises(Unsupported) as caught:
        native.BlaxelDriver._config(  # pylint: disable=protected-access
            {"requirements": {"network_lockdown": {"policy": "open"}}}
        )
    assert str(caught.value) == "Blaxel's proxy firewall cannot be removed to provide open egress"


def test_http_rules_map_hosts_methods_and_paths_with_deny_precedence() -> None:
    config = native.BlaxelDriver._config(  # pylint: disable=protected-access
        {
            "requirements": {
                "network_lockdown": {
                    "policy": "allowlist",
                    "deny_wins": True,
                    "domain_traffic": "http_and_https",
                    "http_rules": True,
                    "allow": [{"hosts": ["api.example"], "methods": ["GET"], "paths": ["/ok/**"]}],
                    "deny": [
                        {"hosts": ["api.example"], "methods": ["POST"], "paths": ["/secret/**"]}
                    ],
                    "switchable": True,
                    "switches_to": ["denylist"],
                }
            }
        }
    )
    assert config["network"]["proxy"] == {  # type: ignore[index]
        "allowed_domains": ["GET:api.example/ok/*"],
        "forbidden_domains": ["POST:api.example/secret/*"],
    }


@pytest.mark.parametrize(
    ("rule", "expected"),
    [
        ({"hosts": ["files.example"]}, ["files.example"]),
        ({"hosts": ["files.example"], "methods": ["GET"]}, ["GET:files.example"]),
        ({"hosts": ["files.example"], "paths": ["/read/**"]}, ["files.example/read/*"]),
    ],
    ids=["create:hosts", "create:methods", "create:paths"],
)
def test_http_rule_input_parts_map_to_proxy_patterns(
    rule: dict[str, object], expected: list[str]
) -> None:
    config = native.BlaxelDriver._config(  # pylint: disable=protected-access
        {
            "requirements": {
                "network_lockdown": {
                    "policy": "allowlist",
                    "http_rules": True,
                    "allow": [rule],
                }
            }
        }
    )
    assert config["network"]["proxy"]["allowed_domains"] == expected  # type: ignore[index]


@pytest.mark.parametrize(
    ("case", "inputs", "reason"),
    [
        (
            "create:join",
            {"join": "sps-first"},
            "Blaxel's SDK has no documented sandbox join interface",
        ),
        (
            "create:private_network",
            {"requirements": {"private_network": {}}},
            "Blaxel's SDK does not document sandbox private-network joins",
        ),
        (
            "create:ip_version=ipv4",
            {"requirements": {"private_network": {"ip_version": "ipv4"}}},
            "Blaxel's SDK does not configure private-network IP versions",
        ),
        (
            "create:ip_version=ipv6",
            {"requirements": {"private_network": {"ip_version": "ipv6"}}},
            "Blaxel's SDK does not configure private-network IP versions",
        ),
        (
            "create:live_resize",
            {"requirements": {"live_resize": {}}},
            "Blaxel sandbox updates may reset state and do not guarantee live resize",
        ),
        (
            "create:shrinks",
            {"requirements": {"live_resize": {"shrinks": True}}},
            "Blaxel sandbox updates do not guarantee live shrinking",
        ),
        (
            "create:build_context",
            {"requirements": {"custom_images": {"source": "dockerfile", "build_context": True}}},
            "Blaxel's SDK does not build an image from a supplied context",
        ),
        (
            "create:image_config=user",
            {"requirements": {"custom_images": {"image_config": ["user"]}}},
            "Blaxel's sandbox SDK cannot set custom image user or workdir",
        ),
        (
            "create:image_config=workdir",
            {"requirements": {"custom_images": {"image_config": ["workdir"]}}},
            "Blaxel's sandbox SDK cannot set custom image user or workdir",
        ),
        (
            "create:source=private_oci",
            {"requirements": {"custom_images": {"source": "private_oci"}}},
            "Blaxel's SDK has no private OCI pull-credential setting",
        ),
        (
            "create:nested_virtualization",
            {"requirements": {"nested_virtualization": {}}},
            "Blaxel's sandbox SDK exposes no nested virtualization setting",
        ),
        (
            "create:ssh.credential=key",
            {"requirements": {"ssh": {"credential": "key"}}},
            "Blaxel's SDK has no SSH access or credential operation",
        ),
        (
            "create:ssh.credential=password",
            {"requirements": {"ssh": {"credential": "password"}}},
            "Blaxel's SDK has no SSH access or credential operation",
        ),
        (
            "create:ssh.credential=token",
            {"requirements": {"ssh": {"credential": "token"}}},
            "Blaxel's SDK has no SSH access or credential operation",
        ),
        (
            "create:egress_proxy",
            {"requirements": {"egress_proxy": {"protocol": "http"}}},
            "Blaxel exposes no caller-configurable egress proxy",
        ),
        (
            "create:workload_identity",
            {"requirements": {"workload_identity": {"delivery": "environment"}}},
            "Blaxel's sandbox SDK exposes no workload identity delivery",
        ),
        (
            "create:cuts_open_connections",
            {
                "requirements": {
                    "network_lockdown": {
                        "policy": "allowlist",
                        "allow": ["api.example"],
                        "switchable": True,
                        "switches_to": ["denylist"],
                        "cuts_open_connections": True,
                    }
                }
            },
            "Blaxel does not document closing established egress connections",
        ),
        (
            "create:switches_to=open",
            {
                "requirements": {
                    "network_lockdown": {
                        "policy": "allowlist",
                        "allow": ["api.example"],
                        "switchable": True,
                        "switches_to": ["open"],
                    }
                }
            },
            "Blaxel's proxy firewall cannot be removed to provide open egress",
        ),
        (
            "create:domain_traffic=https",
            {
                "requirements": {
                    "network_lockdown": {"policy": "allowlist", "domain_traffic": "https"}
                }
            },
            "Blaxel filters HTTP(S) domains, not separate traffic classes",
        ),
        (
            "create:domain_traffic=tls",
            {
                "requirements": {
                    "network_lockdown": {"policy": "allowlist", "domain_traffic": "tls"}
                }
            },
            "Blaxel filters HTTP(S) domains, not separate traffic classes",
        ),
        (
            "create:domain_traffic=all",
            {
                "requirements": {
                    "network_lockdown": {"policy": "allowlist", "domain_traffic": "all"}
                }
            },
            "Blaxel filters HTTP(S) domains, not separate traffic classes",
        ),
    ],
    ids=lambda case: str(case),
)
def test_create_unsupported_inputs_have_fixed_reasons(
    case: str, inputs: dict[str, object], reason: str
) -> None:
    del case
    with pytest.raises(Unsupported) as caught:
        native.BlaxelDriver._config(inputs)  # pylint: disable=protected-access
    assert str(caught.value) == reason


def test_create_maps_memory_and_read_only_volume_mounts() -> None:
    volume = Resource("volume", "sps-volume", lambda: {"result": "deleted"})
    config = native.BlaxelDriver._config(  # pylint: disable=protected-access
        {
            "resources": {"memory_min_mib": 2048},
            "volumes": [{"volume": {"resource": volume}, "path": "/data", "read_only": True}],
            "requirements": {"volumes": {"kind": "filesystem", "read_only_mounts": True}},
        }
    )
    assert config["memory"] == 2048
    assert config["volumes"] == [{"name": "sps-volume", "mount_path": "/data", "read_only": True}]


@pytest.mark.parametrize(
    ("policy", "settings", "expected"),
    [
        ("allowlist", {"allow": ["ok.example"]}, {"allowed_domains": ["ok.example"]}),
        ("allowlist", {"allow": []}, {"forbidden_domains": ["*"]}),
        ("deny_all", {}, {"forbidden_domains": ["*"]}),
        ("denylist", {"deny": ["bad.example"]}, {"forbidden_domains": ["bad.example"]}),
    ],
)
def test_network_update_calls_sdk_and_preserves_proxy_routes(
    monkeypatch: pytest.MonkeyPatch,
    policy: str,
    settings: dict[str, object],
    expected: dict[str, object],
) -> None:
    original_proxy = {
        "routing": [{"destinations": ["secret.example"], "headers": {"X-Key": "{{SECRET:k}}"}}],
        "bypass": ["internal.example"],
        "allowedDomains": ["stale.example"],
    }
    sandbox = SimpleNamespace(
        sandbox=SimpleNamespace(
            spec=SimpleNamespace(
                network={"proxy": original_proxy, "firewall": {"rulesets": ["proxy"]}}
            )
        )
    )
    calls: list[tuple[str, SandboxUpdateNetwork]] = []
    monkeypatch.setattr(
        native,
        "INSTANCE",
        SimpleNamespace(update_network=lambda name, update: calls.append((name, update))),
    )
    driver, target = _binding(sandbox)
    assert driver.call("network.update", target, {"policy": policy, **settings}) == {}
    name, update = calls[0]
    assert name == "sps-v11-test"
    assert isinstance(update, SandboxUpdateNetwork)
    updated_network = cast(dict[str, Any], update.network)
    assert updated_network["proxy"] == {
        **{key: value for key, value in original_proxy.items() if key != "allowedDomains"},
        **expected,
    }
    assert updated_network["firewall"] == {"rulesets": ["proxy"]}


def test_network_update_open_is_unsupported_because_the_firewall_is_immutable() -> None:
    driver = native.BlaxelDriver()
    with pytest.raises(Unsupported) as caught:
        driver.call("network.update", None, {"policy": "open"})
    assert str(caught.value) == "Blaxel's proxy firewall cannot be removed to provide open egress"


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("context", "/tmp/context"),
        ("password", "private"),
        ("username", "private"),
        ("source", "private_oci"),
    ],
    ids=[
        "image.prepare:context",
        "image.prepare:password",
        "image.prepare:username",
        "image.prepare:source=private_oci",
    ],
)
def test_private_image_prepare_inputs_are_unsupported(key: str, value: str) -> None:
    with pytest.raises(Unsupported) as caught:
        native.BlaxelDriver().call("image.prepare", None, {key: value})
    assert str(caught.value) == "Blaxel's SDK cannot authenticate or build a caller-provided image"


@pytest.mark.parametrize("credential", ["key", "password", "token"])
def test_ssh_access_credentials_are_unsupported(credential: str) -> None:
    driver = native.BlaxelDriver()
    with pytest.raises(Unsupported) as caught:
        driver.call("ssh.access", None, {"credential": credential})
    assert str(caught.value) == driver.unsupported["ssh.access"]


def test_resize_resources_are_explicitly_unsupported() -> None:
    driver = native.BlaxelDriver()
    with pytest.raises(Unsupported) as caught:
        driver.call("resize", None, {"resources": {"memory_min_mib": 4096}})
    assert str(caught.value) == driver.unsupported["resize"]


def test_run_as_root_bash_script_is_explicitly_unsupported() -> None:
    driver = native.BlaxelDriver()
    with pytest.raises(Unsupported) as caught:
        driver.call("run.as_root", None, {"bash_script": "id -u"})
    assert str(caught.value) == driver.unsupported["run.as_root"]


def test_preview_link_calls_the_sdk_preview_create() -> None:
    calls: list[dict[str, object]] = []
    preview = SimpleNamespace(
        name="sps-3000-public",
        spec=SimpleNamespace(url="https://preview.example"),
    )

    def create(request: dict[str, object]) -> object:
        calls.append(request)
        return preview

    sandbox = SimpleNamespace(
        previews=SimpleNamespace(create=create), metadata=SimpleNamespace(name="sps-v11-test")
    )
    driver, target = _binding(sandbox)
    observed = driver.call("preview.link", target, {"port": 3000})
    assert observed["url"] == "https://preview.example"
    assert calls[0]["spec"] == {"port": 3000, "public": True}


def test_preview_revoke_calls_the_sdk_preview_delete() -> None:
    calls: list[str] = []

    def delete(name: str) -> None:
        calls.append(name)

    sandbox = SimpleNamespace(
        metadata=SimpleNamespace(name="sps-v11-test"), previews=SimpleNamespace(delete=delete)
    )
    preview = SimpleNamespace(name="sps-preview")
    driver = native.BlaxelDriver()
    link = native.Link(cast(Any, sandbox), cast(Any, preview), None)
    owned = driver.own(
        "preview",
        link,
        lambda: native.BlaxelDriver._delete_preview(link),  # pylint: disable=protected-access
    )
    assert driver.call("preview.revoke", {"resource": owned}, {}) == {
        "kind": "preview",
        "result": "deleted",
    }
    assert calls == ["sps-preview"]


def test_process_start_calls_the_sdk_nonblocking_process_api() -> None:
    calls: list[dict[str, object]] = []

    def exec_(request: dict[str, object]) -> None:
        calls.append(request)

    sandbox = SimpleNamespace(process=SimpleNamespace(exec=exec_))
    driver, target = _binding(sandbox)
    observed = driver.call("process.start", target, {"bash_script": "sleep 5"})
    assert observed["identity"] == calls[0]["name"]
    assert calls[0]["wait_for_completion"] is False
    assert "sleep 5" in str(calls[0]["command"])
    with pytest.raises(Unsupported, match="named-user process"):
        driver.call("process.start", target, {"bash_script": "sleep 5", "run_as": "runner"})


def test_run_calls_the_sdk_process_api() -> None:
    calls: list[dict[str, object]] = []

    def exec_(request: dict[str, object]) -> object:
        calls.append(request)
        return SimpleNamespace(stdout="ok", stderr="", exit_code=0)

    sandbox = SimpleNamespace(process=SimpleNamespace(exec=exec_))
    driver, target = _binding(sandbox)
    observed = driver.call("run", target, {"bash_script": "printf ok"})
    assert observed == {"stdout": "ok", "stderr": "", "exit_code": 0}
    assert calls[0]["wait_for_completion"] is True
    assert "printf ok" in str(calls[0]["command"])
    with pytest.raises(Unsupported, match="named-user command"):
        driver.call("run", target, {"bash_script": "printf ok", "run_as": "runner"})


def test_volume_create_calls_the_pinned_volume_sdk(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(
        native,
        "SyncVolumeInstance",
        SimpleNamespace(create=lambda config: calls.append(config)),
    )
    observed = native.BlaxelDriver().call("volume.create", None, {"kind": "filesystem"})
    assert cast(Resource, observed["resource"]).kind == "volume"
    assert calls == [{"name": calls[0]["name"], "size": 1024}]


def test_snapshot_delete_again_calls_sdk_snapshot_delete_again() -> None:
    deleted: list[str] = []

    def delete_snapshot(identity: str) -> None:
        deleted.append(identity)

    sandbox = SimpleNamespace(
        delete_snapshot=delete_snapshot,
        list_snapshots=lambda: [],
    )
    snapshot = native.Snapshot(cast(Any, sandbox), "snapshot-1")
    driver = native.BlaxelDriver()
    owned = driver.own(
        "snapshot",
        snapshot,
        lambda: native.BlaxelDriver._delete_snapshot(snapshot),  # pylint: disable=protected-access
    )
    target = {"resource": owned}
    assert driver.call("snapshot.delete", target, {}) == {
        "kind": "snapshot",
        "result": "deleted",
    }
    result = driver.call("snapshot.delete_again", target, {})
    assert result == {"native_delete_attempted": True}
    assert deleted == ["snapshot-1", "snapshot-1"]


def test_secret_create_owns_a_write_only_value() -> None:
    observed = native.BlaxelDriver().call("secret.create", None, {"value": "opaque"})
    owned = cast(Resource, observed["resource"])
    assert owned.kind == "secret_value"
    assert owned.native == "opaque"


@pytest.mark.parametrize(
    "operation",
    [
        "desktop.click",
        "desktop.key",
        "desktop.live_link",
        "desktop.screenshot",
        "desktop.start",
        "desktop.type",
        "lifetime.observe_paused_countdown",
        "long_running.observe",
        "snapshot.restore_begin",
        "snapshot.restore_wait",
        "snapshot.retention",
        "tcp.link",
        "terminal.disconnect",
        "terminal.output",
        "terminal.reattach",
        "terminal.write",
        "volume.observe_kind",
        "volume.read_bytes",
        "volume.reload",
    ],
)
def test_documented_absent_operations_have_fixed_unsupported_reasons(operation: str) -> None:
    driver = native.BlaxelDriver()
    with pytest.raises(Unsupported) as caught:
        driver.call(operation, None, {})
    assert str(caught.value) == driver.unsupported[operation]
