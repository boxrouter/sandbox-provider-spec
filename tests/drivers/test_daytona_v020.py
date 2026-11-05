# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Offline conformance checks for the Daytona 0.220.0 reference driver."""

from __future__ import annotations

import base64
import re
from collections.abc import Callable, Mapping
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from daytona import Resources
from daytona.common.volume import Volume
from daytona_api_client.models.volume_state import VolumeState

from sandbox_provider_spec.driver import NotRun, Resource, Unsupported
from sandbox_provider_spec.drivers import daytona as native


class SpyTree:
    """A tiny lazy object tree with pytest-friendly call recording."""

    def __getattr__(self, name: str) -> Any:
        child = Spy() if name != "return_value" else SpyTree()
        setattr(self, name, child)
        return child


class Spy(SpyTree):
    cpu: Any
    memory: Any
    id: Any
    auto_stop_interval: Any
    auto_pause_interval: Any
    session_id: Any

    def __init__(self, **attributes: Any) -> None:
        self.calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        self.return_value: Any = SpyTree()
        self.side_effect: Callable[..., Any] | None = None
        for name, value in attributes.items():
            setattr(self, name, value)

    def __getattr__(self, name: str) -> Any:
        return super().__getattr__(name)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        self.calls.append((args, kwargs))
        if self.side_effect is not None:
            return self.side_effect(*args, **kwargs)
        return self.return_value

    @property
    def call_args(self) -> SimpleNamespace:
        args, kwargs = self.calls[-1]
        return SimpleNamespace(args=args, kwargs=kwargs)

    def assert_called_once_with(self, *args: Any, **kwargs: Any) -> None:
        assert self.calls == [(args, kwargs)]

    def assert_not_called(self) -> None:
        assert self.calls == []


class StatefulNetworkSandbox:
    """Model the SDK's documented network policy updates for transition checks."""

    def __init__(self) -> None:
        self.network_block_all = True
        self.network_allow_list: str | None = None
        self.domain_allow_list: str | None = None

    def update_network_settings(
        self,
        *,
        network_block_all: bool | None = None,
        network_allow_list: str | None = None,
        domain_allow_list: str | None = None,
        request_timeout: float | None = None,
    ) -> None:
        del request_timeout
        if network_block_all is False:
            self.network_block_all = False
            self.network_allow_list = None
            self.domain_allow_list = None
        elif network_block_all is True:
            self.network_block_all = True
        if network_allow_list is not None:
            self.network_block_all = False
            self.network_allow_list = network_allow_list
        if domain_allow_list is not None:
            self.network_block_all = False
            self.domain_allow_list = domain_allow_list


def target(value: object, kind: str = "sandbox") -> dict[str, Resource]:
    return {"resource": Resource(kind, value, lambda: {"result": "deleted"})}


def append_then_return(calls: list[dict[str, object]], result: object) -> Callable[..., object]:
    def record(request: dict[str, object], *args: object, **kwargs: object) -> object:
        del args, kwargs
        calls.append(request)
        return result

    return record


def make_driver(
    monkeypatch: pytest.MonkeyPatch,
    client: object | None = None,
    execution_class: str = "container",
    fixtures: Mapping[str, object] | None = None,
) -> native.DaytonaDriver:
    selected = client if client is not None else Spy()
    monkeypatch.setattr(native, "Daytona", lambda config: selected)
    return native.DaytonaDriver(execution_class, fixtures or {})


def test_owned_resource_names_include_task_id(monkeypatch: pytest.MonkeyPatch) -> None:
    driver = make_driver(monkeypatch, fixtures={"sps_task_id": "V16"})

    assert re.fullmatch(r"sps-r[0-9a-f]{8}-[0-9a-z]{5}-V16-[0-9a-f]{32}", driver._new_name())


def test_allocation_observe_uses_fresh_sdk_values(monkeypatch: pytest.MonkeyPatch) -> None:
    sandbox = SimpleNamespace(id="native-id", cpu=4, memory=8)
    client = Spy()
    client.get.return_value = sandbox
    driver = make_driver(monkeypatch, client)

    assert driver.call("allocation.observe", target(SimpleNamespace(id="native-id")), {}) == {
        "allocation": {"cpu_min": 4, "memory_min_mib": 8192}
    }
    client.get.assert_called_once_with("native-id", request_timeout=30)


def test_create_maps_daytona_snapshot_request(monkeypatch: pytest.MonkeyPatch) -> None:
    params: list[dict[str, object]] = []
    sandbox = SimpleNamespace(id="created-id", sandbox_class="container", gpu=False)
    client = Spy()
    client.create.side_effect = append_then_return(params, sandbox)
    monkeypatch.setattr(native, "CreateSandboxFromSnapshotParams", lambda **values: values)
    driver = make_driver(monkeypatch, client)

    result = driver.call("create", None, {"requirements": {}, "lifetime_seconds": 120})

    assert result["identity"] == "created-id"
    assert params == [
        {"env_vars": {}, "name": params[0]["name"], "ttl_minutes": 2, "snapshot": None}
    ]
    assert cast(str, params[0]["name"]).startswith("sps-")
    assert client.create.call_args.kwargs == {"timeout": 60}


def test_tagged_names_reach_daytona_creation_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    client = Spy()
    client.snapshot.create.return_value = SimpleNamespace(id="sized-image")
    client.create.return_value = SimpleNamespace(
        id="created-id", sandbox_class="container", gpu=False
    )
    client.secret.create.return_value = SimpleNamespace(id="secret-id", name="owned")
    volume = Volume.model_construct(name="volume", state=VolumeState.READY)
    client.volume.create.return_value = volume
    monkeypatch.setattr(native, "CreateSandboxFromSnapshotParams", lambda **values: values)
    monkeypatch.setattr(native, "CreateSnapshotParams", lambda **values: values)
    monkeypatch.setattr(native, "CreateSecretParams", lambda **values: values)
    driver = make_driver(monkeypatch, client, fixtures={"sps_task_id": "V16"})
    expected = re.compile(r"sps-r[0-9a-f]{8}-[0-9a-z]{5}-V16-[0-9a-f]{32}")

    driver.create(None, {"resources": {"cpu_min": 2}})
    driver.call("secret.create", None, {"value": "test-value"})
    driver.call("volume.create", None, {})

    assert expected.fullmatch(client.snapshot.create.call_args.args[0]["name"])
    assert expected.fullmatch(client.create.call_args.args[0]["name"])
    assert expected.fullmatch(client.secret.create.call_args.args[0]["name"])
    assert expected.fullmatch(client.volume.create.call_args.args[0])


@pytest.mark.parametrize(
    ("gate", "settings", "execution_class", "reason"),
    [
        (
            "network_lockdown",
            {"policy": "denylist", "deny": ["example.com"]},
            "container",
            "denylists",
        ),
        (
            "network_lockdown",
            {"policy": "allowlist", "deny_wins": True, "allow": ["example.com"]},
            "container",
            "precedence",
        ),
        (
            "network_lockdown",
            {"policy": "allowlist", "deny": ["example.com"], "allow": ["other.com"]},
            "container",
            "denylists",
        ),
        (
            "network_lockdown",
            {"policy": "allowlist", "http_rules": True, "allow": []},
            "container",
            "HTTP method",
        ),
        (
            "network_lockdown",
            {
                "policy": "allowlist",
                "allow": [{"hosts": ["example.com"], "methods": ["GET"], "paths": ["/"]}],
            },
            "container",
            "HTTP rule",
        ),
        (
            "network_lockdown",
            {"policy": "allowlist", "domain_traffic": "all", "allow": ["example.com"]},
            "container",
            "per-domain",
        ),
        (
            "network_lockdown",
            {"policy": "allowlist", "domain_traffic": "http_and_https", "allow": ["example.com"]},
            "container",
            "per-domain",
        ),
        (
            "network_lockdown",
            {"policy": "allowlist", "domain_traffic": "https", "allow": ["example.com"]},
            "container",
            "per-domain",
        ),
        (
            "network_lockdown",
            {"policy": "allowlist", "domain_traffic": "tls", "allow": ["example.com"]},
            "container",
            "per-domain",
        ),
        (
            "network_lockdown",
            {"policy": "allowlist", "cuts_open_connections": True, "allow": ["example.com"]},
            "container",
            "open connections",
        ),
        (
            "network_lockdown",
            {"policy": "allowlist", "cuts_open_connections": False, "allow": ["example.com"]},
            "container",
            "open connections",
        ),
        (
            "network_lockdown",
            {"policy": "allowlist", "allow": ["*.example.com"]},
            "container",
            "wildcard",
        ),
        (
            "network_lockdown",
            {"policy": "allowlist", "allow": ["2001:db8::/32"]},
            "container",
            "IPv4 CIDRs",
        ),
        (
            "network_lockdown",
            {"policy": "allowlist", "switches_to": ["denylist"], "allow": ["example.com"]},
            "container",
            "denylist",
        ),
        ("private_network", {"ip_version": "ipv6"}, "container", "IPv6 selector"),
        ("ssh", {"credential": "password"}, "container", "token credentials"),
        ("ssh", {"credential": "key"}, "container", "token credentials"),
        ("live_resize", {"shrinks": True}, "container", "increases only"),
        ("volumes", {"read_only_mounts": True}, "container", "read-only selector"),
        ("nested_virtualization", {}, "container", "Linux VM sandboxes"),
    ],
)
def test_create_refuses_unexpressible_gate_settings_before_allocation(
    monkeypatch: pytest.MonkeyPatch,
    gate: str,
    settings: dict[str, object],
    execution_class: str,
    reason: str,
) -> None:
    client = Spy()
    driver = make_driver(monkeypatch, client, execution_class)

    with pytest.raises(Unsupported, match=reason):
        driver.create(None, {"requirements": {gate: settings}})
    client.create.assert_not_called()


@pytest.mark.parametrize(
    ("settings", "expected"),
    [
        ({"policy": "deny_all"}, {"network_block_all": True}),
        ({"policy": "open"}, {"network_block_all": False}),
        ({"policy": "allowlist", "allow": []}, {"network_block_all": True}),
        (
            {"policy": "allowlist", "allow": ["203.0.113.0/24", "example.org"]},
            {"network_allow_list": "203.0.113.0/24", "domain_allow_list": "example.org"},
        ),
        (
            {"policy": "allowlist", "allow": ["203.0.113.7", "daytona.io"]},
            {"network_allow_list": "203.0.113.7/32", "domain_allow_list": "daytona.io"},
        ),
    ],
)
def test_create_maps_supported_network_settings(
    monkeypatch: pytest.MonkeyPatch, settings: dict[str, object], expected: dict[str, object]
) -> None:
    captured: list[dict[str, object]] = []
    client = Spy()
    sandbox = SimpleNamespace(id="created-id", sandbox_class="container", gpu=False)
    client.create.side_effect = append_then_return(captured, sandbox)
    monkeypatch.setattr(native, "CreateSandboxFromSnapshotParams", lambda **values: values)
    driver = make_driver(monkeypatch, client)

    driver.create(None, {"requirements": {"network_lockdown": settings}})

    request = captured[0]
    for key, value in expected.items():
        assert request[key] == value


def test_create_maps_linked_private_network_to_ephemeral_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[dict[str, object]] = []
    client = Spy()
    sandbox = SimpleNamespace(id="child", sandbox_class="container", gpu=False)
    client.create.side_effect = append_then_return(captured, sandbox)
    monkeypatch.setattr(native, "CreateSandboxFromSnapshotParams", lambda **values: values)
    driver = make_driver(monkeypatch, client)
    parent = SimpleNamespace(id="parent-id")

    driver.create(
        None,
        {"requirements": {"private_network": {"ip_version": "ipv4"}}, "join": target(parent)},
    )

    assert captured[0]["linked_sandbox"] == "parent-id"
    assert captured[0]["ephemeral"] is True
    assert captured[0]["auto_delete_interval"] == 0


def test_create_maps_kvm_ssh_and_switchable_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[dict[str, object]] = []
    client = Spy()
    sandbox = SimpleNamespace(id="created-id", sandbox_class="linux-vm", gpu=False)
    client.create.side_effect = append_then_return(captured, sandbox)
    monkeypatch.setattr(native, "CreateSandboxFromSnapshotParams", lambda **values: values)
    monkeypatch.setattr(native, "Daytona", lambda config: client)
    driver = native.DaytonaDriver("vm", {"daytona_vm_snapshot": "vm-base"})

    driver.create(
        None,
        {
            "requirements": {
                "nested_virtualization": {},
                "ssh": {"credential": "token"},
                "network_lockdown": {
                    "policy": "allowlist",
                    "allow": ["example.com"],
                    "switchable": True,
                    "switches_to": ["deny_all"],
                },
                "live_resize": {"shrinks": False},
            }
        },
    )

    assert captured[0]["kvm"] is True
    assert captured[0]["domain_allow_list"] == "example.com"
    assert "switches_to" not in captured[0]


@pytest.mark.parametrize("image_config", ["env", "workdir", "user"])
def test_create_uses_built_daytona_image_for_each_image_config_value(
    monkeypatch: pytest.MonkeyPatch, image_config: str
) -> None:
    captured: list[dict[str, object]] = []
    client = Spy()
    sandbox = SimpleNamespace(id="created-id", sandbox_class="container", gpu=False)
    client.create.side_effect = append_then_return(captured, sandbox)
    monkeypatch.setattr(native, "CreateSandboxFromSnapshotParams", lambda **values: values)
    driver = make_driver(monkeypatch, client)
    built_image = target("snapshot-image", "image")

    driver.create(
        None,
        {
            "image": built_image,
            "requirements": {"custom_images": {"image_config": [image_config]}},
        },
    )

    assert captured[0]["snapshot"] == "snapshot-image"


def test_create_build_context_input_is_used_by_the_bound_image(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = Spy()
    client.create.return_value = SimpleNamespace(
        id="created-id", sandbox_class="container", gpu=False
    )
    monkeypatch.setattr(native, "CreateSandboxFromSnapshotParams", lambda **values: values)
    driver = make_driver(monkeypatch, client)

    driver.create(
        None,
        {
            "image": target("context-image", "image"),
            "requirements": {"custom_images": {"source": "dockerfile", "build_context": True}},
        },
    )

    assert client.create.call_args.args[0]["snapshot"] == "context-image"


def test_create_rounds_memory_minimum_up_to_supported_gib(monkeypatch: pytest.MonkeyPatch) -> None:
    client = Spy()
    client.snapshot.create.return_value = SimpleNamespace(id="sized-image")
    client.create.return_value = SimpleNamespace(
        id="created-id", sandbox_class="container", gpu=False
    )
    driver = make_driver(monkeypatch, client)

    driver.create(None, {"resources": {"memory_min_mib": 1025}})

    resources = client.snapshot.create.call_args.args[0].resources
    assert resources.memory == 2
    assert resources.cpu is None


@pytest.mark.parametrize("path", ["Dockerfile", "./Dockerfile"])
def test_image_prepare_context_cannot_replace_dockerfile(
    monkeypatch: pytest.MonkeyPatch, path: str
) -> None:
    client = Spy()
    driver = make_driver(monkeypatch, client)
    with pytest.raises(ValueError, match="cannot replace"):
        driver.image_prepare(
            None,
            {
                "source": "dockerfile",
                "dockerfile": "FROM python:3.12-slim",
                "context": {path: "FROM scratch"},
            },
        )
    client.snapshot.create.assert_not_called()


def test_image_prepare_builds_dockerfile_with_supplied_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    dockerfile = (
        "FROM python:3.12-slim\nENV SPS_IMAGE_ENV=from-image\nWORKDIR /workspace\nUSER nobody\n"
    )
    client = Spy()
    client.snapshot.create.return_value = SimpleNamespace(id="built-image")

    def create(params: dict[str, object], **_: object) -> SimpleNamespace:
        image = cast(Any, params["image"])
        (context,) = image._context_list
        root = Path(context.source_path)
        captured["archive_path"] = context.archive_path
        captured["dockerfile"] = image.dockerfile()
        captured["files"] = sorted(path.name for path in root.iterdir())
        captured["context"] = (root / "sps-context.txt").read_text(encoding="utf-8")
        return SimpleNamespace(id="built-image")

    monkeypatch.setattr(native, "CreateSnapshotParams", lambda **values: values)
    client.snapshot.create.side_effect = create
    driver = make_driver(monkeypatch, client)

    result = driver.image_prepare(
        None,
        {
            "source": "dockerfile",
            "dockerfile": dockerfile,
            "context": {"sps-context.txt": "from-context"},
        },
    )

    # The whole staged directory is the context, so ADD sources reach the builder too.
    assert captured == {
        "archive_path": ".",
        "dockerfile": dockerfile,
        "files": ["Dockerfile", "sps-context.txt"],
        "context": "from-context",
    }
    assert cast(Resource, result["resource"]).native == "built-image"


@pytest.mark.parametrize(
    ("key", "value"),
    [("username", "registry-user"), ("password", "secret-value")],
)
def test_private_oci_image_prepare_refuses_credentials_before_native_mutation(
    monkeypatch: pytest.MonkeyPatch, key: str, value: str
) -> None:
    client = Spy()
    driver = make_driver(monkeypatch, client)
    inputs = {"source": "private_oci", "image": "registry.invalid/private", key: value}

    with pytest.raises(
        Unsupported,
        match="Daytona SDK 0.220.0 has no per-image private registry credentials",
    ):
        driver.image_prepare(None, inputs)
    client.snapshot.create.assert_not_called()


def test_image_prepare_uses_native_snapshot_creation_for_public_oci(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = Spy()
    client.snapshot.create.return_value = SimpleNamespace(id="public-image")
    monkeypatch.setattr(native, "CreateSnapshotParams", lambda **values: values)
    driver = make_driver(monkeypatch, client)

    result = driver.image_prepare(None, {"source": "oci", "image": "python:3.12-slim"})

    assert client.snapshot.create.call_args.args[0]["image"] == "python:3.12-slim"
    assert cast(Resource, result["resource"]).native == "public-image"


@pytest.mark.parametrize("value", ["allowlist", "deny_all"])
def test_network_update_uses_native_policy_call(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    sandbox = Spy()
    driver = make_driver(monkeypatch)
    mapping: dict[str, object]
    if value == "allowlist":
        mapping = {"policy": value, "allow": ["daytona.io", "192.0.2.0/24"]}
        expected = {
            "network_block_all": None,
            "domain_allow_list": "daytona.io",
            "network_allow_list": "192.0.2.0/24",
            "request_timeout": 30,
        }
    else:
        mapping = {"policy": value}
        expected = {
            "network_block_all": True,
            "network_allow_list": None,
            "domain_allow_list": None,
            "request_timeout": 30,
        }

    assert driver.network_update(target(sandbox), mapping) == {}
    sandbox.update_network_settings.assert_called_once_with(**expected)


def test_network_update_opens_network_with_native_call(monkeypatch: pytest.MonkeyPatch) -> None:
    sandbox = Spy()
    driver = make_driver(monkeypatch)
    assert driver.network_update(target(sandbox), {"policy": "open"}) == {}
    sandbox.update_network_settings.assert_called_once_with(
        network_block_all=False,
        network_allow_list=None,
        domain_allow_list=None,
        request_timeout=30,
    )


def test_network_update_transitions_replace_the_active_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = StatefulNetworkSandbox()
    driver = make_driver(monkeypatch)
    binding = target(sandbox)

    driver.network_update(binding, {"policy": "allowlist", "allow": ["daytona.io"]})

    assert sandbox.network_block_all is False
    assert sandbox.domain_allow_list == "daytona.io"
    assert sandbox.network_allow_list is None

    driver.network_update(binding, {"policy": "open"})

    assert sandbox.network_block_all is False
    assert sandbox.domain_allow_list is None
    assert sandbox.network_allow_list is None


def test_network_update_refuses_denylist_with_fixed_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    sandbox = Spy()
    driver = make_driver(monkeypatch)
    with pytest.raises(
        Unsupported, match="Daytona native egress controls expose allowlists, not denylists"
    ):
        driver.network_update(target(sandbox), {"policy": "denylist", "deny": ["example.com"]})
    sandbox.update_network_settings.assert_not_called()


@pytest.mark.parametrize(
    ("policy", "allow", "expected"),
    [
        ("allowlist_domains", ["daytona.io"], {"domain_allow_list": "daytona.io"}),
        ("allowlist_ips", ["192.0.2.0/24"], {"network_allow_list": "192.0.2.0/24"}),
    ],
)
def test_legacy_network_policy_names_keep_their_exact_native_mapping(
    monkeypatch: pytest.MonkeyPatch,
    policy: str,
    allow: list[str],
    expected: dict[str, str],
) -> None:
    sandbox = Spy()
    driver = make_driver(monkeypatch)

    assert driver.network_update(target(sandbox), {"policy": policy, "allow": allow}) == {}

    settings = sandbox.update_network_settings.call_args.kwargs
    for name, value in expected.items():
        assert settings[name] == value
    assert settings["request_timeout"] == 30


def test_resize_uses_native_resource_resize_and_rounds_minimum_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = Spy()
    sandbox.cpu = 1
    sandbox.memory = 1
    driver = make_driver(monkeypatch)

    assert (
        driver.resize(target(sandbox), {"resources": {"cpu_min": 2, "memory_min_mib": 1025}}) == {}
    )

    call = sandbox.resize.call_args
    assert isinstance(call.args[0], Resources)
    assert call.args[0].cpu == 2
    assert call.args[0].memory == 2
    assert call.kwargs == {"timeout": 60}


@pytest.mark.parametrize(
    ("resources", "current", "reason"),
    [
        ({"disk_min_mib": 2048}, {"cpu": 2, "memory": 4}, "stopped sandbox"),
        ({"cpu_min": 1}, {"cpu": 2, "memory": 4}, "increases only"),
        ({"memory_min_mib": 1024}, {"cpu": 2, "memory": 4}, "increases only"),
    ],
)
def test_resize_refuses_disk_or_decreases(
    monkeypatch: pytest.MonkeyPatch,
    resources: dict[str, int],
    current: dict[str, int],
    reason: str,
) -> None:
    sandbox = Spy(**current)
    driver = make_driver(monkeypatch)
    with pytest.raises(Unsupported, match=reason):
        driver.resize(target(sandbox), {"resources": resources})
    sandbox.resize.assert_not_called()


def test_ssh_access_returns_native_token_and_revokes_it_on_release(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    access = SimpleNamespace(token="opaque-token")
    sandbox = Spy()
    sandbox.create_ssh_access.return_value = access
    driver = make_driver(monkeypatch)

    result = driver.ssh_access(target(sandbox), {"credential": "token"})

    sandbox.create_ssh_access.assert_called_once_with(expires_in_minutes=60, request_timeout=30)
    assert result["host"] == "ssh.app.daytona.io"
    assert result["port"] == 22
    assert result["user"] == "opaque-token"
    assert result["credential"] == "token"
    assert result["token"] == "opaque-token"
    assert driver.release(cast(Resource, result["resource"])) == {
        "kind": "ssh_access",
        "result": "deleted",
    }
    sandbox.revoke_ssh_access.assert_called_once_with("opaque-token", request_timeout=30)


@pytest.mark.parametrize("credential", ["key", "password"])
def test_ssh_access_refuses_other_credential_kinds(
    monkeypatch: pytest.MonkeyPatch, credential: str
) -> None:
    sandbox = Spy()
    driver = make_driver(monkeypatch)
    with pytest.raises(Unsupported, match="token credentials only"):
        driver.ssh_access(target(sandbox), {"credential": credential})
    sandbox.create_ssh_access.assert_not_called()


@pytest.mark.parametrize(
    ("operation", "reason"),
    [
        ("run.as_root", "Daytona exec has no per-command user selector"),
        (
            "snapshot.restore_wait",
            "Daytona SDK restores synchronously and exposes no pending restore handle",
        ),
        ("tcp.link", "Daytona SDK exposes HTTP previews, not public raw TCP endpoints"),
        ("volume.read_bytes", "Daytona SDK has no direct volume byte-read operation"),
        ("volume.reload", "Daytona SDK has no mounted-volume reload operation"),
    ],
)
def test_operation_absences_are_precise_and_fixed(
    monkeypatch: pytest.MonkeyPatch, operation: str, reason: str
) -> None:
    driver = make_driver(monkeypatch)
    inputs = {"bash_script": "id"} if operation == "run.as_root" else {}
    with pytest.raises(Unsupported) as caught:
        driver.call(operation, None, inputs)
    assert str(caught.value) == reason


@pytest.mark.parametrize(
    ("operation", "reason"),
    [
        ("lifetime.observe_paused_countdown", "native_paused_timer_countdown_unobservable"),
        ("snapshot.restore_begin", "native_restore_progress_unobservable"),
        ("snapshot.retention", "native_snapshot_retention_unobservable"),
    ],
)
def test_unobservable_native_metadata_is_not_reported_as_unsupported(
    monkeypatch: pytest.MonkeyPatch, operation: str, reason: str
) -> None:
    driver = make_driver(monkeypatch)
    with pytest.raises(NotRun) as caught:
        driver.call(operation, None, {})
    assert str(caught.value) == reason


def test_idle_and_long_running_operations_use_sdk_reads_and_updates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = Spy()
    sandbox.id = "native-id"
    sandbox.auto_stop_interval = 0
    sandbox.auto_pause_interval = 0
    client = Spy()
    client.get.return_value = sandbox
    driver = make_driver(monkeypatch, client)

    assert driver.call("idle.select_duration", target(sandbox), {"idle_seconds": 120}) == {}
    sandbox.set_autostop_interval.assert_called_once_with(2, request_timeout=30)
    assert driver.call("long_running.observe", target(sandbox), {}) == {"idle_disabled": True}
    client.get.assert_called_once_with("native-id", request_timeout=30)


def test_desktop_operations_map_to_daytona_computer_use_sdk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = Spy()
    sandbox.computer_use.screenshot.take_full_screen.return_value.screenshot = base64.b64encode(
        b"png"
    ).decode()
    driver = make_driver(monkeypatch)
    binding = target(sandbox)

    assert driver.call("desktop.start", binding, {}) == {}
    assert driver.call("desktop.click", binding, {"x": 3, "y": 4}) == {}
    assert driver.call("desktop.type", binding, {"text": "hello"}) == {}
    assert driver.call("desktop.key", binding, {"key": "enter"}) == {}
    assert driver.call("desktop.screenshot", binding, {}) == {"png": b"png"}
    sandbox.computer_use.start.assert_called_once_with(request_timeout=60)
    sandbox.computer_use.mouse.click.assert_called_once_with(3, 4, request_timeout=30)
    sandbox.computer_use.keyboard.type.assert_called_once_with("hello", request_timeout=30)
    sandbox.computer_use.keyboard.press.assert_called_once_with("enter", request_timeout=30)


def test_desktop_live_link_uses_native_private_preview(monkeypatch: pytest.MonkeyPatch) -> None:
    sandbox = Spy()
    sandbox.get_preview_link.return_value.url = "https://preview.invalid/plain"
    sandbox.create_signed_preview_url.return_value.url = "https://preview.invalid/signed"
    sandbox.create_signed_preview_url.return_value.token = "opaque"
    driver = make_driver(monkeypatch)

    result = driver.call("desktop.live_link", target(sandbox), {})

    url = cast(str, result["url"])
    assert url.startswith("https://preview.invalid/vnc.html?")
    assert "autoconnect=true" in url
    assert "resize=scale" in url
    sandbox.create_signed_preview_url.assert_called_once_with(
        6080, expires_in_seconds=300, request_timeout=30
    )


def test_run_and_files_operations_call_native_sdk(monkeypatch: pytest.MonkeyPatch) -> None:
    sandbox = Spy()
    sandbox.process.exec.return_value.result = "ran"
    sandbox.process.exec.return_value.exit_code = 0
    sandbox.fs.download_file.return_value = b"contents"
    driver = make_driver(monkeypatch)
    binding = target(sandbox)

    assert driver.call("run", binding, {"bash_script": "true"}) == {
        "stdout": "ran",
        "exit_code": 0,
    }
    with pytest.raises(Unsupported, match="named-user command"):
        driver.call("run", binding, {"bash_script": "id -un", "run_as": "runner"})
    assert driver.call("files.read_bytes", binding, {"path": "/x"}) == {"data": b"contents"}
    assert (
        driver.call("files.write", binding, {"path": "/x", "data": base64.b64encode(b"x").decode()})
        == {}
    )
    assert driver.call("files.exists", binding, {"path": "/x"}) == {"exists": True}
    sandbox.process.exec.assert_called_once()
    sandbox.fs.download_file.assert_called_once_with("/x")
    sandbox.fs.upload_file.assert_called_once_with(b"x", "/x", timeout=30)
    sandbox.fs.get_file_info.assert_called_once_with("/x", request_timeout=30)


def test_preview_link_and_revoke_use_signed_native_preview(monkeypatch: pytest.MonkeyPatch) -> None:
    signed = SimpleNamespace(url="https://preview.invalid/signed", token="opaque")
    sandbox = Spy()
    sandbox.get_preview_link.return_value.url = "https://preview.invalid/plain"
    sandbox.create_signed_preview_url.return_value = signed
    driver = make_driver(monkeypatch)
    binding = target(sandbox)

    result = driver.call(
        "preview.link", binding, {"port": 8000, "access": "private", "credential": "link"}
    )

    assert result["url"] == "https://preview.invalid/signed"
    assert result["unauthorized_url"] == "https://preview.invalid/plain"
    assert driver.call("preview.revoke", result, {}) == {
        "kind": "preview_credential",
        "result": "deleted",
    }
    sandbox.create_signed_preview_url.assert_called_once_with(
        8000, expires_in_seconds=60, request_timeout=30
    )
    sandbox.expire_signed_preview_url.assert_called_once_with(8000, "opaque", request_timeout=30)


def test_process_start_calls_native_session_command(monkeypatch: pytest.MonkeyPatch) -> None:
    sandbox = Spy()
    sandbox.process.execute_session_command.return_value.cmd_id = "cmd-1"
    driver = make_driver(monkeypatch)

    result = driver.call("process.start", target(sandbox), {"bash_script": "sleep 5"})

    sandbox.process.create_session.assert_called_once()
    sandbox.process.execute_session_command.assert_called_once()
    identity = cast(Mapping[str, object], result["identity"])
    assert identity["command"] == "cmd-1"


def test_secret_operations_use_daytona_vault(monkeypatch: pytest.MonkeyPatch) -> None:
    client = Spy()
    client.secret.create.return_value = SimpleNamespace(id="secret-id", name="owned")
    driver = make_driver(monkeypatch, client)
    monkeypatch.setattr(native, "CreateSecretParams", lambda **values: values)
    monkeypatch.setattr(native, "UpdateSecretParams", lambda **values: values)

    result = driver.call("secret.create", None, {"value": "test-value", "hosts": ["api.example"]})
    assert client.secret.create.call_args.args[0] == {
        "name": client.secret.create.call_args.args[0]["name"],
        "value": "test-value",
        "hosts": ["api.example"],
    }
    assert driver.call("secret.rotate", result, {"value": "next-value"}) == {}
    client.secret.update.assert_called_once_with("secret-id", {"value": "next-value"})


def test_snapshot_delete_again_uses_native_snapshot_delete(monkeypatch: pytest.MonkeyPatch) -> None:
    client = Spy()
    driver = make_driver(monkeypatch, client)
    owned = Resource("snapshot", "snapshot-id", lambda: {"result": "deleted"})

    result = driver.call("snapshot.delete_again", {"resource": owned}, {})

    assert result == {"native_delete_attempted": True}
    client.snapshot.delete.assert_called_once_with("snapshot-id")
    assert owned.released is False


def test_destroy_releases_the_owned_native_resource(monkeypatch: pytest.MonkeyPatch) -> None:
    cleanup = Spy(return_value={"result": "deleted"})
    owned = Resource("sandbox", "native-id", cleanup)
    driver = make_driver(monkeypatch)

    assert driver.call("destroy", {"resource": owned}, {}) == {
        "kind": "sandbox",
        "result": "deleted",
    }
    cleanup.assert_called_once_with()
    assert owned.released is True


def test_terminal_operations_use_native_pty_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    handle = Spy()
    handle.session_id = "pty-session"
    sandbox = Spy()
    sandbox.process.connect_pty_session.return_value = handle
    driver = make_driver(monkeypatch)
    binding: dict[str, object] = {
        "resource": Resource("terminal", handle, lambda: {"result": "deleted"}),
        "sandbox": sandbox,
    }

    assert driver.call("terminal.disconnect", binding, {}) == {}
    assert driver.call("terminal.reattach", binding, {})["sandbox"] is sandbox
    assert driver.call("terminal.write", binding, {"data": base64.b64encode(b"x").decode()}) == {}
    handle.wait.return_value = None
    handle.wait.side_effect = lambda on_data, timeout: on_data(b"out")
    assert driver.call("terminal.output", binding, {}) == {"terminal": b"out"}
    handle.disconnect.assert_called_once()
    sandbox.process.connect_pty_session.assert_called_once_with("pty-session")
    handle.send_input.assert_called_once_with(b"x")


def test_volume_kind_and_create_use_native_volume_api(monkeypatch: pytest.MonkeyPatch) -> None:
    volume = Volume.model_construct(name="volume", state=VolumeState.READY)
    client = Spy()
    client.volume.create.return_value = volume
    driver = make_driver(monkeypatch, client)

    assert driver.call("volume.observe_kind", target(volume, "volume"), {}) == {
        "kind": "object_store"
    }
    result = driver.call("volume.create", None, {})
    assert cast(Resource, result["resource"]).native is volume
    client.volume.create.assert_called_once()
