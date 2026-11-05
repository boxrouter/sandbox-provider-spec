# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Modal 1.6.0 mappings and explicit absences from the v0.2.0 test ledger."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Literal

import modal
import pytest

from sandbox_provider_spec.driver import Resource, Unsupported
from sandbox_provider_spec.drivers import modal as native


class _AppContext:
    def __init__(self, app: object) -> None:
        self.app = app

    def __enter__(self) -> object:
        return self.app

    def __exit__(self, *args: object) -> Literal[False]:
        del args
        return False


def _create_sdk(monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    app = SimpleNamespace(app_id="ap-v9")
    context = _AppContext(app)
    monkeypatch.setattr(modal, "App", lambda *_name: SimpleNamespace(run=lambda: context))
    calls: dict[str, object] = {}

    def create(**options: object) -> object:
        calls.update(options)
        return SimpleNamespace(object_id="sb-v9")

    monkeypatch.setattr(modal.Sandbox, "create", create)
    return calls


@pytest.mark.parametrize(
    ("operation", "inputs"),
    [
        pytest.param("resize", {"resources": {"cpu_min": 2}}, id="resize"),
        pytest.param("ssh.access", {"credential": "key"}, id="ssh-access"),
    ],
)
def test_modal_sdk_absent_operations_have_fixed_reasons(
    operation: str, inputs: dict[str, object]
) -> None:
    driver = native.ModalDriver()
    with pytest.raises(Unsupported) as raised:
        driver.call(operation, None, inputs)
    assert str(raised.value) == driver.unsupported[operation]
    assert "\n" not in str(raised.value)


def test_named_user_command_does_not_use_guest_switch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(native, "box", lambda _target: pytest.fail("dispatched native SDK"))
    with pytest.raises(Unsupported, match="named-user command"):
        native.ModalDriver().run(None, {"bash_script": "id -un", "run_as": "runner"})


@pytest.mark.parametrize("credential", ["key", "password", "token"])
def test_ssh_access_credentials_are_explicitly_unsupported(credential: str) -> None:
    driver = native.ModalDriver()
    with pytest.raises(Unsupported) as raised:
        driver.call("ssh.access", None, {"credential": credential})
    assert str(raised.value) == driver.unsupported["ssh.access"]


_UNSUPPORTED_CREATE_CASES: list[tuple[str, dict[str, object], dict[str, object], str]] = [
    (
        "denylist-policy",
        {"network_lockdown": {"policy": "denylist", "deny": ["blocked.example"]}},
        {},
        "Modal Sandbox egress controls expose allowlists, not denylists",
    ),
    (
        "deny-wins",
        {"network_lockdown": {"policy": "allowlist", "deny_wins": True}},
        {},
        "Modal Sandbox egress controls expose allowlists, not deny entries",
    ),
    (
        "cuts-open-connections-false",
        {"network_lockdown": {"policy": "allowlist", "cuts_open_connections": False}},
        {},
        "Modal policy replacement terminates established connections it blocks",
    ),
    (
        "domain-traffic-all",
        {"network_lockdown": {"policy": "allowlist", "domain_traffic": "all"}},
        {},
        "Modal domain allowlists restrict TLS traffic on port 443 only",
    ),
    (
        "domain-traffic-http-and-https",
        {"network_lockdown": {"policy": "allowlist", "domain_traffic": "http_and_https"}},
        {},
        "Modal domain allowlists restrict TLS traffic on port 443 only",
    ),
    (
        "domain-traffic-tls",
        {"network_lockdown": {"policy": "allowlist", "domain_traffic": "tls"}},
        {},
        "Modal domain allowlists restrict TLS traffic on port 443 only",
    ),
    (
        "http-rules",
        {"network_lockdown": {"policy": "allowlist", "http_rules": True}},
        {},
        "Modal Sandbox egress controls do not filter HTTP methods or paths",
    ),
    (
        "hosts",
        {"network_lockdown": {"policy": "allowlist", "allow": [{"hosts": ["example.test"]}]}},
        {},
        "Modal Sandbox egress controls do not filter HTTP methods or paths",
    ),
    (
        "methods",
        {"network_lockdown": {"policy": "allowlist", "allow": [{"methods": ["GET"]}]}},
        {},
        "Modal Sandbox egress controls do not filter HTTP methods or paths",
    ),
    (
        "paths",
        {"network_lockdown": {"policy": "allowlist", "allow": [{"paths": ["/allowed/**"]}]}},
        {},
        "Modal Sandbox egress controls do not filter HTTP methods or paths",
    ),
    (
        "join",
        {},
        {"join": "prior-sandbox"},
        "Modal Sandbox.create has no private-network join selector",
    ),
    (
        "live-resize",
        {"live_resize": {"shrinks": False}},
        {},
        "Modal Sandbox SDK 1.6.0 has no live resize operation",
    ),
    (
        "nested-virtualization",
        {"nested_virtualization": {}},
        {},
        "Modal nested virtualization requires the VM runtime",
    ),
    (
        "ssh-key",
        {"ssh": {"credential": "key"}},
        {},
        "Modal Sandbox SDK has no sandbox-scoped SSH access operation",
    ),
    (
        "ssh-password",
        {"ssh": {"credential": "password"}},
        {},
        "Modal Sandbox SDK has no sandbox-scoped SSH access operation",
    ),
    (
        "ssh-token",
        {"ssh": {"credential": "token"}},
        {},
        "Modal Sandbox SDK has no sandbox-scoped SSH access operation",
    ),
    (
        "switch-to-denylist",
        {
            "network_lockdown": {
                "policy": "allowlist",
                "allow": ["example.test"],
                "switchable": True,
                "switches_to": ["denylist"],
            }
        },
        {},
        "Modal Sandbox egress controls do not support switching to denylists",
    ),
]


@pytest.mark.parametrize(
    ("case", "requirements", "extra", "reason"),
    [pytest.param(*case, id=case[0]) for case in _UNSUPPORTED_CREATE_CASES],
)
def test_unavailable_create_inputs_fail_before_app_creation(
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    requirements: dict[str, object],
    extra: dict[str, object],
    reason: str,
) -> None:
    del case

    def unexpected_app() -> None:
        pytest.fail("unsupported inputs must be rejected before App allocation")

    monkeypatch.setattr(modal, "App", unexpected_app)
    with pytest.raises(Unsupported) as raised:
        native.ModalDriver().create(None, {"requirements": requirements, **extra})
    assert str(raised.value) == reason


def test_allowlist_create_maps_domains_ranges_and_dynamic_switching() -> None:
    options = native.ModalDriver._network_policy_options(
        {
            "policy": "allowlist",
            "allow": ["api.example.test", "192.0.2.4"],
            "domain_traffic": "https",
            "cuts_open_connections": True,
            "switchable": True,
            "switches_to": ["deny_all"],
        },
        create=True,
    )
    assert options == {
        "outbound_cidr_allowlist": ["192.0.2.4/32"],
        "outbound_domain_allowlist": ["api.example.test"],
    }


def test_private_network_create_uses_pinned_experimental_i6pn_sandbox(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = SimpleNamespace(app_id="ap-v6b")
    context = _AppContext(app)
    monkeypatch.setattr(modal, "App", lambda *_name: SimpleNamespace(run=lambda: context))
    calls: dict[str, object] = {}

    async def experimental_create(**options: object) -> object:
        calls.update(options)
        return SimpleNamespace(
            object_id="sb-v6b",
            terminate=lambda **kwargs: None,
            poll=lambda: "terminated",
        )

    def unexpected_create(**options: object) -> object:
        del options
        pytest.fail("i6pn must use the experimental Sandbox API")

    monkeypatch.setattr(modal.Sandbox, "_experimental_create", experimental_create)
    monkeypatch.setattr(modal.Sandbox, "create", unexpected_create)
    driver = native.ModalDriver()
    result = driver.create(
        None,
        {
            "requirements": {
                "private_network": {},
                "network_lockdown": {"policy": "deny_all"},
            }
        },
    )
    assert calls["i6pn"] is True
    assert calls["region"] == "us-east-1"
    assert calls["app"] is app
    assert calls["outbound_cidr_allowlist"] == []
    assert calls["outbound_domain_allowlist"] == []
    assert "block_network" not in calls
    owned = result["resource"]
    assert isinstance(owned, Resource)
    driver.release(owned)
    app_resource = next(item for item in driver.resources if item.kind == "application_session")
    driver.release(app_resource)


def test_private_network_ipv4_is_unsupported_before_app_creation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_app() -> None:
        pytest.fail("unsupported i6pn address families must be rejected before App allocation")

    monkeypatch.setattr(modal, "App", unexpected_app)
    with pytest.raises(Unsupported, match="Modal i6pn private networking uses IPv6"):
        native.ModalDriver().create(
            None, {"requirements": {"private_network": {"ip_version": "ipv4"}}}
        )


def test_open_creation_selects_dynamic_policy_options() -> None:
    assert native.ModalDriver._network_policy_options({"policy": "open"}, create=True) == {
        "outbound_cidr_allowlist": ["0.0.0.0/0"],
        "outbound_domain_allowlist": ["*"],
    }


def test_network_update_maps_allowlist_and_rejects_denylist() -> None:
    calls: list[dict[str, object]] = []
    sandbox = SimpleNamespace(
        _experimental_set_outbound_network_policy=lambda **options: calls.append(options)
    )
    driver = native.ModalDriver()
    owned = driver.own("sandbox", sandbox, lambda: {"result": "deleted"})
    assert (
        driver.network_update(
            {"resource": owned}, {"policy": "allowlist", "allow": ["192.0.2.0/24"]}
        )
        == {}
    )
    assert calls == [{"outbound_cidr_allowlist": ["192.0.2.0/24"], "outbound_domain_allowlist": []}]
    with pytest.raises(Unsupported) as raised:
        driver.network_update({"resource": owned}, {"policy": "denylist", "deny": []})
    assert str(raised.value) == "Modal Sandbox egress controls expose allowlists, not denylists"


@pytest.mark.parametrize("image_setting", ["user", "workdir"])
def test_custom_image_configuration_is_carried_by_the_native_image(
    monkeypatch: pytest.MonkeyPatch, image_setting: str
) -> None:
    calls = _create_sdk(monkeypatch)
    driver = native.ModalDriver()
    image = modal.Image.debian_slim()
    image_resource = driver.own("image", image, lambda: {"result": "deleted"})
    driver.create(
        None,
        {
            "image": {"resource": image_resource},
            "requirements": {"custom_images": {"image_config": [image_setting]}},
        },
    )
    assert calls["image"] is image


def test_build_context_is_added_to_the_native_dockerfile_build(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = SimpleNamespace(app_id="ap-v9")
    context = _AppContext(app)
    monkeypatch.setattr(modal, "App", lambda *_name: SimpleNamespace(run=lambda: context))
    seen: dict[str, object] = {}
    image = object()

    def from_dockerfile(path: Path, *, context_dir: str) -> object:
        seen["dockerfile"] = path.read_text(encoding="utf-8")
        seen["context"] = (Path(context_dir) / "sps-context.txt").read_text(encoding="utf-8")
        return image

    monkeypatch.setattr(modal.Image, "from_dockerfile", from_dockerfile)
    driver = native.ModalDriver()
    monkeypatch.setattr(
        driver,
        "_build_owned_image",
        lambda native_image, native_app: driver.own(
            "image", native_image, lambda: {"result": "deleted"}
        ),
    )
    prepared = driver.image_prepare(
        None,
        {
            "source": "dockerfile",
            "dockerfile": "FROM python:3.12-slim\nCOPY sps-context.txt /opt/sps-context.txt",
            "context": {"sps-context.txt": "from-context"},
        },
    )
    prepared_resource = prepared["resource"]
    assert isinstance(prepared_resource, Resource)
    assert prepared_resource.native is image
    assert "COPY sps-context.txt /opt/sps-context.txt" in str(seen["dockerfile"])
    assert seen["context"] == "from-context"


@pytest.mark.parametrize("path", ["Dockerfile", "./Dockerfile"])
def test_build_context_cannot_replace_supplied_dockerfile(
    monkeypatch: pytest.MonkeyPatch, path: str
) -> None:
    app = SimpleNamespace(app_id="ap-v9")
    context = _AppContext(app)
    monkeypatch.setattr(modal, "App", lambda *_name: SimpleNamespace(run=lambda: context))
    monkeypatch.setattr(modal.Image, "from_dockerfile", lambda *_args, **_kwargs: object())
    driver = native.ModalDriver()
    monkeypatch.setattr(
        driver,
        "_build_owned_image",
        lambda native_image, _native_app: driver.own("image", native_image, lambda: {}),
    )
    with pytest.raises(ValueError, match="cannot replace"):
        driver.image_prepare(
            None,
            {
                "source": "dockerfile",
                "dockerfile": "FROM python:3.12-slim",
                "context": {path: "FROM scratch"},
            },
        )


def test_private_oci_image_uses_modal_registry_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = SimpleNamespace(app_id="ap-v9")
    context = _AppContext(app)
    monkeypatch.setattr(modal, "App", lambda *_name: SimpleNamespace(run=lambda: context))
    secret = object()
    secret_values: dict[str, str] = {}

    def from_dict(values: dict[str, str]) -> object:
        secret_values.update(values)
        return secret

    monkeypatch.setattr(modal.Secret, "from_dict", from_dict)
    image = object()
    registry_call: dict[str, object] = {}

    def from_registry(tag: str, *, secret: object, setup_dockerfile_commands: list[str]) -> object:
        registry_call.update(
            {"tag": tag, "secret": secret, "setup_dockerfile_commands": setup_dockerfile_commands}
        )
        return image

    monkeypatch.setattr(modal.Image, "from_registry", from_registry)
    driver = native.ModalDriver()
    monkeypatch.setattr(
        driver,
        "_build_owned_image",
        lambda native_image, native_app: driver.own(
            "image", native_image, lambda: {"result": "deleted"}
        ),
    )
    result = driver.image_prepare(
        None,
        {
            "source": "private_oci",
            "image": "registry.example.test/team/image:tag",
            "username": "fixture-user",
            "password": "fixture-password",
        },
    )
    assert secret_values == {
        "REGISTRY_USERNAME": "fixture-user",
        "REGISTRY_PASSWORD": "fixture-password",
    }
    assert registry_call["tag"] == "registry.example.test/team/image:tag"
    assert registry_call["secret"] is secret
    result_resource = result["resource"]
    assert isinstance(result_resource, Resource)
    assert result_resource.native is image


def test_read_only_volume_mount_uses_modal_mount_options(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _create_sdk(monkeypatch)
    volume = modal.Volume.from_name("sps-v9-volume")
    read_only_calls: list[bool | None] = []

    def with_mount_options(
        volume: modal.Volume, *, read_only: bool | None = None, sub_path: str | None = None
    ) -> modal.Volume:
        del sub_path
        read_only_calls.append(read_only)
        return volume

    monkeypatch.setattr(modal.Volume, "with_mount_options", with_mount_options)
    driver = native.ModalDriver()
    owned = driver.own("volume", volume, lambda: {"result": "deleted"})
    driver.create(
        None,
        {
            "volumes": [{"path": "/data", "volume": {"resource": owned}, "read_only": True}],
            "requirements": {"volumes": {"read_only_mounts": True}},
        },
    )
    assert read_only_calls == [True]
    assert calls["volumes"] == {"/data": volume}


def test_vm_execution_class_selects_the_sdk_vm_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _create_sdk(monkeypatch)
    driver = native.make_driver(execution_class="vm", fixtures={})
    assert isinstance(driver, native.ModalDriver)
    driver.create(None, {"requirements": {"nested_virtualization": {}}})
    assert calls["runtime"] == "vm"


def test_custom_image_gate_accepts_a_prepared_image_with_build_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _create_sdk(monkeypatch)
    driver = native.ModalDriver()
    image = modal.Image.debian_slim()
    image_resource = driver.own("image", image, lambda: {"result": "deleted"})
    driver.create(
        None,
        {
            "image": {"resource": image_resource},
            "requirements": {"custom_images": {"build_context": True, "image_config": ["env"]}},
        },
    )
    assert calls["image"] is image
