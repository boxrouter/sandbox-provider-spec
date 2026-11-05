# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Vercel mappings added for the v0.2.0 driver contract."""

from __future__ import annotations

from collections.abc import Mapping
from types import SimpleNamespace
from typing import Any

import pytest
from vercel.sandbox.sync import NetworkPolicy, NetworkPolicySubnets

from sandbox_provider_spec.driver import Reserved, Resource, Unsupported
from sandbox_provider_spec.drivers import vercel as native


def _create(monkeypatch: pytest.MonkeyPatch, inputs: Mapping[str, object]) -> dict[str, Any]:
    calls: dict[str, Any] = {}

    def create_sandbox(**options: Any) -> object:
        calls.update(options)
        return object()

    monkeypatch.setattr(native, "create_sandbox", create_sandbox)
    native.VercelDriver().create(None, inputs)
    return calls


def test_named_user_command_does_not_use_guest_switch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(native, "box", lambda _target: pytest.fail("dispatched native SDK"))
    with pytest.raises(Unsupported, match="named-user command"):
        native.VercelDriver().run(None, {"bash_script": "id -un", "run_as": "runner"})


@pytest.mark.parametrize(
    ("operation", "inputs", "reason"),
    [
        pytest.param(
            "resize",
            {"resources": {"cpu_min": 4}},
            "Vercel Sandbox SDK does not document resource updates taking effect "
            "in the current session",
            id="resize",
        ),
        pytest.param(
            "ssh.access",
            {"credential": "key"},
            "Vercel Sandbox SDK does not expose sandbox SSH access",
            id="ssh-access-key",
        ),
        pytest.param(
            "ssh.access",
            {"credential": "password"},
            "Vercel Sandbox SDK does not expose sandbox SSH access",
            id="ssh-access-password",
        ),
        pytest.param(
            "ssh.access",
            {"credential": "token"},
            "Vercel Sandbox SDK does not expose sandbox SSH access",
            id="ssh-access-token",
        ),
    ],
)
def test_v020_unsupported_operations_have_reasons(
    operation: str, inputs: Mapping[str, object], reason: str
) -> None:
    with pytest.raises(Unsupported) as error:
        native.VercelDriver().call(operation, None, inputs)
    assert str(error.value) == reason


@pytest.mark.parametrize(
    ("item", "inputs", "reason"),
    [
        pytest.param(
            "build_context",
            {"requirements": {"custom_images": {"source": "dockerfile", "build_context": True}}},
            "Vercel Sandbox SDK does not build images from a Dockerfile or context",
            id="build-context",
        ),
        pytest.param(
            "cuts_open_connections",
            {
                "requirements": {
                    "network_lockdown": {
                        "policy": "allowlist",
                        "allow": ["packages.example"],
                        "cuts_open_connections": False,
                    }
                }
            },
            "Vercel Sandbox SDK does not specify whether network updates close "
            "existing connections",
            id="cuts-open-connections",
        ),
        pytest.param(
            "cuts_open_connections",
            {
                "requirements": {
                    "network_lockdown": {
                        "policy": "open",
                        "switchable": True,
                        "switches_to": ["allowlist"],
                        "cuts_open_connections": True,
                    }
                }
            },
            "Vercel Sandbox SDK does not specify whether network updates close "
            "existing connections",
            id="cuts-open-connections-open",
        ),
        pytest.param(
            "http_rules",
            {
                "requirements": {
                    "network_lockdown": {
                        "policy": "allowlist",
                        "http_rules": True,
                        "allow": [{"hosts": ["packages.example"], "methods": ["GET"]}],
                    }
                }
            },
            "Vercel network policy matchers transform or forward requests; "
            "they do not block matching requests",
            id="http-rules",
        ),
        pytest.param(
            "methods",
            {
                "requirements": {
                    "network_lockdown": {
                        "policy": "allowlist",
                        "allow": [{"hosts": ["packages.example"], "methods": ["GET"]}],
                    }
                }
            },
            "Vercel network policy matchers transform or forward requests; "
            "they do not block matching requests",
            id="http-rule-methods",
        ),
        pytest.param(
            "paths",
            {
                "requirements": {
                    "network_lockdown": {
                        "policy": "allowlist",
                        "allow": [{"hosts": ["packages.example"], "paths": ["/v1/**"]}],
                    }
                }
            },
            "Vercel network policy matchers transform or forward requests; "
            "they do not block matching requests",
            id="http-rule-paths",
        ),
        pytest.param(
            "join",
            {"join": "sps-private-member"},
            "Vercel Secure Compute network IDs do not provide sandbox-to-sandbox "
            "private networking",
            id="private-network-join",
        ),
        pytest.param(
            "nested_virtualization",
            {"requirements": {"nested_virtualization": {}}},
            "Vercel Sandbox SDK has no nested virtualization setting",
            id="nested-virtualization",
        ),
        pytest.param(
            "live_resize",
            {"requirements": {"live_resize": {}}},
            "Vercel Sandbox SDK does not document resource updates taking effect "
            "in the current session",
            id="live-resize",
        ),
        pytest.param(
            "shrinks",
            {"requirements": {"live_resize": {"shrinks": True}}},
            "Vercel Sandbox SDK does not document resource updates taking effect "
            "in the current session",
            id="live-resize-shrinks",
        ),
        pytest.param(
            "private_network",
            {"requirements": {"private_network": {}}},
            "Vercel Secure Compute network IDs do not provide sandbox-to-sandbox "
            "private networking",
            id="private-network",
        ),
        pytest.param(
            "ssh",
            {"requirements": {"ssh": {"credential": "key"}}},
            "Vercel Sandbox SDK does not expose sandbox SSH access",
            id="ssh-create-key",
        ),
        pytest.param(
            "ssh",
            {"requirements": {"ssh": {"credential": "password"}}},
            "Vercel Sandbox SDK does not expose sandbox SSH access",
            id="ssh-create-password",
        ),
        pytest.param(
            "ssh",
            {"requirements": {"ssh": {"credential": "token"}}},
            "Vercel Sandbox SDK does not expose sandbox SSH access",
            id="ssh-create-token",
        ),
    ],
)
def test_v020_unsupported_create_inputs_have_reasons(
    item: str, inputs: Mapping[str, object], reason: str
) -> None:
    del item
    with pytest.raises(Unsupported) as error:
        native.VercelDriver._options(inputs)  # pylint: disable=protected-access
    assert str(error.value) == reason


@pytest.mark.parametrize(
    ("value", "settings"),
    [
        pytest.param("https", {"domain_traffic": "https"}, id="https"),
        pytest.param("http_and_https", {"domain_traffic": "http_and_https"}, id="http-and-https"),
        pytest.param("tls", {"domain_traffic": "tls"}, id="tls"),
        pytest.param("all", {"domain_traffic": "all"}, id="all"),
    ],
)
def test_v020_domain_traffic_values_are_explicitly_unsupported(
    value: str, settings: Mapping[str, object]
) -> None:
    del value
    inputs = {
        "requirements": {
            "network_lockdown": {
                "policy": "allowlist",
                "allow": ["packages.example"],
                **settings,
            }
        }
    }
    with pytest.raises(Unsupported) as error:
        native.VercelDriver._options(inputs)  # pylint: disable=protected-access
    assert (
        str(error.value) == "Vercel Sandbox SDK has no network protocol selector for domain rules"
    )


@pytest.mark.parametrize(
    ("value", "requirements"),
    [
        pytest.param("ipv4", {"ip_version": "ipv4"}, id="ipv4"),
        pytest.param("ipv6", {"ip_version": "ipv6"}, id="ipv6"),
    ],
)
def test_v020_private_network_ip_versions_are_explicitly_unsupported(
    value: str, requirements: Mapping[str, object]
) -> None:
    del value
    with pytest.raises(Unsupported) as error:
        native.VercelDriver._options({"requirements": {"private_network": requirements}})  # pylint: disable=protected-access
    assert str(error.value) == (
        "Vercel Secure Compute network IDs do not provide sandbox-to-sandbox private networking"
    )


@pytest.mark.parametrize(
    ("source", "extra", "reason"),
    [
        pytest.param(
            "dockerfile",
            {"context": {"Dockerfile": "FROM scratch"}},
            "Vercel Sandbox SDK does not build images from a Dockerfile or context",
            id="context",
        ),
        pytest.param(
            "private_oci",
            {},
            "Vercel Sandbox SDK accepts image references but has no generic "
            "private registry credentials",
            id="private-oci",
        ),
        pytest.param(
            "private_oci",
            {"username": "user"},
            "Vercel Sandbox SDK accepts image references but has no generic "
            "private registry credentials",
            id="username",
        ),
        pytest.param(
            "private_oci",
            {"password": "password"},
            "Vercel Sandbox SDK accepts image references but has no generic "
            "private registry credentials",
            id="password",
        ),
    ],
)
def test_v020_image_prepare_inputs_are_explicitly_unsupported(
    source: str, extra: Mapping[str, object], reason: str
) -> None:
    with pytest.raises(Unsupported) as error:
        native.VercelDriver().image_prepare(None, {"source": source, **extra})
    assert str(error.value) == reason


@pytest.mark.parametrize(
    ("value", "settings", "mode", "domains", "subnets"),
    [
        pytest.param(
            "allowlist",
            {"policy": "allowlist", "allow": ["packages.example"]},
            "custom",
            {"packages.example"},
            None,
            id="allowlist-domains",
        ),
        pytest.param(
            "denylist",
            {"policy": "denylist", "deny": ["192.0.2.0/24"]},
            "custom",
            {"*"},
            NetworkPolicySubnets(deny=["192.0.2.0/24"]),
            id="denylist-addresses",
        ),
        pytest.param(
            "open",
            {"policy": "open"},
            "allow-all",
            set(),
            None,
            id="open",
        ),
    ],
)
def test_v020_create_maps_network_policies_to_sdk_options(
    monkeypatch: pytest.MonkeyPatch,
    value: str,
    settings: Mapping[str, object],
    mode: str,
    domains: set[str],
    subnets: NetworkPolicySubnets | None,
) -> None:
    del value
    calls = _create(
        monkeypatch,
        {"requirements": {"network_lockdown": settings}},
    )
    policy = calls["network_policy"]
    assert isinstance(policy, NetworkPolicy)
    assert policy.mode == mode
    assert set(policy.allow) == domains
    assert policy.subnets == subnets


def test_v020_deny_wins_maps_to_vendored_subnet_precedence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _create(
        monkeypatch,
        {
            "requirements": {
                "network_lockdown": {
                    "policy": "allowlist",
                    "allow": ["packages.example"],
                    "deny": ["192.0.2.0/24"],
                    "deny_wins": True,
                }
            }
        },
    )
    policy = calls["network_policy"]
    assert policy.allow == {"packages.example": ()}
    assert policy.subnets == NetworkPolicySubnets(deny=["192.0.2.0/24"])


@pytest.mark.parametrize("image_config", ["user", "workdir"])
def test_v020_custom_image_configuration_travels_with_the_image_reference(
    monkeypatch: pytest.MonkeyPatch, image_config: str
) -> None:
    image = Resource("image_reference", "registry.example/team/image:tag", lambda: {})
    calls = _create(
        monkeypatch,
        {
            "image": {"resource": image},
            "requirements": {"custom_images": {"image_config": [image_config]}},
        },
    )
    assert calls["image"] == "registry.example/team/image:tag"
    assert "image_config" not in calls


def test_v020_read_only_mount_uses_the_sdk_snapshot_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    volume = Resource("volume", SimpleNamespace(name="drive-v12"), lambda: {})
    calls = _create(
        monkeypatch,
        {
            "volumes": [{"path": "/data", "volume": {"resource": volume}, "read_only": True}],
            "requirements": {"volumes": {"read_only_mounts": True}},
        },
    )
    mount = calls["mounts"]["/data"]
    assert mount.drive == "drive-v12"
    assert mount.mode == "snapshot"


def test_v020_switchable_allowlist_can_update_to_address_denylist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Sandbox:
        def update_network_policy(self, policy: NetworkPolicy) -> None:
            self.policy = policy

    box = Sandbox()
    create_calls = _create(
        monkeypatch,
        {
            "requirements": {
                "network_lockdown": {
                    "policy": "allowlist",
                    "allow": ["packages.example"],
                    "switchable": True,
                    "switches_to": ["denylist"],
                }
            }
        },
    )
    assert create_calls["network_policy"].allow == {"packages.example": ()}
    driver = native.VercelDriver()
    owned = driver.own("sandbox", Reserved("sps-v12", box), lambda: {})
    driver.network_update({"resource": owned}, {"policy": "denylist", "deny": ["192.0.2.0/24"]})
    assert box.policy.mode == "custom"
    assert set(box.policy.allow) == {"*"}
    assert box.policy.subnets == NetworkPolicySubnets(deny=["192.0.2.0/24"])


@pytest.mark.parametrize(
    ("settings", "domains", "subnets"),
    [
        pytest.param(
            {"policy": "allowlist", "allow": ["packages.example"]},
            {"packages.example"},
            None,
            id="allowlist",
        ),
        pytest.param(
            {"policy": "denylist", "deny": ["192.0.2.0/24"]},
            {"*"},
            NetworkPolicySubnets(deny=["192.0.2.0/24"]),
            id="denylist",
        ),
    ],
)
def test_v020_network_update_maps_supported_policy_values(
    settings: Mapping[str, object], domains: set[str], subnets: NetworkPolicySubnets | None
) -> None:
    class Sandbox:
        policy: NetworkPolicy

        def update_network_policy(self, policy: NetworkPolicy) -> None:
            self.policy = policy

    box = Sandbox()
    driver = native.VercelDriver()
    owned = driver.own("sandbox", Reserved("sps-v12", box), lambda: {})
    driver.network_update({"resource": owned}, settings)
    assert set(box.policy.allow) == domains
    assert box.policy.subnets == subnets


def test_v020_denylist_rejects_domain_entries() -> None:
    with pytest.raises(Unsupported) as error:
        native._policy({"policy": "denylist", "deny": ["blocked.example"]})  # pylint: disable=protected-access
    assert str(error.value) == "Vercel network policies deny address ranges, not domains"
