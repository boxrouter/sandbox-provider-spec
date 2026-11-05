# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""E2B driver mapping for the frozen v0.2.0 operation and input tables."""

from __future__ import annotations

import base64
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from e2b import NotFoundException, Sandbox, Secret, Template

from sandbox_provider_spec.driver import NotRun, Resource, Unsupported
from sandbox_provider_spec.drivers import e2b as native

TASK_OPERATIONS = (
    "allocation.observe",
    "create",
    "desktop.click",
    "desktop.key",
    "desktop.live_link",
    "desktop.screenshot",
    "desktop.start",
    "desktop.type",
    "destroy",
    "files.exists",
    "files.read_bytes",
    "files.write",
    "idle.select_duration",
    "image.prepare",
    "lifetime.observe_paused_countdown",
    "long_running.observe",
    "network.update",
    "preview.link",
    "preview.revoke",
    "process.start",
    "resize",
    "run",
    "run.as_root",
    "secret.create",
    "secret.rotate",
    "snapshot.delete_again",
    "snapshot.restore_begin",
    "snapshot.restore_wait",
    "snapshot.retention",
    "ssh.access",
    "tcp.link",
    "terminal.disconnect",
    "terminal.output",
    "terminal.reattach",
    "terminal.write",
    "volume.create",
    "volume.observe_kind",
    "volume.read_bytes",
    "volume.reload",
)


def bound(driver: native.E2BDriver, value: object, kind: str = "sandbox") -> dict[str, object]:
    return {"resource": driver.own(kind, value, lambda: {"result": "deleted"})}


def fake_create(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, object]]:
    calls: list[dict[str, object]] = []

    def create(**options: object) -> SimpleNamespace:
        calls.append(options)
        return SimpleNamespace(sandbox_id="sandbox-id")

    monkeypatch.setattr(Sandbox, "create", create)
    return calls


@pytest.mark.parametrize("operation", TASK_OPERATIONS)
def test_every_gen_52_operation_has_a_reviewed_mapping(operation: str) -> None:
    driver = native.E2BDriver()
    method_name = operation.replace(".", "_")
    assert (
        operation in driver.unsupported
        or operation in driver.unobservable
        or callable(getattr(driver, method_name, None))
    ), operation


@pytest.mark.parametrize(
    ("operation", "reason"),
    [
        ("idle.select_duration", "E2B timeout is a lifetime, not an idle-activity timer"),
        (
            "long_running.observe",
            "E2B exposes no observation that a sandbox remains active indefinitely",
        ),
        ("preview.revoke", "E2B SDK cannot revoke one public preview link"),
        ("resize", "E2B SDK has no sandbox resize operation"),
        ("ssh.access", "E2B SDK has no sandbox-scoped SSH access operation"),
        (
            "tcp.link",
            "E2B SDK exposes HTTP preview hosts, not public raw TCP endpoints",
        ),
    ],
)
def test_documented_absences_return_fixed_reasons(operation: str, reason: str) -> None:
    with pytest.raises(Unsupported, match=f"^{reason}$"):
        native.E2BDriver().call(operation, None, {})


@pytest.mark.parametrize(
    ("operation", "reason"),
    [
        ("lifetime.observe_paused_countdown", "native_paused_timer_countdown_unobservable"),
        ("snapshot.restore_begin", "native_restore_progress_unobservable"),
        ("snapshot.retention", "native_snapshot_retention_unobservable"),
    ],
)
def test_unobservable_metadata_is_not_called_unsupported(operation: str, reason: str) -> None:
    with pytest.raises(NotRun, match=f"^{reason}$"):
        native.E2BDriver().call(operation, None, {})


@pytest.mark.parametrize(
    ("operation", "inputs", "expected"),
    [
        ("files.exists", {"path": "/x"}, {"exists": True}),
        ("files.read_bytes", {"path": "/x"}, {"data": b"bytes"}),
        ("files.write", {"path": "/x", "data": base64.b64encode(b"bytes").decode()}, {}),
    ],
)
def test_file_operations_call_native_files_api(
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    inputs: dict[str, object],
    expected: dict[str, object],
) -> None:
    calls: list[tuple[object, ...]] = []

    class Files:
        def exists(self, path: str, **options: object) -> bool:
            calls.append(("exists", path, options["request_timeout"]))
            return True

        def read(self, path: str, *, format: str, **options: object) -> bytes:
            calls.append(("read", path, format, options["request_timeout"]))
            return b"bytes"

        def write(self, path: str, data: bytes, **options: object) -> None:
            calls.append(("write", path, data, options["request_timeout"]))

    driver = native.E2BDriver()
    target = bound(driver, SimpleNamespace(files=Files()))
    result = driver.call(operation, target, inputs)
    assert result == expected
    assert calls == [
        {
            "files.exists": ("exists", "/x", 30),
            "files.read_bytes": ("read", "/x", "bytes", 30),
            "files.write": ("write", "/x", b"bytes", 30),
        }[operation]
    ]


@pytest.mark.parametrize(
    ("operation", "inputs", "expected"),
    [
        ("desktop.start", {}, {}),
        ("desktop.screenshot", {}, {"png": b"png"}),
        ("desktop.click", {"x": 3, "y": 4}, {}),
        ("desktop.type", {"text": "hello"}, {}),
        ("desktop.key", {"key": "ENTER"}, {}),
        ("desktop.live_link", {}, {"url": "https://desktop.example"}),
    ],
)
def test_desktop_operations_use_companion_sdk(
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    inputs: dict[str, object],
    expected: dict[str, object],
) -> None:
    calls: list[object] = []

    class Desktop:
        def screenshot(self) -> bytes:
            calls.append("screenshot")
            return b"png"

        def left_click(self, x: int, y: int) -> None:
            calls.append(("click", x, y))

        def write(self, text: str) -> None:
            calls.append(("type", text))

        def press(self, key: str) -> None:
            calls.append(("key", key))

        class stream:
            @staticmethod
            def start(*, require_auth: bool) -> None:
                calls.append(("start", require_auth))

            @staticmethod
            def get_auth_key() -> str:
                return "auth-key"

            @staticmethod
            def get_url(*, auth_key: str) -> str:
                calls.append(("url", auth_key))
                return "https://desktop.example"

    monkeypatch.setattr(native, "DesktopSandbox", Desktop)
    driver = native.E2BDriver()
    target = bound(driver, Desktop())
    assert driver.call(operation, target, inputs) == expected
    assert (
        calls
        == {
            "desktop.start": [],
            "desktop.screenshot": ["screenshot"],
            "desktop.click": [("click", 3, 4)],
            "desktop.type": [("type", "hello")],
            "desktop.key": [("key", "ENTER")],
            "desktop.live_link": [("start", True), ("url", "auth-key")],
        }[operation]
    )


@pytest.mark.parametrize(
    ("operation", "expected"),
    [
        ("allocation.observe", {"allocation": {"cpu_min": 4, "memory_min_mib": 2048}}),
        ("preview.link", {"url": "https://sandbox-id-3000.e2b.app", "headers": {}}),
        ("snapshot.restore_wait", {"ready": True}),
    ],
)
def test_metadata_and_preview_calls_use_native_sandbox(
    operation: str, expected: dict[str, object]
) -> None:
    calls: list[object] = []

    class SandboxHandle:
        sandbox_id = "sandbox-id"

        def get_info(self, **options: object) -> SimpleNamespace:
            calls.append(("get_info", options["request_timeout"]))
            return SimpleNamespace(cpu_count=4, memory_mb=2048, state="running")

        def get_host(self, port: int) -> str:
            calls.append(("get_host", port))
            return "sandbox-id-3000.e2b.app"

    driver = native.E2BDriver()
    target = bound(driver, SandboxHandle())
    assert driver.call(operation, target, {"port": 3000}) == expected
    if operation == "allocation.observe":
        assert calls == [("get_info", 30)]
    elif operation == "preview.link":
        assert calls == [("get_host", 3000)]
    else:
        assert calls == [("get_info", 30)]


@pytest.mark.parametrize(
    ("policy", "fields"),
    [
        ("allowlist", {"allow": ["api.example", "203.0.113.0/24"]}),
        ("denylist", {"deny": ["203.0.113.0/24"]}),
        ("deny_all", {}),
        ("open", {}),
    ],
)
def test_network_update_replaces_native_egress_policy(
    policy: str, fields: dict[str, object]
) -> None:
    calls: list[object] = []

    class SandboxHandle:
        sandbox_id = "sandbox-id"

        def update_network(self, options: object, **kwargs: object) -> None:
            calls.append((options, kwargs["request_timeout"]))

    driver = native.E2BDriver()
    driver._network_configs["sandbox-id"] = {
        "rules": {"api.example": []},
        "egress_proxy": {"address": "proxy.example:1080", "password": "secret"},
    }
    target = bound(driver, SandboxHandle())
    assert driver.call("network.update", target, {"policy": policy, **fields}) == {}
    native_call = cast(tuple[object, int], calls[0])
    network = cast(dict[str, Any], native_call[0])
    assert network["rules"] == {"api.example": []}
    assert network["egress_proxy"]["address"] == "proxy.example:1080"
    assert native_call[1] == 30
    if policy == "allowlist":
        assert network["allow_out"] == ["api.example", "203.0.113.0/24"]
        assert network["deny_out"] == ["0.0.0.0/0"]
    elif policy == "denylist":
        assert network["deny_out"] == ["203.0.113.0/24"]
    elif policy == "deny_all":
        assert network["deny_out"] == ["0.0.0.0/0"]
    else:
        assert "allow_out" not in network and "deny_out" not in network


def test_create_passes_native_create_options_and_proves_minimum_allocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = fake_create(monkeypatch)

    class SandboxHandle:
        sandbox_id = "sandbox-id"

        def get_info(self, **options: object) -> SimpleNamespace:
            assert options["request_timeout"] == 30
            return SimpleNamespace(cpu_count=4, memory_mb=2048)

    def create(**options: object) -> SandboxHandle:
        calls.append(options)
        return SandboxHandle()

    monkeypatch.setattr(Sandbox, "create", create)
    result = native.E2BDriver().create(
        None,
        {"resources": {"cpu_min": 2, "memory_min_mib": 1024}},
    )
    assert result["identity"] == "sandbox-id"
    assert calls[0]["timeout"] == 120
    assert calls[0]["request_timeout"] == 60
    assert calls[0]["lifecycle"] == {"on_timeout": "kill"}


@pytest.mark.parametrize(
    ("settings", "expected"),
    [
        (
            {"policy": "allowlist", "allow": ["api.example", "203.0.113.0/24"]},
            {"allow_out": ["api.example", "203.0.113.0/24"], "deny_out": ["0.0.0.0/0"]},
        ),
        (
            {"policy": "denylist", "deny": ["203.0.113.0/24"]},
            {"deny_out": ["203.0.113.0/24"]},
        ),
        ({"policy": "open"}, {}),
        (
            {"policy": "allowlist", "allow": [{"hosts": ["api.example"]}]},
            {"allow_out": ["api.example"], "deny_out": ["0.0.0.0/0"]},
        ),
    ],
)
def test_create_maps_network_policies(
    monkeypatch: pytest.MonkeyPatch,
    settings: dict[str, object],
    expected: dict[str, object],
) -> None:
    calls = fake_create(monkeypatch)
    native.E2BDriver().create(None, {"requirements": {"network_lockdown": settings}})
    assert calls[0]["network"] == (expected or None)


@pytest.mark.parametrize(
    ("requirements", "reason"),
    [
        (
            {"network_lockdown": {"policy": "allowlist", "deny_wins": True}},
            "E2B allows a destination that also appears in deny_out",
        ),
        (
            {"network_lockdown": {"policy": "allowlist", "http_rules": True}},
            "E2B network rules transform requests but cannot filter methods or paths",
        ),
        (
            {
                "network_lockdown": {
                    "policy": "allowlist",
                    "allow": [{"hosts": ["api.example"], "methods": ["GET"]}],
                }
            },
            "E2B network rules cannot filter HTTP methods or paths",
        ),
        (
            {
                "network_lockdown": {
                    "policy": "allowlist",
                    "allow": [{"hosts": ["api.example"], "paths": ["/v1"]}],
                }
            },
            "E2B network rules cannot filter HTTP methods or paths",
        ),
        (
            {"network_lockdown": {"policy": "denylist", "deny": ["blocked.example"]}},
            "E2B deny lists accept IP addresses and CIDRs, not domains",
        ),
        (
            {
                "network_lockdown": {
                    "policy": "allowlist",
                    "allow": ["api.example"],
                    "domain_traffic": "all",
                }
            },
            "E2B hostname rules cover HTTP and HTTPS together",
        ),
        (
            {
                "network_lockdown": {
                    "policy": "allowlist",
                    "allow": ["api.example"],
                    "domain_traffic": "https",
                }
            },
            "E2B hostname rules cover HTTP and HTTPS together",
        ),
        (
            {
                "network_lockdown": {
                    "policy": "allowlist",
                    "allow": ["api.example"],
                    "domain_traffic": "tls",
                }
            },
            "E2B hostname rules cover HTTP and HTTPS together",
        ),
        (
            {"private_network": {"ip_version": "ipv4", "join": "team-net"}},
            "E2B SDK has no private-network membership or join option",
        ),
        (
            {"private_network": {"ip_version": "ipv6"}},
            "E2B SDK has no private-network membership or join option",
        ),
        ({"nested_virtualization": {}}, "E2B SDK has no nested-virtualization selector"),
        ({"live_resize": {"shrinks": True}}, "E2B SDK has no live sandbox resize operation"),
        ({"live_resize": {"shrinks": False}}, "E2B SDK has no live sandbox resize operation"),
        ({"ssh": {"credential": "key"}}, "E2B SDK has no sandbox-scoped SSH access operation"),
        ({"ssh": {"credential": "password"}}, "E2B SDK has no sandbox-scoped SSH access operation"),
        ({"ssh": {"credential": "token"}}, "E2B SDK has no sandbox-scoped SSH access operation"),
        ({"volumes": {"read_only_mounts": True}}, "E2B SDK volume mount has no read-only selector"),
    ],
)
def test_create_rejects_unavailable_input_semantics_before_allocation(
    monkeypatch: pytest.MonkeyPatch,
    requirements: dict[str, object],
    reason: str,
) -> None:
    monkeypatch.setattr(
        Sandbox,
        "create",
        lambda **_options: pytest.fail("unsupported input must not allocate a sandbox"),
    )
    with pytest.raises(Unsupported, match=f"^{reason}$"):
        native.E2BDriver().create(None, {"requirements": requirements})


@pytest.mark.parametrize("value", ["http_and_https"])
def test_create_accepts_native_domain_traffic_scope(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    calls = fake_create(monkeypatch)
    native.E2BDriver().create(
        None,
        {
            "requirements": {
                "network_lockdown": {
                    "policy": "allowlist",
                    "allow": ["api.example"],
                    "domain_traffic": value,
                    "deny_wins": False,
                    "http_rules": False,
                }
            }
        },
    )
    assert calls[0]["network"] == {
        "allow_out": ["api.example"],
        "deny_out": ["0.0.0.0/0"],
    }


@pytest.mark.parametrize("cuts_open_connections", [False, True])
def test_create_records_network_transition_inputs_for_update(
    monkeypatch: pytest.MonkeyPatch,
    cuts_open_connections: bool,
) -> None:
    updates: list[object] = []

    class SandboxHandle:
        sandbox_id = "sandbox-id"

        def update_network(self, options: object, **_kwargs: object) -> None:
            updates.append(options)

    monkeypatch.setattr(Sandbox, "create", lambda **_options: SandboxHandle())
    driver = native.E2BDriver()
    created = driver.create(
        None,
        {
            "requirements": {
                "network_lockdown": {
                    "policy": "allowlist",
                    "allow": ["api.example"],
                    "switchable": True,
                    "switches_to": ["denylist"],
                    "cuts_open_connections": cuts_open_connections,
                }
            }
        },
    )
    target = {"resource": created["resource"]}
    assert driver.network_update(target, {"policy": "denylist", "deny": ["203.0.113.0/24"]}) == {}
    assert updates[0] == {"deny_out": ["203.0.113.0/24"]}
    assert driver.network_update(target, {"policy": "allowlist", "allow": ["api.example"]}) == {}
    assert updates[1] == {
        "allow_out": ["api.example"],
        "deny_out": ["0.0.0.0/0"],
    }
    with pytest.raises(Unsupported, match="^E2B network update target is outside switches_to$"):
        driver.network_update(target, {"policy": "open"})


def test_network_update_honors_immutable_policy_and_switchability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    updates: list[object] = []

    class SandboxHandle:
        sandbox_id = "sandbox-id"

        def update_network(self, options: object, **_kwargs: object) -> None:
            updates.append(options)

    monkeypatch.setattr(Sandbox, "create", lambda **_options: SandboxHandle())
    driver = native.E2BDriver()
    created = driver.create(
        None,
        {
            "requirements": {
                "network_lockdown": {
                    "policy": "allowlist",
                    "allow": ["api.example"],
                    "changeable": False,
                }
            }
        },
    )
    target = {"resource": created["resource"]}
    with pytest.raises(
        Unsupported,
        match="^E2B network policy was created as non-changeable$",
    ):
        driver.network_update(target, {"policy": "allowlist", "allow": ["other.example"]})
    with pytest.raises(
        Unsupported,
        match="^E2B network policy was not created as switchable$",
    ):
        driver.network_update(target, {"policy": "open"})
    assert updates == []


def test_create_accepts_image_config_and_read_only_mounts_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = fake_create(monkeypatch)
    image = bound(native.E2BDriver(), "template-id", kind="template")
    native.E2BDriver().create(
        None,
        {
            "image": image,
            "requirements": {
                "custom_images": {"image_config": ["env", "user", "workdir"]},
                "volumes": {"read_only_mounts": False},
            },
        },
    )
    assert calls[0]["template"] == "template-id"
    assert calls[0]["volume_mounts"] is None


@pytest.mark.parametrize("credential", ["key", "password", "token"])
def test_ssh_access_credentials_are_explicitly_unsupported(credential: str) -> None:
    with pytest.raises(
        Unsupported,
        match="^E2B SDK has no sandbox-scoped SSH access operation$",
    ):
        native.E2BDriver().call("ssh.access", None, {"credential": credential})


@pytest.mark.parametrize(
    ("delivery", "expected_reason"),
    [("environment", "E2B identity tokens are injected into egress requests, not the environment")],
)
def test_workload_identity_rejects_environment_delivery(
    monkeypatch: pytest.MonkeyPatch, delivery: str, expected_reason: str
) -> None:
    monkeypatch.setattr(
        Sandbox,
        "create",
        lambda **_options: pytest.fail("unsupported delivery must not allocate a sandbox"),
    )
    with pytest.raises(Unsupported, match=f"^{expected_reason}$"):
        native.E2BDriver(
            {"workload_identity": {"audience": "service", "hosts": ["api.example"]}}
        ).create(None, {"requirements": {"workload_identity": {"delivery": delivery}}})


def test_create_configures_injected_identity_and_egress_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = fake_create(monkeypatch)
    monkeypatch.setattr(
        Secret, "iam_token", lambda **_options: {"audience": "service", "token_type": "JWT-SVID"}
    )
    fixtures = {
        "egress_proxy": {
            "address": "proxy.example:1080",
            "username": "proxy-user",
            "password": "proxy-password",
        },
        "workload_identity": {
            "audience": "service",
            "hosts": ["api.example"],
            "header": "Authorization",
            "token_name": "sps",
        },
    }
    native.E2BDriver(fixtures).create(
        None,
        {
            "requirements": {
                "egress_proxy": {
                    "protocol": "socks5",
                    "traffic": "any_tcp",
                    "transparent": True,
                    "fails_closed": True,
                },
                "workload_identity": {"delivery": "injected", "custom_audience": True},
            }
        },
    )
    options = calls[0]
    network = cast(dict[str, Any], options["network"])
    assert network["egress_proxy"]["address"] == "proxy.example:1080"
    assert network["egress_proxy"]["password"] == "proxy-password"
    iam = cast(dict[str, Any], options["iam"])
    assert iam["tokens"]["sps"]["audience"] == "service"
    transform = network["rules"]["api.example"][0]["transform"]
    assert transform(SimpleNamespace(iam=SimpleNamespace(tokens={"sps": "placeholder"}))) == {
        "headers": {"Authorization": "Bearer placeholder"}
    }


@pytest.mark.parametrize(
    ("settings", "reason"),
    [
        (
            {"protocol": "http", "traffic": "http"},
            "E2B BYOP tunnels TCP through SOCKS5, not an HTTP-only proxy",
        ),
        (
            {"protocol": "socks5", "traffic": "http"},
            "E2B BYOP tunnels TCP through SOCKS5, not an HTTP-only proxy",
        ),
    ],
)
def test_egress_proxy_rejects_mismatched_protocol_or_traffic(
    monkeypatch: pytest.MonkeyPatch, settings: dict[str, object], reason: str
) -> None:
    monkeypatch.setattr(
        Sandbox,
        "create",
        lambda **_options: pytest.fail("unsupported proxy must not allocate a sandbox"),
    )
    with pytest.raises(Unsupported, match=f"^{reason}$"):
        native.E2BDriver({"egress_proxy": {"address": "proxy.example:1080"}}).create(
            None,
            {"requirements": {"egress_proxy": settings}},
        )


def test_private_oci_uses_registry_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[object, ...]] = []

    class FakeTemplate:
        def from_image(self, image: str, **credentials: str) -> object:
            calls.append(("from_image", image, credentials))
            return object()

        def from_dockerfile(self, content: str) -> object:
            calls.append(("from_dockerfile", content))
            return object()

        @staticmethod
        def build(_template: object, **options: object) -> SimpleNamespace:
            return SimpleNamespace(template_id="template-id")

    monkeypatch.setattr(native, "Template", FakeTemplate)
    driver = native.E2BDriver()
    result = driver.image_prepare(
        None,
        {
            "source": "private_oci",
            "image": "registry.example/image:tag",
            "username": "registry-user",
            "password": "registry-password",
        },
    )
    assert cast(Resource, result["resource"]).kind == "template"
    assert calls == [
        (
            "from_image",
            "registry.example/image:tag",
            {"username": "registry-user", "password": "registry-password"},
        )
    ]


def test_image_config_dockerfile_is_passed_to_native_template_parser(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    content = "FROM alpine\nENV SPS_VALUE=expected\nUSER nobody\nWORKDIR /srv"
    calls: list[str] = []

    class FakeTemplate:
        def __init__(self, *, file_context_path: Path) -> None:
            del file_context_path

        def from_dockerfile(self, dockerfile: str) -> object:
            calls.append(Path(dockerfile).read_text())
            return object()

        @staticmethod
        def build(_template: object, **_options: object) -> SimpleNamespace:
            return SimpleNamespace(template_id="template-id")

    monkeypatch.setattr(native, "Template", FakeTemplate)
    result = native.E2BDriver().image_prepare(None, {"source": "dockerfile", "dockerfile": content})
    assert cast(Resource, result["resource"]).native == "template-id"
    assert calls == [content]


@pytest.mark.parametrize("operation", ["run", "run.as_root"])
def test_run_operations_call_commands_api_with_expected_user(
    operation: str,
) -> None:
    calls: list[dict[str, object]] = []

    class Commands:
        def run(self, script: str, **options: object) -> SimpleNamespace:
            calls.append({"script": script, **options})
            return SimpleNamespace(stdout="out", stderr="err", exit_code=7)

    driver = native.E2BDriver()
    target = bound(driver, SimpleNamespace(commands=Commands()))
    result = driver.call(operation, target, {"bash_script": "id", "timeout_ms": 2500})
    assert result == {"stdout": "out", "stderr": "err", "exit_code": 7}
    if operation == "run.as_root":
        assert calls[0]["user"] == "root"
    else:
        assert calls[0]["user"] is None
    assert calls[0]["timeout"] == 2.5


def test_files_write_and_process_start_forward_named_user() -> None:
    writes: list[dict[str, object]] = []
    starts: list[dict[str, object]] = []

    class Files:
        def write(self, path: str, data: bytes, **options: object) -> None:
            writes.append({"path": path, "data": data, **options})

    class Commands:
        def run(self, _script: str, **options: object) -> SimpleNamespace:
            starts.append(options)
            return SimpleNamespace(pid=73)

    driver = native.E2BDriver()
    binding = bound(driver, SimpleNamespace(files=Files(), commands=Commands()))
    driver.call("files.write", binding, {"path": "/tmp/new", "data": "eA==", "user": "runner"})
    driver.call("process.start", binding, {"bash_script": "id -un", "run_as": "runner"})
    assert writes == [{"path": "/tmp/new", "data": b"x", "user": "runner", "request_timeout": 30}]
    assert starts[0]["user"] == "runner"


def test_destroy_kills_native_sandbox_and_confirms_absence() -> None:
    calls: list[object] = []

    class SandboxHandle:
        def kill(self, **options: object) -> None:
            calls.append(("kill", options["request_timeout"]))

        def get_info(self, **options: object) -> None:
            calls.append(("get_info", options["request_timeout"]))
            raise NotFoundException("gone")

    driver = native.E2BDriver()
    handle = SandboxHandle()
    target = {
        "resource": driver.own(
            "sandbox", handle, lambda: native.E2BDriver._delete(cast(Sandbox, handle))
        )
    }
    assert driver.call("destroy", target, {}) == {"kind": "sandbox", "result": "deleted"}
    assert calls == [("kill", 30), ("get_info", 30)]


def test_process_start_calls_sdk_and_returns_owned_handle() -> None:
    calls: list[object] = []

    class Handle:
        pid = 42

    class Commands:
        def run(self, script: str, **options: object) -> Handle:
            calls.append((script, options))
            return Handle()

    driver = native.E2BDriver()
    result = driver.call(
        "process.start",
        bound(driver, SimpleNamespace(commands=Commands())),
        {"bash_script": "sleep 1", "run_as": "runner"},
    )
    assert result["identity"] == 42
    assert cast(Resource, result["resource"]).kind == "process"
    assert calls == [
        ("sleep 1", {"background": True, "stdin": True, "user": "runner", "timeout": 120.0})
    ]


@pytest.mark.parametrize(
    ("operation", "inputs", "expected"),
    [
        ("terminal.disconnect", {}, {}),
        (
            "terminal.output",
            {"first_chunk": True},
            {"stdout": "out", "stderr": "err", "terminal": b"tty"},
        ),
        ("terminal.write", {"data": base64.b64encode(b"input").decode()}, {}),
        ("terminal.reattach", {}, {"sandbox": "parent", "identity": 42}),
    ],
)
def test_terminal_operations_use_native_pty_or_command_handle(
    operation: str, inputs: dict[str, object], expected: dict[str, object]
) -> None:
    calls: list[object] = []

    class Handle:
        pid = 42

        def disconnect(self) -> None:
            calls.append("disconnect")

        def __iter__(self) -> Any:
            yield ("out", "err", b"tty")

    class Pty:
        def connect(self, pid: int, **_options: object) -> Handle:
            calls.append(("connect", pid))
            return Handle()

        def send_stdin(self, pid: int, data: bytes, **_options: object) -> None:
            calls.append(("send", pid, data))

    class Parent:
        pty = Pty()

    driver = native.E2BDriver()
    handle = Handle()
    if operation == "terminal.reattach":
        target = bound(driver, handle)
        native_parent = Parent()
        target["sandbox"] = native_parent
        expected = {"sandbox": native_parent, "identity": 42}
        result = driver.call(operation, target, inputs)
        assert result["identity"] == expected["identity"]
        assert cast(Resource, result["resource"]).kind == "observer"
    elif operation == "terminal.write":
        target = bound(driver, handle)
        parent = Parent()
        target["sandbox"] = parent
        assert driver.call(operation, target, inputs) == expected
        assert calls == [("send", 42, b"input")]
    else:
        result = driver.call(operation, bound(driver, handle), inputs)
        if operation == "terminal.output":
            assert result == expected
        else:
            assert result == expected
    if operation == "terminal.disconnect":
        assert calls == ["disconnect"]
    elif operation == "terminal.output":
        assert calls == []
    elif operation == "terminal.reattach":
        assert calls == [("connect", 42)]


def test_secret_create_rotate_and_snapshot_delete_call_native_sdk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[object] = []
    monkeypatch.setattr(
        Secret, "create", lambda name, value, **_opts: calls.append(("create", name, value))
    )
    monkeypatch.setattr(
        Secret, "update", lambda name, value, **_opts: calls.append(("update", name, value))
    )
    monkeypatch.setattr(
        Sandbox,
        "delete_snapshot",
        lambda snapshot_id, **_opts: calls.append(("snapshot.delete", snapshot_id)),
    )
    driver = native.E2BDriver()
    created = driver.secret_create(None, {"value": "secret-value"})
    driver.secret_rotate({"resource": created["resource"]}, {"value": "rotated-value"})
    snapshot = driver.own(
        "snapshot", SimpleNamespace(snapshot_id="snapshot-id"), lambda: {"result": "deleted"}
    )
    driver.snapshot_delete_again({"resource": snapshot}, {})
    create_call = cast(tuple[str, str, str], calls[0])
    assert create_call[0] == "create" and create_call[2] == "secret-value"
    assert calls[1] == ("update", create_call[1], "rotated-value")
    assert calls[2] == ("snapshot.delete", "snapshot-id")


def test_volume_create_kind_and_read_use_sdk_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[object] = []

    class FakeVolume:
        volume_id = "volume-id"
        name = "test-volume"

        @staticmethod
        def create(name: str, **_options: object) -> FakeVolume:
            calls.append(("create", name))
            return FakeVolume()

        @staticmethod
        def get_info(volume_id: str, **_options: object) -> object:
            calls.append(("get_info", volume_id))
            return object()

        def exists(self, path: str, **_options: object) -> bool:
            calls.append(("exists", path))
            return True

        def read_file(self, path: str, *, format: str, **_options: object) -> bytes:
            calls.append(("read_file", path, format))
            return b"volume-data"

    monkeypatch.setattr(native, "Volume", FakeVolume)
    driver = native.E2BDriver()
    volume = driver.volume_create(None, {})["resource"]
    assert driver.volume_observe_kind({"resource": volume}, {}) == {"kind": "filesystem"}
    assert driver.volume_read_bytes({"resource": volume}, {"path": "/marker"}) == {
        "exists": True,
        "data": b"volume-data",
    }
    assert cast(tuple[str, str], calls[0])[0] == "create"
    assert calls[1:] == [
        ("get_info", "volume-id"),
        ("exists", "/marker"),
        ("read_file", "/marker", "bytes"),
    ]


def test_volume_reload_is_unsupported_with_sdk_reason() -> None:
    with pytest.raises(
        Unsupported,
        match="^E2B Volume SDK has no mounted-volume refresh operation$",
    ):
        native.E2BDriver().call("volume.reload", None, {})


@pytest.mark.rule("custom_images/build-context")
def test_dockerfile_context_is_available_during_native_build_and_removed_afterward(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    roots: list[Path] = []

    def build(template: Any, **_options: object) -> SimpleNamespace:
        root = Path(template._template._file_context_path)
        roots.append(root)
        assert (root / "nested/copied.txt").read_bytes() == b"copied"
        assert (root / "added.txt").read_bytes() == b"added"
        assert (root / "binary.bin").read_bytes() == b"\x00\xff\x00\x80\xfef\x00"
        assert [
            item["args"][:2] for item in template._template._instructions if item["type"] == "COPY"
        ] == [["nested/copied.txt", "/copy"], ["added.txt", "/add"]]
        return SimpleNamespace(template_id="template-id")

    monkeypatch.setattr(Template, "build", build)
    driver = native.E2BDriver()
    image = driver.image_prepare(
        None,
        {
            "source": "dockerfile",
            "dockerfile": "FROM python:3.12-slim\nCOPY nested/copied.txt /copy\nADD added.txt /add",
            "context": {
                "nested/copied.txt": "copied",
                "added.txt": b"added",
                "binary.bin": {"base64": "AP8AgP5mAA=="},
            },
        },
    )
    assert roots and not roots[0].exists()
    calls = fake_create(monkeypatch)
    driver.create(
        None,
        {
            "image": image,
            "requirements": {"custom_images": {"source": "dockerfile", "build_context": True}},
        },
    )
    assert calls[0]["template"] == "template-id"


@pytest.mark.rule("custom_images/build-context")
@pytest.mark.parametrize(
    "path", ["../escape", "/absolute", "Dockerfile", "bad\\path", "", "nul\x00path"]
)
def test_dockerfile_context_rejects_paths_outside_the_supplied_context(
    monkeypatch: pytest.MonkeyPatch,
    path: str,
) -> None:
    monkeypatch.setattr(
        Template,
        "build",
        lambda *_args, **_kwargs: pytest.fail("invalid context must not allocate"),
    )
    with pytest.raises(ValueError, match="paths must stay inside the context"):
        native.E2BDriver().image_prepare(
            None,
            {
                "source": "dockerfile",
                "dockerfile": "FROM alpine",
                "context": {path: "bytes"},
            },
        )
