# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Docker Engine driver: every driver item the v0.2.0 tests reach (task V13).

Each item is either implemented, asserted here by the native SDK call made against a mocked
client, or unsupported, asserted by the error and its one-line reason.
"""

from __future__ import annotations

import io
import tarfile
from collections.abc import Mapping
from types import SimpleNamespace
from typing import Any, cast

import pytest
from docker.errors import NotFound  # type: ignore[import-untyped]

from sandbox_provider_spec.driver import NotRun, Resource, Unsupported
from sandbox_provider_spec.drivers.docker_engine import DockerDriver

MIB = 1024 * 1024
ABSENT_FILTER = "Docker Engine has no native domain or CIDR egress filter"
ABSENT_SSH = "Docker Engine has no SSH access operation; exec is not SSH"


class Container:
    def __init__(self, name: str, options: Mapping[str, object], networks: list[str]) -> None:
        self.id = f"id-{name}"
        self.name = name
        self.options = options
        self.labels = dict(cast(dict[str, str], options.get("labels", {})))
        self.started = False
        self.updates: list[dict[str, object]] = []
        self.execs: list[dict[str, object]] = []
        self.attrs: dict[str, Any] = {
            "HostConfig": {
                "CpuQuota": options.get("cpu_quota", 0),
                "CpuPeriod": options.get("cpu_period", 0),
                "Memory": int(str(options["mem_limit"]).removesuffix("m")) * MIB
                if "mem_limit" in options
                else 0,
            },
            "NetworkSettings": {"Networks": {n: {} for n in networks}},
        }

    def start(self) -> None:
        self.started = True

    def reload(self) -> None:
        pass

    def update(self, **limits: object) -> None:
        self.updates.append(limits)

    def exec_run(self, command: list[str], **options: object) -> SimpleNamespace:
        self.execs.append({"command": command, **options})
        return SimpleNamespace(output=(b"out", b""), exit_code=0)

    def remove(self, *, force: bool, v: bool) -> None:
        assert force and v
        self.name = ""


class Network:
    def __init__(self, name: str, registry: dict[str, Network] | None = None) -> None:
        self.name = name
        self.registry = registry
        self.disconnected: list[tuple[object, bool]] = []
        self.removed = False

    def disconnect(self, container: object, *, force: bool) -> None:
        self.disconnected.append((container, force))

    def remove(self) -> None:
        self.removed = True
        if self.registry is not None:
            del self.registry[self.name]


class Client:
    """The part of the Docker SDK client the driver calls, recording every call."""

    def __init__(self) -> None:
        self.created: list[Container] = []
        self.network_list: dict[str, Network] = {}
        self.network_creates: list[dict[str, object]] = []
        self.pulls: list[tuple[str, dict[str, object]]] = []
        self.builds: list[dict[str, object]] = []
        self.local_images = {"python:3.12-slim"}
        client = self

        class Containers:
            @staticmethod
            def create(image: str, **options: object) -> Container:
                networks = [str(options["network"])] if "network" in options else ["bridge"]
                native = Container(str(options["name"]), {"image": image, **options}, networks)
                client.created.append(native)
                return native

            @staticmethod
            def get(name: str) -> Container:
                for native in client.created:
                    if native.name == name or native.id == name:
                        return native
                raise NotFound("gone")

        class Images:
            @staticmethod
            def get(reference: str) -> SimpleNamespace:
                if reference not in client.local_images:
                    raise NotFound("absent")
                return SimpleNamespace(id=f"image-{reference}")

            @staticmethod
            def pull(reference: str, **options: object) -> SimpleNamespace:
                client.pulls.append((reference, options))
                client.local_images.add(reference)
                return SimpleNamespace(id=f"image-{reference}")

            @staticmethod
            def build(**options: object) -> None:
                client.builds.append(options)

            @staticmethod
            def list(all: bool) -> list[object]:  # pylint: disable=redefined-builtin
                del all
                return []

        class Networks:
            @staticmethod
            def create(name: str, **options: object) -> Network:
                client.network_creates.append({"name": name, **options})
                network = Network(name, client.network_list)
                client.network_list[name] = network
                return network

            @staticmethod
            def get(name: str) -> Network:
                if name not in client.network_list:
                    raise NotFound("gone")
                return client.network_list[name]

        self.containers = Containers()
        self.images = Images()
        self.networks = Networks()


def driver(**fixtures: object) -> tuple[DockerDriver, Client]:
    docker_driver = DockerDriver(fixtures)
    client = Client()
    docker_driver._client = client  # pylint: disable=protected-access
    return docker_driver, client


def start(docker_driver: DockerDriver, **inputs: object) -> Mapping[str, object]:
    return docker_driver.call("create", None, inputs)


def sandbox(docker_driver: DockerDriver, **inputs: object) -> Mapping[str, object]:
    return start(docker_driver, **inputs)


def locked(**settings: object) -> dict[str, object]:
    return {"requirements": {"network_lockdown": settings}}


def native(binding: Mapping[str, object]) -> Container:
    resource = binding["resource"]
    assert isinstance(resource, Resource)
    assert isinstance(resource.native, Container)
    return resource.native


# --- Driver operations -------------------------------------------------------------------


def test_allocation_observe_reads_the_native_cgroup_limits() -> None:
    docker_driver, client = driver()
    binding = sandbox(docker_driver, resources={"cpu_min": 0.5, "memory_min_mib": 512})
    assert client.created[0].options["cpu_quota"] == 50_000
    assert client.created[0].options["cpu_period"] == 100_000
    assert client.created[0].options["mem_limit"] == "512m"
    assert docker_driver.call("allocation.observe", binding, {}) == {
        "allocation": {"cpu_min": 0.5, "memory_min_mib": 512}
    }


def test_allocation_observe_without_a_native_limit_is_not_run() -> None:
    docker_driver, _ = driver()
    binding = sandbox(docker_driver)
    with pytest.raises(NotRun, match="^native_allocation_not_limited$"):
        docker_driver.call("allocation.observe", binding, {})


def test_resize_updates_the_running_container() -> None:
    docker_driver, client = driver()
    binding = sandbox(docker_driver, resources={"cpu_min": 1, "memory_min_mib": 256})
    docker_driver.call("resize", binding, {"resources": {"cpu_min": 2, "memory_min_mib": 128}})
    assert client.created[0].updates == [
        {"cpu_period": 100_000, "cpu_quota": 200_000, "mem_limit": "128m", "memswap_limit": "128m"}
    ]


def test_run_as_root_execs_as_root() -> None:
    docker_driver, client = driver()
    binding = sandbox(docker_driver)
    result = docker_driver.call("run.as_root", binding, {"bash_script": "id -u"})
    assert result == {"stdout": b"out", "stderr": b"", "exit_code": 0}
    assert client.created[0].execs[0]["user"] == "root"
    docker_driver.call("run", binding, {"bash_script": "id -u"})
    assert client.created[0].execs[1]["user"] == ""


def test_network_update_deny_all_leaves_every_network() -> None:
    docker_driver, client = driver()
    binding = sandbox(docker_driver, **locked(policy="open", switchable=True))
    client.network_list["bridge"] = Network("bridge")
    docker_driver.call("network.update", binding, {"policy": "deny_all"})
    assert client.network_list["bridge"].disconnected == [(client.created[0], True)]


@pytest.mark.parametrize("policy", ["allowlist", "denylist"])
def test_network_update_policy(policy: str) -> None:
    docker_driver, _ = driver()
    binding = sandbox(docker_driver)
    with pytest.raises(Unsupported, match=f"^{ABSENT_FILTER}$"):
        docker_driver.call("network.update", binding, {"policy": policy})


@pytest.mark.parametrize("credential", [None, "key", "token", "password"])
def test_ssh_access_is_unsupported(credential: str | None) -> None:
    docker_driver, _ = driver()
    binding = sandbox(docker_driver)
    inputs = {} if credential is None else {"credential": credential}
    with pytest.raises(Unsupported, match=f"^{ABSENT_SSH}$"):
        docker_driver.call("ssh.access", binding, inputs)


def test_secret_create_is_unsupported() -> None:
    docker_driver, _ = driver()
    with pytest.raises(
        Unsupported, match="^Standalone Docker Engine has no hidden HTTP credential injection$"
    ):
        docker_driver.call("secret.create", sandbox(docker_driver), {})


# --- create input keys -------------------------------------------------------------------


def test_create_build_context_needs_no_native_create_option() -> None:
    docker_driver, client = driver()
    image = docker_driver.call(
        "image.prepare", None, {"source": "oci", "image": "python:3.12-slim"}
    )
    sandbox(
        docker_driver,
        image=image,
        requirements={"custom_images": {"source": "dockerfile", "build_context": True}},
    )
    assert sorted(client.created[0].options) == [
        "command",
        "environment",
        "image",
        "labels",
        "name",
    ]


def test_create_cuts_open_connections_needs_no_native_option() -> None:
    docker_driver, client = driver()
    sandbox(docker_driver, **locked(policy="open", switchable=True, cuts_open_connections=True))
    assert "network_disabled" not in client.created[0].options


@pytest.mark.parametrize(
    "settings",
    [
        {"policy": "allowlist", "allow": ["a.example"], "deny_wins": True},
        {"policy": "allowlist", "allow": ["a.example"], "domain_traffic": "https"},
        {"policy": "allowlist", "allow": [{"host": "a.example", "methods": ["GET"]}]},
        {"policy": "allowlist", "allow": [{"host": "a.example", "paths": ["/x"]}]},
        {"policy": "allowlist", "allow": ["a.example"], "http_rules": True},
        {"policy": "denylist", "deny": ["a.example"], "hosts": ["a.example"]},
    ],
    ids=["deny_wins", "domain_traffic", "methods", "paths", "http_rules", "hosts"],
)
def test_create_egress_filter_keys_are_unsupported(settings: dict[str, object]) -> None:
    docker_driver, client = driver()
    with pytest.raises(Unsupported, match=f"^{ABSENT_FILTER}$"):
        sandbox(docker_driver, **locked(**settings))
    assert not client.created


def test_create_image_config_needs_no_native_option() -> None:
    docker_driver, client = driver()
    sandbox(
        docker_driver, requirements={"custom_images": {"image_config": ["env", "workdir", "user"]}}
    )
    # The image's own environment, working directory and user apply to the container.
    options = client.created[0].options
    assert not {"user", "working_dir"} & set(options)
    assert options["environment"] == {}


def test_create_ip_version_enables_ipv6_on_the_private_network() -> None:
    docker_driver, client = driver()
    sandbox(docker_driver, requirements={"private_network": {"ip_version": "ipv6"}})
    assert client.network_creates[0]["enable_ipv6"] is True


def test_create_join_attaches_to_the_first_sandboxes_network() -> None:
    docker_driver, client = driver()
    first = sandbox(docker_driver, requirements={"private_network": {}})
    second = sandbox(docker_driver, requirements={"private_network": {}}, join=first)
    assert len(client.network_creates) == 1
    name = client.network_creates[0]["name"]
    assert [c.options["network"] for c in client.created] == [name, name]
    assert native(second).labels["sps.network"] == name


def test_create_live_resize_takes_its_size_from_resources() -> None:
    docker_driver, client = driver()
    sandbox(
        docker_driver,
        requirements={"live_resize": {}},
        resources={"cpu_min": 1, "memory_min_mib": 64},
    )
    assert client.created[0].options["mem_limit"] == "64m"


def test_create_memory_min_mib_sets_the_native_memory_limit() -> None:
    docker_driver, client = driver()
    sandbox(docker_driver, resources={"memory_min_mib": 300})
    options = client.created[0].options
    assert (options["mem_limit"], options["memswap_limit"]) == ("300m", "300m")


def test_create_nested_virtualization_is_unsupported() -> None:
    docker_driver, _ = driver()
    with pytest.raises(
        Unsupported, match="^Docker Engine has no native nested virtualization option$"
    ):
        sandbox(docker_driver, requirements={"nested_virtualization": {}})


def test_create_private_network_creates_an_owned_bridge_network() -> None:
    docker_driver, client = driver()
    sandbox(docker_driver, requirements={"private_network": {}})
    created = client.network_creates[0]
    name = str(created["name"])
    assert name.startswith("sps-")
    assert (created["driver"], created["enable_ipv6"]) == ("bridge", False)
    assert [owned.kind for owned in docker_driver.resources] == ["network", "sandbox"]
    assert docker_driver.release(docker_driver.resources[0]) == {
        "kind": "network",
        "result": "deleted",
    }
    assert name not in client.network_list


def test_create_read_only_mounts_bind_read_only() -> None:
    docker_driver, client = driver()
    volume = Resource("volume", "vol", lambda: {"result": "deleted"})
    sandbox(
        docker_driver,
        requirements={"volumes": {"read_only_mounts": True}},
        volumes=[{"volume": {"resource": volume}, "path": "/data", "read_only": True}],
    )
    assert client.created[0].options["volumes"] == {"vol": {"bind": "/data", "mode": "ro"}}


def test_create_shrinks_lowers_the_native_limits() -> None:
    docker_driver, client = driver()
    binding = sandbox(
        docker_driver,
        requirements={"live_resize": {"shrinks": True}},
        resources={"memory_min_mib": 512},
    )
    docker_driver.call("resize", binding, {"resources": {"memory_min_mib": 256}})
    assert client.created[0].updates[0]["mem_limit"] == "256m"


@pytest.mark.parametrize("credential", ["key", "password", "token"])
def test_create_ssh_credential_is_unsupported(credential: str) -> None:
    docker_driver, client = driver()
    with pytest.raises(Unsupported, match=f"^{ABSENT_SSH}$"):
        sandbox(docker_driver, requirements={"ssh": {"credential": credential}})
    assert not client.created


def test_create_switchable_deny_all_needs_no_native_option() -> None:
    docker_driver, client = driver()
    sandbox(docker_driver, **locked(policy="open", switchable=True, switches_to=["deny_all"]))
    assert "network_disabled" not in client.created[0].options


def test_create_switches_to_denylist_is_unsupported() -> None:
    docker_driver, _ = driver()
    with pytest.raises(Unsupported, match=f"^{ABSENT_FILTER}$"):
        sandbox(docker_driver, **locked(policy="open", switchable=True, switches_to=["denylist"]))


# --- create values -----------------------------------------------------------------------


@pytest.mark.parametrize("traffic", ["all", "http_and_https", "https", "tls"])
def test_create_domain_traffic_value_is_unsupported(traffic: str) -> None:
    docker_driver, _ = driver()
    with pytest.raises(Unsupported, match=f"^{ABSENT_FILTER}$"):
        sandbox(
            docker_driver,
            **locked(policy="allowlist", allow=["a.example"], domain_traffic=traffic),
        )


@pytest.mark.parametrize("config", ["env", "user", "workdir"])
def test_create_image_config_value_needs_no_native_option(config: str) -> None:
    docker_driver, client = driver()
    sandbox(docker_driver, requirements={"custom_images": {"image_config": [config]}})
    assert not {"user", "working_dir"} & set(client.created[0].options)


@pytest.mark.parametrize("version", ["ipv4", "ipv6"])
def test_create_ip_version_value(version: str) -> None:
    docker_driver, client = driver()
    sandbox(docker_driver, requirements={"private_network": {"ip_version": version}})
    assert client.network_creates[0]["enable_ipv6"] is (version == "ipv6")


def test_create_policy_open_runs_on_the_default_network() -> None:
    docker_driver, client = driver()
    sandbox(docker_driver, **locked(policy="open"))
    assert "network_disabled" not in client.created[0].options


@pytest.mark.parametrize("policy", ["allowlist", "denylist"])
def test_create_policy_value_is_unsupported(policy: str) -> None:
    docker_driver, _ = driver()
    with pytest.raises(Unsupported, match=f"^{ABSENT_FILTER}$"):
        sandbox(docker_driver, **locked(policy=policy))


def test_create_policy_deny_all_disables_the_network() -> None:
    docker_driver, client = driver()
    sandbox(docker_driver, **locked(policy="deny_all"))
    assert client.created[0].options["network_disabled"] is True


@pytest.mark.parametrize(
    "requirements",
    [
        {"private_network": {}, "network_lockdown": {"policy": "deny_all"}},
        {"network_lockdown": {"policy": "deny_all"}, "private_network": {}},
    ],
)
def test_create_private_network_with_deny_all_is_unsupported(
    requirements: dict[str, object],
) -> None:
    docker_driver, client = driver()
    with pytest.raises(
        Unsupported,
        match="^Docker Engine cannot combine a private network with network lockdown deny_all$",
    ):
        sandbox(docker_driver, requirements=requirements)
    assert not client.created
    assert not client.network_creates


def test_create_join_with_deny_all_is_unsupported() -> None:
    docker_driver, client = driver()
    first = sandbox(docker_driver, requirements={"private_network": {}})
    with pytest.raises(
        Unsupported,
        match="^Docker Engine cannot combine a private network with network lockdown deny_all$",
    ):
        sandbox(
            docker_driver,
            requirements={"private_network": {}, "network_lockdown": {"policy": "deny_all"}},
            join=first,
        )
    assert len(client.created) == 1
    assert len(client.network_creates) == 1


def test_create_switches_to_deny_all_value() -> None:
    docker_driver, client = driver()
    binding = sandbox(
        docker_driver, **locked(policy="open", switchable=True, switches_to=["deny_all"])
    )
    client.network_list["bridge"] = Network("bridge")
    docker_driver.call("network.update", binding, {"policy": "deny_all"})
    assert client.network_list["bridge"].disconnected


# --- image.prepare -----------------------------------------------------------------------


def test_image_prepare_private_oci_pulls_with_the_supplied_credentials() -> None:
    docker_driver, client = driver()
    image = docker_driver.call(
        "image.prepare",
        None,
        {
            "source": "private_oci",
            "image": "registry.example/private:1",
            "username": "sps-user",
            "password": "sps-secret",
        },
    )
    assert client.pulls == [
        (
            "registry.example/private:1",
            {"auth_config": {"username": "sps-user", "password": "sps-secret"}},
        )
    ]
    assert cast_native(image) == "registry.example/private:1"
    # The pull is owned, so cleanup removes the image it added.
    assert [owned.kind for owned in docker_driver.resources] == ["pulled_image"]


def cast_native(binding: Mapping[str, object]) -> object:
    resource = binding["resource"]
    assert isinstance(resource, Resource)
    return resource.native


def test_image_prepare_private_oci_pulls_even_when_the_image_is_local() -> None:
    docker_driver, client = driver()
    client.local_images.add("registry.example/private:1")
    docker_driver.call(
        "image.prepare",
        None,
        {
            "source": "private_oci",
            "image": "registry.example/private:1",
            "username": "u",
            "password": "p",
        },
    )
    assert len(client.pulls) == 1
    assert not docker_driver.resources


def test_image_prepare_context_is_a_tar_build_context() -> None:
    docker_driver, client = driver(docker_engine_exclusive_daemon=True)
    docker_driver.call(
        "image.prepare",
        None,
        {
            "source": "dockerfile",
            "dockerfile": "FROM python:3.12-slim\nCOPY sps-context.txt /opt/sps-context.txt\n",
            "context": {"sps-context.txt": "from-context"},
        },
    )
    build = client.builds[0]
    assert build["custom_context"] is True
    with tarfile.open(fileobj=cast(io.BytesIO, build["fileobj"]), mode="r") as archive:
        assert archive.getnames() == ["Dockerfile", "sps-context.txt"]
        member = archive.extractfile("sps-context.txt")
        assert member is not None and member.read() == b"from-context"
        dockerfile = archive.extractfile("Dockerfile")
        assert dockerfile is not None and b"COPY sps-context.txt" in dockerfile.read()


def test_image_prepare_context_dockerfile_does_not_replace_the_input() -> None:
    docker_driver, client = driver(docker_engine_exclusive_daemon=True)
    explicit = "FROM python:3.12-slim\nCOPY keep.txt /opt/keep.txt\n"
    docker_driver.call(
        "image.prepare",
        None,
        {
            "source": "dockerfile",
            "dockerfile": explicit,
            "context": {
                "Dockerfile": "FROM scratch\n",
                "./Dockerfile": "FROM alpine\n",
                "keep.txt": "kept",
            },
        },
    )
    build = client.builds[0]
    with tarfile.open(fileobj=cast(io.BytesIO, build["fileobj"]), mode="r") as archive:
        assert archive.getnames() == ["Dockerfile", "keep.txt"]
        dockerfile = archive.extractfile("Dockerfile")
        assert dockerfile is not None and dockerfile.read() == explicit.encode()
        kept = archive.extractfile("keep.txt")
        assert kept is not None and kept.read() == b"kept"


def test_image_prepare_dockerfile_without_context_keeps_the_plain_build() -> None:
    docker_driver, client = driver(docker_engine_exclusive_daemon=True)
    docker_driver.call(
        "image.prepare", None, {"source": "dockerfile", "dockerfile": "FROM python:3.12-slim\n"}
    )
    build = client.builds[0]
    assert "custom_context" not in build
    assert isinstance(build["fileobj"], io.BytesIO)
