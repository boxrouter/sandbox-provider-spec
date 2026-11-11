# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Request and declaration validation follows the checked-in vocabulary."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

import sandbox_provider_spec
from sandbox_provider_spec import check, cli
from sandbox_provider_spec.check import UNKNOWN_WORD, _check_declared_limit
from sandbox_provider_spec.load import DuplicateKeyError, load

ROOT = Path(__file__).resolve().parents[1]


def declaration() -> dict[str, Any]:
    return {
        "spec": "sandbox-provider-spec/0.1",
        "provider": "acme",
        "verified": {"date": "2026-09-29", "sdks": {"acme": "1.0.0"}},
        "resources": {"kernel": "unknown"},
        "gates": {},
        "evidence": {},
    }


def test_catalog_vocabulary_has_a_checked_schema() -> None:
    catalog = sandbox_provider_spec.load_catalog()
    assert sandbox_provider_spec.schema_errors(catalog, "catalog-schema.json") == []
    assert catalog["declaration_top_level"] == [
        "spec",
        "provider",
        "class",
        "verified",
        "resources",
        "lifetime_timer",
        "evidence",
        "gates",
    ]
    assert catalog["gates"]["hidden_secrets"]["settings"] == {
        "inject_into": {
            "kind": "list",
            "required": True,
            "item": {"kind": "hostname"},
            "distinct": True,
            "wildcards": True,
        },
        "headers": {
            "kind": "list",
            "required": False,
            "item": {
                "kind": "object",
                "required": ["name"],
                "properties": {
                    "name": {"kind": "nonempty_string"},
                    "prefix": {"kind": "string"},
                    "suffix": {"kind": "string"},
                },
                "additional_properties": False,
            },
        },
    }
    assert catalog["gates"]["hidden_secrets"]["limits"] == [
        "max_inject_into",
        "inject_wildcards",
    ]
    assert catalog["limits"]["inject_wildcards"] == {
        "kinds": ["yes_no", "unknown"],
        "left_out": "unknown",
    }
    assert catalog["gates"]["volumes"]["settings"]["mounts"]["item"]["required"] == [
        "provider",
        "volume",
        "path",
    ]
    assert catalog["gates"]["volumes"]["settings"]["mounts"]["item"]["properties"]["read_only"] == {
        "kind": "boolean"
    }
    assert catalog["gates"]["custom_images"]["settings"]["image"]["kind"] == [
        "string",
        "object",
    ]
    assert sandbox_provider_spec.catalog_documents_differ() is False

    invalid = deepcopy(catalog)
    invalid["limits"]["max_allow"]["unknown_fits"] = "one"
    assert sandbox_provider_spec.schema_errors(invalid, "catalog-schema.json")

    invalid = deepcopy(catalog)
    invalid["gates"]["idle_shutdown"]["knobs"]["auto_wake"]["only_when"]["unknown_rule"] = True
    assert sandbox_provider_spec.schema_errors(invalid, "catalog-schema.json")

    invalid = deepcopy(catalog)
    invalid["declaration_resources"]["max_lifetime_seconds"]["floor"]["at_least"] = 0
    assert sandbox_provider_spec.schema_errors(invalid, "catalog-schema.json")

    invalid = deepcopy(catalog)
    invalid["evidence"]["quotable_paths"] = ["resources.?unsafe"]
    assert sandbox_provider_spec.schema_errors(invalid, "catalog-schema.json")


def test_catalog_rejects_consumer_operation_mappings() -> None:
    catalog = sandbox_provider_spec.load_catalog()
    assert "operation_requirements" not in catalog
    catalog["operation_requirements"] = {"deleteWorkspaceSnapshot": {"snapshot_owned": True}}

    assert sandbox_provider_spec.schema_errors(catalog, "catalog-schema.json")


def test_catalog_command_checks_schema_and_compiled_copy(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli.main(["check-catalog"]) == 0
    assert capsys.readouterr().out == "catalog: ok\n"


@pytest.mark.rule("request/refused-before-matching")
def test_request_types_ranges_and_unique_values() -> None:
    good = {
        "requirements": {
            "previews": {"access": "private", "ports": [3000]},
            "network_lockdown": {"policy": "allowlist", "allow": ["api.example.com"]},
            "hidden_secrets": {"inject_into": ["api.example.com"]},
        },
        "resources": {
            "cpu_min": 0.5,
            "memory_min_mib": 1024,
            "long_running": True,
            "paused_retention_seconds": 0.5,
        },
    }
    assert sandbox_provider_spec.check_request(good) == []

    invalid = [
        {"requirements": {"previews": {"access": "public", "ports": [3000, 3000]}}},
        {"requirements": {"previews": {"access": "public", "ports": [0]}}},
        {"requirements": {"previews": {"access": "public", "ports": [70000]}}},
        {"requirements": {"previews": {"access": "public", "ports": ["3000"]}}},
        {
            "requirements": {
                "network_lockdown": {
                    "policy": "allowlist",
                    "allow": ["a.example", "a.example"],
                }
            }
        },
        {"requirements": {"idle_shutdown": {"custom_idle_time": True, "idle_seconds": "x"}}},
        {"requirements": {"idle_shutdown": {"custom_idle_time": True, "idle_seconds": -1}}},
        {"resources": {"cpu_min": -1}},
        {"resources": {"paused_retention_seconds": 0}},
        {"resources": {"paused_retention_seconds": True}},
        {"resources": {"long_running": "maybe"}},
        {"resources": {"long_running": [True]}},
        {"resources": {"extendable_lifetime": 1}},
    ]
    for request in invalid:
        assert sandbox_provider_spec.check_request(request), request


@pytest.mark.rule("request/refused-before-matching")
def test_waitlisted_connection_cutting_is_an_unknown_knob() -> None:
    request = {
        "requirements": {
            "network_lockdown": {
                "policy": "allowlist",
                "allow": ["pypi.org"],
                "cuts_open_connections": True,
            }
        }
    }
    assert sandbox_provider_spec.check_request(request) == [
        "any word the spec does not define: network_lockdown.cuts_open_connections"
    ]


@pytest.mark.rule("registries/unknown-identifier-matches-nothing")
def test_registry_additions_do_not_make_files_unreadable() -> None:
    assert sandbox_provider_spec.check_request({"resources": {"region": "CH"}}) == []
    assert sandbox_provider_spec.check_request({"resources": {"region": "vendor:future"}}) == []
    assert (
        sandbox_provider_spec.check_request({"resources": {"gpu_model": "vendor:unknown-gpu"}})
        == []
    )

    countries = sandbox_provider_spec.load(
        sandbox_provider_spec.spec_dir() / "registries/regions.json"
    )
    assert len(countries["countries"]) >= 249
    assert {"CH", "US", "DE", "ZA"} <= set(countries["countries"])


@pytest.mark.rule("request/refused-before-matching")
def test_mounts_secret_hosts_and_provider_pins() -> None:
    mounts = {
        "requirements": {
            "volumes": {
                "kind": "filesystem",
                "mounts": [{"provider": "acme", "volume": "shared-data", "path": "/data"}],
            }
        }
    }
    assert sandbox_provider_spec.check_request(mounts) == []

    secret_allowed = {
        "requirements": {
            "network_lockdown": {"policy": "allowlist", "allow": ["*.example.com"]},
            "hidden_secrets": {"inject_into": ["api.example.com"]},
        }
    }
    assert sandbox_provider_spec.check_request(secret_allowed) == []
    secret_wildcard = {"requirements": {"hidden_secrets": {"inject_into": ["*.example.com"]}}}
    assert sandbox_provider_spec.check_request(secret_wildcard) == []
    for allow, accepted in (
        (["*.example.com"], True),
        (["*.googleapis.com"], False),
        (["api.example.com"], False),
    ):
        assert (
            sandbox_provider_spec.check_request(
                {
                    "requirements": {
                        "network_lockdown": {"policy": "allowlist", "allow": allow},
                        "hidden_secrets": {"inject_into": ["*.example.com"]},
                    }
                }
            )
            == []
        ) is accepted
    assert (
        sandbox_provider_spec.check_request(
            {
                "requirements": {
                    "network_lockdown": {"policy": "allowlist", "allow": ["*.example.com"]},
                    "hidden_secrets": {"inject_into": ["*.sub.example.com"]},
                }
            }
        )
        == []
    )
    for deny, accepted in (
        (["api.example.com"], False),
        (["example.com"], False),
        (["com"], False),
        (["*.example.com"], False),
    ):
        assert (
            sandbox_provider_spec.check_request(
                {
                    "requirements": {
                        "network_lockdown": {"policy": "denylist", "deny": deny},
                        "hidden_secrets": {"inject_into": ["*.example.com"]},
                    }
                }
            )
            == []
        ) is accepted
    secret_open = {
        "requirements": {
            "network_lockdown": {
                "policy": "open",
                "switchable": True,
                "switches_to": ["deny_all"],
            },
            "hidden_secrets": {"inject_into": ["api.example.com"]},
        }
    }
    assert sandbox_provider_spec.check_request(secret_open) == []
    # Without network_lockdown nothing shuts the hosts out, so nothing is refused.
    assert (
        sandbox_provider_spec.check_request(
            {"requirements": {"hidden_secrets": {"inject_into": ["api.example.com"]}}}
        )
        == []
    )
    for lockdown, refused in (
        ({"policy": "denylist", "deny": ["other.example.com"]}, False),
        ({"policy": "denylist", "deny": ["203.0.113.0/24"]}, False),
        ({"policy": "denylist", "deny": ["API.example.com"]}, True),
        ({"policy": "deny_all"}, True),
        ({"policy": "allowlist", "allow": ["203.0.113.7"]}, True),
    ):
        errors = sandbox_provider_spec.check_request(
            {
                "requirements": {
                    "network_lockdown": lockdown,
                    "hidden_secrets": {"inject_into": ["api.example.com"]},
                }
            }
        )
        assert any("inject_into host" in error for error in errors) is refused, lockdown
    assert sandbox_provider_spec.check_request(
        {
            "requirements": {
                "network_lockdown": {"policy": "allowlist", "allow": ["other.example.com"]},
                "hidden_secrets": {"inject_into": ["api.example.com"]},
            }
        }
    )

    assert sandbox_provider_spec.check_request(
        {
            "requirements": {
                "volumes": {
                    "kind": "filesystem",
                    "mounts": [
                        {"provider": "acme", "volume": "one", "path": "/one"},
                        {"provider": "other", "volume": "two", "path": "/two"},
                    ],
                }
            }
        }
    )
    assert sandbox_provider_spec.check_request(
        {
            "image": {"provider_artifact": "golden", "provider": "acme"},
            "requirements": {"x-other": {"feature": True}},
        }
    )


def test_yes_no_declaration_limit_kind_accepts_booleans_and_unknown() -> None:
    limit = {"kinds": ["yes_no", "unknown"], "left_out": "unknown"}
    for value in (True, False, "unknown"):
        errors: list[str] = []
        _check_declared_limit(
            "inject_wildcards", value, "gates.hidden_secrets.0.inject_wildcards", limit, errors
        )
        assert errors == []
    errors = []
    _check_declared_limit(
        "inject_wildcards", 1, "gates.hidden_secrets.0.inject_wildcards", limit, errors
    )
    assert errors == ["any word the spec does not define: gates.hidden_secrets.0.inject_wildcards"]


@pytest.mark.rule("request/refused-before-matching")
def test_read_only_mount_requires_the_volumes_knob() -> None:
    read_only = {
        "requirements": {
            "volumes": {
                "kind": "filesystem",
                "read_only_mounts": True,
                "mounts": [
                    {
                        "provider": "modal",
                        "volume": "weights",
                        "path": "/data",
                        "read_only": True,
                    }
                ],
            }
        }
    }
    assert sandbox_provider_spec.check_request(read_only) == []
    assert sandbox_provider_spec.schema_errors(read_only, "request-schema.json") == []

    writable = {
        "requirements": {
            "volumes": {
                "kind": "filesystem",
                "mounts": [
                    {
                        "provider": "modal",
                        "volume": "weights",
                        "path": "/data",
                        "read_only": False,
                    }
                ],
            }
        }
    }
    assert sandbox_provider_spec.check_request(writable) == []

    missing_knob = {
        "requirements": {
            "volumes": {
                "kind": "filesystem",
                "mounts": [
                    {
                        "provider": "modal",
                        "volume": "weights",
                        "path": "/data",
                        "read_only": True,
                    }
                ],
            }
        }
    }
    assert sandbox_provider_spec.check_request(missing_knob) == [
        "read_only on a mount unless read_only_mounts is true"
    ]

    invalid_type = {
        "requirements": {
            "volumes": {
                "kind": "filesystem",
                "read_only_mounts": True,
                "mounts": [
                    {
                        "provider": "modal",
                        "volume": "weights",
                        "path": "/data",
                        "read_only": "yes",
                    }
                ],
            }
        }
    }
    assert sandbox_provider_spec.check_request(invalid_type)


@pytest.mark.rule("request/refused-before-matching")
def test_mounts_that_differ_only_in_read_only_repeat_the_mount_key() -> None:
    repeated = {
        "requirements": {
            "volumes": {
                "kind": "filesystem",
                "read_only_mounts": True,
                "mounts": [
                    {"provider": "modal", "volume": "weights", "path": "/data", "read_only": False},
                    {"provider": "modal", "volume": "weights", "path": "/data", "read_only": True},
                ],
            }
        }
    }
    assert sandbox_provider_spec.schema_errors(repeated, "request-schema.json") == []
    assert sandbox_provider_spec.check_request(repeated) == ["volumes.mounts repeats a mount"]

    same_object = {
        "requirements": {
            "volumes": {
                "kind": "filesystem",
                "mounts": [
                    {"provider": "modal", "volume": "weights", "path": "/data"},
                    {"provider": "modal", "volume": "weights", "path": "/data"},
                ],
            }
        }
    }
    assert sandbox_provider_spec.check_request(same_object) == ["volumes.mounts repeats a mount"]

    distinct = {
        "requirements": {
            "volumes": {
                "kind": "filesystem",
                "read_only_mounts": True,
                "mounts": [
                    {"provider": "modal", "volume": "weights", "path": "/data", "read_only": True},
                    {
                        "provider": "modal",
                        "volume": "weights",
                        "path": "/other",
                        "read_only": False,
                    },
                ],
            }
        }
    }
    assert sandbox_provider_spec.check_request(distinct) == []


@pytest.mark.rule("declaration/unknown-words-reported")
def test_documented_values_are_checked_against_the_catalog() -> None:
    document = declaration()
    document["resources"] = {
        "kernel": "vm",
        "needs": ["plan_pro"],
    }
    document["gates"] = {"pause_resume": [{"keeps": "everything"}]}
    result = sandbox_provider_spec.check_declaration(document)
    assert any("resources.kernel" in error for error in result.errors)
    assert any("'vm'" in error for error in result.errors)
    assert any("resources.needs" in error for error in result.errors)
    assert any("pause_resume.keeps" in error for error in result.errors)


def test_default_size_is_optional_unknown_or_one_concrete_schema_size() -> None:
    assert sandbox_provider_spec.schema_errors(declaration(), "declaration-schema.json") == []
    for value in (
        "unknown",
        {"cpu": 2, "memory_mib": 4096},
        {"cpu": 0.5, "memory_mib": 1024, "disk_mib": 2048},
    ):
        document = declaration()
        document["resources"]["default_size"] = value
        assert sandbox_provider_spec.schema_errors(document, "declaration-schema.json") == []


@pytest.mark.parametrize(
    "value",
    [
        [{"cpu": 2, "memory_mib": 4096}],
        {"cpu": [1, 8], "memory_mib": 4096},
        {"cpu": 2, "memory_mib": 4096, "memory_gib": 4},
        {"cpu": 0, "memory_mib": 4096},
        {"cpu": 2, "memory_mib": -1},
        {"memory_mib": 4096},
        {"cpu": 2},
    ],
)
def test_default_size_rejects_non_concrete_or_incomplete_shapes(value: object) -> None:
    document = declaration()
    document["resources"]["default_size"] = value
    assert sandbox_provider_spec.schema_errors(document, "declaration-schema.json")


def test_explicit_unknown_default_size_accepts_an_explanatory_quote() -> None:
    document = declaration()
    document["resources"] = {"default_size": "unknown"}
    document["evidence"] = {
        "resources.default_size": {
            "source": "https://example.invalid/default-size",
            "read": "2026-10-18",
            "quote": "The selected create path does not establish one stable allocation.",
        }
    }
    assert sandbox_provider_spec.check_declaration(document).errors == []


def test_default_size_checker_rejects_invalid_fields() -> None:
    document = declaration()
    document["resources"] = {"default_size": {"cpu": 2, "memory_mib": -1, "memory_gib": 4}}
    errors = sandbox_provider_spec.check_declaration(document).errors
    assert any("resources.default_size.memory_mib" in error for error in errors)
    assert any("resources.default_size.memory_gib" in error for error in errors)


def test_egress_ip_declarations_use_the_catalog_values() -> None:
    document = declaration()
    document["resources"] = {"egress_ips": ["published_ranges", "dedicated"]}
    document["evidence"] = {
        "resources.egress_ips": {
            "source": "https://example.invalid/egress",
            "read": "2026-09-30",
            "quote": "Outbound connections use published or dedicated addresses.",
        }
    }
    assert sandbox_provider_spec.check_declaration(document).errors == []

    document["resources"]["egress_ips"] = []
    assert sandbox_provider_spec.check_declaration(document).errors == []

    for retired in (["static"], ["rotating"]):
        document["resources"]["egress_ips"] = retired
        result = sandbox_provider_spec.check_declaration(document)
        assert any("resources.egress_ips" in error for error in result.errors)

    document["resources"]["egress_ips"] = ["unknown"]
    result = sandbox_provider_spec.check_declaration(document)
    assert any("unknown inside a list" in error for error in result.errors)


def test_tcp_port_tls_documentation_is_citable() -> None:
    document = declaration()
    document["gates"] = {"tcp_ports": [{"tls": "none"}]}
    document["evidence"] = {
        "gates.tcp_ports.0.tls": {
            "source": "https://docs.example.invalid/tunnels",
            "read": "2026-10-05",
            "quote": "Unencrypted TCP tunnels are supported.",
        }
    }
    assert sandbox_provider_spec.check_declaration(document).errors == []


@pytest.mark.rule("declaration/unknown-words-reported")
def test_needs_use_one_map_shape_and_unknown_registry_words_are_kept() -> None:
    document = declaration()
    document["resources"] = {
        "located_in": ["CH", "XX"],
        "regions": ["acme:future-region"],
        "needs": {"located_in": ["plan-pro"]},
    }
    document["evidence"] = {
        "resources.located_in": {
            "source": "https://docs.example.invalid/location",
            "read": "2026-09-29",
            "quote": "Locations are in Switzerland.",
        },
        "resources.regions": {
            "source": "https://docs.example.invalid/regions",
            "read": "2026-09-29",
            "quote": "A region is available.",
        },
        "resources.needs.located_in": {
            "source": "https://docs.example.invalid/plans",
            "read": "2026-09-29",
            "quote": "This feature requires the Pro plan.",
        },
    }
    assert sandbox_provider_spec.check_declaration(document).errors == []

    document["resources"]["needs"] = ["plan-pro"]
    assert any(
        "resources.needs" in error
        for error in sandbox_provider_spec.check_declaration(document).errors
    )


@pytest.mark.rule("declaration/unknown-words-reported")
def test_needs_must_name_values_present_in_the_declaration() -> None:
    document = declaration()
    document["resources"] = {"needs": {"disk_mib": ["paid_plan"]}}
    assert any(
        "needs names no declared resource value" in error
        for error in sandbox_provider_spec.check_declaration(document).errors
    )

    document = declaration()
    document["gates"] = {"pause_resume": [{"needs": {"keeps": ["beta"]}}]}
    assert any(
        "needs names no declared variant value" in error
        for error in sandbox_provider_spec.check_declaration(document).errors
    )


def test_new_declaration_facts_and_gates_follow_the_catalog() -> None:
    document = declaration()
    document["resources"] = {
        "default_user": "sandbox",
        "default_cwd": "/workspace",
        "paused_retention_seconds": {"at_least": 3600},
        "max_lifetime_seconds": {"at_least": 300},
    }
    document["gates"] = {
        "processes": [{"input": True, "cancel": False, "reattach": True}],
        "terminal": [{}],
        "snapshots": [{"retention_seconds": {"at_least": 86400}}],
    }
    cited = (
        "resources.default_user",
        "resources.default_cwd",
        "resources.paused_retention_seconds",
        "resources.max_lifetime_seconds",
        "gates.processes.0.input",
        "gates.processes.0.cancel",
        "gates.processes.0.reattach",
        "gates.terminal.0",
        "gates.snapshots.0.retention_seconds",
    )
    document["evidence"] = {
        path: {"tests": ["fixture.test"], "report": "reports/fixture.json"} for path in cited
    }

    assert sandbox_provider_spec.schema_errors(document, "declaration-schema.json") == []
    assert sandbox_provider_spec.check_declaration(document).errors == []


def test_new_declaration_facts_and_gates_reject_wrong_shapes() -> None:
    document = declaration()
    document["resources"] = {
        "default_user": 1000,
        "default_cwd": "workspace",
        "paused_retention_seconds": True,
    }
    document["gates"] = {
        "processes": [{"input": "yes", "cancel": 0}],
        "terminal": [{"input": True}],
        "snapshots": [{"retention_seconds": {"minimum": 86400}}],
    }

    result = sandbox_provider_spec.check_declaration(document)
    assert any("resources.default_user" in error for error in result.errors)
    assert any("resources.default_cwd" in error for error in result.errors)
    assert any("resources.paused_retention_seconds" in error for error in result.errors)
    assert any("processes.input" in error for error in result.errors)
    assert any("processes.cancel" in error for error in result.errors)
    assert any("terminal" in error and "input" in error for error in result.errors)
    assert any("snapshots.retention_seconds" in error for error in result.errors)

    document = declaration()
    document["resources"] = {"max_lifetime_seconds": {"at_least": 299}}
    assert any(
        "resources.max_lifetime_seconds" in error
        for error in sandbox_provider_spec.check_declaration(document).errors
    )

    document["resources"] = {"max_lifetime_seconds": "unknown"}
    assert any(
        "resources.max_lifetime_seconds" in error
        for error in sandbox_provider_spec.check_declaration(document).errors
    )


@pytest.mark.rule("request/refused-before-matching")
def test_coverage_requests_follow_the_catalog() -> None:
    good = {
        "requirements": {
            "previews": {
                "access": "public",
                "websocket": True,
                "loopback": False,
                "any_port": True,
                "survives_pause": True,
                "ports": [3000],
            },
            "pause_resume": {},
            "terminal": {"reattach": True},
            "docker": {"networking": "host"},
            "tcp_ports": {"tls": "none", "ports": [5432, 6379]},
            "desktop": {"live_view": True},
        },
        "resources": {
            "memory_min_mib": 2048,
            "disk_min_mib": 4096,
            "root": ["sudo", "per_command"],
            "arch": ["arm64", "amd64"],
            "package_manager": "apt",
            "libc": ["glibc", "musl"],
            "run_seconds": 3600,
            "process_seconds": 86400,
        },
    }
    assert sandbox_provider_spec.check_request(good) == []
    assert "previews or tcp_ports with no ports" in sandbox_provider_spec.check_request(
        {"requirements": {"tcp_ports": {"tls": "none"}}}
    )
    assert "previews or tcp_ports with no ports" in sandbox_provider_spec.check_request(
        {"requirements": {"tcp_ports": {"ports": []}}}
    )
    assert any(
        "duplicate ports, allowlist or denylist entries" in error
        for error in sandbox_provider_spec.check_request(
            {
                "requirements": {
                    "network_lockdown": {
                        "policy": "allowlist",
                        "allow": ["pypi.org", "pypi.org"],
                    }
                }
            }
        )
    )
    invalid = [
        {"requirements": {"tcp_ports": {"ports": [5432, 5432]}}},
        {"requirements": {"tcp_ports": {"ports": [70000]}}},
        {"requirements": {"tcp_ports": {"ports": [5432], "tls": "passthrough"}}},
        {"requirements": {"tcp_ports": {"ports": [5432], "max_tcp_ports": 2}}},
        {
            "requirements": {
                "previews": {"access": "public", "ports": [3000], "reserved_ports": [22]}
            }
        },
        {"requirements": {"previews": {"access": "public", "ports": [3000], "websocket": "yes"}}},
        {"requirements": {"docker": {"networking": "overlay"}}},
        {"requirements": {"nested_virtualization": {"kvm": True}}},
        {"requirements": {"ssh": {"credential": "certificate"}}},
        {"requirements": {"terminal": {"reattach": 1}}},
        {"requirements": {"desktop": {"live_view": "yes"}}},
        {"requirements": {"custom_images": {"runs_entrypoint": True}}},
        {"resources": {"root": False}},
        {"resources": {"root": True}},
        {"resources": {"root": "default_user"}},
        {"resources": {"arch": "x86_64"}},
        {"resources": {"egress_ips": "rotating"}},
        {"requirements": {"tcp_ports": {"ports": [5432]}}},
        {"resources": {"arch": "sparc"}},
        {"resources": {"arch": []}},
        {"resources": {"package_manager": ["apt", "apt"]}},
        {"resources": {"package_manager": "yum"}},
        {"resources": {"libc": "bionic"}},
        {"resources": {"run_seconds": 0}},
        {"resources": {"run_seconds": 1.5}},
        {"resources": {"process_seconds": "60"}},
        {"resources": {"max_run_seconds": 60}},
        {"resources": {"disk_in_memory": True}},
    ]
    for request in invalid:
        assert sandbox_provider_spec.check_request(request), request


@pytest.mark.rule("request/refused-before-matching")
def test_pick_knobs_take_one_value_or_a_list() -> None:
    good = [
        {"requirements": {"idle_shutdown": {"on_idle": ["paused", "stopped"]}}},
        {"requirements": {"pause_resume": {"keeps": ["files_only", "files_and_memory"]}}},
        {
            "requirements": {
                "previews": {"access": "private", "credential": ["link", "header"], "ports": [1]}
            }
        },
        {
            "requirements": {
                "snapshots": {
                    "keeps": ["files_only"],
                    "original_after": ["continues", "terminated"],
                }
            }
        },
        {
            "requirements": {
                "volumes": {
                    "sharing": ["many_writers"],
                    "kind": "any",
                    "mounts": [{"provider": "acme", "volume": "data", "path": "/data"}],
                }
            }
        },
        {
            "requirements": {
                "volumes": {
                    "kind": ["filesystem", "object_store"],
                    "mounts": [{"provider": "acme", "volume": "data", "path": "/data"}],
                }
            }
        },
        {
            "requirements": {
                "hidden_secrets": {
                    "inject_into": ["api.example.com"],
                    "intercepts": ["injected_hosts", "all_https"],
                    "transparent": True,
                }
            }
        },
        {"requirements": {"tcp_ports": {"tls": ["none"], "ports": [5432]}}},
    ]
    for request in good:
        assert sandbox_provider_spec.check_request(request) == [], request
    invalid = [
        {"requirements": {"network_lockdown": {"policy": ["deny_all"]}}},
        {"requirements": {"network_lockdown": {"policy": "any"}}},
        {"requirements": {"idle_shutdown": {"on_idle": []}}},
        {"requirements": {"idle_shutdown": {"on_idle": ["paused", "paused"]}}},
        {"requirements": {"idle_shutdown": {"on_idle": ["any", "paused"]}}},
        {"requirements": {"idle_shutdown": {"on_idle": "never"}}},
        {"requirements": {"pause_resume": {"keeps": "any"}}},
        {"requirements": {"snapshots": {"original_after": ["any"]}}},
        {"requirements": {"hidden_secrets": {"inject_into": ["a.example.com"], "injection": []}}},
        {
            "requirements": {
                "hidden_secrets": {"inject_into": ["a.example.com"], "transparent": "yes"}
            }
        },
    ]
    for request in invalid:
        assert sandbox_provider_spec.check_request(request), request


@pytest.mark.rule("request/refused-before-matching")
def test_denylist_requests_follow_the_catalog() -> None:
    good = [
        {
            "policy": "denylist",
            "deny": ["ads.example.com", "203.0.113.0/24"],
            "changeable": True,
        },
        {"policy": "allowlist", "allow": ["*.example.com"]},
    ]
    for lockdown in good:
        assert (
            sandbox_provider_spec.check_request({"requirements": {"network_lockdown": lockdown}})
            == []
        ), lockdown

    def errors(lockdown: dict[str, Any]) -> list[str]:
        return sandbox_provider_spec.check_request({"requirements": {"network_lockdown": lockdown}})

    wrong_list = "allow with anything but an allowlist, or deny with anything but a denylist"
    empty = "an allowlist or a denylist with nothing in it"
    entry = "an allow or deny entry that is neither a host name nor an IPv4 address or range"
    for lockdown, expected in (
        (
            {"policy": "allowlist", "allow": ["a.example.com"], "deny": ["b.example.com"]},
            wrong_list,
        ),
        (
            {"policy": "denylist", "allow": ["a.example.com"], "deny": ["b.example.com"]},
            wrong_list,
        ),
        (
            {
                "policy": "denylist",
                "deny_wins": True,
                "deny": ["b.example.com"],
            },
            "any word the spec does not define: network_lockdown.deny_wins",
        ),
        ({"policy": "deny_all", "deny": ["b.example.com"]}, wrong_list),
        ({"policy": "denylist"}, empty),
        ({"policy": "denylist", "deny": []}, empty),
        ({"policy": "denylist", "deny": ["*.example.com"]}, "a wildcard in deny"),
        ({"policy": "denylist", "deny": ["203.0.113.999"]}, entry),
        ({"policy": "denylist", "deny": ["example.com:443"]}, entry),
        ({"policy": "denylist", "deny": ["2001:db8::1"]}, entry),
    ):
        assert any(expected in error for error in errors(lockdown)), lockdown
    for lockdown in (
        {"policy": "denylist", "deny": ["203.0.113.7", "203.0.113.7"]},
        {"policy": "denylist", "deny": ["203.0.113.7"], "changeable": "yes"},
    ):
        assert errors(lockdown), lockdown


@pytest.mark.rule("request/refused-before-matching")
def test_waitlisted_http_rule_knob_is_unknown() -> None:
    request = {
        "requirements": {
            "network_lockdown": {
                "policy": "allowlist",
                "http_rules": True,
                "allow": ["api.github.com"],
            }
        }
    }
    assert "any word the spec does not define: network_lockdown.http_rules" in (
        sandbox_provider_spec.check_request(request)
    )
    assert sandbox_provider_spec.schema_errors(request, "request-schema.json")


@pytest.mark.rule("request/refused-before-matching")
def test_conditional_lockdown_knobs_need_their_condition() -> None:
    def errors(lockdown: dict[str, Any]) -> list[str]:
        return sandbox_provider_spec.check_request({"requirements": {"network_lockdown": lockdown}})

    lockdown: dict[str, Any]
    for lockdown in (
        {"policy": "allowlist", "allow": ["203.0.113.7"], "changeable": False},
        {"policy": "denylist", "deny": ["ads.example.com"], "changeable": True},
    ):
        assert errors(lockdown) == [], lockdown
    for lockdown in (
        {"policy": "deny_all", "changeable": True},
        {"policy": "deny_all", "changeable": False},
    ):
        assert errors(lockdown) == ["changeable with deny_all or open"], lockdown
        # The schema holds the same condition on its own.
        document = {"requirements": {"network_lockdown": lockdown}}
        assert sandbox_provider_spec.schema_errors(document, "request-schema.json"), lockdown


@pytest.mark.rule("request/refused-before-matching")
def test_waitlisted_domain_traffic_knob_is_unknown() -> None:
    request = {
        "requirements": {
            "network_lockdown": {
                "policy": "allowlist",
                "allow": ["github.com"],
                "domain_traffic": "all",
            }
        }
    }
    assert "any word the spec does not define: network_lockdown.domain_traffic" in (
        sandbox_provider_spec.check_request(request)
    )
    assert sandbox_provider_spec.schema_errors(request, "request-schema.json")


@pytest.mark.rule("request/refused-before-matching")
def test_switchable_policy_settings_follow_the_catalog() -> None:
    def errors(lockdown: dict[str, Any]) -> list[str]:
        return sandbox_provider_spec.check_request({"requirements": {"network_lockdown": lockdown}})

    assert (
        errors(
            {
                "policy": "allowlist",
                "allow": ["pypi.org"],
                "switchable": True,
                "switches_to": ["deny_all"],
            }
        )
        == []
    )
    assert (
        errors(
            {
                "policy": "allowlist",
                "allow": ["pypi.org"],
                "switchable": False,
                "switches_to": ["deny_all"],
            }
        )
        == []
    )
    for lockdown in (
        {"policy": "allowlist", "allow": ["pypi.org"], "switchable": True},
        {"policy": "deny_all", "switches_to": ["allowlist"]},
    ):
        assert "switchable without switches_to, or switches_to without switchable" in errors(
            lockdown
        ), lockdown
    assert "switches_to naming the request's own policy" in errors(
        {"policy": "deny_all", "switchable": True, "switches_to": ["deny_all"]}
    )
    assert errors(
        {"policy": "deny_all", "switchable": True, "switches_to": ["denylist", "denylist"]}
    )
    assert (
        errors({"policy": "open", "switchable": True, "switches_to": ["allowlist", "deny_all"]})
        == []
    )
    assert errors({"policy": "open"}) == ["open without switchable"]
    for entry_name in ("allow", "deny"):
        open_with_entries = {
            "policy": "open",
            "switchable": True,
            "switches_to": ["deny_all"],
            entry_name: ["pypi.org"],
        }
        assert errors(open_with_entries)
        assert sandbox_provider_spec.schema_errors(
            {"requirements": {"network_lockdown": open_with_entries}}, "request-schema.json"
        )
    transition_to_open = {
        "policy": "allowlist",
        "allow": ["pypi.org"],
        "switchable": False,
        "switches_to": ["open"],
    }
    assert errors(transition_to_open) == ["open without switchable"]
    assert sandbox_provider_spec.schema_errors(
        {"requirements": {"network_lockdown": transition_to_open}}, "request-schema.json"
    )
    assert errors(
        {
            "policy": "open",
            "changeable": True,
            "switchable": True,
            "switches_to": ["deny_all"],
        }
    ) == ["changeable with deny_all or open"]


@pytest.mark.rule("request/refused-before-matching")
def test_condition_image_and_pause_refusals() -> None:
    image = "debian:stable"
    lockdown = "network_lockdown"
    good: list[dict[str, Any]] = [
        {
            "requirements": {
                lockdown: {"policy": "denylist", "deny": ["203.0.113.7"], "changeable": True}
            }
        },
        {
            "requirements": {
                "idle_shutdown": {"on_idle": ["paused", "destroyed"], "auto_wake": True}
            }
        },
        {"requirements": {"idle_shutdown": {"auto_wake": True}}},
        {
            "requirements": {
                "idle_shutdown": {"on_idle": "stopped"},
                "previews": {"access": "public", "ports": [3000], "survives_pause": True},
            }
        },
        {"image": image, "requirements": {"custom_images": {"runs_entrypoint": True}}},
        {"image": image, "resources": {"arch": "arm64", "egress_ips": "dedicated"}},
        {
            "requirements": {
                lockdown: {"policy": "denylist", "deny": ["example.com"]},
                "hidden_secrets": {"inject_into": ["example.org"]},
            }
        },
    ]
    for request in good:
        assert sandbox_provider_spec.check_request(request) == [], request
    refused: list[tuple[dict[str, Any], str]] = [
        (
            {"requirements": {lockdown: {"policy": "deny_all", "changeable": False}}},
            "changeable with deny_all or open",
        ),
        (
            {"requirements": {"idle_shutdown": {"on_idle": "destroyed", "auto_wake": True}}},
            "auto_wake with on_idle naming only destroyed",
        ),
        (
            {"requirements": {"idle_shutdown": {"on_idle": ["destroyed"], "auto_wake": False}}},
            "auto_wake with on_idle naming only destroyed",
        ),
        (
            {
                "requirements": {
                    "previews": {"access": "public", "ports": [3000], "survives_pause": True}
                }
            },
            "survives_pause in a request that names neither pause_resume nor idle_shutdown",
        ),
        (
            {"requirements": {"custom_images": {"runs_entrypoint": True}}},
            "source under requirements, or custom_images under requirements without an image",
        ),
        (
            {"image": image, "requirements": {"custom_images": {"source": "oci"}}},
            "source under requirements, or custom_images under requirements without an image",
        ),
        (
            {"image": image, "resources": {"root": "sudo"}},
            "root, package_manager, libc or kernel_features together with an image",
        ),
        (
            {
                "requirements": {
                    lockdown: {"policy": "denylist", "deny": ["example.com"]},
                    "hidden_secrets": {"inject_into": ["api.example.com"]},
                }
            },
            "an inject_into host an allowlist does not list or cover by name",
        ),
    ]
    for request, expected in refused:
        errors = sandbox_provider_spec.check_request(request)
        assert any(expected in error for error in errors), (request, errors)
    # The schema holds each refusal on its own, apart from the host-name comparison.
    for request, _expected in refused[:-1]:
        assert sandbox_provider_spec.schema_errors(request, "request-schema.json"), request
    # A restores_need carries no image, so it never names custom_images.
    restore = {
        "requirements": {"snapshots": {"original_after": "any"}},
        "restores_need": {"requirements": {"custom_images": {"runs_entrypoint": True}}},
    }
    assert sandbox_provider_spec.check_request(restore)


@pytest.mark.rule("custom_images/build-context", "request/refused-before-matching")
@pytest.mark.parametrize("image", [{"dockerfile": "FROM alpine\nCOPY a /a"}, "alpine:3"])
def test_build_context_requires_a_dockerfile_image(image: object) -> None:
    request = {"image": image, "requirements": {"custom_images": {"build_context": True}}}
    accepted = isinstance(image, dict)
    assert bool(sandbox_provider_spec.check_request(request)) is not accepted
    assert bool(sandbox_provider_spec.schema_errors(request, "request-schema.json")) is not accepted


def coverage_declaration() -> dict[str, Any]:
    document = declaration()
    document["resources"] = {
        "sizes": [{"cpu": 2, "memory_mib": 4096}],
        "disk_in_memory": True,
        "root": [],
        "arch": ["arm64", "amd64"],
        "package_manager": "apk",
        "libc": "musl",
        "max_run_seconds": 3600,
        "max_process_seconds": "unlimited",
        "egress_ips": ["published_ranges"],
    }
    document["gates"] = {
        "idle_shutdown": [{"on_idle": "stopped", "auto_wake": True}],
        "network_lockdown": [
            {"policy": ["allowlist", "denylist"], "changeable": True, "max_deny": {"at_least": 100}}
        ],
        "hidden_secrets": [
            {
                "rotates": False,
                "scrubs_responses": True,
                "transparent": True,
                "injection": "sets_header",
                "intercepts": "all_https",
            }
        ],
        "previews": [
            {
                "access": "public",
                "websocket": True,
                "loopback": True,
                "any_port": False,
                "survives_pause": True,
                "reserved_ports": [22, 49983],
                "max_ports": 3,
            }
        ],
        "custom_images": [{"source": "oci", "runs_entrypoint": False}],
        "terminal": [{"reattach": True}],
        "docker": [{"networking": "host", "conflicts": ["custom_images"]}],
        "processes": "unsupported",
        "tcp_ports": [{"tls": "none", "max_tcp_ports": {"at_least": 2}}],
        "desktop": [{"live_view": False}],
    }
    cited = [f"resources.{name}" for name in document["resources"]]
    cited.append("gates.processes")
    for gate, variants in document["gates"].items():
        if isinstance(variants, list):
            cited.extend(
                f"gates.{gate}.0.{key}" for key, value in variants[0].items() if value != "unknown"
            )
    document["evidence"] = {
        path: {"tests": ["fixture.test"], "report": "reports/fixture.json"} for path in cited
    }
    return document


def test_coverage_declaration_values_follow_the_catalog() -> None:
    document = coverage_declaration()
    assert sandbox_provider_spec.schema_errors(document, "declaration-schema.json") == []
    assert sandbox_provider_spec.check_declaration(document).errors == []


@pytest.mark.parametrize(
    "path,value",
    [
        ("resources.root", ["admin"]),
        ("resources.root", "sudo"),
        ("resources.root", ["sudo", "sudo"]),
        ("resources.arch", []),
        ("resources.arch", "x86_64"),
        ("resources.arch", ["x86_64", "unknown"]),
        ("resources.package_manager", "yum"),
        ("resources.package_manager", ["apt", "dnf"]),
        ("resources.libc", "bionic"),
        ("resources.max_run_seconds", -1),
        ("resources.max_process_seconds", {"minimum": 60}),
        ("resources.disk_in_memory", 1),
        ("gates.previews.0.reserved_ports", [0]),
        ("gates.previews.0.reserved_ports", ["22"]),
        ("gates.previews.0.reserved_ports", [22, 22]),
        ("gates.previews.0.reserved_ports", "unknown"),
        ("gates.previews.0.websocket", "yes"),
        ("gates.custom_images.0.image_must_have", ["bash"]),
        ("gates.custom_images.0.runs_entrypoint", "yes"),
        ("gates.tcp_ports.0.max_tcp_ports", "many"),
        ("gates.tcp_ports.0.reserved_ports", [22]),
        ("gates.tcp_ports.0.tls", "passthrough"),
        ("gates.docker.0.networking", "overlay"),
        ("gates.terminal.0.max_ports", 2),
        ("resources.egress_ips", ["static"]),
        ("resources.egress_ips", ["rotating"]),
        ("resources.arch", []),
        ("resources.arch", ["x86_64"]),
        ("resources.root", ["default_user"]),
        ("gates.network_lockdown.0.policy", "deny_all"),
        ("gates.network_lockdown.0.max_deny", "many"),
        ("gates.idle_shutdown.0.on_idle", "destroyed"),
        ("gates.previews.0.reserved_ports", {"at_least": 1}),
        ("resources.egress_ips", "dedicated"),
        ("gates.idle_shutdown.0.auto_wake", "yes"),
        ("gates.network_lockdown.0.policy", "blocklist_domains"),
        ("gates.network_lockdown.0.deny", ["a.example.com"]),
        ("gates.hidden_secrets.0.injection", "header"),
        ("gates.hidden_secrets.0.intercepts", ["all_https", "all_https"]),
        ("gates.hidden_secrets.0.rotates", "unknown-ish"),
        ("gates.hidden_secrets.0.transparent", "yes"),
    ],
)
@pytest.mark.rule("declaration/unknown-words-reported")
def test_coverage_declaration_values_reject_wrong_shapes(path: str, value: Any) -> None:
    document = coverage_declaration()
    parts = path.split(".")
    parent: Any = document
    for part in parts[:-1]:
        parent = parent[int(part)] if part.isdigit() else parent[part]
    parent[parts[-1]] = value
    assert sandbox_provider_spec.check_declaration(document).errors, path


@pytest.mark.parametrize(
    "document",
    [
        {
            "spec": "sandbox-provider-spec/0.1",
            "provider": "acme",
            "verified": {"date": "2026-09-29", "sdks": {"acme": "1.0"}},
            "resources": {},
            "gates": {},
            "evidence": {},
            "old_key": True,
        },
        {
            "spec": "sandbox-provider-spec/0.1",
            "provider": "acme",
            "verified": {"date": "2026-09-29", "sdks": {"acme": "1.0"}},
            "resources": {},
            "gates": {"made_up": "unsupported"},
            "evidence": {},
        },
        {
            "spec": "sandbox-provider-spec/0.1",
            "provider": "acme",
            "verified": {"date": "2026-09-29", "sdks": {"acme": "1.0"}},
            "resources": {},
            "lifetime_timer": {
                "enforced_by": "application",
                "counts_paused_time": False,
                "at_end": "terminated",
            },
            "gates": {},
            "evidence": {},
        },
    ],
)
@pytest.mark.rule("declaration/unknown-words-reported")
def test_unknown_declaration_keys_and_values_fail(document: dict[str, Any]) -> None:
    assert sandbox_provider_spec.check_declaration(document).errors


@pytest.mark.rule(
    "declaration/conditional-knob",
    "declaration/conflicts-name-real-things",
    "declaration/gate-not-empty",
    "declaration/no-baseline",
    "declaration/unknown-not-in-a-list",
)
def test_declaration_semantic_edges_are_rejected() -> None:
    conditional = declaration()
    conditional["gates"] = {"previews": [{"access": "public", "credential": "header"}]}
    assert any(
        "knob outside the variant" in error
        for error in sandbox_provider_spec.check_declaration(conditional).errors
    )

    waitlisted = declaration()
    waitlisted["gates"] = {
        "network_lockdown": [{"policy": "allowlist", "cuts_open_connections": True}]
    }
    assert sandbox_provider_spec.schema_errors(waitlisted, "declaration-schema.json")

    conflict = declaration()
    conflict["gates"] = {"previews": [{"conflicts": ["pause_resume.missing=files_only"]}]}
    assert any(
        "conflicts names a knob" in error
        for error in sandbox_provider_spec.check_declaration(conflict).errors
    )

    empty_gate = declaration()
    empty_gate["gates"] = {"pause_resume": []}
    assert sandbox_provider_spec.check_declaration(empty_gate).errors

    baseline = declaration()
    baseline["baseline"] = "passed"
    assert any(
        "baseline" in error for error in sandbox_provider_spec.check_declaration(baseline).errors
    )

    unknown_list = declaration()
    unknown_list["resources"] = {"gpus": ["unknown"]}
    assert any(
        "unknown inside a list" in error
        for error in sandbox_provider_spec.check_declaration(unknown_list).errors
    )


@pytest.mark.rule("declaration/required-fields")
def test_declaration_requires_all_format_fields() -> None:
    document = declaration()
    del document["verified"]
    assert any(
        "verified" in error for error in sandbox_provider_spec.check_declaration(document).errors
    )


@pytest.mark.rule("version/unknown-version-refused")
def test_checker_refuses_unknown_declaration_versions() -> None:
    document = declaration()
    document["spec"] = "sandbox-provider-spec/0.2"
    assert any(
        "spec" in error for error in sandbox_provider_spec.check_declaration(document).errors
    )


def test_catalog_must_match_yaml_and_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    catalog = json.loads((ROOT / "spec/catalog.json").read_text(encoding="utf-8"))
    catalog["spec"] = "sandbox-provider-spec/0.2"
    (tmp_path / "catalog.yaml").write_text(
        (ROOT / "spec/catalog.yaml").read_text(encoding="utf-8"), encoding="utf-8"
    )
    (tmp_path / "catalog.json").write_text(json.dumps(catalog), encoding="utf-8")
    monkeypatch.setattr(check, "spec_dir", lambda: tmp_path)
    assert sandbox_provider_spec.catalog_documents_differ() is True


@pytest.mark.rule("declaration/duplicate-key")
def test_duplicate_keys_are_rejected_for_yaml_and_json(tmp_path: Path) -> None:
    for suffix, contents in (("yaml", "a: 1\na: 2\n"), ("json", '{"a": 1, "a": 2}')):
        path = tmp_path / f"duplicate.{suffix}"
        path.write_text(contents, encoding="utf-8")
        with pytest.raises(DuplicateKeyError, match="duplicate key: a"):
            sandbox_provider_spec.load(path)


def test_check_command_accepts_a_request(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "request.json"
    path.write_text('{"resources": {"region": "CH"}}', encoding="utf-8")
    assert cli.main(["check", str(path)]) == 0
    assert "ok" in capsys.readouterr().out


def test_unknown_words_are_reported() -> None:
    errors = sandbox_provider_spec.check_request({"preferences": {"sort": "price"}})
    assert errors and all(UNKNOWN_WORD in error for error in errors)
    invalid_policy = sandbox_provider_spec.check_request(
        {"requirements": {"network_lockdown": {"policy": "allow_all"}}}
    )
    assert any(
        "network_lockdown.policy" in error and "allow_all" in error for error in invalid_policy
    )


def test_kernel_features_request_is_a_known_unique_all_of_list() -> None:
    assert not sandbox_provider_spec.check_request(
        {"resources": {"kernel_features": ["fuse", "nested_cgroups"]}}
    )
    for value in (["systemd"], ["fuse", "fuse"], "fuse"):
        assert sandbox_provider_spec.check_request({"resources": {"kernel_features": value}})


@pytest.mark.rule("matching/kernel-features-with-image")
def test_kernel_features_request_with_image_is_refused() -> None:
    errors = sandbox_provider_spec.check_request(
        {"image": "alpine", "resources": {"kernel_features": ["fuse"]}}
    )
    assert "together with an image: resources.kernel_features" in errors[0]


@pytest.mark.rule("matching/no-lifetime")
def test_a_null_lifetime_is_a_request_and_takes_no_at_end() -> None:
    open_ended = {"lifetime_seconds": None}
    assert not sandbox_provider_spec.check_request(open_ended)
    assert sandbox_provider_spec.schema_errors(open_ended, "request-schema.json") == []
    with_end = {"lifetime_seconds": None, "at_end": "destroyed"}
    assert sandbox_provider_spec.check_request(with_end) == [check.NO_LIFETIME_AT_END]
    assert sandbox_provider_spec.schema_errors(with_end, "request-schema.json")


def test_outbound_traffic_request_is_a_known_unique_all_of_list() -> None:
    assert not sandbox_provider_spec.check_request(
        {"resources": {"outbound_traffic": ["http", "any_tcp"]}}
    )
    unknown = sandbox_provider_spec.check_request({"resources": {"outbound_traffic": ["smtp"]}})
    assert any(UNKNOWN_WORD in error for error in unknown)
    duplicate = sandbox_provider_spec.check_request(
        {"resources": {"outbound_traffic": ["any_tcp", "any_tcp"]}}
    )
    assert any(error.startswith("schema:") for error in duplicate)

    document = declaration()
    document["resources"] = {"outbound_traffic": []}
    document["evidence"] = {
        "resources.outbound_traffic": {
            "source": "https://example.invalid/outbound",
            "read": "2026-10-02",
            "quote": "The sandbox permits HTTPS only.",
        }
    }
    assert not sandbox_provider_spec.check_declaration(document).errors

    for evidence in (
        {"tests": ["outbound-traffic.test"], "report": "reports/outbound.json"},
        {
            "reports": [
                {"tests": ["outbound-traffic.test"], "report": "reports/outbound-a.json"},
                {"tests": ["outbound-traffic.test"], "report": "reports/outbound-b.json"},
            ]
        },
    ):
        document["resources"]["outbound_traffic"] = ["http"]
        document["evidence"] = {"resources.outbound_traffic": evidence}
        assert not sandbox_provider_spec.check_declaration(document).errors


def test_outbound_ip_families_request_is_known_and_destination_fact_is_informative() -> None:
    request = {"resources": {"outbound_ip_families": ["ipv4", "ipv6"]}}
    assert not sandbox_provider_spec.check_request(request)
    assert sandbox_provider_spec.schema_errors(request, "request-schema.json") == []
    declaration_doc = declaration()
    declaration_doc["resources"] = {
        "outbound_ip_families": ["ipv4", "ipv6"],
        "ipv4_destination_reach": "nat64",
    }
    assert sandbox_provider_spec.schema_errors(declaration_doc, "declaration-schema.json") == []
    unknown = sandbox_provider_spec.check_request({"resources": {"outbound_ip_families": ["inet"]}})
    assert any(UNKNOWN_WORD in error for error in unknown)
    informative_only = sandbox_provider_spec.check_request(
        {"resources": {"ipv4_destination_reach": "native"}}
    )
    assert informative_only


@pytest.mark.parametrize("value", [["shared"], ["shared", "filtered"], [], ["unknown"], True])
def test_declared_kernel_rejects_lists_and_other_shapes(value: Any) -> None:
    document = declaration()
    document["resources"]["kernel"] = value
    assert any(
        f"{UNKNOWN_WORD}: resources.kernel" in error
        for error in sandbox_provider_spec.check_declaration(document).errors
    )


@pytest.mark.parametrize("value", ["shared", "filtered", "dedicated", "unknown"])
def test_declared_kernel_accepts_one_boundary_or_unknown(value: str) -> None:
    document = declaration()
    document["resources"]["kernel"] = value
    assert not any(
        f"{UNKNOWN_WORD}: resources.kernel" in error
        for error in sandbox_provider_spec.check_declaration(document).errors
    )


@pytest.mark.rule("custom_images/build-context")
@pytest.mark.parametrize("value", [True, False, "unknown", "yes"])
def test_declared_build_context_is_boolean_or_unknown(value: object) -> None:
    document = declaration()
    document["gates"] = {"custom_images": [{"source": "dockerfile", "build_context": value}]}
    assert bool(sandbox_provider_spec.schema_errors(document, "declaration-schema.json")) is (
        value == "yes"
    )


def test_daytona_container_default_size_uses_the_explicit_documented_default() -> None:
    native = load(ROOT / "providers" / "daytona" / "declaration-container.yaml")

    assert native["class"] == "container"
    assert native["verified"]["sdks"]["daytona"] == "0.226.1"
    assert native["resources"]["default_size"] == {"cpu": 1, "memory_mib": 1024, "disk_mib": 3072}
    assert native["evidence"]["resources.default_size"] == {
        "source": "https://www.daytona.io/docs/en/sandboxes/",
        "read": "2026-09-30",
        "quote": "Sandboxes have 1 vCPU, 1GB RAM, and 3GiB disk by default.",
    }
    assert sandbox_provider_spec.schema_errors(native, "declaration-schema.json") == []


def _with_timer(**extra: Any) -> dict[str, Any]:
    document = declaration()
    document["lifetime_timer"] = {
        "enforced_by": "provider",
        "counts_paused_time": False,
        "at_end": ["destroyed", "paused"],
        **extra,
    }
    return document


def _after_resume_errors(value: object) -> list[str]:
    """Errors naming the fact, other than the citation every declared value needs."""
    errors = sandbox_provider_spec.check_declaration(_with_timer(after_resume=value)).errors
    return [
        error
        for error in errors
        if "lifetime_timer.after_resume" in error and "missing a citation" not in error
    ]


@pytest.mark.parametrize("value", ["same", "pauses", "unknown"])
def test_lifetime_timer_after_resume_accepts_its_words(value: str) -> None:
    assert _after_resume_errors(value) == []
    assert (
        sandbox_provider_spec.schema_errors(
            _with_timer(after_resume=value), "declaration-schema.json"
        )
        == []
    )


@pytest.mark.parametrize("value", ["destroys", True, 5, None])
def test_lifetime_timer_after_resume_refuses_other_values(value: object) -> None:
    assert _after_resume_errors(value)
    assert sandbox_provider_spec.schema_errors(
        _with_timer(after_resume=value), "declaration-schema.json"
    )


def test_the_catalog_lists_after_resume_as_a_timer_fact() -> None:
    catalog = sandbox_provider_spec.load_catalog()
    assert "after_resume" in catalog["lifetime_timer"]
