# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Frozen, provider-free cases for the reference matcher."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from sandbox_provider_spec.check import check_request, spec_dir
from sandbox_provider_spec.load import load
from sandbox_provider_spec.matcher import Registry, Snapshot, declared_fit, match, match_restore
from sandbox_provider_spec.matcher.matching import ProviderResult
from sandbox_provider_spec.suite import read_suite

ROOT = Path(__file__).resolve().parent
FIXTURES = ROOT / "fixtures/providers"
VECTORS = json.loads((ROOT / "vectors/matching.json").read_text(encoding="utf-8"))
BASELINE_IDS = read_suite().baseline_ids


def _registry() -> Registry:
    regions: dict[str, Any] = load(spec_dir() / "registries/regions.json")
    regions["regions"].update(
        {
            "alpha:us-east": {"countries": ["US"]},
            "beta:us-west": {"countries": ["US"]},
            "gamma:eu-west": {"countries": ["FR"]},
            "gamma:global": {"countries": ["FR", "US"]},
        }
    )
    gpu_models: dict[str, Any] = load(spec_dir() / "registries/gpu-models.json")
    gpu_models["gpu_models"].setdefault(
        "amd:mi355x", {"vendor": "amd", "family": None, "compute_capability": None}
    )
    return Registry.from_documents(regions, gpu_models)


REGISTRY = _registry()


@pytest.mark.rule("request/refused-before-matching")
def test_matcher_rejects_kernel_features_with_image() -> None:
    request = {"image": "alpine", "resources": {"kernel_features": ["fuse"]}}
    result = match(request, [_declaration("alpha")], registry=REGISTRY)

    assert result["rejected"] is not None
    assert result["eligible"] == []


@pytest.mark.rule("request/refused-before-matching")
@pytest.mark.parametrize(
    ("policy", "entry", "accepted"),
    [
        ("allowlist", "localhost", True),
        ("denylist", "internal", True),
        ("allowlist", "API.Example.COM", True),
        ("allowlist", "*.localhost", True),
        ("allowlist", "*.example.com", True),
        ("denylist", "*.example.com", False),
        ("allowlist", "a" * 63, True),
        ("allowlist", "a" * 64, False),
        ("allowlist", ".".join(["a" * 63] * 3 + ["a" * 61]), True),
        ("allowlist", ".".join(["a" * 63] * 3 + ["a" * 62]), False),
        ("allowlist", "-internal", False),
        ("allowlist", "internal-", False),
        ("allowlist", "a..example.com", False),
        ("allowlist", "example.com.", False),
        ("allowlist", "example.com:443", False),
        ("allowlist", "example.com/path", False),
        ("allowlist", "123", False),
        ("allowlist", "*.123", False),
        ("allowlist", "*.203.0.113.7", False),
        ("allowlist", "2001:db8::1", False),
        ("allowlist", "éxample.com", False),
        ("allowlist", "203.0.113.7", True),
        ("allowlist", "203.0.113.0/24", True),
        ("allowlist", "10.0.0.1/24", True),
        ("allowlist", "10.0.0.1/0", True),
        ("allowlist", "0.0.0.0/0", True),
        ("allowlist", "10.0.0.1/032", True),
        ("denylist", "10.0.0.1/000", True),
        ("allowlist", "010.0.0.1", False),
        ("denylist", "10.0.0.256", False),
        ("allowlist", "10.0.0.1/33", False),
        ("allowlist", "10.0.0.1/255.255.255.0", False),
        ("denylist", "10.0.0.1/0.0.0.255", False),
        ("allowlist", "10.0.0.1/+24", False),
        ("denylist", "localhost", True),
    ],
)
def test_checker_and_matcher_agree_on_network_entries(
    policy: str, entry: str, accepted: bool
) -> None:
    setting = "allow" if policy.startswith("allowlist") else "deny"
    request = {"requirements": {"network_lockdown": {"policy": policy, setting: [entry]}}}
    assert (check_request(request) == []) is accepted
    result = match(request, [_declaration("alpha")], registry=REGISTRY)
    assert (result["rejected"] is None) is accepted


@pytest.mark.rule("request/refused-before-matching")
@pytest.mark.parametrize(
    ("host", "accepted"),
    [
        pytest.param("localhost", True, id="single-label-localhost"),
        pytest.param("1.2.3.4", False, id="ipv4-is-not-a-hostname"),
        pytest.param("123", False, id="numeric-label-is-not-a-hostname"),
        pytest.param("*.example.com", True, id="wildcard-secret-hostname"),
        pytest.param("*.123.4", False, id="wildcard-numeric-hostname"),
        pytest.param("*.*.example.com", False, id="multiple-wildcard-labels"),
        pytest.param("", False, id="empty-hostname"),
        pytest.param("app", True, id="single-label"),
        pytest.param("a" * 63, True, id="maximum-label-length"),
        pytest.param("a" * 64, False, id="overlong-label"),
        pytest.param(".".join(["a" * 63] * 3 + ["a" * 61]), True, id="maximum-host-length"),
        pytest.param(".".join(["a" * 63] * 3 + ["a" * 62]), False, id="overlong-host"),
        pytest.param("a.com.", False, id="trailing-dot"),
        pytest.param("a.com\n", False, id="trailing-line-feed"),
        pytest.param("localhost\n", False, id="localhost-line-feed"),
        pytest.param("a.com\r\n", False, id="trailing-crlf"),
        pytest.param("localhost\r\n", False, id="localhost-crlf"),
    ],
)
def test_checker_and_matcher_agree_on_secret_destination_hostnames(
    host: str, accepted: bool
) -> None:
    request = {"requirements": {"hidden_secrets": {"inject_into": [host]}}}
    assert (check_request(request) == []) is accepted
    result = match(request, [], registry=REGISTRY)
    assert (result["rejected"] is None) is accepted


@pytest.mark.rule("request/refused-before-matching")
@pytest.mark.parametrize(
    ("host", "policy", "entries", "accepted"),
    [
        pytest.param("*.example.com", "allowlist", ["*.example.com"], True, id="same-wildcard"),
        pytest.param(
            "*.sub.example.com", "allowlist", ["*.example.com"], True, id="parent-wildcard"
        ),
        pytest.param(
            "*.example.com", "allowlist", ["api.example.com"], False, id="exact-allow-host"
        ),
        pytest.param(
            "*.example.com", "denylist", ["api.example.com"], False, id="denied-name-under"
        ),
        pytest.param("*.example.com", "denylist", ["example.com"], False, id="denied-bare-domain"),
        pytest.param("*.example.com", "denylist", ["com"], False, id="denied-parent-domain"),
        pytest.param(
            "*.example.com", "denylist", ["other.googleapis.com"], True, id="denied-name-outside"
        ),
    ],
)
def test_checker_and_matcher_agree_on_secret_destination_policy(
    host: str, policy: str, entries: list[str], accepted: bool
) -> None:
    listing = "allow" if policy == "allowlist" else "deny"
    request = {
        "requirements": {
            "network_lockdown": {"policy": policy, listing: entries},
            "hidden_secrets": {"inject_into": [host]},
        }
    }
    assert (check_request(request) == []) is accepted
    result = match(request, [], registry=REGISTRY)
    assert (result["rejected"] is None) is accepted


@pytest.mark.rule("request/refused-before-matching")
def test_open_switch_target_requires_switchable_true() -> None:
    request = {
        "requirements": {
            "network_lockdown": {
                "policy": "allowlist",
                "allow": ["pypi.org"],
                "switchable": False,
                "switches_to": ["open"],
            }
        }
    }
    assert check_request(request) == ["open without switchable"]
    result = match(request, [], registry=REGISTRY)
    assert result["rejected"] is not None
    assert result["rejected"]["reason"] == "setting"


@pytest.mark.rule("request/refused-before-matching")
def test_open_network_policy_allows_secret_destinations() -> None:
    request = {
        "requirements": {
            "network_lockdown": {
                "policy": "open",
                "switchable": True,
                "switches_to": ["deny_all"],
            },
            "hidden_secrets": {"inject_into": ["api.example.com"]},
        }
    }
    assert check_request(request) == []
    result = match(request, [], registry=REGISTRY)
    assert result["rejected"] is None


def _declaration(name: str) -> dict[str, Any]:
    document = load(FIXTURES / f"{name}.yaml")
    assert isinstance(document, dict)
    return document


def test_outbound_ip_family_requests_require_every_declared_family() -> None:
    declaration = _declaration("alpha")
    declaration["resources"]["outbound_ip_families"] = ["ipv6"]

    unknown = declared_fit(
        {"resources": {"outbound_ip_families": ["ipv6"]}},
        [_declaration("beta")],
        registry=REGISTRY,
    )
    partial = declared_fit(
        {"resources": {"outbound_ip_families": ["ipv4", "ipv6"]}},
        [declaration],
        registry=REGISTRY,
    )
    full_declaration = deepcopy(declaration)
    full_declaration["resources"]["outbound_ip_families"] = ["ipv4", "ipv6"]
    full = declared_fit(
        {"resources": {"outbound_ip_families": ["ipv4", "ipv6"]}},
        [full_declaration],
        registry=REGISTRY,
    )

    assert unknown["compatible"] == []
    assert unknown["results"]["beta"]["failed"][0]["reason"] == "resource_unknown"
    assert partial["compatible"] == []
    assert partial["results"]["alpha"]["failed"][0]["reason"] == "resource_mismatch"
    assert full["compatible"] == ["alpha"]


def test_default_size_does_not_change_sized_or_sizeless_matching() -> None:
    declaration_without = _declaration("alpha")
    declaration_unknown = deepcopy(declaration_without)
    declaration_unknown["resources"]["default_size"] = "unknown"
    declaration_concrete = deepcopy(declaration_without)
    declaration_concrete["resources"]["default_size"] = {"cpu": 2, "memory_mib": 4096}

    for request in ({}, {"resources": {"cpu_min": 1, "memory_min_mib": 1024}}):
        unknown_result = match(
            request,
            [declaration_unknown],
            reports=[_report(declaration_unknown, "2026-09-30T00:00:00Z")],
            registry=REGISTRY,
        )
        concrete_result = match(
            request,
            [declaration_concrete],
            reports=[_report(declaration_concrete, "2026-09-30T00:00:00Z")],
            registry=REGISTRY,
        )
        assert unknown_result == concrete_result


def test_omitted_class_resolves_route_identity_and_keeps_report_identity_raw() -> None:
    declaration = _declaration("alpha")
    old_report = _report(declaration, "2026-09-30T00:00:00Z")

    matched = match({}, [declaration], reports=[old_report], registry=REGISTRY)

    assert matched["eligible"] == ["alpha"]
    assert list(matched["results"]) == ["alpha"]
    assert matched["results"]["alpha"]["name"] == "alpha"
    assert matched["results"]["alpha"]["class"] == "default"

    wrong_class_report = {**old_report, "class": "default"}
    rejected_proof = match({}, [declaration], reports=[wrong_class_report], registry=REGISTRY)
    assert rejected_proof["eligible"] == []
    assert [failure["reason"] for failure in rejected_proof["results"]["alpha"]["failed"]] == [
        "baseline_failed"
    ]

    malformed = {**declaration, "class": None}
    malformed_result = match({}, [malformed], registry=REGISTRY)
    assert malformed_result["results"]["alpha"]["class"] is None
    assert malformed_result["results"]["alpha"]["failed"][0]["reason"] == ("declaration_unusable")


def test_explicit_default_vm_and_container_classes_remain_named() -> None:
    template = _declaration("alpha")
    declarations = []
    for provider, class_name in (
        ("modal", "default"),
        ("modal", "vm"),
        ("daytona", "container"),
    ):
        declaration = deepcopy(template)
        declaration["provider"] = provider
        declaration["class"] = class_name
        for key in list(declaration):
            if key.startswith("x-"):
                del declaration[key]
        declarations.append(declaration)

    result = match(
        {},
        declarations,
        reports=[_report(item, "2026-09-30T00:00:00Z") for item in declarations],
        registry=REGISTRY,
    )

    assert result["eligible"] == ["modal/default", "modal/vm", "daytona/container"]
    assert {name: item["class"] for name, item in result["results"].items()} == {
        "modal/default": "default",
        "modal/vm": "vm",
        "daytona/container": "container",
    }


def _report(
    declaration: dict[str, Any], finished: str, *, failed_id: str | None = None
) -> dict[str, Any]:
    rows = [
        {"id": test_id, "result": "differs" if test_id == failed_id else "passed"}
        for test_id in BASELINE_IDS
    ]
    baseline = "differs" if failed_id else "passed"
    return {
        "spec": "sandbox-provider-spec/0.1",
        "provider": declaration["provider"],
        "class": declaration.get("class"),
        "sdk_versions": declaration["verified"]["sdks"],
        "finished_at": finished,
        "clean": True,
        "baseline": baseline,
        "selected_tests": list(BASELINE_IDS),
        "tests": rows,
    }


def _reports(declarations: list[dict[str, Any]], case: dict[str, Any]) -> list[dict[str, Any]]:
    baseline = case.get("baseline", "passed")
    if baseline == "missing":
        return []
    reports: list[dict[str, Any]] = []
    for declaration in declarations:
        provider = declaration["provider"]
        if baseline in {"latest_failure", "tied_failure"} and provider == case.get(
            "baseline_provider"
        ):
            passing_time = (
                "2026-09-28T00:00:00Z" if baseline == "latest_failure" else "2026-09-29T00:00:00Z"
            )
            reports.append(_report(declaration, passing_time))
            reports.append(
                _report(
                    declaration,
                    "2026-09-29T00:00:00Z",
                    failed_id=BASELINE_IDS[0],
                )
            )
        else:
            reports.append(_report(declaration, "2026-09-29T00:00:00Z"))
    return list(reversed(reports)) if case.get("reverse_reports") else reports


def _grant_values(result: ProviderResult, path: str) -> Any:
    gate, knob = path.split(".", 1)
    grant = result["gates"][gate]["knobs"][knob]["values"]
    return None if grant is None else [entry["value"] for entry in grant]


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda case: case["id"])
def test_reference_matches_frozen_vectors(case: dict[str, Any]) -> None:
    provider_names = case["providers"] if "providers" in case else [case["provider"]]
    declarations = [_declaration(name) for name in provider_names]
    result = match(
        case["request"],
        declarations,
        reports=_reports(declarations, case),
        registry=REGISTRY,
        met_needs=case.get("met_needs", []),
    )
    expected = case["expect"]
    assert result["eligible"] == expected["eligible"], case["id"]
    assert result["chosen"] == expected.get("chosen"), case["id"]
    if "rejected" in expected:
        rejection = result["rejected"]
        assert rejection is not None
        assert rejection["reason"] == expected["rejected"], case["id"]
    for provider, assertion in expected.get("results", {}).items():
        provider_result = result["results"][provider]
        if "eligible" in assertion:
            assert provider_result["eligible"] is assertion["eligible"], case["id"]
        if "failure_reasons" in assertion:
            assert [entry["reason"] for entry in provider_result["failed"]] == assertion[
                "failure_reasons"
            ], case["id"]
        for gate, index in assertion.get("variants", {}).items():
            assert provider_result["gates"][gate]["variant"] == index, case["id"]
        for path, values in assertion.get("grants", {}).items():
            assert _grant_values(provider_result, path) == values, case["id"]
        for path, value in assertion.get("resources", {}).items():
            actual: Any = provider_result["resources"]
            for part in path.split("."):
                actual = actual[part]
            assert actual == value, case["id"]


@pytest.mark.rule("matching/volumes-pin")
@pytest.mark.parametrize("owner", ["alpha", "delta"])
def test_volume_mount_matches_only_its_provider(owner: str) -> None:
    declarations = [_declaration("alpha"), _declaration("delta")]
    result = match(
        {
            "requirements": {
                "volumes": {
                    "kind": "filesystem",
                    "mounts": [{"provider": owner, "volume": "weights", "path": "/data"}],
                }
            }
        },
        declarations,
        reports=[_report(declaration, "2026-09-30T00:00:00Z") for declaration in declarations],
        registry=REGISTRY,
    )
    assert result["rejected"] is None
    assert result["eligible"] == [owner]
    assert result["chosen"] == owner
    other = "delta" if owner == "alpha" else "alpha"
    assert [failure["reason"] for failure in result["results"][other]["failed"]] == [
        "volume_provider_mismatch"
    ]


def test_match_restore_binds_snapshot_owner_and_recorded_source_size() -> None:
    declaration = _declaration("alpha")
    reports = [_report(declaration, "2026-09-30T00:00:00Z")]
    snapshot: Snapshot = {
        "provider": "alpha",
        "class": None,
        "keeps": "files_only",
        "source_resources": {"cpu": 4, "memory_mib": 8192, "disk_mib": None},
    }

    fits_source = match_restore(
        {"resources": {"cpu_min": 2, "memory_min_mib": 2048}},
        snapshot,
        [declaration],
        reports=reports,
        registry=REGISTRY,
    )
    assert fits_source["eligible"] == ["alpha"]
    # A variant that cannot resize provisions the recorded source size, never the minima;
    # a field the source did not record is not taken from the declared range.
    assert fits_source["results"]["alpha"]["resources"]["size"] == {"cpu": 4, "memory_mib": 8192}

    resizes = match_restore(
        {"resources": {"cpu_min": 2, "memory_min_mib": 2048}},
        {**snapshot, "keeps": "files_and_memory"},
        [declaration],
        reports=reports,
        registry=REGISTRY,
    )
    assert resizes["results"]["alpha"]["resources"]["size"] == {
        "cpu": 2,
        "memory_mib": 2048,
        "disk_mib": 1024,
    }

    exceeds_source = match_restore(
        {"resources": {"memory_min_mib": 16384}},
        snapshot,
        [declaration],
        reports=reports,
        registry=REGISTRY,
    )
    assert exceeds_source["eligible"] == []
    assert [failure["reason"] for failure in exceeds_source["results"]["alpha"]["failed"]] == [
        "resource_mismatch"
    ]

    other_owner = match_restore(
        {"resources": {"memory_min_mib": 2048}},
        {**snapshot, "provider": "beta"},
        [declaration],
        reports=reports,
        registry=REGISTRY,
    )
    assert other_owner["results"] == {}


def test_restore_matches_raw_or_resolved_default_owner_in_both_public_paths() -> None:
    unnamed = _declaration("alpha")
    vm = {**deepcopy(unnamed), "class": "vm"}
    reports = [
        _report(unnamed, "2026-09-30T00:00:00Z"),
        _report(vm, "2026-09-30T00:00:00Z"),
    ]
    request: dict[str, Any] = {}

    for snapshot_class, expected in ((None, "alpha"), ("default", "alpha"), ("vm", "alpha/vm")):
        snapshot: Snapshot = {
            "provider": "alpha",
            "class": snapshot_class,
            "keeps": "files_only",
            "source_resources": None,
        }
        for result in (
            match(
                request,
                [unnamed, vm],
                reports=reports,
                registry=REGISTRY,
                mode="restore",
                snapshot=snapshot,
            ),
            declared_fit(
                request, [unnamed, vm], registry=REGISTRY, mode="restore", snapshot=snapshot
            ),
        ):
            selected = result.get("eligible", result.get("compatible"))
            assert selected == [expected]
            assert list(result["results"]) == [expected]

    wrong_snapshots: tuple[Snapshot, ...] = (
        {"provider": "other", "class": "default", "keeps": "files_only"},
        {"provider": "alpha", "class": "container", "keeps": "files_only"},
    )
    for wrong_snapshot in wrong_snapshots:
        assert (
            match_restore(
                request, wrong_snapshot, [unnamed, vm], reports=reports, registry=REGISTRY
            )["results"]
            == {}
        )
        assert (
            match(
                request,
                [unnamed, vm],
                reports=reports,
                registry=REGISTRY,
                mode="restore",
                snapshot=wrong_snapshot,
            )["results"]
            == {}
        )
        assert (
            declared_fit(
                request,
                [unnamed, vm],
                registry=REGISTRY,
                mode="restore",
                snapshot=wrong_snapshot,
            )["results"]
            == {}
        )


@pytest.mark.rule("matching/extensions-pin")
@pytest.mark.parametrize(
    ("offered", "asked", "eligible"),
    [
        (True, 1, False),
        (False, 0, False),
        (1, True, False),
        ({"items": [True]}, {"items": [1]}, False),
        ([{"active": False}], [{"active": 0}], False),
        ([1, 2], [2, 1], False),
        ([1], [1, 2], False),
        ({"first": 1, "second": True}, {"second": True, "first": 1.0}, True),
        (None, None, True),
    ],
)
def test_extension_values_compare_as_json(offered: Any, asked: Any, eligible: bool) -> None:
    declaration = _declaration("alpha")
    declaration["x-alpha"] = {"value": offered}
    result = match(
        {"requirements": {"x-alpha": {"value": asked}}},
        [declaration],
        reports=[_report(declaration, "2026-09-30T00:00:00Z")],
        registry=REGISTRY,
    )
    assert result["eligible"] == (["alpha"] if eligible else [])
    assert [entry["reason"] for entry in result["results"]["alpha"]["failed"]] == (
        [] if eligible else ["extra_mismatch"]
    )


@pytest.mark.parametrize(
    ("alternatives", "eligible"),
    [(["shared"], True), (["filtered", "shared"], True), (["filtered"], False)],
)
def test_kernel_request_alternatives_match_one_declared_boundary(
    alternatives: list[str], eligible: bool
) -> None:
    declaration = _declaration("alpha")
    result = match(
        {"resources": {"kernel": alternatives}},
        [declaration],
        reports=[_report(declaration, "2026-09-30T00:00:00Z")],
        registry=REGISTRY,
    )
    assert result["rejected"] is None
    assert bool(result["eligible"]) is eligible


@pytest.mark.rule("matching/four-checks")
def test_lifetime_below_the_timer_minimum_does_not_match() -> None:
    declaration = _declaration("alpha")
    declaration["lifetime_timer"]["min_seconds"] = 300

    def lifetime_failures(seconds: int) -> list[str]:
        result = match({"lifetime_seconds": seconds}, [declaration], registry=REGISTRY)
        return [
            failure["detail"]
            for failure in result["results"]["alpha"]["failed"]
            if failure.get("resource") == "lifetime_seconds"
        ]

    assert lifetime_failures(120) == ["lifetime 120 s: declared lifetime_timer min_seconds 300"]
    assert lifetime_failures(300) == []


@pytest.mark.parametrize(
    "case_id",
    [
        "outbound-traffic-left-out-does-not-fit",
        "conflict-against-unknown-fires",
        "snapshot-conflict-binds-restores-need",
        "restores-need-larger-than-source-size-does-not-fit",
        "unsupported-pause-resume-does-not-fit",
        "conditional-knobless-variant-unmet-does-not-fit",
        "conditional-knobless-variant-met-fits",
    ],
)
def test_declared_fit_reuses_resource_conflict_and_recursive_restore_checks(case_id: str) -> None:
    case = next(item for item in VECTORS["cases"] if item["id"] == case_id)
    declaration = _declaration(case["provider"])
    result = declared_fit(
        case["request"],
        [declaration],
        met_needs=case.get("met_needs", []),
        registry=REGISTRY,
    )
    assert result["rejected"] is None
    assert result["compatible"] == case["expect"]["eligible"]
    assert all("eligible" not in item for item in result["results"].values())
    if not result["compatible"]:
        provider_result = next(iter(result["results"].values()))
        assert provider_result["failed"]
