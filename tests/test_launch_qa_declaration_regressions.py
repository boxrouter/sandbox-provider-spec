# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Guard native provider evidence after the launch QA refresh."""

from pathlib import Path
from typing import Any

import pytest

from sandbox_provider_spec.load import load
from sandbox_provider_spec.matcher import MatchResult, Registry, match

ROOT = Path(__file__).resolve().parents[1]


def test_boxd_regional_offer_matches_registry_countries_without_expanding_gates() -> None:
    declaration = load(ROOT / "providers/boxd/declaration.yaml")
    registry = load(ROOT / "spec/registries/regions.json")
    regions = declaration["resources"]["regions"]
    assert regions == ["boxd:eu-fra", "boxd:us-nyc"]
    assert registry["regions"]["boxd:eu-fra"]["countries"] == ["DE"]
    assert registry["regions"]["boxd:us-nyc"]["countries"] == ["US"]
    assert declaration["resources"]["located_in"] == ["DE", "US"]
    assert "snapshots" not in declaration["gates"]
    assert "custom_images" not in declaration["gates"]


def test_boxd_size_resolution_fills_the_fixed_disk_for_a_request_that_names_none() -> None:
    """Boxd bills disk, and a quote needs the disk of the size the request resolves to.

    The 100 GiB allocation is fixed on every machine, so the declaration publishes it on each
    size and a request that names no disk resolves to a size that carries it.
    """
    declaration = load(ROOT / "providers/boxd/declaration.yaml")
    sizes = declaration["resources"]["sizes"]
    assert {size["disk_mib"] for size in sizes} == {102400}
    assert declaration["resources"]["disk_mib"] == 102400
    registry = Registry.from_documents(
        load(ROOT / "spec/registries/regions.json"),
        load(ROOT / "spec/registries/gpu-models.json"),
    )
    for size in sizes:
        request = {"resources": {"cpu_min": size["cpu"], "memory_min_mib": size["memory_mib"]}}
        result = match(request, [declaration], reports=[], registry=registry)
        assert result["results"]["boxd"]["resources"]["size"] == size


def _match_e2b(request: dict[str, Any]) -> MatchResult:
    provider = ROOT / "providers/e2b"
    registry = Registry.from_documents(
        load(ROOT / "spec/registries/regions.json"),
        load(ROOT / "spec/registries/gpu-models.json"),
    )
    result = match(
        request,
        [load(provider / "declaration.yaml")],
        reports=[load(path) for path in sorted((provider / "reports").glob("*.json"))],
        registry=registry,
    )
    # These immutable launch reports predate the EOF check. Assert that they
    # cannot admit the provider, then inspect the independent capability findings.
    assert result["eligible"] == []
    failures = result["results"]["e2b"]["failed"]
    assert any(row["reason"] == "baseline_failed" for row in failures)
    result["results"]["e2b"]["failed"] = [
        row for row in failures if row["reason"] != "baseline_failed"
    ]
    return result


def test_e2b_activation_only_region_is_not_an_unconditional_offer() -> None:
    assert _match_e2b({"resources": {"region": "e2b:us"}})["results"]["e2b"]["failed"] == []
    result = _match_e2b({"resources": {"region": "e2b:us-west-2"}})
    assert result["rejected"] is None
    assert result["eligible"] == []
    assert result["results"]["e2b"]["failed"][0]["reason"] == "resource_mismatch"


@pytest.mark.parametrize("entrypoint", [True, False])
def test_e2b_prepared_snapshot_does_not_prove_per_create_entrypoint(entrypoint: bool) -> None:
    image = {"dockerfile": 'FROM ubuntu:24.04\nENTRYPOINT ["sleep", "infinity"]'}
    knobs = {"prepared": True, "build_context": True}
    assert (
        _match_e2b({"image": image, "requirements": {"custom_images": knobs}})["results"]["e2b"][
            "failed"
        ]
        == []
    )
    result = _match_e2b(
        {
            "image": image,
            "requirements": {"custom_images": {**knobs, "runs_entrypoint": entrypoint}},
        }
    )
    assert result["rejected"] is None
    assert result["eligible"] == []
    assert (
        f"runs_entrypoint: asked [{entrypoint}], declared unknown"
        in result["results"]["e2b"]["failed"][0]["detail"]
    )


def test_e2b_declares_deny_all_network_lockdown() -> None:
    assert (
        _match_e2b({"requirements": {"network_lockdown": {"policy": "deny_all"}}})["results"][
            "e2b"
        ]["failed"]
        == []
    )


@pytest.mark.parametrize("name", ["allowed.example", "*.allowed.example"])
def test_e2b_name_filter_scope_does_not_admit_unproven_authorities(name: str) -> None:
    def request(entry: str) -> dict[str, Any]:
        return {"requirements": {"network_lockdown": {"policy": "allowlist", "allow": [entry]}}}

    assert _match_e2b(request("192.0.2.1"))["results"]["e2b"]["failed"] == []
    result = _match_e2b(request(name))
    assert result["rejected"] is None
    assert result["eligible"] == []
    assert result["results"]["e2b"]["failed"][0]["reason"] == "limit_exceeded"


def test_blaxel_missing_rotation_mapping_is_not_evidence_of_provider_absence() -> None:
    declaration = load(ROOT / "providers/blaxel/declaration.yaml")
    assert declaration["gates"]["hidden_secrets"][0]["rotates"] == "unknown"
    assert "gates.hidden_secrets.0.rotates" not in declaration["evidence"]


def test_vercel_keeps_both_native_proven_lifetime_end_states() -> None:
    declaration = load(ROOT / "providers/vercel/declaration.yaml")
    assert declaration["lifetime_timer"]["at_end"] == ["destroyed", "stopped"]
    citation = declaration["evidence"]["lifetime_timer.at_end"]
    report = load(ROOT / "providers/vercel" / citation["report"])
    rows = {row["id"]: row for row in report["tests"]}
    for state in declaration["lifetime_timer"]["at_end"]:
        identifier = f"lifetime_timer.at_end.{state}"
        assert identifier in citation["tests"]
        assert rows[identifier]["result"] == "passed"
        assert {"fact": "lifetime_timer.at_end", "value": state} in rows[identifier]["proves"]


def test_modal_vm_keeps_non_native_proofs_out_of_provider_declaration() -> None:
    declaration = load(ROOT / "providers/modal/declaration-vm.yaml")

    assert declaration["verified"]["sdks"] == {"modal": "1.6.1"}
    assert "lifetime_timer" not in declaration
    assert "custom_images" not in declaration["gates"]
    assert all("qa218-modal-vm" not in str(entry) for entry in declaration["evidence"].values())

    native = ROOT / "providers/modal/reports"
    assert not list(native.glob("qa218-modal-vm-*.json"))
