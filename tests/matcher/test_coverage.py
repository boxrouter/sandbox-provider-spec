# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""`coverage` names what some provider declares and proves, by the matcher's own rules."""

from __future__ import annotations

from typing import Any

from sandbox_provider_spec.check import load_catalog
from sandbox_provider_spec.matcher import coverage, setting_backers
from sandbox_provider_spec.suite import read_suite

CATALOG = load_catalog()
BASELINE_IDS = read_suite().baseline_ids


def declaration(provider: str = "acme", **parts: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "spec": "sandbox-provider-spec/0.1",
        "provider": provider,
        "verified": {"date": "2026-09-30", "sdks": {"acme-sdk": "1.0.0"}},
        "resources": {},
        "gates": {},
    }
    for section in ("resources", "gates"):
        document[section].update(parts.pop(section, {}))
    document.update(parts)
    return document


def passing_report(provider: str = "acme") -> dict[str, Any]:
    return {
        "spec": "sandbox-provider-spec/0.1",
        "provider": provider,
        "class": None,
        "sdk_versions": {"acme-sdk": "1.0.0"},
        "finished_at": "2026-09-30T00:00:00Z",
        "clean": True,
        "selected_tests": list(BASELINE_IDS),
        "tests": [{"id": test_id, "result": "passed"} for test_id in BASELINE_IDS],
    }


def test_a_declared_gate_and_knob_are_backed_and_a_false_or_unknown_one_is_not() -> None:
    declared = declaration(
        gates={
            "idle_shutdown": [
                {"on_idle": "stopped", "custom_idle_time": False, "auto_wake": "unknown"}
            ],
            "processes": [{"cancel": True}],
            "terminal": [{}],
            "docker": "unsupported",
        }
    )
    backed = coverage(CATALOG, [declared], require_baseline=False)
    assert {"idle_shutdown", "idle_shutdown.on_idle", "processes", "processes.cancel"} <= backed
    assert "terminal" in backed
    assert (
        not {
            "idle_shutdown.custom_idle_time",
            "idle_shutdown.auto_wake",
            "processes.input",
            "terminal.reattach",
            "docker",
        }
        & backed
    )


def test_a_number_knob_and_a_pick_knob_with_any_value_are_backed() -> None:
    declared = declaration(
        gates={"previews": [{"access": "public", "link_lifetime_seconds": {"at_least": 60}}]}
    )
    assert {"previews.access", "previews.link_lifetime_seconds"} <= coverage(
        CATALOG, [declared], require_baseline=False
    )


def test_one_provider_is_enough_and_the_variants_are_pooled() -> None:
    first = declaration("acme", gates={"processes": [{"input": True}]})
    second = declaration("other", gates={"processes": [{"cancel": True}, {"reattach": True}]})
    backed = coverage(CATALOG, [first, second], require_baseline=False)
    assert {"processes.input", "processes.cancel", "processes.reattach"} <= backed


def test_an_unusable_declaration_or_variant_backs_nothing() -> None:
    broken_declaration = declaration(spec="not-the-spec", gates={"processes": [{"input": True}]})
    broken_variant = declaration("other", gates={"terminal": [{"reattach": True, "bogus": 1}]})
    assert coverage(CATALOG, [broken_declaration, broken_variant], require_baseline=False) == set()


def test_resources_are_backed_by_the_fact_that_answers_them() -> None:
    declared = declaration(
        resources={
            "kernel": "dedicated",
            "sizes": [{"cpu": 2, "memory_mib": 4096}],
            "regions": ["acme:east"],
            "extendable_lifetime": False,
            "arch": "unknown",
            "max_run_seconds": 3600,
        }
    )
    backed = coverage(CATALOG, [declared], require_baseline=False)
    assert {
        "resources.kernel",
        "resources.cpu_min",
        "resources.memory_min_mib",
        "resources.region",
        "resources.run_seconds",
    } <= backed
    assert not {"resources.extendable_lifetime", "resources.arch", "resources.gpu_count"} & backed


def test_the_default_needs_the_matchers_baseline_proof() -> None:
    declared = declaration(gates={"processes": [{"input": True}]})
    assert coverage(CATALOG, [declared]) == set()
    assert coverage(CATALOG, [declared], [passing_report()]) >= {"processes", "processes.input"}
    other_sdks = {**passing_report(), "sdk_versions": {"acme-sdk": "2.0.0"}}
    assert coverage(CATALOG, [declared], [other_sdks]) == set()
    unclean = {**passing_report(), "clean": False}
    assert coverage(CATALOG, [declared], [unclean]) == set()


def test_a_setting_follows_its_knob_or_else_its_gate() -> None:
    follows = setting_backers(CATALOG)
    assert follows["idle_shutdown.idle_seconds"] == "idle_shutdown.custom_idle_time"
    assert follows["previews.ports"] == "previews"
    assert follows["network_lockdown.allow"] == "network_lockdown"
