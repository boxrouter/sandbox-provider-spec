# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Declaration evidence maps must cite values that committed reports establish."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, cast

import pytest

import sandbox_provider_spec.evidence as evidence
from sandbox_provider_spec.check import load_catalog
from sandbox_provider_spec.conformance import DRIVERS
from sandbox_provider_spec.evidence import check_evidence

CATALOG = load_catalog()


@pytest.fixture(autouse=True)
def _use_fixture_suite(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source_suite_rules = evidence._source_suite_rules

    def fixture_suite_rules(digest: Any) -> tuple[dict[str, Any] | None, list[str]]:
        for suite_path in tmp_path.rglob("conformance/suite.yaml"):
            with monkeypatch.context() as patch:
                patch.setattr(
                    evidence, "_conformance_root", lambda root=suite_path.parent.parent: root
                )
                rules, errors = source_suite_rules(digest)
            if rules is not None:
                return rules, errors
        return source_suite_rules(digest)

    monkeypatch.setattr(evidence, "_source_suite_rules", fixture_suite_rules)


def _declaration() -> dict[str, Any]:
    return {
        "provider": "e2b",
        "class": "default",
        "verified": {"date": "2026-09-30", "sdks": {"sdk": "1"}},
        "resources": {"default_user": "agent", "max_lifetime_seconds": "unknown"},
        "gates": {"processes": [{"input": True}], "terminal": [{}]},
        "evidence": {},
    }


def _report_repository(
    tmp_path: Path,
    tests: list[dict[str, Any]],
    *,
    provider: str = "e2b",
    execution_class: str = "default",
    clean: bool = True,
    reports: list[dict[str, Any]] | None = None,
    coverage_tests: list[dict[str, Any]] | None = None,
    report_tests: list[dict[str, Any]] | None = None,
) -> Path:
    root = tmp_path / "repo"
    provider_dir = root / "providers" / provider
    report_dir = provider_dir / "reports"
    report_dir.mkdir(parents=True)
    (root / "conformance").mkdir()
    suite = {
        "spec": "sandbox-provider-spec/0.1",
        "tests": [
            {
                "id": test["id"],
                "title": test["id"],
                "steps": [],
                "proves": test["proves"],
                "rules": test["rules"],
            }
            for test in tests
        ],
    }
    suite_text = json.dumps(suite) + "\n"
    (root / "conformance" / "suite.yaml").write_text(suite_text, encoding="utf-8")
    coverage_text: str | None = None
    if coverage_tests is not None:
        coverage_suite = {
            "spec": "sandbox-provider-spec/0.1",
            "tests": [
                {
                    "id": test["id"],
                    "title": test["id"],
                    "steps": [],
                    "proves": test["proves"],
                    "rules": test["rules"],
                }
                for test in coverage_tests
            ],
        }
        coverage_text = json.dumps(coverage_suite) + "\n"
        (root / "conformance" / "coverage.yaml").write_text(coverage_text, encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(
        ["git", "-C", str(root), "config", "user.email", "evidence-test@example.invalid"],
        check=True,
    )
    subprocess.run(["git", "-C", str(root), "config", "user.name", "Evidence test"], check=True)
    subprocess.run(["git", "-C", str(root), "add", "conformance"], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-qm", "source revision"], check=True)
    revision = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    report_configs = reports if reports is not None else [{}]
    selected_results = report_tests if report_tests is not None else tests
    payload = (
        suite_text.encode("utf-8")
        if coverage_text is None
        else b"suite.yaml\0"
        + suite_text.encode("utf-8")
        + b"\0coverage.yaml\0"
        + coverage_text.encode("utf-8")
        + b"\0"
    )
    for config in report_configs:
        selected_results = config.get("results", report_tests or tests)
        report = {
            "spec": "sandbox-provider-spec/0.1",
            "provider": provider,
            "class": execution_class,
            "driver": {"name": "test", "version": "1"},
            "sdk_versions": {"sdk": "1"},
            "started_at": "2026-09-30T00:00:00Z",
            "finished_at": "2026-09-30T00:00:01Z",
            "revision": revision,
            "suite_digest": "sha256:" + hashlib.sha256(payload).hexdigest(),
            "clean": clean,
            "baseline": "passed",
            "tests": selected_results,
            "selected_tests": [test["id"] for test in selected_results],
        }
        report.update(
            {
                key: value
                for key, value in config.items()
                if key not in {"name", "results", "omit_sdk_versions"}
            }
        )
        if config.get("omit_sdk_versions"):
            report.pop("sdk_versions")
        report_name = str(config.get("name", "run.json"))
        (report_dir / report_name).write_text(json.dumps(report) + "\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "providers"], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-qm", "committed report"], check=True)
    return provider_dir / "declaration.yaml"


def _test(
    identifier: str,
    result: str,
    proves: list[dict[str, Any]],
    *,
    rules: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "id": identifier,
        "result": result,
        "steps": [],
        "cleanup": [],
        "duration_ms": 1,
        "rules": [] if rules is None else rules,
        "proves": proves,
    }


def _schema_errors(_document: Any, _name: str) -> list[str]:
    return []


def _fact_evidence_declaration() -> dict[str, Any]:
    declaration = _declaration()
    declaration["resources"] = {"default_user": "agent"}
    declaration["gates"] = {}
    declaration["evidence"] = {
        "resources.default_user": {
            "tests": ["facts.default_user"],
            "report": "reports/run.json",
        }
    }
    return declaration


def _fact_report(tmp_path: Path, *, reports: list[dict[str, Any]] | None = None) -> Path:
    return _report_repository(
        tmp_path,
        [
            _test(
                "facts.default_user",
                "passed",
                [{"fact": "resources.default_user", "value": "agent"}],
            )
        ],
        reports=reports,
    )


@pytest.mark.rule("declaration/evidence", "declaration/evidence-holds")
def test_evidence_map_covers_every_non_unknown_value_and_rejects_orphans() -> None:
    declaration = _declaration()
    declaration["evidence"] = {
        "resources.default_user": {
            "source": "https://example.invalid",
            "read": "2026-09-30",
            "quote": "The default user is agent.",
        },
        "gates.processes.0.input": {
            "source": "https://example.invalid",
            "read": "2026-09-30",
            "quote": "Input is available.",
        },
        "resources.not_declared": {
            "source": "https://example.invalid",
            "read": "2026-09-30",
            "quote": "Orphan.",
        },
    }

    errors = check_evidence(
        declaration, source_path=None, schema_errors=_schema_errors, catalog=CATALOG
    )

    assert "evidence is missing a citation for gates.terminal.0" in errors
    assert "evidence has no declared value at resources.not_declared" in errors
    assert any("documentation quote is not allowed" in error for error in errors)
    assert not any("max_lifetime_seconds" in error for error in errors)


def test_explicit_unknown_default_size_requires_a_reason_quote() -> None:
    declaration = _declaration()
    declaration["resources"] = {"default_size": "unknown"}
    declaration["gates"] = {}
    quote = {
        "source": "https://example.invalid/default-size",
        "read": "2026-10-18",
        "quote": "The selected create path does not establish one stable allocation.",
    }
    declaration["evidence"]["resources.default_size"] = quote
    assert (
        check_evidence(declaration, source_path=None, schema_errors=_schema_errors, catalog=CATALOG)
        == []
    )

    declaration["evidence"].pop("resources.default_size")
    errors = check_evidence(
        declaration, source_path=None, schema_errors=_schema_errors, catalog=CATALOG
    )
    assert "evidence is missing a citation for resources.default_size" in errors

    declaration["evidence"]["resources.default_size"] = {
        "tests": ["facts.default_size"],
        "report": "reports/run.json",
    }
    errors = check_evidence(
        declaration, source_path=None, schema_errors=_schema_errors, catalog=CATALOG
    )
    assert any("explicit unknown needs a source quote" in error for error in errors)


def test_omitted_default_size_cannot_have_a_reason_entry() -> None:
    declaration = _declaration()
    declaration["resources"] = {}
    declaration["gates"] = {}
    declaration["evidence"]["resources.default_size"] = {
        "source": "https://example.invalid/default-size",
        "read": "2026-10-18",
        "quote": "The selected create path does not establish one stable allocation.",
    }
    errors = check_evidence(
        declaration, source_path=None, schema_errors=_schema_errors, catalog=CATALOG
    )
    assert "evidence has no declared value at resources.default_size" in errors


@pytest.mark.rule("declaration/evidence")
def test_documentation_quotes_are_limited_to_catalog_paths() -> None:
    declaration: dict[str, Any] = {
        "provider": "acme",
        "resources": {
            "kernel": "dedicated",
            "needs": {"kernel": ["enterprise"]},
            "gpus": [],
            "egress_ips": [],
            "default_user": "agent",
        },
        "gates": {"pause_resume": "unsupported"},
        "x-acme": {"note": "documented"},
        "evidence": {
            "resources.kernel": {
                "source": "https://example.invalid",
                "read": "2026-09-30",
                "quote": "The sandbox runs with a dedicated kernel.",
            },
            "resources.needs.kernel": {
                "source": "https://example.invalid",
                "read": "2026-09-30",
                "quote": "This feature requires the enterprise plan.",
            },
            "resources.gpus": {
                "source": "https://example.invalid",
                "read": "2026-09-30",
                "quote": "The current plan does not include GPUs.",
            },
            "resources.egress_ips": {
                "source": "https://example.invalid/egress",
                "read": "2026-09-30",
                "quote": "Sandbox outbound addresses rotate.",
            },
            "gates.pause_resume": {
                "source": "https://example.invalid",
                "read": "2026-09-30",
                "quote": "Pause and resume are not available.",
            },
            "x-acme.note": {
                "source": "https://example.invalid",
                "read": "2026-09-30",
                "quote": "The extension is documented by its provider.",
            },
            "resources.default_user": {
                "source": "https://example.invalid",
                "read": "2026-09-30",
                "quote": "The image starts as agent.",
            },
        },
    }

    errors = check_evidence(
        declaration, source_path=None, schema_errors=_schema_errors, catalog=CATALOG
    )

    assert errors == [
        "evidence resources.default_user: documentation quote is not allowed for this value"
    ]

    declaration["resources"].pop("default_user")
    quote = declaration["evidence"].pop("resources.default_user")
    declaration["gates"] = {"pause_resume": [{"keeps": "files_and_memory"}]}
    declaration["evidence"].pop("gates.pause_resume")
    declaration["evidence"]["gates.pause_resume.0.keeps"] = quote

    errors = check_evidence(
        declaration, source_path=None, schema_errors=_schema_errors, catalog=CATALOG
    )

    assert errors == [
        "evidence gates.pause_resume.0.keeps: documentation quote is not allowed for this value"
    ]


@pytest.mark.rule("declaration/evidence")
def test_documentation_quote_can_support_variant_conflicts() -> None:
    declaration: dict[str, Any] = {
        "provider": "e2b",
        "gates": {"docker": [{"conflicts": ["desktop"]}]},
        "evidence": {
            "gates.docker.0": {"tests": ["docker.present"], "report": "reports/docker.json"},
            "gates.docker.0.conflicts": {
                "source": "https://example.invalid/templates",
                "read": "2026-09-30",
                "quote": "The Docker Engine and desktop use separate templates.",
            },
        },
    }

    errors = check_evidence(
        declaration, source_path=None, schema_errors=_schema_errors, catalog=CATALOG
    )

    assert errors == []


@pytest.mark.rule("declaration/unknown-variant-needs-evidence")
@pytest.mark.parametrize(
    "variant",
    [
        {"conflicts": ["resources.gpus"]},
        {"needs": {"keeps": ["paid_plan"]}},
        {"keeps": "unknown", "conflicts": ["resources.gpus"]},
        {"keeps": "unknown", "needs": {"keeps": ["paid_plan"]}},
    ],
)
@pytest.mark.parametrize("presence", [False, True])
def test_metadata_never_substitutes_for_gate_presence(
    tmp_path: Path, variant: dict[str, Any], presence: bool
) -> None:
    present = _test("snapshots.present", "passed", [{"gate": "snapshots", "value": True}])
    path = _report_repository(tmp_path, [present])
    declaration: dict[str, Any] = {
        "provider": "e2b",
        "class": "default",
        "verified": {"date": "2026-09-30", "sdks": {"sdk": "1"}},
        "resources": {},
        "gates": {"snapshots": [variant]},
        "evidence": {},
    }
    citations: dict[str, Any] = declaration["evidence"]
    metadata_path = "conflicts" if "conflicts" in variant else "needs.keeps"
    citations[f"gates.snapshots.0.{metadata_path}"] = {
        "source": "https://example.invalid/snapshot-conditions",
        "read": "2026-09-30",
        "quote": "Snapshots have the stated plan conditions and resource conflicts.",
    }
    if presence:
        citations["gates.snapshots.0"] = {
            "tests": ["snapshots.present"],
            "report": "reports/run.json",
        }
    assert check_evidence(
        declaration, source_path=path, schema_errors=_schema_errors, catalog=CATALOG
    ) == ([] if presence else ["evidence is missing a citation for gates.snapshots.0"])


@pytest.mark.rule("declaration/evidence-holds")
def test_report_evidence_checks_exact_facts_and_knobless_gate_presence(tmp_path: Path) -> None:
    report_path = _report_repository(
        tmp_path,
        [
            _test(
                "facts.default_user",
                "passed",
                [{"fact": "resources.default_user", "value": "agent"}],
            ),
            _test(
                "processes.input.true",
                "passed",
                [{"gate": "processes", "knob": "input", "value": True}],
            ),
            _test("terminal.interactive", "passed", [{"gate": "terminal", "value": True}]),
        ],
    )
    declaration = _declaration()
    declaration["evidence"] = {
        "resources.default_user": {"tests": ["facts.default_user"], "report": "reports/run.json"},
        "gates.processes.0.input": {
            "tests": ["processes.input.true"],
            "report": "reports/run.json",
        },
        "gates.terminal.0": {"tests": ["terminal.interactive"], "report": "reports/run.json"},
    }

    errors = check_evidence(
        declaration,
        source_path=report_path,
        schema_errors=_schema_errors,
        catalog=CATALOG,
    )

    assert errors == []


@pytest.mark.rule("declaration/evidence-holds")
def test_report_evidence_checks_gate_presence_for_variants_with_knobs(tmp_path: Path) -> None:
    report_path = _report_repository(
        tmp_path,
        [
            _test("desktop.control", "passed", [{"gate": "desktop", "value": True}]),
            _test(
                "desktop.live_view",
                "passed",
                [
                    {"gate": "desktop", "value": True},
                    {"gate": "desktop", "knob": "live_view", "value": True},
                ],
            ),
            _test("terminal.interactive", "passed", [{"gate": "terminal", "value": True}]),
            _test(
                "terminal.reattach",
                "passed",
                [{"gate": "terminal", "knob": "reattach", "value": True}],
            ),
        ],
    )
    declaration = _declaration()
    declaration["resources"] = {}
    declaration["gates"] = {
        "desktop": [{"live_view": True}],
        "terminal": [{"reattach": True}],
    }
    declaration["evidence"] = {
        "gates.desktop.0": {"tests": ["desktop.control"], "report": "reports/run.json"},
        "gates.desktop.0.live_view": {
            "tests": ["desktop.live_view"],
            "report": "reports/run.json",
        },
        "gates.terminal.0": {
            "tests": ["terminal.interactive"],
            "report": "reports/run.json",
        },
        "gates.terminal.0.reattach": {
            "tests": ["terminal.reattach"],
            "report": "reports/run.json",
        },
    }

    errors = check_evidence(
        declaration,
        source_path=report_path,
        schema_errors=_schema_errors,
        catalog=CATALOG,
    )

    assert errors == []


@pytest.mark.rule("declaration/evidence-holds")
@pytest.mark.parametrize(
    ("value", "present"),
    [
        ("files_only", True),
        ("files_and_memory", True),
        (False, False),
        ("unknown", False),
        ("unsupported", False),
        ("", False),
    ],
)
def test_concrete_enum_knob_proof_establishes_gate_presence(
    tmp_path: Path, value: Any, present: bool
) -> None:
    report_path = _report_repository(
        tmp_path,
        [
            _test(
                "pause_resume.probe",
                "passed",
                [{"gate": "pause_resume", "knob": "keeps", "value": value}],
            )
        ],
    )
    declaration = _declaration()
    declaration["resources"] = {}
    declaration["gates"] = {"pause_resume": [{"keeps": "unknown"}]}
    declaration["evidence"] = {
        "gates.pause_resume.0": {"tests": ["pause_resume.probe"], "report": "reports/run.json"}
    }
    errors = check_evidence(
        declaration, source_path=report_path, schema_errors=_schema_errors, catalog=CATALOG
    )
    assert errors == (
        []
        if present
        else ["evidence gates.pause_resume.0: cited tests do not prove declared value True"]
    )


@pytest.mark.rule("declaration/evidence-holds")
def test_coverage_report_evidence_uses_the_combined_core_and_coverage_suite(tmp_path: Path) -> None:
    baseline = _test("baseline.example", "passed", [])
    coverage_fact = _test(
        "coverage.facts.default_user",
        "passed",
        [{"fact": "resources.default_user", "value": "agent"}],
    )
    report_path = _report_repository(
        tmp_path,
        [baseline],
        coverage_tests=[coverage_fact],
        report_tests=[baseline, coverage_fact],
    )
    declaration = _declaration()
    declaration["gates"] = {}
    declaration["evidence"] = {
        "resources.default_user": {
            "tests": ["coverage.facts.default_user"],
            "report": "reports/run.json",
        }
    }

    errors = check_evidence(
        declaration,
        source_path=report_path,
        schema_errors=_schema_errors,
        catalog=CATALOG,
    )

    assert errors == []


@pytest.mark.rule("declaration/evidence-holds")
def test_report_evidence_requires_every_list_value_and_at_least_floor(tmp_path: Path) -> None:
    report_path = _report_repository(
        tmp_path,
        [
            _test(
                "network.deny",
                "passed",
                [{"gate": "network_lockdown", "knob": "policy", "value": "deny_all"}],
            ),
            _test(
                "network.domains",
                "passed",
                [{"gate": "network_lockdown", "knob": "policy", "value": "allowlist_domains"}],
            ),
            _test("ports", "passed", [{"gate": "previews", "knob": "max_ports", "value": 2}]),
        ],
    )
    declaration = {
        "provider": "e2b",
        "class": "default",
        "verified": {"date": "2026-09-30", "sdks": {"sdk": "1"}},
        "resources": {},
        "gates": {
            "network_lockdown": [{"policy": ["deny_all", "allowlist_domains"]}],
            "previews": [{"max_ports": {"at_least": 2}}],
        },
        "evidence": {
            "gates.network_lockdown.0.policy": {
                "tests": ["network.deny", "network.domains"],
                "report": "reports/run.json",
            },
            "gates.previews.0.max_ports": {"tests": ["ports"], "report": "reports/run.json"},
        },
    }

    assert (
        check_evidence(
            declaration, source_path=report_path, schema_errors=_schema_errors, catalog=CATALOG
        )
        == []
    )
    mutable = cast(dict[str, Any], declaration)
    policy = cast(list[str], mutable["gates"]["network_lockdown"][0]["policy"])
    policy.append("allowlist_ips")
    assert any(
        "allowlist_ips" in error
        for error in check_evidence(
            declaration, source_path=report_path, schema_errors=_schema_errors, catalog=CATALOG
        )
    )


@pytest.mark.rule("declaration/unknown-variant-needs-evidence")
def test_all_unknown_gate_variant_requires_existence_evidence() -> None:
    declaration = {
        "provider": "e2b",
        "verified": {"date": "2026-09-30", "sdks": {"sdk": "1"}},
        "resources": {},
        "gates": {"snapshots": [{"keeps": "unknown", "original_after": "unknown"}]},
        "evidence": {},
    }

    errors = check_evidence(
        declaration, source_path=None, schema_errors=_schema_errors, catalog=CATALOG
    )

    assert errors == ["evidence is missing a citation for gates.snapshots.0"]


@pytest.mark.rule("declaration/unknown-variant-needs-evidence")
def test_all_unknown_gate_variant_can_cite_existence(tmp_path: Path) -> None:
    present = _test("snapshots.present", "passed", [{"gate": "snapshots", "value": True}])
    report_path = _report_repository(tmp_path, [present])
    declaration = {
        "provider": "e2b",
        "class": "default",
        "verified": {"date": "2026-09-30", "sdks": {"sdk": "1"}},
        "resources": {},
        "gates": {"snapshots": [{"keeps": "unknown", "original_after": "unknown"}]},
        "evidence": {
            "gates.snapshots.0": {
                "tests": ["snapshots.present"],
                "report": "reports/run.json",
            }
        },
    }

    errors = check_evidence(
        declaration, source_path=report_path, schema_errors=_schema_errors, catalog=CATALOG
    )

    assert errors == []


@pytest.mark.rule("declaration/no-gate-against-its-report")
@pytest.mark.parametrize("result", ["differs", "error"])
def test_unconditional_failed_rule_blocks_declared_gate(tmp_path: Path, result: str) -> None:
    default_user = _test(
        "facts.default_user", "passed", [{"fact": "resources.default_user", "value": "agent"}]
    )
    gate_failure = _test(
        "network_lockdown.root_cannot_lift",
        result,
        [],
        rules=["network_lockdown/root-cannot-lift"],
    )
    gate_proof = _test(
        "network_lockdown.allowlist_ips",
        "passed",
        [{"gate": "network_lockdown", "knob": "policy", "value": "allowlist_ips"}],
    )
    report_path = _report_repository(tmp_path, [default_user, gate_proof, gate_failure])
    declaration = {
        "provider": "e2b",
        "class": "default",
        "verified": {"date": "2026-09-30", "sdks": {"sdk": "1"}},
        "resources": {"default_user": "agent"},
        "gates": {"network_lockdown": [{"policy": "allowlist_ips"}]},
        "evidence": {
            "resources.default_user": {
                "tests": ["facts.default_user"],
                "report": "reports/run.json",
            },
            "gates.network_lockdown.0.policy": {
                "tests": ["network_lockdown.allowlist_ips"],
                "report": "reports/run.json",
            },
        },
    }

    errors = check_evidence(
        declaration, source_path=report_path, schema_errors=_schema_errors, catalog=CATALOG
    )

    assert any(
        f"unconditional rule network_lockdown/root-cannot-lift: "
        f"network_lockdown.root_cannot_lift came back {result}" in error
        for error in errors
    )


@pytest.mark.rule("declaration/no-gate-against-its-report")
def test_later_cited_retry_supersedes_a_transient_rule_error(tmp_path: Path) -> None:
    gate_proof = _test(
        "network_lockdown.allowlist_ips",
        "passed",
        [{"gate": "network_lockdown", "knob": "policy", "value": "allowlist_ips"}],
    )
    failed = _test(
        "network_lockdown.root_cannot_lift",
        "error",
        [],
        rules=["network_lockdown/root-cannot-lift"],
    )
    passed = {**failed, "result": "passed"}
    report_path = _report_repository(
        tmp_path,
        [gate_proof, failed],
        reports=[
            {"name": "old.json", "results": [gate_proof, failed]},
            {
                "name": "retry.json",
                "results": [gate_proof, passed],
                "started_at": "2026-09-30T00:01:00Z",
                "finished_at": "2026-09-30T00:01:01Z",
            },
        ],
    )
    declaration = {
        "provider": "e2b",
        "class": "default",
        "verified": {"date": "2026-09-30", "sdks": {"sdk": "1"}},
        "resources": {},
        "gates": {"network_lockdown": [{"policy": "allowlist_ips"}]},
        "evidence": {
            "gates.network_lockdown.0.policy": {
                "reports": [
                    {"tests": ["network_lockdown.allowlist_ips"], "report": "reports/old.json"},
                    {"tests": ["network_lockdown.allowlist_ips"], "report": "reports/retry.json"},
                ]
            }
        },
    }

    assert (
        check_evidence(
            declaration, source_path=report_path, schema_errors=_schema_errors, catalog=CATALOG
        )
        == []
    )


@pytest.mark.rule("declaration/no-gate-against-its-report")
@pytest.mark.parametrize(
    ("new_result", "finished", "blocked"),
    [
        (None, "2026-09-30T00:01:01Z", True),
        ("not_run", "2026-09-30T00:01:01Z", True),
        ("unsupported", "2026-09-30T00:01:01Z", True),
        ("passed", "2026-09-30T00:01:01Z", False),
        ("passed", "2026-09-30T00:00:01Z", True),
        ("passed", "2026-09-29T23:00:01-01:00", True),
    ],
)
def test_failure_cited_for_a_fact_requires_a_newer_completed_observation(
    tmp_path: Path, new_result: str | None, finished: str, blocked: bool
) -> None:
    fact = _test(
        "facts.default_user", "passed", [{"fact": "resources.default_user", "value": "agent"}]
    )
    gate = _test(
        "network_lockdown.allowlist_ips",
        "passed",
        [{"gate": "network_lockdown", "knob": "policy", "value": "allowlist_ips"}],
    )
    failure = _test(
        "network_lockdown.root_cannot_lift",
        "error",
        [],
        rules=["network_lockdown/root-cannot-lift"],
    )
    retry = [] if new_result is None else [{**failure, "result": new_result}]
    path = _report_repository(
        tmp_path,
        [fact, gate, failure],
        reports=[
            {"name": "facts.json", "results": [fact, failure]},
            {"name": "gate.json", "results": [gate, *retry], "finished_at": finished},
        ],
    )
    declaration = {
        "provider": "e2b",
        "class": "default",
        "verified": {"date": "2026-09-30", "sdks": {"sdk": "1"}},
        "resources": {"default_user": "agent"},
        "gates": {"network_lockdown": [{"policy": "allowlist_ips"}]},
        "evidence": {
            "resources.default_user": {
                "tests": ["facts.default_user"],
                "report": "reports/facts.json",
            },
            "gates.network_lockdown.0.policy": {
                "tests": ["network_lockdown.allowlist_ips"],
                "report": "reports/gate.json",
            },
        },
    }
    errors = check_evidence(
        declaration, source_path=path, schema_errors=_schema_errors, catalog=CATALOG
    )
    assert errors == (
        [
            "gates.network_lockdown: unconditional rule network_lockdown/root-cannot-lift: "
            "network_lockdown.root_cannot_lift came back error"
        ]
        if blocked
        else []
    )


@pytest.mark.rule("declaration/no-gate-against-its-report")
def test_failed_knob_specific_rule_does_not_block_other_gate_value(tmp_path: Path) -> None:
    allowlist_ips = _test(
        "network_lockdown.allowlist_ips",
        "passed",
        [{"gate": "network_lockdown", "knob": "policy", "value": "allowlist_ips"}],
        rules=["network_lockdown/allowlist-ips"],
    )
    deny_all = _test(
        "network_lockdown.deny_all",
        "differs",
        [{"gate": "network_lockdown", "knob": "policy", "value": "deny_all"}],
        rules=["network_lockdown/deny-all"],
    )
    report_path = _report_repository(tmp_path, [allowlist_ips, deny_all])
    declaration = {
        "provider": "e2b",
        "class": "default",
        "verified": {"date": "2026-09-30", "sdks": {"sdk": "1"}},
        "resources": {},
        "gates": {"network_lockdown": [{"policy": "allowlist_ips"}]},
        "evidence": {
            "gates.network_lockdown.0.policy": {
                "tests": ["network_lockdown.allowlist_ips"],
                "report": "reports/run.json",
            }
        },
    }

    errors = check_evidence(
        declaration, source_path=report_path, schema_errors=_schema_errors, catalog=CATALOG
    )

    assert errors == []


@pytest.mark.rule("declaration/evidence-holds")
def test_report_evidence_can_combine_tests_from_multiple_reports(tmp_path: Path) -> None:
    deny_all = _test(
        "network.deny_all",
        "passed",
        [{"gate": "network_lockdown", "knob": "policy", "value": "deny_all"}],
    )
    denylist = _test(
        "coverage.network_lockdown.denylist.addresses",
        "passed",
        [{"gate": "network_lockdown", "knob": "policy", "value": "denylist"}],
        rules=["network_lockdown/denylist"],
    )
    report_path = _report_repository(
        tmp_path,
        [deny_all, denylist],
        reports=[
            {"name": "baseline.json", "results": [deny_all]},
            {"name": "supplementary.json", "results": [denylist]},
        ],
    )
    declaration = {
        "provider": "e2b",
        "class": "default",
        "verified": {"date": "2026-09-30", "sdks": {"sdk": "1"}},
        "resources": {},
        "gates": {"network_lockdown": [{"policy": ["deny_all", "denylist"]}]},
        "evidence": {
            "gates.network_lockdown.0.policy": {
                "reports": [
                    {"tests": ["network.deny_all"], "report": "reports/baseline.json"},
                    {
                        "tests": ["coverage.network_lockdown.denylist.addresses"],
                        "report": "reports/supplementary.json",
                    },
                ]
            }
        },
    }

    errors = check_evidence(
        declaration, source_path=report_path, schema_errors=_schema_errors, catalog=CATALOG
    )

    assert errors == []


@pytest.mark.rule("declaration/evidence-holds")
def test_unsupported_claim_requires_a_selected_unsupported_result(tmp_path: Path) -> None:
    report_path = _report_repository(
        tmp_path,
        [
            _test(
                "snapshots.unsupported",
                "unsupported",
                [{"gate": "snapshots", "knob": "keeps", "value": "files_only"}],
                rules=["snapshots/files-only"],
            )
        ],
    )
    declaration = {
        "provider": "e2b",
        "class": "default",
        "resources": {},
        "gates": {"snapshots": "unsupported"},
        "evidence": {
            "gates.snapshots": {
                "tests": ["snapshots.unsupported"],
                "report": "reports/run.json",
            }
        },
    }

    assert (
        check_evidence(
            declaration, source_path=report_path, schema_errors=_schema_errors, catalog=CATALOG
        )
        == []
    )


@pytest.mark.rule("declaration/evidence-holds")
@pytest.mark.parametrize(
    ("identifier", "rules", "proves"),
    [
        (
            "pause_resume.forged",
            ["processes/cancel"],
            [{"gate": "pause_resume", "knob": "keeps", "value": "files_only"}],
        ),
        (
            "pause_resume.bare",
            ["pause_resume"],
            [{"gate": "pause_resume", "knob": "keeps", "value": "files_only"}],
        ),
        ("baseline.unsupported", ["baseline/process"], []),
    ],
)
def test_unsupported_gate_rejects_unrelated_test_ownership(
    tmp_path: Path, identifier: str, rules: list[str], proves: list[dict[str, Any]]
) -> None:
    report_path = _report_repository(
        tmp_path,
        [_test(identifier, "unsupported", proves, rules=rules)],
    )
    declaration = {
        "provider": "e2b",
        "class": "default",
        "resources": {},
        "gates": {"pause_resume": "unsupported"},
        "evidence": {
            "gates.pause_resume": {
                "tests": [identifier],
                "report": "reports/run.json",
            }
        },
    }

    errors = check_evidence(
        declaration, source_path=report_path, schema_errors=_schema_errors, catalog=CATALOG
    )

    assert errors == [
        f"evidence gates.pause_resume: test {identifier} does not establish gate pause_resume"
    ]


@pytest.mark.rule("declaration/evidence-holds")
def test_unsupported_gate_evidence_is_bound_to_the_same_gate(tmp_path: Path) -> None:
    declaration_path = _report_repository(
        tmp_path,
        [
            _test(
                "pause_resume.files_only",
                "unsupported",
                [{"gate": "pause_resume", "knob": "keeps", "value": "files_only"}],
                rules=["pause_resume/files-only"],
            ),
            _test(
                "pause_resume.files_and_memory",
                "unsupported",
                [{"gate": "pause_resume", "knob": "keeps", "value": "files_and_memory"}],
                rules=["pause_resume/files-and-memory"],
            ),
            _test(
                "processes.cancel.true",
                "unsupported",
                [{"gate": "processes", "knob": "cancel", "value": True}],
                rules=["processes/cancel"],
            ),
        ],
    )
    declaration: dict[str, Any] = {
        "provider": "e2b",
        "class": "default",
        "resources": {},
        "gates": {"pause_resume": "unsupported"},
        "evidence": {
            "gates.pause_resume": {
                "tests": ["pause_resume.files_only", "pause_resume.files_and_memory"],
                "report": "reports/run.json",
            }
        },
    }

    errors = check_evidence(
        declaration, source_path=declaration_path, schema_errors=_schema_errors, catalog=CATALOG
    )

    assert errors == []

    declaration["evidence"]["gates.pause_resume"]["tests"] = ["processes.cancel.true"]
    errors = check_evidence(
        declaration, source_path=declaration_path, schema_errors=_schema_errors, catalog=CATALOG
    )

    assert errors == [
        "evidence gates.pause_resume: test processes.cancel.true "
        "does not establish gate pause_resume"
    ]


@pytest.mark.rule("declaration/evidence-holds")
def test_audited_unsupported_process_knob_can_prove_false(tmp_path: Path) -> None:
    report_path = _report_repository(
        tmp_path,
        [
            _test(
                "processes.input.false",
                "unsupported",
                [{"gate": "processes", "knob": "input", "value": False}],
            )
        ],
    )
    declaration = {
        "provider": "e2b",
        "class": "default",
        "verified": {"date": "2026-09-30", "sdks": {"sdk": "1"}},
        "resources": {},
        "gates": {"processes": [{"input": False}]},
        "evidence": {
            "gates.processes.0.input": {
                "tests": ["processes.input.false"],
                "report": "reports/run.json",
            }
        },
    }

    errors = check_evidence(
        declaration,
        source_path=report_path,
        schema_errors=_schema_errors,
        catalog=CATALOG,
    )

    assert errors == []


@pytest.mark.rule("declaration/evidence-holds")
def test_dirty_or_mismatched_report_cannot_establish_a_value(tmp_path: Path) -> None:
    report_path = _report_repository(
        tmp_path,
        [
            _test(
                "facts.default_user",
                "passed",
                [{"fact": "resources.default_user", "value": "agent"}],
            )
        ],
        clean=False,
    )
    declaration = {
        "provider": "e2b",
        "class": "default",
        "resources": {"default_user": "agent"},
        "gates": {},
        "evidence": {
            "resources.default_user": {
                "tests": ["facts.default_user"],
                "report": "reports/run.json",
            }
        },
    }

    errors = check_evidence(
        declaration, source_path=report_path, schema_errors=_schema_errors, catalog=CATALOG
    )

    assert any("report is not clean" in error for error in errors)


@pytest.mark.rule("declaration/evidence-holds")
def test_unrelated_report_revision_uses_recognized_suite(tmp_path: Path) -> None:
    declaration_path = _fact_report(tmp_path, reports=[{"revision": "f" * 40}])

    assert (
        check_evidence(
            _fact_evidence_declaration(),
            source_path=declaration_path,
            schema_errors=_schema_errors,
            catalog=CATALOG,
        )
        == []
    )


@pytest.mark.rule("declaration/evidence-holds")
def test_unknown_suite_digest_cannot_establish_a_value(tmp_path: Path) -> None:
    declaration_path = _fact_report(tmp_path, reports=[{"suite_digest": "sha256:" + "0" * 64}])

    errors = check_evidence(
        _fact_evidence_declaration(),
        source_path=declaration_path,
        schema_errors=_schema_errors,
        catalog=CATALOG,
    )
    assert any("suite digest is not recognized" in error for error in errors)


@pytest.mark.rule("declaration/evidence-holds")
def test_digest_for_another_recognized_suite_cannot_establish_a_value(tmp_path: Path) -> None:
    fact = _test(
        "facts.default_user", "passed", [{"fact": "resources.default_user", "value": "agent"}]
    )
    coverage = _test("coverage.unrelated", "passed", [])
    declaration_path = _report_repository(
        tmp_path, [fact], coverage_tests=[coverage], report_tests=[fact, coverage]
    )
    report_path = declaration_path.parent / "reports/run.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    core_bytes = (tmp_path / "repo/conformance/suite.yaml").read_bytes()
    report["suite_digest"] = "sha256:" + hashlib.sha256(core_bytes).hexdigest()
    report_path.write_text(json.dumps(report) + "\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path / "repo"), "add", "providers"], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path / "repo"), "commit", "-qm", "changed digest"], check=True
    )

    errors = check_evidence(
        _fact_evidence_declaration(),
        source_path=declaration_path,
        schema_errors=_schema_errors,
        catalog=CATALOG,
    )
    assert any("coverage.unrelated is absent from its source suite" in error for error in errors)


@pytest.mark.rule("declaration/evidence-holds")
def test_uncommitted_or_dirty_report_cannot_establish_a_value(tmp_path: Path) -> None:
    declaration_path = _fact_report(tmp_path)
    report_path = declaration_path.parent / "reports/run.json"
    report_path.write_text(report_path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    declaration = _fact_evidence_declaration()

    errors = check_evidence(
        declaration, source_path=declaration_path, schema_errors=_schema_errors, catalog=CATALOG
    )
    assert any("report has uncommitted changes" in error for error in errors)

    untracked_path = report_path.with_name("untracked.json")
    untracked_path.write_bytes(report_path.read_bytes())
    declaration["evidence"]["resources.default_user"]["report"] = "reports/untracked.json"
    errors = check_evidence(
        declaration, source_path=declaration_path, schema_errors=_schema_errors, catalog=CATALOG
    )
    assert any("report is not committed" in error for error in errors)


@pytest.mark.rule("declaration/evidence-holds")
def test_source_checkout_inside_an_installation_directory_still_owns_its_reports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(evidence, "getsitepackages", lambda: [str(tmp_path)])
    declaration_path = _fact_report(tmp_path)
    report_path = declaration_path.parent / "reports/run.json"
    report_path.write_text(report_path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    assert check_evidence(
        _fact_evidence_declaration(),
        source_path=declaration_path,
        schema_errors=_schema_errors,
        catalog=CATALOG,
    ) == ["evidence resources.default_user: report has uncommitted changes"]


@pytest.mark.rule("declaration/evidence-holds")
def test_packaged_report_without_git_uses_recognized_suite(tmp_path: Path) -> None:
    declaration_path = _fact_report(tmp_path)
    shutil.rmtree(tmp_path / "repo/.git")

    assert (
        check_evidence(
            _fact_evidence_declaration(),
            source_path=declaration_path,
            schema_errors=_schema_errors,
            catalog=CATALOG,
        )
        == []
    )


@pytest.mark.rule("declaration/evidence-holds")
def test_historical_cited_report_can_use_an_exact_sdk_subset(tmp_path: Path) -> None:
    tests = [
        _test(
            "facts.default_user", "passed", [{"fact": "resources.default_user", "value": "agent"}]
        ),
        _test(
            "facts.default_cwd",
            "passed",
            [{"fact": "resources.default_cwd", "value": "/workspace"}],
        ),
    ]
    report_path = _report_repository(
        tmp_path,
        tests,
        reports=[
            {
                "name": "older.json",
                "sdk_versions": {"sdk": "1"},
                "started_at": "2026-09-29T00:00:00Z",
                "finished_at": "2026-09-29T00:00:01Z",
            },
            {
                "name": "newest.json",
                "sdk_versions": {"sdk": "1", "companion": "2"},
            },
        ],
    )
    declaration = {
        "provider": "e2b",
        "class": "default",
        "verified": {"date": "2026-09-30", "sdks": {"sdk": "1", "companion": "2"}},
        "resources": {"default_user": "agent", "default_cwd": "/workspace"},
        "gates": {},
        "evidence": {
            "resources.default_user": {
                "tests": ["facts.default_user"],
                "report": "reports/older.json",
            },
            "resources.default_cwd": {
                "tests": ["facts.default_cwd"],
                "report": "reports/newest.json",
            },
        },
    }

    errors = check_evidence(
        declaration, source_path=report_path, schema_errors=_schema_errors, catalog=CATALOG
    )

    assert errors == []


@pytest.mark.rule("declaration/evidence-holds")
def test_newest_full_baseline_report_must_use_every_verified_sdk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(evidence, "_baseline_test_ids", lambda _root: {"baseline.fixture"})
    report_path = _report_repository(
        tmp_path,
        [
            _test("baseline.fixture", "passed", []),
            _test(
                "facts.default_user",
                "passed",
                [{"fact": "resources.default_user", "value": "agent"}],
            ),
        ],
        reports=[{"sdk_versions": {"sdk": "1"}}],
    )
    declaration = {
        "provider": "e2b",
        "class": "default",
        "verified": {"date": "2026-09-30", "sdks": {"sdk": "1", "companion": "2"}},
        "resources": {"default_user": "agent"},
        "gates": {},
        "evidence": {
            "resources.default_user": {
                "tests": ["facts.default_user"],
                "report": "reports/run.json",
            }
        },
    }

    errors = check_evidence(
        declaration, source_path=report_path, schema_errors=_schema_errors, catalog=CATALOG
    )

    assert (
        "newest full-baseline report SDK versions do not match declaration verified.sdks" in errors
    )


@pytest.mark.rule("declaration/evidence-holds")
@pytest.mark.parametrize("sdk_versions", [None, "missing"])
def test_newest_full_report_with_bad_sdk_versions_returns_errors(
    tmp_path: Path, sdk_versions: Any
) -> None:
    report: dict[str, Any] = (
        {"omit_sdk_versions": True} if sdk_versions == "missing" else {"sdk_versions": sdk_versions}
    )
    report_path = _report_repository(
        tmp_path,
        [
            _test("baseline.fixture", "passed", []),
            _test(
                "facts.default_user",
                "passed",
                [{"fact": "resources.default_user", "value": "agent"}],
            ),
        ],
        reports=[report],
    )
    declaration = {
        "provider": "e2b",
        "class": "default",
        "verified": {"date": "2026-09-30", "sdks": {"sdk": "1"}},
        "resources": {"default_user": "agent"},
        "gates": {},
        "evidence": {
            "resources.default_user": {
                "tests": ["facts.default_user"],
                "report": "reports/run.json",
            }
        },
    }

    errors = check_evidence(
        declaration, source_path=report_path, schema_errors=_schema_errors, catalog=CATALOG
    )

    assert errors


@pytest.mark.rule("declaration/evidence-holds")
def test_newest_full_baseline_report_uses_timezone_aware_finished_at(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(evidence, "_baseline_test_ids", lambda _root: {"baseline.fixture"})
    tests = [
        _test("baseline.fixture", "passed", []),
        _test(
            "facts.default_user", "passed", [{"fact": "resources.default_user", "value": "agent"}]
        ),
        _test(
            "facts.default_cwd",
            "passed",
            [{"fact": "resources.default_cwd", "value": "/workspace"}],
        ),
    ]
    report_path = _report_repository(
        tmp_path,
        tests,
        reports=[
            {
                "name": "full.json",
                "sdk_versions": {"sdk": "1", "companion": "2"},
                "finished_at": "2026-09-30T01:00:01+01:00",
            },
            {
                "name": "newer.json",
                "sdk_versions": {"sdk": "1"},
                "finished_at": "2026-09-30T00:00:02Z",
            },
        ],
    )
    declaration = {
        "provider": "e2b",
        "class": "default",
        "verified": {"date": "2026-09-30", "sdks": {"sdk": "1", "companion": "2"}},
        "resources": {"default_user": "agent", "default_cwd": "/workspace"},
        "gates": {},
        "evidence": {
            "resources.default_user": {
                "tests": ["facts.default_user"],
                "report": "reports/full.json",
            },
            "resources.default_cwd": {
                "tests": ["facts.default_cwd"],
                "report": "reports/newer.json",
            },
        },
    }

    errors = check_evidence(
        declaration, source_path=report_path, schema_errors=_schema_errors, catalog=CATALOG
    )

    assert (
        "newest full-baseline report SDK versions do not match declaration verified.sdks" in errors
    )


@pytest.mark.rule("declaration/evidence-holds")
def test_newest_uncited_full_baseline_report_controls_verified_sdks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(evidence, "_baseline_test_ids", lambda _root: {"baseline.fixture"})
    tests = [
        _test("baseline.fixture", "passed", []),
        _test(
            "facts.default_user",
            "passed",
            [{"fact": "resources.default_user", "value": "agent"}],
        ),
    ]
    report_path = _report_repository(
        tmp_path,
        tests,
        reports=[
            {
                "name": "cited.json",
                "sdk_versions": {"sdk": "1", "companion": "2"},
                "finished_at": "2026-09-30T00:00:01Z",
            },
            {
                "name": "newest-uncited.json",
                "sdk_versions": {"sdk": "1"},
                "finished_at": "2026-09-30T00:00:02Z",
            },
        ],
    )
    declaration = {
        "provider": "e2b",
        "class": "default",
        "verified": {"date": "2026-09-30", "sdks": {"sdk": "1", "companion": "2"}},
        "resources": {"default_user": "agent"},
        "gates": {},
        "evidence": {
            "resources.default_user": {
                "tests": ["facts.default_user"],
                "report": "reports/cited.json",
            }
        },
    }

    errors = check_evidence(
        declaration, source_path=report_path, schema_errors=_schema_errors, catalog=CATALOG
    )

    assert (
        "newest full-baseline report SDK versions do not match declaration verified.sdks" in errors
    )


@pytest.mark.rule("declaration/evidence-holds")
def test_newer_partial_report_does_not_displace_full_baseline_sdk_report(tmp_path: Path) -> None:
    user = _test(
        "facts.default_user", "passed", [{"fact": "resources.default_user", "value": "agent"}]
    )
    cwd = _test(
        "facts.default_cwd", "passed", [{"fact": "resources.default_cwd", "value": "/workspace"}]
    )
    report_path = _report_repository(
        tmp_path,
        [_test("baseline.fixture", "passed", []), user, cwd],
        reports=[
            {
                "name": "full.json",
                "sdk_versions": {"sdk": "1", "companion": "2"},
                "finished_at": "2026-09-30T00:00:01Z",
            },
            {
                "name": "partial.json",
                "results": [cwd],
                "sdk_versions": {"sdk": "1"},
                "finished_at": "2026-09-30T00:00:02Z",
            },
        ],
    )
    declaration = {
        "provider": "e2b",
        "class": "default",
        "verified": {"date": "2026-09-30", "sdks": {"sdk": "1", "companion": "2"}},
        "resources": {"default_user": "agent", "default_cwd": "/workspace"},
        "gates": {},
        "evidence": {
            "resources.default_user": {
                "tests": ["facts.default_user"],
                "report": "reports/full.json",
            },
            "resources.default_cwd": {
                "tests": ["facts.default_cwd"],
                "report": "reports/partial.json",
            },
        },
    }

    errors = check_evidence(
        declaration, source_path=report_path, schema_errors=_schema_errors, catalog=CATALOG
    )

    assert errors == []


STACK = {"acme-adapter": "9", "boxrouter-core": "3", "boxrouter-adapter-kit": "4"}


@pytest.mark.rule("declaration/evidence-holds")
@pytest.mark.parametrize(
    ("config", "accepted"),
    [
        ({"implementation": "acme_adapter", "sdk_versions": {"sdk": "1", **STACK}}, True),
        (
            {
                "implementation": "acme_adapter",
                "sdk_versions": {"sdk": "1", "other-sdk": "1", **STACK},
            },
            False,
        ),
        ({"implementation": "acme_adapter", "sdk_versions": {"sdk": "2", **STACK}}, False),
        ({"sdk_versions": {"sdk": "1", **STACK}}, False),
        (
            {"implementation": "acme_adapter", "sdk_versions": {"sdk": "1", "acme-other": "1"}},
            False,
        ),
    ],
    ids=[
        "adapter-stack-is-identity",
        "unidentified-extra-sdk-fails",
        "provider-sdk-mismatch-fails",
        "no-implementation-no-exemption",
        "other-adapter-is-not-identity",
    ],
)
def test_report_implementation_stack_is_identity_not_a_verified_sdk(
    tmp_path: Path, config: dict[str, Any], accepted: bool
) -> None:
    tests = [
        _test("baseline.fixture", "passed", []),
        _test(
            "facts.default_user", "passed", [{"fact": "resources.default_user", "value": "agent"}]
        ),
    ]
    report_path = _report_repository(tmp_path, tests, reports=[{"name": "run.json", **config}])
    declaration = {
        "provider": "e2b",
        "class": "default",
        "verified": {"date": "2026-09-30", "sdks": {"sdk": "1"}},
        "resources": {"default_user": "agent"},
        "gates": {},
        "evidence": {
            "resources.default_user": {
                "tests": ["facts.default_user"],
                "report": "reports/run.json",
            },
        },
    }

    errors = check_evidence(
        declaration, source_path=report_path, schema_errors=_schema_errors, catalog=CATALOG
    )

    subset = [error for error in errors if "version-matching subset" in error]
    assert (subset == []) is accepted


@pytest.mark.rule("declaration/evidence-holds")
@pytest.mark.parametrize(
    "reported_sdks",
    [{"sdk": None}, {"sdk": "2"}],
    ids=["missing-version", "different-version"],
)
def test_cited_report_requires_each_sdk_version_to_match(
    tmp_path: Path, reported_sdks: dict[str, Any]
) -> None:
    tests = [
        _test("baseline.fixture", "passed", []),
        _test(
            "facts.default_user", "passed", [{"fact": "resources.default_user", "value": "agent"}]
        ),
        _test(
            "facts.default_cwd",
            "passed",
            [{"fact": "resources.default_cwd", "value": "/workspace"}],
        ),
    ]
    report_path = _report_repository(
        tmp_path,
        tests,
        reports=[
            {
                "name": "older.json",
                "sdk_versions": reported_sdks,
                "started_at": "2026-09-29T00:00:00Z",
                "finished_at": "2026-09-29T00:00:01Z",
            },
            {
                "name": "newest.json",
                "sdk_versions": {"sdk": "1", "companion": "2"},
            },
        ],
    )
    declaration = {
        "provider": "e2b",
        "class": "default",
        "verified": {"date": "2026-09-30", "sdks": {"sdk": "1", "companion": "2"}},
        "resources": {"default_user": "agent", "default_cwd": "/workspace"},
        "gates": {},
        "evidence": {
            "resources.default_user": {
                "tests": ["facts.default_user"],
                "report": "reports/older.json",
            },
            "resources.default_cwd": {
                "tests": ["facts.default_cwd"],
                "report": "reports/newest.json",
            },
        },
    }

    errors = check_evidence(
        declaration, source_path=report_path, schema_errors=_schema_errors, catalog=CATALOG
    )

    assert any("report SDK versions are not a version-matching subset" in error for error in errors)


@pytest.mark.rule("declaration/evidence-holds")
@pytest.mark.parametrize("sdk_versions", [None, "missing"])
def test_cited_report_with_bad_sdk_versions_returns_errors(
    tmp_path: Path, sdk_versions: Any
) -> None:
    report: dict[str, Any] = (
        {"omit_sdk_versions": True} if sdk_versions == "missing" else {"sdk_versions": sdk_versions}
    )
    report_path = _report_repository(
        tmp_path,
        [
            _test(
                "facts.default_user",
                "passed",
                [{"fact": "resources.default_user", "value": "agent"}],
            )
        ],
        reports=[report],
    )
    declaration = {
        "provider": "e2b",
        "class": "default",
        "verified": {"date": "2026-09-30", "sdks": {"sdk": "1"}},
        "resources": {"default_user": "agent"},
        "gates": {},
        "evidence": {
            "resources.default_user": {
                "tests": ["facts.default_user"],
                "report": "reports/run.json",
            }
        },
    }

    errors = check_evidence(
        declaration, source_path=report_path, schema_errors=_schema_errors, catalog=CATALOG
    )

    assert errors


@pytest.mark.rule("declaration/evidence", "declaration/evidence-holds")
@pytest.mark.parametrize("driver_name", ["CoreDriver", "HTTPDriver"])
def test_new_provider_needs_no_native_driver_or_report(tmp_path: Path, driver_name: str) -> None:
    provider = "new-provider"
    assert provider not in DRIVERS
    versions = {"boxrouter-new-provider": "1.0.0", "boxrouter-adapter-kit": "1.0.0"}
    source = _report_repository(
        tmp_path,
        [
            _test(
                "facts.default_user",
                "passed",
                [{"fact": "resources.default_user", "value": "agent"}],
            )
        ],
        provider=provider,
        reports=[
            {
                "driver": {"name": driver_name, "version": "1.0.0"},
                "sdk_versions": versions,
                "implementation": "boxrouter_new_provider",
                "implementation_digest": "sha256:" + "1" * 64,
            }
        ],
    )
    declaration = _fact_evidence_declaration()
    declaration["provider"] = provider
    declaration["verified"]["sdks"] = versions
    assert (
        check_evidence(
            declaration, source_path=source, schema_errors=_schema_errors, catalog=CATALOG
        )
        == []
    )
