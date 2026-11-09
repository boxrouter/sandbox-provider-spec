# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Checker and matcher parity for numeric and extension request constraints."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest

from sandbox_provider_spec.check import check_declaration, check_request
from sandbox_provider_spec.load import load
from sandbox_provider_spec.matcher import match, validate_request
from sandbox_provider_spec.suite import read_suite

ROOT = Path(__file__).resolve().parents[1]
ALPHA_PATH = ROOT / "tests/matcher/fixtures/providers/alpha.yaml"
BASELINE_IDS = read_suite().baseline_ids


def _alpha() -> dict[str, Any]:
    document = load(ALPHA_PATH)
    assert isinstance(document, dict)
    return document


def _alpha_report(declaration: dict[str, Any]) -> dict[str, Any]:
    return {
        "spec": "sandbox-provider-spec/0.1",
        "provider": declaration["provider"],
        "class": declaration.get("class"),
        "sdk_versions": declaration["verified"]["sdks"],
        "finished_at": "2026-09-29T00:00:00Z",
        "clean": True,
        "baseline": "passed",
        "selected_tests": list(BASELINE_IDS),
        "tests": [{"id": test_id, "result": "passed"} for test_id in BASELINE_IDS],
    }


def _integer_at(request: Any, path: tuple[str, ...], *, mode: str = "create") -> Any:
    parsed = validate_request(request, mode=mode)  # type: ignore[arg-type]
    if path == ("lifetime_seconds",):
        return parsed.lifetime_seconds
    if path[0] == "resources":
        return parsed.resources[path[1]]
    if path[0] == "requirements":
        return parsed.gates[path[1]].settings[path[2]]
    if path[0] == "restores_need":
        assert parsed.restores_need is not None
        if path[1] == "lifetime_seconds":
            return parsed.restores_need.lifetime_seconds
        return parsed.restores_need.resources[path[2]]
    raise AssertionError(f"unknown test path: {path}")


@pytest.mark.parametrize(
    ("suffix", "source"),
    [
        (".json", '{"resources":{"memory_min_mib":2.0}}'),
        (".yaml", "resources:\n  memory_min_mib: 2.0\n"),
    ],
)
@pytest.mark.rule("request/refused-before-matching")
def test_json_and_yaml_integral_numbers_are_schema_integers(
    tmp_path: Path, suffix: str, source: str
) -> None:
    path = tmp_path / f"request{suffix}"
    path.write_text(source, encoding="utf-8")
    request = load(path)

    assert isinstance(request["resources"]["memory_min_mib"], float)
    assert check_request(request) == []
    normalized = validate_request(request).resources["memory_min_mib"]
    assert normalized == 2
    assert type(normalized) is int


@pytest.mark.parametrize(
    ("document", "path", "mode"),
    [
        pytest.param({"lifetime_seconds": 2.0}, ("lifetime_seconds",), "create", id="lifetime"),
        pytest.param(
            {"resources": {"memory_min_mib": 2.0}},
            ("resources", "memory_min_mib"),
            "create",
            id="memory",
        ),
        pytest.param(
            {"resources": {"disk_min_mib": 2.0}}, ("resources", "disk_min_mib"), "create", id="disk"
        ),
        pytest.param(
            {"resources": {"gpu_count": 2.0}}, ("resources", "gpu_count"), "create", id="gpu-count"
        ),
        pytest.param(
            {"resources": {"run_seconds": 2.0}},
            ("resources", "run_seconds"),
            "create",
            id="run-seconds",
        ),
        pytest.param(
            {"resources": {"process_seconds": 2.0}},
            ("resources", "process_seconds"),
            "create",
            id="process-seconds",
        ),
        pytest.param(
            {"requirements": {"previews": {"access": "private", "ports": [3000.0]}}},
            ("requirements", "previews", "ports"),
            "create",
            id="preview-port",
        ),
        pytest.param(
            {"requirements": {"tcp_ports": {"tls": "none", "ports": [3000.0]}}},
            ("requirements", "tcp_ports", "ports"),
            "create",
            id="tcp-port",
        ),
        pytest.param(
            {"requirements": {"idle_shutdown": {"custom_idle_time": True, "idle_seconds": 2.0}}},
            ("requirements", "idle_shutdown", "idle_seconds"),
            "create",
            id="idle-seconds",
        ),
        pytest.param(
            {"resources": {"memory_min_mib": 2.0}},
            ("resources", "memory_min_mib"),
            "restore",
            id="restore",
        ),
    ],
)
@pytest.mark.rule("request/refused-before-matching")
def test_integral_float_requests_pass_both_validators_and_normalize(
    document: dict[str, Any], path: tuple[str, ...], mode: str
) -> None:
    assert check_request(document, in_restore=mode == "restore") == []
    normalized = _integer_at(document, path, mode=mode)
    if path[-1] == "ports":
        assert normalized == [3000]
        assert type(normalized[0]) is int
    else:
        assert normalized == 2
        assert type(normalized) is int


@pytest.mark.rule("request/refused-before-matching")
def test_integral_float_restores_need_values_are_normalized() -> None:
    request: dict[str, Any] = {
        "requirements": {"snapshots": {"original_after": "continues"}},
        "restores_need": {
            "lifetime_seconds": 2.0,
            "resources": {"memory_min_mib": 2.0},
        },
    }
    assert check_request(request) == []
    assert _integer_at(request, ("restores_need", "lifetime_seconds")) == 2
    normalized = _integer_at(request, ("restores_need", "resources", "memory_min_mib"))
    assert normalized == 2
    assert type(normalized) is int


@pytest.mark.rule("request/refused-before-matching")
def test_integral_float_request_remains_eligible_after_normalization() -> None:
    declaration = _alpha()
    report = _alpha_report(declaration)
    request = {
        "lifetime_seconds": 3600.0,
        "requirements": {
            "previews": {"access": "private", "credential": "link", "ports": [3000.0]}
        },
        "resources": {"cpu_min": 2.0, "memory_min_mib": 4096.0},
    }
    integral_request: dict[str, Any] = copy.deepcopy(request)
    integral_request["lifetime_seconds"] = 3600
    integral_request["requirements"]["previews"]["ports"] = [3000]
    integral_request["resources"]["memory_min_mib"] = 4096

    assert check_request(request) == []
    conditions = {"alpha": ["plan.long"]}
    result = match(request, [declaration], reports=[report], met_needs=conditions)
    reference = match(integral_request, [declaration], reports=[report], met_needs=conditions)
    assert result["rejected"] is None
    assert result["eligible"] == ["alpha"]
    assert result["eligible"] == reference["eligible"]


@pytest.mark.parametrize(
    ("suffix", "source"),
    [
        (".json", '{"resources":{"cpu_min":NaN}}'),
        (".json", '{"resources":{"cpu_min":Infinity}}'),
        (".json", '{"resources":{"cpu_min":-Infinity}}'),
        (".yaml", "resources:\n  cpu_min: .nan\n"),
        (".yaml", "resources:\n  cpu_min: .inf\n"),
        (".yaml", "resources:\n  cpu_min: -.inf\n"),
    ],
)
@pytest.mark.rule("request/refused-before-matching")
def test_loaded_nonfinite_numbers_are_refused_before_matching(
    tmp_path: Path, suffix: str, source: str
) -> None:
    path = tmp_path / f"request{suffix}"
    path.write_text(source, encoding="utf-8")
    request = load(path)

    assert any(
        "resources.cpu_min" in error and "finite" in error for error in check_request(request)
    )
    result = match(request, [_alpha()], reports=[])
    assert result["rejected"] is not None
    assert result["rejected"]["reason"] == "wrong_type"
    assert result["eligible"] == []


@pytest.mark.parametrize(
    ("document", "path"),
    [
        pytest.param({"lifetime_seconds": float("inf")}, "lifetime_seconds", id="lifetime"),
        pytest.param(
            {"resources": {"memory_min_mib": float("nan")}},
            "resources.memory_min_mib",
            id="integer-resource",
        ),
        pytest.param(
            {
                "requirements": {
                    "previews": {
                        "access": "private",
                        "ports": [3000],
                        "link_lifetime_seconds": float("-inf"),
                    }
                }
            },
            "requirements.previews.link_lifetime_seconds",
            id="numeric-knob",
        ),
        pytest.param(
            {
                "requirements": {
                    "idle_shutdown": {"custom_idle_time": True, "idle_seconds": float("inf")}
                }
            },
            "requirements.idle_shutdown.idle_seconds",
            id="integer-setting",
        ),
        pytest.param(
            {
                "requirements": {"snapshots": {"original_after": "continues"}},
                "restores_need": {"resources": {"cpu_min": float("nan")}},
            },
            "restores_need.resources.cpu_min",
            id="restore-need",
        ),
    ],
)
@pytest.mark.rule("request/refused-before-matching")
def test_nonfinite_numbers_in_common_fields_do_not_match(
    document: dict[str, Any], path: str
) -> None:
    errors = check_request(document)
    assert any(path in error and "finite" in error for error in errors)
    result = match(document, [_alpha()], reports=[])
    assert result["rejected"] is not None
    assert result["rejected"]["reason"] == "wrong_type"


@pytest.mark.rule("request/refused-before-matching")
def test_nonfinite_values_inside_extensions_remain_opaque() -> None:
    request = {"requirements": {"x-acme": {"future-number": float("inf")}}}
    assert check_request(request) == []
    assert match(request, [], reports=[])["rejected"] is None


@pytest.mark.parametrize(
    ("name", "accepted"),
    [
        pytest.param("x-acme", True, id="simple-provider"),
        pytest.param("x-acme-2", True, id="hyphenated-provider"),
        pytest.param("x-", False, id="empty-provider"),
        pytest.param("x--acme", False, id="empty-first-segment"),
        pytest.param("x-acme-", False, id="empty-last-segment"),
        pytest.param("x-acme--cloud", False, id="empty-middle-segment"),
        pytest.param("x-Acme", False, id="uppercase-provider"),
        pytest.param("x-acme_cloud", False, id="underscore-provider"),
        pytest.param("x-é", False, id="non-ascii-provider"),
    ],
)
@pytest.mark.rule("request/refused-before-matching")
def test_extension_name_schema_and_matcher_agree(name: str, accepted: bool) -> None:
    request: dict[str, Any] = {"requirements": {name: {}}}
    assert (check_request(request) == []) is accepted
    result = match(request, [], reports=[])
    assert (result["rejected"] is None) is accepted


@pytest.mark.rule("request/refused-before-matching")
def test_large_python_integers_do_not_overflow_finite_checks() -> None:
    request = {"resources": {"memory_min_mib": 10**400}}
    assert check_request(request) == []
    normalized = validate_request(request).resources["memory_min_mib"]
    assert normalized == 10**400
    assert type(normalized) is int


@pytest.mark.rule("declaration/unknown-words-reported")
@pytest.mark.parametrize("offered_cpu", [float("nan"), float("inf")], ids=["nan", "infinity"])
def test_nonfinite_declared_size_cannot_enable_a_provider_route(offered_cpu: float) -> None:
    declaration = _alpha()
    report = _alpha_report(declaration)
    assert match({"resources": {"cpu_min": 2.0}}, [declaration], reports=[report])["eligible"]
    declaration["resources"]["sizes"][0]["cpu"] = offered_cpu

    checked = check_declaration(declaration, source_path=ALPHA_PATH)
    assert any("resources.sizes.0.cpu" in error for error in checked.errors)

    result = match({"resources": {"cpu_min": 2.0}}, [declaration], reports=[report])
    assert result["rejected"] is None
    assert result["eligible"] == []
    assert result["results"]["alpha"]["eligible"] is False
