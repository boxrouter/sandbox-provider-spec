# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Selected hidden-secret header request validation and matching."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from sandbox_provider_spec import load, spec_dir
from sandbox_provider_spec.matcher import Registry, Rejected, match, validate_request
from sandbox_provider_spec.suite import read_suite

ROOT = Path(__file__).resolve().parent
BASELINE_IDS = read_suite().baseline_ids
REGIONS = load(spec_dir() / "registries/regions.json")
GPU_MODELS = load(spec_dir() / "registries/gpu-models.json")
REGISTRY = Registry.from_documents(REGIONS, GPU_MODELS)


def _legacy_request() -> dict[str, Any]:
    return {"requirements": {"hidden_secrets": {"inject_into": ["api.example.com"]}}}


def _selected_request(headers: Any) -> dict[str, Any]:
    return {
        "requirements": {
            "hidden_secrets": {
                "inject_into": ["api.example.com"],
                "injection": "sets_header",
                "header_templates": True,
                "headers": headers,
            }
        }
    }


def _declaration(header_templates: bool | str | None, provider: str = "fixture") -> dict[str, Any]:
    declaration: dict[str, Any] = {
        "spec": "sandbox-provider-spec/0.1",
        "provider": provider,
        "verified": {"date": "2026-10-09", "sdks": {f"{provider}-sdk": "1.0"}},
        "resources": {},
        "gates": {"hidden_secrets": [{"injection": "sets_header", "max_inject_into": 3}]},
        "evidence": {},
    }
    if header_templates is not None:
        declaration["gates"]["hidden_secrets"][0]["header_templates"] = header_templates
    return declaration


def _report(provider: str = "fixture") -> dict[str, Any]:
    return {
        "spec": "sandbox-provider-spec/0.1",
        "provider": provider,
        "sdk_versions": {f"{provider}-sdk": "1.0"},
        "finished_at": "2026-10-09T00:00:00Z",
        "clean": True,
        "baseline": "passed",
        "selected_tests": list(BASELINE_IDS),
        "tests": [{"id": test_id, "result": "passed"} for test_id in BASELINE_IDS],
    }


def test_legacy_request_parses_without_header_template_semantics() -> None:
    parsed = validate_request(_legacy_request())
    assert parsed.gates["hidden_secrets"].knobs == {}
    assert parsed.gates["hidden_secrets"].settings == {"inject_into": ["api.example.com"]}


@pytest.mark.parametrize(
    "headers",
    [
        [{"name": "Authorization", "prefix": "Bearer "}],
        [{"name": "x-api-key"}],
        [{"name": "X-Key"}],
        [{"name": "X-Key", "suffix": "-tail"}],
        [{"name": "Authorization"}, {"name": "x-api-key", "prefix": "key:"}],
    ],
)
def test_selected_header_templates_parse_and_default_affixes(headers: list[dict[str, str]]) -> None:
    request = _selected_request(headers)
    request["requirements"]["hidden_secrets"]["inject_into"] = [
        "api.example.com",
        "auth.example.net",
    ]
    parsed = validate_request(request)
    normalized = parsed.gates["hidden_secrets"].settings["headers"]
    assert all("prefix" in entry and "suffix" in entry for entry in normalized)
    assert len(parsed.gates["hidden_secrets"].settings["inject_into"]) == 2


@pytest.mark.parametrize(
    ("headers", "reason"),
    [
        ([], "setting"),
        ("Authorization", "setting"),
        (["Authorization"], "setting"),
        ([{}], "setting"),
        ([{"name": ""}], "setting"),
        ([{"name": "Bad Header"}], "setting"),
        ([{"name": "Bad,Name"}], "setting"),
        ([{"name": "Bad:Name"}], "setting"),
        ([{"name": "Bad/Name"}], "setting"),
        ([{"name": "Authorization", "other": "x"}], "setting"),
        ([{"name": "X-Key", "prefix": 1}], "setting"),
        ([{"name": "X-Key", "suffix": "bad\rvalue"}], "setting"),
        ([{"name": "X-Key", "prefix": "bad\nvalue"}], "setting"),
        ([{"name": "X-Key", "prefix": "bad\x00value"}], "setting"),
        ([{"name": "Key"}, {"name": "key"}], "setting"),
    ],
)
def test_malformed_header_templates_are_refused(headers: Any, reason: str) -> None:
    with pytest.raises(Rejected) as rejected:
        validate_request(_selected_request(headers))
    assert rejected.value.reason == reason


@pytest.mark.parametrize("part", ["prefix", "suffix"])
@pytest.mark.parametrize(
    "codepoint",
    (*range(0, 9), *range(10, 32), *range(127, 160)),
    ids=lambda value: f"U+{value:04X}",
)
def test_header_affixes_refuse_all_controls_except_horizontal_tab(
    part: str, codepoint: int
) -> None:
    request = _selected_request([{"name": "X-Key", part: f"a{chr(codepoint)}b"}])
    with pytest.raises(Rejected) as rejected:
        validate_request(request)
    assert rejected.value.reason == "setting"


@pytest.mark.parametrize("part", ["prefix", "suffix"])
def test_header_affixes_allow_horizontal_tab(part: str) -> None:
    parsed = validate_request(_selected_request([{"name": "X-Key", part: "a\tb"}]))
    assert parsed.gates["hidden_secrets"].settings["headers"][0][part] == "a\tb"


@pytest.mark.parametrize(
    "host",
    [
        "*.example.com",
        "127.0.0.1",
        "https://api.example.com",
        "api.example.com:443",
        "api.example.com/path",
    ],
)
def test_selected_headers_require_exact_dns_hosts(host: str) -> None:
    request = _selected_request([{"name": "Authorization"}])
    request["requirements"]["hidden_secrets"]["inject_into"] = [host]
    with pytest.raises(Rejected) as rejected:
        validate_request(request)
    assert rejected.value.reason == "setting"


def test_selected_headers_refuse_case_insensitive_duplicate_hosts() -> None:
    request = _selected_request([{"name": "Authorization"}])
    request["requirements"]["hidden_secrets"]["inject_into"] = [
        "API.Example.com",
        "api.example.com",
    ]
    with pytest.raises(Rejected) as rejected:
        validate_request(request)
    assert rejected.value.reason == "setting"


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"headers": [{"name": "Authorization"}], "header_templates": None}, "wrong_type"),
        ({"headers": [{"name": "Authorization"}], "header_templates": False}, "setting"),
        ({"header_templates": True, "headers": None}, "setting"),
        ({"header_templates": True}, "setting"),
        ({"headers": [{"name": "Authorization"}]}, "setting"),
    ],
)
def test_header_setting_requires_explicit_semantic_knobs(
    changes: dict[str, Any], reason: str
) -> None:
    request = _selected_request([{"name": "Authorization"}])
    gate = request["requirements"]["hidden_secrets"]
    gate.pop("headers")
    gate.pop("header_templates")
    gate.update(changes)
    with pytest.raises(Rejected) as rejected:
        validate_request(request)
    assert rejected.value.reason == reason


def test_selected_headers_require_sets_header_injection() -> None:
    request = _selected_request([{"name": "Authorization"}])
    request["requirements"]["hidden_secrets"].pop("injection")
    with pytest.raises(Rejected) as rejected:
        validate_request(request)
    assert rejected.value.reason == "setting"


def test_selected_header_request_matches_only_declared_header_template_support() -> None:
    request = _selected_request([{"name": "Authorization", "prefix": "Bearer "}])
    declarations = [
        _declaration(True, "fixture-true"),
        _declaration(False, "fixture-false"),
        _declaration(None, "fixture-absent"),
        _declaration("unknown", "fixture-unknown"),
    ]
    reports = [_report(declaration["provider"]) for declaration in declarations]
    result = match(request, declarations, reports=reports, registry=REGISTRY)

    assert result["rejected"] is None
    assert result["eligible"] == ["fixture-true"]
    assert result["results"]["fixture-true"]["eligible"] is True
    assert result["results"]["fixture-false"]["failed"][0]["reason"] == "knob_mismatch"
    assert result["results"]["fixture-absent"]["failed"][0]["reason"] == "knob_unknown"
    assert result["results"]["fixture-unknown"]["failed"][0]["reason"] == "knob_unknown"


def test_header_support_variant_does_not_change_legacy_admission() -> None:
    request = _legacy_request()
    baseline = _declaration(None)
    selected = _declaration(True)
    legacy_result = match(
        request,
        [baseline],
        reports=[_report()],
        registry=REGISTRY,
    )
    selected_result = match(
        request,
        [selected],
        reports=[_report()],
        registry=REGISTRY,
    )
    assert legacy_result["eligible"] == ["fixture"]
    assert selected_result["eligible"] == ["fixture"]
