# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Check declaration evidence maps and the reports they cite."""

from __future__ import annotations

import hashlib
import json
import subprocess
from collections.abc import Callable
from datetime import datetime
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath
from site import getsitepackages
from typing import Any

import yaml

from sandbox_provider_spec.document_cache import cached_load
from sandbox_provider_spec.load import load
from sandbox_provider_spec.timestamps import parse_aware_datetime

DEVELOPMENT_REVISION = "0" * 40
"""Git's null object id. A consumer records it as the source revision of a local development run
whose SPS source it could not verify. A report carrying it is never evidence."""
ADAPTER_STACK_DISTRIBUTIONS = frozenset({"boxrouter-core", "boxrouter-adapter-kit"})
"""The Core and Kit distributions an adapter-driven report ran on (identity, not provider SDKs)."""


def check_evidence(
    declaration: dict[str, Any],
    *,
    source_path: str | Path | None,
    schema_errors: Callable[[Any, str], list[str]],
    catalog: dict[str, Any],
) -> list[str]:
    """Require citations for declared values and validate report-backed entries."""
    expected = _declared_values(declaration)
    evidence = declaration.get("evidence")
    if not isinstance(evidence, dict):
        return []  # The declaration schema reports the malformed map.
    expected.update(_cited_variant_presence_values(declaration, evidence))

    expected_paths = set(expected)
    cited_paths = set(evidence)
    errors = [
        f"evidence is missing a citation for {path}"
        for path in sorted(expected_paths - cited_paths)
    ]
    errors.extend(
        f"evidence has no declared value at {path}" for path in sorted(cited_paths - expected_paths)
    )
    for path in sorted(expected_paths & cited_paths):
        entry = evidence[path]
        if path == "resources.default_size" and expected[path] == "unknown":
            if (
                not isinstance(entry, dict)
                or "source" not in entry
                or any(key in entry for key in ("tests", "reports"))
            ):
                errors.append(
                    "evidence resources.default_size: an explicit unknown needs a source quote "
                    "explaining why the size is unestablished"
                )
                continue
            catalog_evidence = catalog.get("evidence")
            allowed = (
                catalog_evidence.get("quotable_paths", [])
                if isinstance(catalog_evidence, dict)
                else []
            )
            if not _matches_quotable_path(path, allowed):
                errors.append(f"evidence {path}: documentation quote is not allowed for this value")
            continue
        if isinstance(entry, dict) and "source" in entry:
            catalog_evidence = catalog.get("evidence")
            allowed = (
                catalog_evidence.get("quotable_paths", [])
                if isinstance(catalog_evidence, dict)
                else []
            )
            if not _matches_quotable_path(path, allowed):
                errors.append(f"evidence {path}: documentation quote is not allowed for this value")
    if source_path is None:
        return errors

    declaration_path = Path(source_path)
    provider_dir = declaration_path.resolve().parent
    report_cache: dict[Path, tuple[dict[str, Any] | None, list[str]]] = {}
    for path in sorted(expected_paths & cited_paths):
        if path == "resources.default_size" and expected[path] == "unknown":
            continue
        entry = evidence[path]
        if not isinstance(entry, dict) or ("tests" not in entry and "reports" not in entry):
            continue  # Quote entry shape and date are covered by the JSON Schema.
        report_entries = _report_evidence_entries(entry)
        if not report_entries:
            continue
        path_error_count = len(errors)
        all_proofs: list[Any] = []
        for report_entry in report_entries:
            report_name = report_entry.get("report")
            if not isinstance(report_name, str):
                continue
            report_path, path_error = _report_path(provider_dir, report_name)
            if path_error:
                errors.append(f"evidence {path}: {path_error}")
                continue
            assert report_path is not None
            if report_path not in report_cache:
                report_cache[report_path] = _load_report(
                    report_path,
                    declaration=declaration,
                    schema_errors=schema_errors,
                )
            report, report_errors = report_cache[report_path]
            errors.extend(f"evidence {path}: {message}" for message in report_errors)
            if report is None:
                continue
            cited_errors, proofs = _check_cited_tests(
                report_entry,
                report=report,
                evidence_path=path,
                declared_value=expected[path],
            )
            errors.extend(f"evidence {path}: {message}" for message in cited_errors)
            all_proofs.extend(proofs)
        if len(errors) == path_error_count and not (
            path.startswith("gates.") and expected[path] == "unsupported"
        ):
            expected_values = (
                expected[path]
                if isinstance(expected[path], list) and expected[path]
                else [expected[path]]
            )
            for value in expected_values:
                if not any(_value_proves(proved, value) for proved in all_proofs):
                    errors.append(
                        f"evidence {path}: cited tests do not prove declared value {value!r}"
                    )
    errors.extend(
        _check_newest_full_baseline_report_sdks(
            provider_dir=provider_dir,
            declaration=declaration,
            schema_errors=schema_errors,
        )
    )
    repository_root = _conformance_root()
    errors.extend(_check_declared_gates_against_reports(declaration, report_cache, repository_root))
    return errors


def _conformance_root() -> Path:
    """Find the specification suites beside source or in its installed wheel."""
    package = Path(__file__).resolve().parent
    source = package.parents[1]
    if (source / "conformance/suite.yaml").is_file():
        return source
    return package / "data"


def _git_repository(provider_dir: Path) -> Path | None:
    """Find source-owned reports' checkout without adopting an installed wheel's host."""
    try:
        root = subprocess.run(
            ["git", "-C", str(provider_dir), "rev-parse", "--show-toplevel"],
            capture_output=True,
            check=False,
            text=True,
        )
    except FileNotFoundError:
        return None
    if root.returncode != 0:
        return None
    repository = Path(root.stdout.strip()).resolve()
    installed = [
        Path(__file__).resolve().parent / "data" / "providers",
        *(Path(directory).resolve() for directory in getsitepackages()),
    ]
    if any(
        provider_dir.resolve().is_relative_to(directory)
        and not repository.is_relative_to(directory)
        for directory in installed
    ):
        return None
    return repository


_CONDITIONAL_RULES = {
    "previews/private-credential-is-its-own": ("access", "private"),
}


def _unconditional_rule_tests(gate: str, repository_root: Path) -> dict[str, list[str]]:
    """Return gate rules whose tests all prove no knob value."""
    named: dict[str, list[tuple[str, bool]]] = {}
    conformance = repository_root / "conformance"
    for path in (conformance / "suite.yaml", conformance / "coverage.yaml"):
        if not path.is_file():
            continue
        document = cached_load(path)
        if not isinstance(document, dict) or not isinstance(document.get("tests"), list):
            continue
        for test in document["tests"]:
            if not isinstance(test, dict) or not isinstance(test.get("id"), str):
                continue
            proves = test.get("proves")
            has_knob_proof = isinstance(proves, list) and bool(proves)
            rules = test.get("rules")
            if not isinstance(rules, list):
                continue
            for rule in rules:
                if isinstance(rule, str) and rule.startswith(f"{gate}/"):
                    named.setdefault(rule, []).append((test["id"], has_knob_proof))
    return {
        rule: [test_id for test_id, _ in tests]
        for rule, tests in named.items()
        if rule not in _CONDITIONAL_RULES and not any(has_proof for _, has_proof in tests)
    }


def _check_declared_gates_against_reports(
    declaration: dict[str, Any],
    report_cache: dict[Path, tuple[dict[str, Any] | None, list[str]]],
    repository_root: Path,
) -> list[str]:
    """Check each unconditional test's newest completed observations across all citations."""
    declared_gates = _mapping(declaration.get("gates"))
    provider = declaration.get("provider")
    execution_class = declaration.get("class")
    errors: list[str] = []
    for gate, mode in declared_gates.items():
        if mode is None or mode in ("unknown", "unsupported"):
            continue
        latest: dict[str, tuple[datetime, set[str]]] = {}
        for report, report_errors in report_cache.values():
            if (
                report_errors
                or not isinstance(report, dict)
                or report.get("clean") is not True
                or report.get("provider") != provider
                or report.get("class") != execution_class
            ):
                continue
            finished = parse_aware_datetime(report.get("finished_at"))
            selected = report.get("selected_tests")
            results = report.get("tests")
            if finished is None or not isinstance(selected, list) or not isinstance(results, list):
                continue
            for test in results:
                if not isinstance(test, dict) or test.get("id") not in selected:
                    continue
                test_id, result = test.get("id"), test.get("result")
                if (
                    not isinstance(test_id, str)
                    or not isinstance(result, str)
                    or result not in {"passed", "differs", "error"}
                ):
                    continue
                previous = latest.get(test_id)
                if previous is None or finished > previous[0]:
                    latest[test_id] = (finished, {result})
                elif finished == previous[0]:
                    previous[1].add(result)
        for rule, test_ids in _unconditional_rule_tests(gate, repository_root).items():
            for test_id in test_ids:
                observation = latest.get(test_id)
                if observation is None:
                    continue
                for result in sorted(observation[1] & {"differs", "error"}):
                    errors.append(
                        f"gates.{gate}: unconditional rule {rule}: {test_id} came back {result}"
                    )
    return errors


def _report_evidence_entries(entry: dict[str, Any]) -> list[dict[str, Any]]:
    """Normalize one-report and multi-report evidence to report/test pairs."""
    if "tests" in entry:
        return [entry]
    reports = entry.get("reports")
    if isinstance(reports, list):
        return [item for item in reports if isinstance(item, dict)]
    return []


def _cited_variant_presence_values(
    declaration: dict[str, Any], evidence: dict[str, Any]
) -> dict[str, bool]:
    """Recognize optional citations that a variant supports its gate."""
    variants_by_gate = _mapping(declaration.get("gates"))
    values: dict[str, bool] = {}
    for path in evidence:
        parts = path.split(".")
        if len(parts) != 3 or parts[0] != "gates" or not parts[2].isdigit():
            continue
        variants = variants_by_gate.get(parts[1])
        index = int(parts[2])
        if (
            isinstance(variants, list)
            and index < len(variants)
            and isinstance(variants[index], dict)
            and variants[index]
        ):
            values[path] = True
    return values


def _matches_quotable_path(path: str, patterns: Any) -> bool:
    """Match a declaration path against catalog patterns, one dotted segment at a time."""
    if not isinstance(patterns, list):
        return False
    parts = path.split(".")
    for pattern in patterns:
        if not isinstance(pattern, str):
            continue
        pattern_parts = pattern.split(".")
        if len(parts) == len(pattern_parts) and all(
            fnmatchcase(part, pattern_part)
            for part, pattern_part in zip(parts, pattern_parts, strict=True)
        ):
            return True
    return False


#: Declaration resources written per direction, `{read: N, write: N}` (catalog kind per_operation).
PER_OPERATION_FACTS = frozenset({"file_stream_max_bytes"})


def _declared_values(declaration: dict[str, Any]) -> dict[str, Any]:
    """Collect evidence-bearing values using stable dotted, zero-based paths."""
    values: dict[str, Any] = {}

    resources = _mapping(declaration.get("resources"))
    for name, value in resources.items():
        if name == "needs" and isinstance(value, dict):
            for resource, conditions in value.items():
                _add_value(values, f"resources.needs.{resource}", conditions)
        elif name == "unmet_limits" and isinstance(value, dict):
            for resource, ceilings in value.items():
                if isinstance(ceilings, dict):
                    for condition, ceiling in ceilings.items():
                        _add_value(
                            values, f"resources.unmet_limits.{resource}.{condition}", ceiling
                        )
        elif name in PER_OPERATION_FACTS and isinstance(value, dict):
            # Each direction is proven by its own transfer, so each is cited on its own.
            for operation, amount in value.items():
                _add_value(values, f"resources.{name}.{operation}", amount)
        else:
            _add_value(values, f"resources.{name}", value)

    if resources.get("default_size") == "unknown":
        values["resources.default_size"] = "unknown"

    for name, value in _mapping(declaration.get("lifetime_timer")).items():
        _add_value(values, f"lifetime_timer.{name}", value)

    for gate, variants in _mapping(declaration.get("gates")).items():
        prefix = f"gates.{gate}"
        if variants == "unsupported":
            _add_value(values, prefix, variants)
            continue
        if not isinstance(variants, list):
            continue
        for index, variant in enumerate(variants):
            variant_path = f"{prefix}.{index}"
            if not isinstance(variant, dict):
                continue
            behavior = [
                value for name, value in variant.items() if name not in {"needs", "conflicts"}
            ]
            if all(value == "unknown" for value in behavior):
                # A knobless gate is still a provider claim; the report's strict
                # {gate, value: true} proof establishes its presence. Metadata cannot
                # replace it when every behavioral value is absent or unknown.
                values[variant_path] = True
            for name, value in variant.items():
                if name == "needs" and isinstance(value, dict):
                    for knob, conditions in value.items():
                        _add_value(values, f"{variant_path}.needs.{knob}", conditions)
                else:
                    _add_value(values, f"{variant_path}.{name}", value)

    provider = declaration.get("provider")
    extension = declaration.get(f"x-{provider}")
    for name, value in _mapping(extension).items():
        _add_value(values, f"x-{provider}.{name}", value)
    return values


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _add_value(values: dict[str, Any], path: str, value: Any) -> None:
    if value != "unknown":
        values[path] = value


def _report_path(provider_dir: Path, report_name: str) -> tuple[Path | None, str | None]:
    relative = PurePosixPath(report_name)
    if (
        relative.is_absolute()
        or ".." in relative.parts
        or relative.parts[:1] != ("reports",)
        or len(relative.parts) != 2
    ):
        return None, "report must be a file directly under reports/"
    path = (provider_dir / Path(*relative.parts)).resolve()
    if not path.is_relative_to(provider_dir):
        return None, "report escapes the provider directory"
    if not path.is_file():
        return None, f"report does not exist: {report_name}"
    return path, None


def _load_report(
    report_path: Path,
    *,
    declaration: dict[str, Any],
    schema_errors: Callable[[Any, str], list[str]],
) -> tuple[dict[str, Any] | None, list[str]]:
    try:
        report = load(report_path)
    except (OSError, ValueError) as error:
        return None, [f"cannot read report: {error}"]
    errors = schema_errors(report, "report-schema.json")
    if not isinstance(report, dict):
        return None, errors or ["report is not an object"]
    if report.get("provider") != declaration.get("provider"):
        errors.append("report provider does not match declaration")
    if report.get("class") != declaration.get("class"):
        errors.append("report class does not match declaration")
    if report.get("clean") is not True:
        errors.append("report is not clean")
    verified = declaration.get("verified")
    if isinstance(verified, dict):
        verified_sdks = verified.get("sdks")
        report_sdks = provider_sdk_versions(report, verified_sdks)
        if not _is_version_matching_subset(report_sdks, verified_sdks):
            errors.append(
                "report SDK versions are not a version-matching subset of declaration verified.sdks"
            )
        started_at = report.get("started_at")
        verified_date = verified.get("date")
        if isinstance(started_at, str) and isinstance(verified_date, str):
            if started_at[:10] > verified_date:
                errors.append("report is newer than declaration verified.date")
    errors.extend(check_report_evidence(report, source_path=report_path))
    return report, errors


def implementation_distributions(report: dict[str, Any]) -> frozenset[str]:
    """The distributions a report records as its own implementation stack.

    An adapter-driven report names its adapter module in `implementation`; that adapter and the
    Core and Kit it ran on are the report's identity (tracked by the adapter's support file and
    the release matrix), not SDKs the provider's declaration verifies. A report without an
    `implementation` has no such stack.
    """
    implementation = report.get("implementation")
    if not isinstance(implementation, str) or not implementation:
        return frozenset()
    return frozenset({implementation.replace("_", "-"), *ADAPTER_STACK_DISTRIBUTIONS})


def provider_sdk_versions(report: dict[str, Any], verified_sdks: Any) -> Any:
    """The report's `sdk_versions` without its own implementation stack.

    A stack distribution the declaration does name in `verified.sdks` is still compared exactly.
    """
    sdks = report.get("sdk_versions")
    if not isinstance(sdks, dict):
        return sdks
    identity = implementation_distributions(report)
    named = verified_sdks if isinstance(verified_sdks, dict) else {}
    return {
        package: version
        for package, version in sdks.items()
        if package not in identity or package in named
    }


def _is_version_matching_subset(report_sdks: Any, verified_sdks: Any) -> bool:
    """Whether report SDKs match the declaration's verified versions."""
    return (
        isinstance(report_sdks, dict)
        and bool(report_sdks)
        and isinstance(verified_sdks, dict)
        and bool(verified_sdks)
        and all(
            isinstance(version, str)
            and bool(version)
            and package in verified_sdks
            and version == verified_sdks[package]
            for package, version in report_sdks.items()
        )
    )


def _check_newest_full_baseline_report_sdks(
    *,
    provider_dir: Path,
    declaration: dict[str, Any],
    schema_errors: Callable[[Any, str], list[str]],
) -> list[str]:
    """Require the newest committed full-baseline report to use every verified SDK."""
    verified = declaration.get("verified")
    sdks = verified.get("sdks") if isinstance(verified, dict) else None
    if not isinstance(sdks, dict) or not sdks:
        return []

    repository_root = _conformance_root()
    try:
        baseline_ids = _baseline_test_ids(repository_root)
    except (OSError, TypeError, ValueError, yaml.YAMLError):
        return ["cannot load baseline tests while checking declaration verified.sdks"]
    if not baseline_ids:
        return []

    repository = _git_repository(provider_dir)
    report_contents: list[tuple[Path, bytes]] = []
    if repository is not None:
        try:
            report_directory = provider_dir.resolve().relative_to(repository) / "reports"
        except ValueError:
            return ["provider reports are outside the repository"]
        committed = subprocess.run(
            [
                "git",
                "-C",
                str(repository),
                "ls-tree",
                "-r",
                "--name-only",
                "HEAD",
                "--",
                report_directory.as_posix(),
            ],
            capture_output=True,
            check=False,
            text=True,
        )
        if committed.returncode != 0:
            return ["cannot inspect committed reports while checking declaration verified.sdks"]
        for report_name in committed.stdout.splitlines():
            if not report_name.endswith(".json"):
                continue
            response = subprocess.run(
                ["git", "-C", str(repository), "show", f"HEAD:{report_name}"],
                capture_output=True,
                check=False,
            )
            if response.returncode == 0:
                report_contents.append((repository / report_name, response.stdout))
    else:
        try:
            report_contents = [
                (path, path.read_bytes())
                for path in sorted((provider_dir / "reports").rglob("*.json"))
            ]
        except OSError:
            return ["cannot inspect packaged reports while checking declaration verified.sdks"]

    finished_at: list[tuple[datetime, dict[str, Any]]] = []
    errors: list[str] = []
    for report_path, contents in report_contents:
        try:
            report = json.loads(contents)
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if (
            not isinstance(report, dict)
            or report.get("provider") != declaration.get("provider")
            or report.get("class") != declaration.get("class")
        ):
            continue
        selected = report.get("selected_tests")
        if (
            not isinstance(selected, list)
            or any(not isinstance(test_id, str) for test_id in selected)
            or not baseline_ids <= set(selected)
        ):
            continue
        report_errors = schema_errors(report, "report-schema.json")
        report_errors.extend(check_report_evidence(report, source_path=report_path))
        errors.extend(
            f"full-baseline report {report_path.name}: {message}" for message in report_errors
        )
        timestamp = parse_aware_datetime(report.get("finished_at"))
        if timestamp is None:
            return ["full-baseline report finished_at must be a timezone-aware datetime"]
        finished_at.append((timestamp, report))
    if errors:
        return errors
    if not finished_at:
        return []
    newest = max(timestamp for timestamp, _ in finished_at)
    if any(
        timestamp == newest and provider_sdk_versions(report, sdks) != sdks
        for timestamp, report in finished_at
    ):
        return ["newest full-baseline report SDK versions do not match declaration verified.sdks"]
    return []


def _baseline_test_ids(repository_root: Path) -> set[str]:
    """Read current baseline ids without importing the conformance runner."""
    identifiers: set[str] = set()
    for suite_path in (
        repository_root / "conformance" / "suite.yaml",
        repository_root / "conformance" / "coverage.yaml",
    ):
        if not suite_path.is_file():
            continue
        document = cached_load(suite_path)
        tests = document.get("tests") if isinstance(document, dict) else None
        if not isinstance(tests, list):
            continue
        identifiers.update(
            test["id"]
            for test in tests
            if isinstance(test, dict)
            and isinstance(test.get("id"), str)
            and test["id"].startswith("baseline.")
        )
    return identifiers


def _check_cited_tests(
    entry: dict[str, Any], *, report: dict[str, Any], evidence_path: str, declared_value: Any
) -> tuple[list[str], list[Any]]:
    errors: list[str] = []
    tests = report.get("tests")
    selected = report.get("selected_tests")
    if not isinstance(tests, list) or not isinstance(selected, list):
        return ["report has no test results or selected test list"], []

    by_id: dict[str, dict[str, Any]] = {}
    for test in tests:
        if isinstance(test, dict) and isinstance(test.get("id"), str):
            identifier = test["id"]
            if identifier in by_id:
                errors.append(f"report repeats test {identifier}")
            by_id[identifier] = test

    unsupported = evidence_path.startswith("gates.") and declared_value == "unsupported"
    proved_values: list[Any] = []
    for identifier in entry.get("tests", []):
        test = by_id.get(identifier)
        if test is None or identifier not in selected:
            errors.append(f"report did not select test {identifier}")
            continue
        expected_result = (
            "unsupported"
            if unsupported or (declared_value is False and test.get("result") == "unsupported")
            else "passed"
        )
        if test.get("result") != expected_result:
            errors.append(f"test {identifier} must be {expected_result}, not {test.get('result')}")
            continue
        if unsupported:
            parts = evidence_path.split(".")
            gate = parts[1] if len(parts) > 1 else ""
            if not gate or not _test_rules_establish_gate(test, gate):
                errors.append(f"test {identifier} does not establish gate {gate}")
            continue
        proved_values.extend(_proof_values(test, evidence_path))

    return errors, [] if unsupported or errors else proved_values


def _proof_values(test: dict[str, Any], evidence_path: str) -> list[Any]:
    proofs = test.get("proves")
    if not isinstance(proofs, list):
        return []
    parts = evidence_path.split(".")
    expected_gate: str | None = None
    expected_knob: str | None = None
    expected_fact: str | None = None
    gate_presence = False
    if len(parts) >= 4 and parts[0] == "gates" and parts[2].isdigit():
        expected_gate, expected_knob = parts[1], parts[3]
    elif len(parts) == 3 and parts[0] == "gates" and parts[2].isdigit():
        expected_gate, gate_presence = parts[1], True
    elif parts[0] in {"resources", "lifetime_timer"}:
        expected_fact = ".".join(parts)
    # One direction of a per-direction fact is proven by `{fact: resources.<name>, value:
    # {<direction>: ...}}`, so a test proves only the direction it moved.
    direction = (
        parts[2]
        if len(parts) == 3 and parts[0] == "resources" and parts[1] in PER_OPERATION_FACTS
        else None
    )
    if direction is not None:
        expected_fact = ".".join(parts[:2])

    values: list[Any] = []
    for proof in proofs:
        if not isinstance(proof, dict):
            continue
        if expected_gate is not None and proof.get("gate") == expected_gate:
            value = proof.get("value")
            if gate_presence and (
                value is True
                or (
                    isinstance(value, str)
                    and value not in {"", "unknown", "unsupported"}
                    and isinstance(proof.get("knob"), str)
                )
            ):
                values.append(True)
            elif proof.get("knob") == expected_knob:
                values.append(proof.get("value"))
        elif expected_fact is not None and proof.get("fact") == expected_fact:
            value = proof.get("value")
            if direction is None:
                values.append(value)
            elif isinstance(value, dict) and direction in value:
                values.append(value[direction])
    return values


def _test_rules_establish_gate(test: dict[str, Any], gate: str) -> bool:
    """Use source-verified rule ids to bind unsupported evidence to one gate."""
    rules = test.get("rules")
    return isinstance(rules, list) and any(
        isinstance(rule, str) and rule.startswith(f"{gate}/") for rule in rules
    )


def _value_proves(proved: Any, declared: Any) -> bool:
    """Exact values match; a measured number may also substantiate an at-least floor."""
    if declared == []:
        return bool(proved == [])
    if isinstance(proved, list):
        return any(_value_proves(item, declared) for item in proved)
    if isinstance(declared, dict) and set(declared) == {"at_least"}:
        floor = declared["at_least"]
        if isinstance(proved, bool):
            return False
        if (
            isinstance(proved, (int, float))
            and not isinstance(proved, bool)
            and isinstance(floor, (int, float))
            and not isinstance(floor, bool)
        ):
            return bool(proved >= floor)
        if isinstance(proved, dict) and set(proved) == {"at_least"}:
            amount = proved["at_least"]
            return (
                isinstance(amount, (int, float))
                and not isinstance(amount, bool)
                and isinstance(floor, (int, float))
                and not isinstance(floor, bool)
                and bool(amount >= floor)
            )
        return False
    if isinstance(declared, dict) and isinstance(proved, dict):
        return all(
            key in proved and _value_proves(proved[key], value) for key, value in declared.items()
        )
    if type(proved) is not type(declared):
        if isinstance(proved, (int, float)) and not isinstance(proved, bool):
            if isinstance(declared, (int, float)) and not isinstance(declared, bool):
                return proved == declared
        return False
    if isinstance(declared, list):
        if isinstance(proved, list):
            return all(
                any(_value_proves(actual, wanted) for actual in proved) for wanted in declared
            )
        return any(_value_proves(proved, wanted) for wanted in declared)
    return bool(proved == declared)


def _source_suite_rules(suite_digest: Any) -> tuple[dict[str, Any] | None, list[str]]:
    """Find test rules in the shipped suites or recorded historical suite data."""
    conformance = _conformance_root() / "conformance"
    try:
        core_bytes = (conformance / "suite.yaml").read_bytes()
    except OSError:
        return None, ["package has no conformance suite"]
    core_digest = "sha256:" + hashlib.sha256(core_bytes).hexdigest()
    coverage_path = conformance / "coverage.yaml"
    try:
        coverage_bytes = coverage_path.read_bytes() if coverage_path.is_file() else None
    except OSError:
        return None, ["package has no readable coverage suite"]
    coverage_digest = (
        "sha256:"
        + hashlib.sha256(
            b"suite.yaml\0" + core_bytes + b"\0coverage.yaml\0" + coverage_bytes + b"\0"
        ).hexdigest()
        if coverage_bytes is not None
        else None
    )
    if suite_digest in (core_digest, coverage_digest):
        try:
            core = cached_load(conformance / "suite.yaml", content=core_bytes)
            core_tests = core["tests"]
            if suite_digest == core_digest:
                source_tests = core_tests
            else:
                assert coverage_bytes is not None
                coverage = cached_load(coverage_path, content=coverage_bytes)
                source_tests = [
                    test for test in core_tests if test["id"].startswith("baseline.")
                ] + coverage["tests"]
            return {test["id"]: test.get("rules", []) for test in source_tests}, []
        except (KeyError, TypeError, ValueError, yaml.YAMLError) as error:
            return None, [f"package has an invalid conformance suite: {error}"]
    try:
        historical = json.loads((conformance / "historical-suite-rules.json").read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        return None, [f"package historical suite registry is unavailable: {error}"]
    source_rules = (
        historical.get(suite_digest)
        if isinstance(historical, dict) and isinstance(suite_digest, str)
        else None
    )
    if not isinstance(source_rules, dict):
        return None, ["report suite digest is not recognized by this package"]
    return source_rules, []


def check_report_evidence(
    report: dict[str, Any], *, source_path: str | Path | None = None
) -> list[str]:
    """Check suite/result integrity and, for a source file, its committed provenance."""
    revision = report.get("revision")
    if not isinstance(revision, str):
        return ["report has no source revision"]
    if revision == DEVELOPMENT_REVISION:
        return ["report is a local development run (null source revision) and is not evidence"]
    report_path = Path(source_path).resolve() if source_path is not None else None
    repository = _git_repository(report_path.parent) if report_path is not None else None
    if repository is not None:
        assert report_path is not None
        try:
            relative_report = report_path.resolve().relative_to(repository).as_posix()
        except ValueError:
            return ["report is outside the repository"]

        tracked = subprocess.run(
            ["git", "-C", str(repository), "ls-files", "--error-unmatch", "--", relative_report],
            capture_output=True,
            check=False,
            text=True,
        )
        if tracked.returncode != 0:
            return ["report is not committed"]
        dirty = subprocess.run(
            ["git", "-C", str(repository), "status", "--porcelain", "--", relative_report],
            capture_output=True,
            check=False,
            text=True,
        )
        if dirty.returncode != 0 or dirty.stdout.strip():
            return ["report has uncommitted changes"]

    suite_by_id, errors = _source_suite_rules(report.get("suite_digest"))
    if suite_by_id is None:
        return errors
    report_tests = report.get("tests")
    selected = report.get("selected_tests")
    if not isinstance(report_tests, list) or not isinstance(selected, list):
        return errors + ["report has no test results or selected test list"]
    report_by_id = {
        str(test["id"]): test
        for test in report_tests
        if isinstance(test, dict) and isinstance(test.get("id"), str)
    }
    if len(report_by_id) != len(report_tests):
        errors.append("report test results must have unique test ids")
    if set(report_by_id) != set(selected):
        errors.append("report results do not cover exactly its selected tests")
    digests = report.get("check_digests")
    if digests is not None and (not isinstance(digests, dict) or set(digests) != set(selected)):
        errors.append("report check digests do not cover exactly its selected tests")
    for identifier, result in report_by_id.items():
        source_rules = suite_by_id.get(identifier)
        if source_rules is None:
            errors.append(f"report test {identifier} is absent from its source suite")
        elif result.get("rules") != source_rules:
            errors.append(f"report test {identifier} rules differ from its source suite")
    return errors
