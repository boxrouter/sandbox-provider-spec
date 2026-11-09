# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The ``sandbox-provider-spec`` command."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import yaml

from sandbox_provider_spec import conformance, provider_assets, starter
from sandbox_provider_spec.check import (
    check_catalog,
    check_path,
    check_report,
    check_request,
    spec_dir,
)
from sandbox_provider_spec.installed import installed_declaration_path
from sandbox_provider_spec.load import DuplicateKeyError, load
from sandbox_provider_spec.matcher import Registry, match
from sandbox_provider_spec.rule_accounting import check_rule_accounting
from sandbox_provider_spec.suite import SPEC


class _InputError(ValueError):
    """A user-supplied file could not be read or parsed."""


def _yaml_diagnostic(path: str | Path, error: yaml.MarkedYAMLError) -> str:
    location = str(path)
    if error.problem_mark is not None:
        mark = error.problem_mark
        location += f":{mark.line + 1}:{mark.column + 1}"
    return f"{location}: error: invalid YAML: {error.problem or error.context}"


@contextmanager
def _input_file(path: str | Path) -> Iterator[None]:
    """Keep input diagnostics at the CLI boundary, including the parser's location."""
    try:
        yield
    except (
        OSError,
        UnicodeError,
        yaml.YAMLError,
        json.JSONDecodeError,
        DuplicateKeyError,
    ) as error:
        location = str(path)
        if isinstance(error, json.JSONDecodeError):
            location += f":{error.lineno}:{error.colno}"
            reason = f"invalid JSON: {error.msg}"
        elif isinstance(error, yaml.MarkedYAMLError):
            raise _InputError(_yaml_diagnostic(path, error)) from error
        elif isinstance(error, FileNotFoundError):
            reason = "file not found"
        elif isinstance(error, UnicodeError):
            reason = "invalid UTF-8"
        elif isinstance(error, OSError):
            reason = error.strerror or str(error)
        else:
            reason = str(error)
        raise _InputError(f"{location}: error: {reason}") from error


def _check(paths: list[str]) -> int:
    """Print ``<path>: ok`` or each error. Warnings are printed and do not fail."""
    failed = False
    for path in paths:
        try:
            with _input_file(path):
                result = check_path(path)
        except _InputError as input_error:
            print(input_error, file=sys.stderr)
            failed = True
            continue
        for warning in result.warnings:
            print(f"{path}: warning: {warning}")
        for error in result.errors:
            print(f"{path}: {error}")
        if result.errors:
            failed = True
        else:
            print(f"{path}: ok")
    return 1 if failed else 0


def _match(request_path: str, declaration_paths: list[str], met_needs: list[str]) -> int:
    """Print whether each declaration satisfies the request, and why not.

    Every file is checked first, as the matching rules require. Reports are the JSON files in
    the `reports/` directory beside each declaration whose `spec` names this specification;
    other files there are notes. Exits 0 when at least one declaration is eligible.
    """
    with _input_file(request_path):
        request = load(Path(request_path))
    errors = [f"{request_path}: {error}" for error in check_request(request)]
    if errors:
        print("\n".join(errors))
        return 1
    declarations: list[Any] = []
    reports: list[Any] = []
    for path in declaration_paths:
        with _input_file(path):
            result = check_path(path)
            declaration = load(Path(path))
        errors.extend(f"{path}: {error}" for error in result.errors)
        declarations.append(declaration)
        for report_path in sorted((Path(path).parent / "reports").glob("*.json")):
            with _input_file(report_path):
                report = load(report_path)
            if not isinstance(report, dict) or report.get("spec") != SPEC:
                continue
            errors.extend(
                f"{report_path}: {error}"
                for error in check_report(report, source_path=report_path).errors
            )
            reports.append(report)
    if errors:
        print("\n".join(errors))
        return 1
    spec = spec_dir()
    registry = Registry.from_documents(
        load(spec / "registries/regions.json"), load(spec / "registries/gpu-models.json")
    )
    found = match(
        request, declarations, reports=reports, registry=registry, met_needs=met_needs or None
    )
    rejected = found["rejected"]
    if rejected is not None:
        print(f"{request_path}: refused: {rejected['message']}")
        return 1
    for name, provider in found["results"].items():
        print(f"{name}: {'eligible' if provider['eligible'] else 'not eligible'}")
        for failure in provider["failed"]:
            print(f"  - {failure['reason']}: {failure['detail']}")
    return 0 if found["eligible"] else 1


def _check_rules() -> int:
    """Print rule-accounting errors, or confirm that every rule is accounted for."""
    errors = check_rule_accounting()
    for error in errors:
        print(error)
    if errors:
        return 1
    print("rule accounting: ok")
    return 0


def _check_catalog() -> int:
    """Check the catalog schema and its compiled JSON copy."""
    errors = check_catalog()
    for error in errors:
        print(error)
    if errors:
        return 1
    print("catalog: ok")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sandbox-provider-spec",
        description="Tools for the Sandbox Provider Specification.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    scaffold = commands.add_parser("scaffold", help="generate an honest native declaration")
    starter.arguments(scaffold)
    scaffold.set_defaults(run=starter.run)
    check = commands.add_parser(
        "check", help="check declarations, requests or conformance reports against the spec"
    )
    check.add_argument("paths", nargs="+", metavar="FILE", help="a YAML or JSON file")
    check.set_defaults(run=lambda args: _check(args.paths))
    matching = commands.add_parser(
        "match", help="say which declarations satisfy a request, and why the others do not"
    )
    matching.add_argument("request", metavar="REQUEST", help="a YAML or JSON request")
    matching.add_argument(
        "declarations", nargs="+", metavar="DECLARATION", help="a YAML or JSON declaration"
    )
    matching.add_argument(
        "--met-need",
        dest="met_needs",
        action="append",
        default=[],
        metavar="CONDITION",
        help="an account condition from `needs` known to hold, such as pro_plan (repeatable)",
    )
    matching.set_defaults(run=lambda args: _match(args.request, args.declarations, args.met_needs))
    installed = commands.add_parser(
        "installed-declaration", help="print the path of a declaration an installed package ships"
    )
    installed.add_argument(
        "provider", help="a provider an installed package registers, or docker-engine"
    )
    installed.add_argument(
        "--class", dest="execution_class", help="execution class, when applicable"
    )

    def show_installed(args: argparse.Namespace) -> int:
        try:
            print(installed_declaration_path(args.provider, args.execution_class))
        except (ValueError, FileNotFoundError) as error:
            print(f"installed-declaration: {error}")
            return 1
        return 0

    installed.set_defaults(run=show_installed)
    commands.add_parser(
        "check-rules", help="check normative rule coverage and waivers"
    ).set_defaults(run=lambda args: _check_rules())
    commands.add_parser(
        "check-catalog", help="check the catalog schema and JSON copy"
    ).set_defaults(run=lambda args: _check_catalog())
    assets = commands.add_parser(
        "provider-assets",
        help="check providers' brand and publication files; write release JSON with --out",
    )
    provider_assets.arguments(assets)
    assets.set_defaults(run=provider_assets.run)
    run = commands.add_parser("run", help="run native provider conformance tests")
    conformance.arguments(run)
    run.set_defaults(run=conformance.run)
    sweep = commands.add_parser(
        "sweep",
        help="delete run-labelled resources that crashed runs left behind (older than a TTL)",
    )
    conformance.sweep_arguments(sweep)
    sweep.set_defaults(run=conformance.sweep)
    args = parser.parse_args(argv)
    try:
        result: int = args.run(args)
    except _InputError as error:
        print(error, file=sys.stderr)
        return 1
    return result
