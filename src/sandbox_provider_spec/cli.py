# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The ``sandbox-provider-spec`` command."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from importlib.metadata import entry_points
from pathlib import Path
from typing import Any

import yaml

from sandbox_provider_spec import conformance, fixtures, provider_assets, starter
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
from sandbox_provider_spec.report import write_report
from sandbox_provider_spec.rule_accounting import check_rule_accounting
from sandbox_provider_spec.suite import SPEC
from sandbox_provider_spec.v1 import tester
from sandbox_provider_spec.v1.errors import SpsError
from sandbox_provider_spec.v1.provider import Provider
from sandbox_provider_spec.v1.server import run_server

PROVIDER_GROUP = "sandbox_provider_spec.providers"
# The specification is distributed from its GitHub repository only.
HTTP_EXTRA_INSTALL = (
    "pip install 'sandbox-provider-spec[http] @ "
    "git+https://github.com/boxrouter/sandbox-provider-spec'"
)


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


def _serve(args: argparse.Namespace) -> int:
    """Serve an installed provider over the 1.0 HTTP API."""
    provider_class = _load_provider_class(args.provider_id, "serve")
    if provider_class is None:
        return 1
    try:
        run_server(provider_class, host=args.host, port=args.port, socket=args.socket)
    except ModuleNotFoundError as error:
        if error.name != "uvicorn":
            raise
        print(
            f"serve: the HTTP server needs the `http` extra: {HTTP_EXTRA_INSTALL}",
            file=sys.stderr,
        )
        return 1
    return 0


def _load_provider_class(provider_id: str, command: str) -> type[Provider] | None:
    """The installed `Provider` registered as `provider_id`, or None after saying why not."""
    entries = {entry.name: entry for entry in entry_points(group=PROVIDER_GROUP)}
    entry = entries.get(provider_id)
    if entry is None:
        known = ", ".join(sorted(entries)) or "none"
        print(
            f"{command}: no installed provider {provider_id!r} in the entry-point group "
            f"{PROVIDER_GROUP} (installed: {known})",
            file=sys.stderr,
        )
        return None
    provider_class = entry.load()
    if not (isinstance(provider_class, type) and issubclass(provider_class, Provider)):
        print(f"{command}: {provider_id!r} is not a Provider subclass", file=sys.stderr)
        return None
    return provider_class


def _credentials(pairs: list[str]) -> dict[str, str] | None:
    """Read each `<field>=<ENV_VAR>` from the environment, or print the problem and return None."""
    values: dict[str, str] = {}
    for pair in pairs:
        name, separator, variable = pair.partition("=")
        if not separator or not name or not variable:
            print(f"test: --credential needs <field>=<ENV_VAR>, got {pair!r}", file=sys.stderr)
            return None
        if variable not in os.environ:
            print(f"test: environment variable {variable} is not set", file=sys.stderr)
            return None
        values[name] = os.environ[variable]
    return values


def _on_class(row: dict[str, Any]) -> str:
    return f" (class {row['class']})" if "class" in row else ""


def _report_suite(args: argparse.Namespace) -> str | None:
    """The suite a `--reports-dir` report is named for: `baseline` (only `--test baseline.`),
    `coverage` (only `--test coverage.`) or `core` (no `--test`). None without `--reports-dir`. A
    `--quick` run and any other selection are refused: proof reads whole selections."""
    if args.reports_dir is None:
        return None
    if args.quick:
        raise _InputError("test: --reports-dir keeps whole selections; drop --quick")
    if not args.test:
        return "core"
    if args.test in (["baseline."], ["coverage."]):
        return str(args.test[0]).rstrip(".")
    raise _InputError(
        "test: --reports-dir takes no --test, or exactly --test baseline. or coverage."
    )


def _report_name(suite: str, result: Mapping[str, Any]) -> str:
    """`tester-<class>-<suite>.json`: one report per class, never several classes in one."""
    classes = sorted({str(row["class"]) for row in result["tests"] if "class" in row})
    if len(classes) != 1:
        raise _InputError(
            f"test: --reports-dir keeps one class per report; this run used {len(classes)} "
            "(pin one with --class)"
        )
    return f"tester-{classes[0]}-{suite}.json"


def _test(args: argparse.Namespace) -> int:
    """Run the shared tests against an installed provider or a base URL."""
    suite = _report_suite(args)
    credentials = _credentials(args.credential)
    if credentials is None:
        return 1
    try:
        given = fixtures.read_fixtures(args.fixture, args.fixtures)
    except fixtures.FixtureError as error:
        print(f"test: {error}", file=sys.stderr)
        return 1
    target: str = args.target
    try:
        if target.startswith(("http://", "https://")):
            if set(credentials) != {"token"}:
                print("test: a URL target takes one credential, token=<ENV_VAR>", file=sys.stderr)
                return 1
            # The client needs the `http` extra, so it loads only for a URL target.
            # pylint: disable-next=import-outside-toplevel
            from sandbox_provider_spec.v1.http_client import HttpProvider  # noqa: PLC0415

            provider: Provider = HttpProvider(target, credentials["token"])
            new_client: Callable[[], Provider] = lambda: HttpProvider(  # noqa: E731
                target, credentials["token"]
            )
        else:
            provider_class = _load_provider_class(target, "test")
            if provider_class is None:
                return 1
            declared = {item.name for item in provider_class.credential_fields}
            unknown = sorted(set(credentials) - declared)
            if unknown:
                print(
                    f"test: {target} declares no credential field {unknown[0]!r} "
                    f"(declared: {', '.join(sorted(declared)) or 'none'})",
                    file=sys.stderr,
                )
                return 1
            provider = provider_class(credentials)
            new_client = lambda: provider_class(credentials)  # noqa: E731
    except ModuleNotFoundError as error:
        if error.name != "httpx":
            raise
        print(
            f"test: a URL target needs the `http` extra: {HTTP_EXTRA_INSTALL}",
            file=sys.stderr,
        )
        return 1
    except SpsError as error:
        print(f"test: {error}", file=sys.stderr)
        return 1
    options = tester.TestOptions(
        reachable_url=args.reachable_url,
        tests=args.test,
        quick=args.quick,
        fixtures=given,
        new_client=new_client,
        sandbox_class=args.sandbox_class,
    )
    try:
        result = tester.run_tests(provider, options)
    except ValueError as error:
        print(f"test: {error}", file=sys.stderr)
        return 1
    print("\n".join(result.lines))
    for row in result["tests"]:
        if row["result"] not in {"passed", "unsupported"}:
            print(
                f"{row['id']}{_on_class(row)}: {row.get('reason', row['result'])}",
                file=sys.stderr,
            )
            for step in row["steps"]:
                if "command" in step:
                    print(f"  command: {step['command']}", file=sys.stderr)
                if step.get("stderr"):
                    print(f"  stderr: {step['stderr']}", file=sys.stderr)
    if any(row.get("reason") == "probe_connection_failed" for row in result["tests"]):
        print(
            f"hint: a sandbox could not reach {args.reachable_url}; "
            "pass --reachable-url with an HTTPS URL that your sandboxes can reach",
            file=sys.stderr,
        )
    write_report(Path(args.output), result)
    print(f"report: {args.output}", file=sys.stderr)
    if suite is not None:
        kept = Path(args.reports_dir) / _report_name(suite, result)
        write_report(kept, result)
        print(f"report: {kept}", file=sys.stderr)
    if not result.all_passed:
        return 1
    return 3 if args.quick else 0


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
    serve = commands.add_parser(
        "serve", help="serve an installed provider over the 1.0 HTTP API (needs the http extra)"
    )
    serve.add_argument("provider_id", help="the entry-point name of an installed provider")
    serve.add_argument(
        "--host", default="127.0.0.1", help="interface for --port (default 127.0.0.1)"
    )
    where = serve.add_mutually_exclusive_group(required=True)
    where.add_argument("--port", type=int, help="TCP port to listen on")
    where.add_argument("--socket", help="Unix socket path to listen on (plain HTTP)")
    serve.set_defaults(run=_serve)
    test_cmd = commands.add_parser(
        "test",
        help="run the shared tests against an installed provider or a base URL "
        "(exit 0 pass, 3 pass under --quick, 1 otherwise)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=fixtures.help_text(),
    )
    test_cmd.add_argument("target", help="an installed provider id, or an http(s):// base URL")
    test_cmd.add_argument(
        "--credential",
        action="append",
        default=[],
        metavar="FIELD=ENV_VAR",
        help="a credential field and the environment variable that holds it (repeatable); "
        "a URL target takes token=<ENV_VAR>",
    )
    test_cmd.add_argument(
        "--reachable-url",
        default="https://example.com",
        help="an HTTPS URL that a sandbox can reach (default https://example.com)",
    )
    test_cmd.add_argument(
        "--class",
        dest="sandbox_class",
        metavar="NAME",
        help="run every test on this class and only what it claims (default: each test runs on "
        "the first class, in discovery order, that claims what it proves; the baseline runs on "
        "`default`)",
    )
    test_cmd.add_argument(
        "--fixture",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help="a runner fixture a test needs (repeatable; names are listed below). VALUE is JSON "
        "when it parses as JSON, else text; env:VAR reads the environment variable VAR, so a "
        "secret is never printed. A test whose fixture is not supplied is not_run",
    )
    test_cmd.add_argument(
        "--fixtures",
        action="append",
        default=[],
        metavar="FILE",
        help="a YAML or JSON map of fixture name to value (repeatable; --fixture wins); a string "
        "env:VAR at any depth is read from the environment",
    )
    test_cmd.add_argument(
        "--test", action="append", default=[], help="test id or prefix; repeatable"
    )
    test_cmd.add_argument(
        "--quick", action="store_true", help="skip the slow tests; a pass exits 3, never 0"
    )
    test_cmd.add_argument(
        "--output",
        default="sps-report.json",
        help="where to write the report (default sps-report.json)",
    )
    test_cmd.add_argument(
        "--reports-dir",
        default=None,
        metavar="DIR",
        help="also write the report to DIR/tester-<class>-<suite>.json, <suite> being baseline "
        "(--test baseline.), coverage (--test coverage.) or core (no --test); one class, "
        "no --quick",
    )
    test_cmd.set_defaults(run=_test)
    args = parser.parse_args(argv)
    try:
        result: int = args.run(args)
    except _InputError as error:
        print(error, file=sys.stderr)
        return 1
    return result
