# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Run the shared suite through one explicitly selected native SDK driver."""

from __future__ import annotations

import argparse
import json
import pkgutil
import signal
import threading
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from importlib import import_module
from pathlib import Path
from typing import cast

from sandbox_provider_spec import drivers as drivers_package
from sandbox_provider_spec.coverage_file_transfer import FileTransferRunner
from sandbox_provider_spec.driver import Driver, Observation
from sandbox_provider_spec.report import report, revision, write_report
from sandbox_provider_spec.runner import now
from sandbox_provider_spec.suite import Suite, read_suite, suite_path


def select(suite: Suite, prefixes: list[str]) -> Suite:
    """Focused runs retain both files' digest and the complete baseline identity."""
    tests = tuple(
        test for test in suite.tests if any(test.id.startswith(prefix) for prefix in prefixes)
    )
    if not tests:
        raise ValueError("no shared tests match selection")
    return Suite(suite.digest, tests, suite.baseline_ids)


def run_suite(
    driver: Driver, suite: Suite, fixtures: dict[str, object] | None = None
) -> list[dict[str, object]]:
    """Run shared checks, then record any driver-owned cleanup after the suite."""
    try:
        results = FileTransferRunner(driver, fixtures).run(suite)
    except BaseException:
        reclaim(driver)  # an interrupt must not strand what the run created
        raise
    finish = getattr(driver, "finish", None)
    if callable(finish):
        for cleanup in cast(list[Observation], finish()):
            if results:
                cleanups = results[-1].setdefault("cleanup", [])
                if isinstance(cleanups, list):
                    cleanups.append(dict(cleanup))
    return results


def reclaim(driver: Driver) -> None:
    """After an interrupted run, release what it still owns (newest first), then look for its
    leftovers; best effort, since the interrupt is already being raised."""
    for owned in reversed(driver.resources):
        with suppress(Exception):
            driver.release(owned)
    finish = getattr(driver, "finish", None)
    if callable(finish):
        with suppress(Exception):
            finish()


@contextmanager
def terminating_as_interrupt() -> Iterator[None]:
    """Make SIGTERM unwind like Ctrl-C, so a stopped run still reaches its cleanup."""
    if threading.current_thread() is not threading.main_thread():
        yield
        return

    def handler(signum: int, frame: object) -> None:
        del signum, frame
        raise KeyboardInterrupt

    previous = signal.signal(signal.SIGTERM, handler)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)


def installed_drivers() -> frozenset[str]:
    """Native driver module names packaged under sandbox_provider_spec.drivers."""
    return frozenset(
        module.name
        for module in pkgutil.iter_modules(drivers_package.__path__)
        if not module.name.startswith("_")
    )


DRIVERS = installed_drivers()


def arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("provider", choices=sorted(installed_drivers()))
    parser.add_argument("--class", dest="execution_class", default="default")
    parser.add_argument(
        "--fixtures", type=Path, help="JSON runner fixtures; never recorded verbatim"
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--suite",
        choices=("core", "coverage"),
        default="core",
        help="core selects original tests; coverage selects baseline and supplementary tests",
    )
    parser.add_argument("--test", action="append", default=[], help="test id or prefix; repeatable")
    parser.add_argument("--live", action="store_true", help="explicitly authorize native resources")


def sweep_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("provider", choices=sorted(installed_drivers()))
    parser.add_argument("--class", dest="execution_class", default="default")
    parser.add_argument(
        "--fixtures", type=Path, help="JSON runner fixtures; never recorded verbatim"
    )
    parser.add_argument(
        "--ttl-hours",
        type=float,
        default=2.0,
        help="delete only run-labelled resources older than this; nothing else is touched",
    )
    parser.add_argument("--live", action="store_true", help="explicitly authorize deletions")


def sweep(args: argparse.Namespace) -> int:
    """Delete what crashed runs left behind: run-labelled resources older than the TTL."""
    if not args.live:
        raise ValueError("sweep requires --live because it deletes provider resources")
    fixtures = json.loads(args.fixtures.read_text()) if args.fixtures else {}
    try:
        module = import_module(f"sandbox_provider_spec.drivers.{args.provider}")
        driver = cast(
            Driver, module.make_driver(execution_class=args.execution_class, fixtures=fixtures)
        )
    except Exception as error:  # pylint: disable=broad-exception-caught
        print(f"driver initialization failed: {type(error).__name__}")
        return 1
    swept = driver.sweep_stale(args.ttl_hours * 3600)
    for item in swept:
        print(f"deleted {item}")
    print(f"{driver.provider}: swept {len(swept)} stale run-labelled resources")
    return 0


def run(args: argparse.Namespace) -> int:
    if not args.live:
        raise ValueError("run requires --live because it creates provider resources")
    root = suite_path().parents[1]
    spec_revision = revision(root)
    selected_suite = getattr(args, "suite", "core")
    if selected_suite not in {"core", "coverage"}:
        raise ValueError("unknown conformance suite")
    suite = (
        read_suite(suite_path().with_name("coverage.yaml"))
        if selected_suite == "coverage"
        else read_suite()
    )
    if args.test:
        suite = select(suite, args.test)
    fixtures = json.loads(args.fixtures.read_text()) if args.fixtures else {}
    try:
        module = import_module(f"sandbox_provider_spec.drivers.{args.provider}")
        driver = cast(
            Driver, module.make_driver(execution_class=args.execution_class, fixtures=fixtures)
        )
    except Exception as error:  # pylint: disable=broad-exception-caught
        # SDK initialization errors can contain credentials; never print their message.
        print(f"driver initialization failed: {type(error).__name__}")
        return 1
    started = now()
    with terminating_as_interrupt():
        results = run_suite(driver, suite, fixtures)
    document = report(
        driver,
        suite,
        results,
        spec_revision=spec_revision,
        started_at=started,
    )
    if revision(root) != spec_revision:
        raise ValueError("the spec checkout changed during the run")
    write_report(args.output, document)
    print(f"{driver.provider}: {len(results)} tests; clean={document['clean']}")
    return 0 if document["clean"] and not any(r["result"] == "error" for r in results) else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sandbox-provider-spec run")
    arguments(parser)
    return run(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
