# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The tester: run the shared tests against any 1.0 `Provider` and report what happened."""

from __future__ import annotations

import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, cast
from uuid import uuid4

from sandbox_provider_spec.conformance import run_suite
from sandbox_provider_spec.report import DEVELOPMENT_REVISION, report, revision
from sandbox_provider_spec.runner import now
from sandbox_provider_spec.suite import Suite, Test, read_suite, suite_path
from sandbox_provider_spec.v1.errors import SpsError
from sandbox_provider_spec.v1.provider import Provider
from sandbox_provider_spec.v1.suite_driver import ProviderDriver
from sandbox_provider_spec.v1.types import CreateRequest, Discovery

# Worst first: a section or operation takes the worst status of its tests.
SEVERITY = ("error", "differs", "not_run", "unsupported", "passed")

# Tests that `--quick` leaves out because they are slow.
QUICK_SKIPS = frozenset({"contract.files_1gib_roundtrip", "contract.cost_final"})

# The required operations (contract section 1) and the steps of a test that exercise each.
OPERATIONS = (
    "discovery",
    "create",
    "get",
    "list",
    "destroy",
    "run",
    "files.read",
    "files.write",
    "process.start",
    "process.output",
    "cost",
)
STEP_OPERATION = {
    "create": "create",
    "get": "get",
    "list": "list",
    "destroy": "destroy",
    "run": "run",
    "files.read_bytes": "files.read",
    "files.write": "files.write",
    "process.start": "process.start",
    "process.output": "process.output",
}

# What each optional operation needs discovery to claim. Without the claim the driver reports
# the operation as unsupported, which is how the suite tests a variant that a provider lacks.
OPERATION_CLAIMS = {
    "files.link": ("gate", "file_links"),
    "pause": ("gate", "pause_resume"),
    "resume": ("gate", "pause_resume"),
    "preview.link": ("gate", "previews"),
    "tcp.link": ("gate", "tcp_ports"),
    "lifetime.extend": ("fact", "extendable_lifetime"),
    "process.write_stdin": ("knob", ("processes", "input")),
    "process.close_stdin": ("knob", ("processes", "input")),
    "process.cancel": ("knob", ("processes", "cancel")),
}


@dataclass
class TestOptions:
    """What a run may be told. `tests` are test ids or prefixes; empty selects the default set."""

    __test__ = False  # not a pytest class, despite the name

    reachable_url: str = "https://example.com"
    tests: Sequence[str] = ()
    quick: bool = False
    fixtures: Mapping[str, object] = field(default_factory=dict)


class Report(dict[str, Any]):
    """The report document, plus what a command prints about the run."""

    lines: list[str]
    """`<test id> <status>`, then `operation <name> <status>` and `section <name> <status>`."""
    all_passed: bool
    """Whether every selected test passed."""


def _variants(gates: Mapping[str, object] | None, gate: str) -> list[Mapping[str, object]]:
    value = (gates or {}).get(gate)
    if value is None:
        return []
    items = value if isinstance(value, list) else [value]
    return [item for item in items if isinstance(item, Mapping)]


def claimed_gates(discovery: Discovery) -> dict[str, list[Mapping[str, object]]]:
    """Each optional section that some class of the discovery document claims, with its variants."""
    found: dict[str, list[Mapping[str, object]]] = {}
    for item in discovery.classes:
        for gate in item.gates or {}:
            found.setdefault(gate, []).extend(_variants(item.gates, gate))
    return found


def unsupported_operations(discovery: Discovery) -> dict[str, str]:
    """The optional operations that discovery does not claim, each with a fixed reason."""
    gates = claimed_gates(discovery)
    facts = {
        key for item in discovery.classes for key, value in item.resources.items() if value is True
    }
    missing: dict[str, str] = {}
    for operation, (kind, key) in OPERATION_CLAIMS.items():
        if kind == "gate":
            claimed = key in gates
        elif kind == "fact":
            claimed = key in facts
        else:
            gate, knob = cast("tuple[str, str]", key)
            claimed = any(variant.get(knob) is True for variant in gates.get(gate, []))
        if not claimed:
            missing[operation] = "discovery does not claim the section that needs this operation"
    return missing


def _consistent(test: Test, gates: Mapping[str, list[Mapping[str, object]]]) -> bool:
    """A test of a section variant runs only when a claimed variant has that knob value."""
    for proof in test.proves:
        if "gate" not in proof:
            continue
        gate = proof["gate"]
        if gate not in gates:
            return False
        if "knob" not in proof:
            continue
        knob: str = proof["knob"]
        value = proof["value"]

        def holds(variant: Mapping[str, object], knob: str = knob, value: object = value) -> bool:
            claimed = variant.get(knob)
            return claimed == value or (isinstance(claimed, list) and value in claimed)

        if not any(holds(variant) for variant in gates[gate]):
            return False
    return True


def shared_suite() -> Suite:
    """Every shared test: `suite.yaml` and `coverage.yaml`, under the digest that covers both."""
    core = read_suite()
    coverage = read_suite(suite_path().with_name("coverage.yaml"))
    known = {test.id for test in core.tests}
    extra = tuple(test for test in coverage.tests if test.id not in known)
    return Suite(coverage.digest, core.tests + extra, coverage.baseline_ids)


def select_tests(suite: Suite, discovery: Discovery | None, options: TestOptions) -> Suite:
    """The baseline tests, every `contract.` test, and the tests of each claimed section."""
    gates = claimed_gates(discovery) if discovery is not None else {}
    chosen: list[Test] = []
    for test in suite.tests:
        head = test.id.split(".", 1)[0]
        if options.tests:
            wanted = any(test.id.startswith(prefix) for prefix in options.tests)
        elif head in {"baseline", "contract"}:
            wanted = True
        else:
            wanted = head in gates and _consistent(test, gates)
        if wanted and not (options.quick and test.id in QUICK_SKIPS):
            chosen.append(test)
    if not chosen:
        raise ValueError("no shared tests match the selection")
    return Suite(suite.digest, tuple(chosen), suite.baseline_ids)


def _worst(statuses: Sequence[str]) -> str:
    return next((status for status in SEVERITY if status in statuses), "not_run")


def _source_revision() -> str:
    """The commit of a clean spec checkout, or the development marker when there is none."""
    try:
        return revision(suite_path().parents[1])
    except (ValueError, subprocess.CalledProcessError, OSError):
        return DEVELOPMENT_REVISION


def _probe_cost(driver: ProviderDriver) -> str:
    """Create a sandbox, read its cost, destroy it: the one operation no baseline test uses."""
    created = None
    try:
        created = driver.wait(
            driver.api.create(
                CreateRequest(labels={"sps.test.run": driver.run_id}), idempotency_key=str(uuid4())
            )
        )
        driver.wait(driver.api.cost(created.id))
        return "passed"
    except SpsError:
        return "error"
    except Exception:  # pylint: disable=broad-exception-caught
        return "error"
    finally:
        if created is not None:
            driver.sweep_run()


def _summary(
    results: Sequence[Mapping[str, Any]],
    discovery_status: str,
    cost_status: str,
    gates: Mapping[str, object],
) -> list[str]:
    lines = [f"{row['id']} {row['result']}" for row in results]
    by_operation: dict[str, list[str]] = {name: [] for name in OPERATIONS}
    by_section: dict[str, list[str]] = {name: [] for name in sorted(gates)}
    for row in results:
        head = str(row["id"]).split(".", 1)[0]
        if head in by_section:
            by_section[head].append(str(row["result"]))
        if head != "baseline":
            continue
        for step in row["steps"]:
            operation = STEP_OPERATION.get(str(step.get("operation")))
            if operation is not None:
                by_operation[operation].append(str(row["result"]))
    by_operation["discovery"].append(discovery_status)
    by_operation["cost"].append(cost_status)
    lines += [f"operation {name} {_worst(by_operation[name])}" for name in OPERATIONS]
    lines += [f"section {name} {_worst(by_section[name])}" for name in by_section]
    return lines


def run_tests(provider: Provider, options: TestOptions | None = None) -> Report:
    """Run the tests against `provider` and return the report. The sandboxes it creates are
    labelled `sps.test.run=<run id>`, and every one is deleted before this returns."""
    options = options or TestOptions()
    driver = ProviderDriver(provider)
    started = now()
    try:
        discovery: Discovery | None
        try:
            discovery = driver.wait(provider.discovery())
            discovery_status = "passed"
        except SpsError:
            discovery, discovery_status = None, "error"
        except Exception:  # pylint: disable=broad-exception-caught
            discovery, discovery_status = None, "error"
        if discovery is not None:
            driver.provider = discovery.provider.id
            driver.unsupported = {**driver.unsupported, **unsupported_operations(discovery)}
        suite = select_tests(shared_suite(), discovery, options)
        # The 1 GiB transfer of `contract.files_1gib_roundtrip` is a requirement of the contract,
        # so a run allows it unless the caller says otherwise.
        fixtures = {
            "file_stream_large": True,
            **options.fixtures,
            "reachable_url": options.reachable_url,
        }
        results = run_suite(driver, suite, fixtures)
        cost_status = _probe_cost(driver)
        leftovers = driver.sweep_run()
        if leftovers and results:
            cast("list[Any]", results[-1].setdefault("cleanup", [])).extend(leftovers)
        document = Report(
            report(driver, suite, results, spec_revision=_source_revision(), started_at=started)
        )
        gates = claimed_gates(discovery) if discovery is not None else {}
        document.lines = _summary(results, discovery_status, cost_status, gates)
        document.all_passed = discovery_status == "passed" and all(
            row["result"] == "passed" for row in results
        )
        return document
    finally:
        driver.close()
