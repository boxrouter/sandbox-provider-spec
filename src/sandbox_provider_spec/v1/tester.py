# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The tester: run the shared tests against any 1.0 `Provider` and report what happened."""

from __future__ import annotations

import dataclasses
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, cast
from uuid import uuid4

from sandbox_provider_spec.conformance import run_suite
from sandbox_provider_spec.driver import NativeFailure, NotRun
from sandbox_provider_spec.proofs import proof_fixtures
from sandbox_provider_spec.report import DEVELOPMENT_REVISION, report, revision
from sandbox_provider_spec.runner import now
from sandbox_provider_spec.suite import Suite, Test, read_suite, suite_path
from sandbox_provider_spec.v1.provider import Provider
from sandbox_provider_spec.v1.suite_driver import ProviderDriver
from sandbox_provider_spec.v1.two_instances import two_instances
from sandbox_provider_spec.v1.types import CreateRequest, Discovery, SandboxClass

# Worst first: a section or operation takes the worst status of its tests.
SEVERITY = ("error", "differs", "not_run", "unsupported", "passed")

# Tests that `--quick` leaves out because they are slow.
QUICK_SKIPS = frozenset(
    {
        "contract.files_1gib_roundtrip",
        "contract.cost_final",
        "contract.lifetime_ends",
        "snapshots.v1.cost",
        "terminal.v1.idle_kept",
    }
)

# The lifetime test is not claimed by a class that states `lifetime_enforced_by: router`: the
# router ends its sandboxes, so no timer of the provider's is there to check. It is `not_run`
# in the report schema, with this reason, and counts for neither its section nor the run.
LIFETIME_TEST = "contract.lifetime_ends"
LIFETIME_NOT_CLAIMED = (
    "not_claimed: the class states lifetime_enforced_by router, so the router ends its sandboxes"
)

# A test that cannot apply to this form of the provider says so with one of these reasons, and
# then counts for neither its section nor the run: the Python form has no link to reuse.
NOT_APPLICABLE = frozenset({"the Python form has no link", LIFETIME_NOT_CLAIMED})

# The tests that need an offered `cost` (contract section 10): a run of a 1.0 provider leaves them
# out, and the `cost` operation reports `unsupported`, when discovery states no
# `cost_final_within_seconds`. From 1.1 `cost` is required, so a run keeps them and they fail.
SNAPSHOT_COST_TEST = "snapshots.v1.cost"
COST_TESTS = ("contract.cost", SNAPSHOT_COST_TEST)

# `contract.cost_final` reads a destroyed sandbox's cost, which a class that lists `cost.capture` is
# exempt from keeping (contract section 10), so a run leaves it out for such a provider.
CAPTURE_EXEMPT = ("contract.cost_final",)

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
)  # `cost` is required of a provider that offers it or states 1.1 or later
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
    # `resume` with `lifetime_seconds`, armed in that call (rule `provider-api/resume-lifetime`).
    "resume.lifetime": ("operations", "resume.lifetime"),
    "preview.link": ("gate", "previews"),
    "preview.revoke": ("knob", ("previews", "revocable")),
    "tcp.link": ("gate", "tcp_ports"),
    "terminal.open": ("gate", "terminal"),
    "terminal.disconnect": ("knob", ("terminal", "reattach")),
    "terminal.reattach": ("knob", ("terminal", "reattach")),
    "terminal.end": ("knob", ("terminal", "reattach")),
    # Either knob claims it: a variant that can switch or change its policy.
    "network.update": ("knobs", ("network_lockdown", ("switchable", "changeable"))),
    "lifetime.extend": ("fact", "extendable_lifetime"),
    "process.write_stdin": ("knob", ("processes", "input")),
    "process.close_stdin": ("knob", ("processes", "input")),
    "process.cancel": ("knob", ("processes", "cancel")),
    "files.list": ("operations", "files.list"),
    "files.mkdir": ("operations", "files.mkdir"),
    "files.remove": ("operations", "files.remove"),
    "files.exists": ("operations", "files.exists"),
    "run.user": ("knob", ("user_selection", "commands")),
    "files.write.user": ("knob", ("user_selection", "files_write")),
    "process.start.user": ("knob", ("user_selection", "process_start")),
    "run.base64": ("operations", "run.base64"),
    "image.prepare": ("operations", "image.prepare"),
    "image.get": ("operations", "image.get"),
    "image.list": ("operations", "image.list"),
    "image.delete": ("operations", "image.delete"),
    "labels.update": ("operations", "labels.update"),
    "image.cost": ("operations", "image.cost"),
    "snapshot.create": ("gate", "snapshots"),
    "snapshot.get": ("gate", "snapshots"),
    "snapshot.list": ("gate", "snapshots"),
    "snapshot.delete": ("gate", "snapshots"),
    "snapshot.cost": ("gate", "snapshots"),
}

# Operations that a driver can do with commands where discovery does not claim them. They are
# not marked unsupported; the driver falls back to the command.
COMMAND_FALLBACK = frozenset({"files.exists"})

# The tests of a section whose ids do not start with the section's name: `user_selection` is
# proved by the three operation tests that select a user, so its summary line counts them.
SECTION_TESTS = {
    "user_selection": ("run.user", "files.write.user", "process.start.user"),
}
TEST_SECTION = {test: section for section, tests in SECTION_TESTS.items() for test in tests}

# The sections of tests that discovery's `classes[].operations` turns on, in place of a gate: a
# section runs when some class lists every operation of its group.
DIRECTORIES = "directories"
DIRECTORY_OPERATIONS = ("files.list", "files.mkdir", "files.remove", "files.exists")
IMAGES = "images"
IMAGE_OPERATIONS = ("image.prepare", "image.get", "image.list", "image.delete")
LABELS = "labels"
LABEL_OPERATIONS = ("labels.update",)
OPERATION_GROUPS = {
    DIRECTORIES: DIRECTORY_OPERATIONS,
    IMAGES: IMAGE_OPERATIONS,
    LABELS: LABEL_OPERATIONS,
}
# Claims that change how the `images` tests run, or that add one test to the section.
OCI_LAYOUT = "image.prepare.oci_layout"
# A test of a claimed section that runs only when the class also lists this operation.
CLAIMED_TESTS = {"images.v1.cost": "image.cost"}


# What a run says when discovery cannot be read for one of these reasons: nothing else could run.
CANNOT_RUN = {
    "unavailable": "the provider could not be reached (unavailable): check its base URL or "
    "endpoint, and that the service is running",
    "timeout": "the provider did not answer in time (timeout): check its base URL or endpoint",
    "unauthenticated": "the provider refused the credential (unauthenticated): check the value "
    "that each --credential names",
    "forbidden": "the provider refused the credential (forbidden): check the value that each "
    "--credential names, and what its account may do",
}


class CannotRun(ValueError):
    """The run cannot start; the message is one plain line for a person."""


@dataclass
class TestOptions:
    """What a run may be told. `tests` are test ids or prefixes; empty selects the default set."""

    __test__ = False  # not a pytest class, despite the name

    reachable_url: str = "https://example.com"
    tests: Sequence[str] = ()
    quick: bool = False
    fixtures: Mapping[str, object] = field(default_factory=dict)
    new_client: Callable[[], Provider] | None = None
    """Makes a fresh client of the same provider, which `processes.reattach` reads through."""
    two_instances: bool = False
    """Answer the run's calls from two provider objects in turn (needs `new_client`), so an adapter
    that keeps per-sandbox state in its object fails: a later call lands on another object in
    production."""
    sandbox_class: str | None = None
    """Pins every test to this class (and to what it claims); None runs each test on a class that
    claims what the test proves."""


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


def claimed_operations(discovery: Discovery) -> set[str]:
    """The operations that some class lists in `operations`."""
    return {name for item in discovery.classes for name in item.operations}


def claimed_sections(discovery: Discovery | None) -> list[str]:
    """The sections whose tests a run includes: the claimed gates, and `directories`, `images` and
    `labels` when some class lists all the operations of that group."""
    if discovery is None:
        return []
    found = list(claimed_gates(discovery))
    listed = claimed_operations(discovery)
    found += [section for section, names in OPERATION_GROUPS.items() if set(names) <= listed]
    return found


def unsupported_operations(discovery: Discovery) -> dict[str, str]:
    """The optional operations that discovery does not claim, each with a fixed reason."""
    gates = claimed_gates(discovery)
    facts = {
        key for item in discovery.classes for key, value in item.resources.items() if value is True
    }
    listed = claimed_operations(discovery)
    missing: dict[str, str] = {}
    for operation, (kind, key) in OPERATION_CLAIMS.items():
        if kind == "gate":
            claimed = key in gates
        elif kind == "fact":
            claimed = key in facts
        elif kind == "operations":
            claimed = key in listed
        elif kind == "knobs":
            gate, knobs = cast("tuple[str, tuple[str, ...]]", key)
            claimed = any(
                variant.get(knob) is True for variant in gates.get(gate, []) for knob in knobs
            )
        else:
            gate, knob = cast("tuple[str, str]", key)
            claimed = any(variant.get(knob) is True for variant in gates.get(gate, []))
        if not claimed:
            missing[operation] = "discovery does not claim the section that needs this operation"
    if snapshot_cost_unavailable(discovery):
        missing["snapshot.cost"] = "the class states snapshot_cost unavailable"
    return missing


def not_claimed_tests(discovery: Discovery | None, class_name: str | None = None) -> dict[str, str]:
    """The tests that a claim leaves out, each with its reason. A test runs in the class that
    `class_for_test` names (the baseline's class, `default` else the first, for a test that claims
    nothing), so `contract.lifetime_ends` is left out when that class states `router`."""
    if discovery is None:
        return {}
    name = class_name or default_class(discovery)
    chosen = next((item for item in discovery.classes if item.id == name), None)
    if chosen is not None and chosen.lifetime_enforced_by == "router":
        return {LIFETIME_TEST: LIFETIME_NOT_CLAIMED}
    return {}


# The steps that read a label back, by the kind of record whose labels they read. A provider whose
# class states `*_labels_kept_by: router` keeps no labels on that kind (rules
# `provider-api/image-labels-router-kept` and `provider-api/snapshot-labels-router-kept`), so the
# tester leaves out the label assertions and checks everything else.
LABEL_READS = {"image.state": "image", "snapshot.get": "snapshot"}
LABEL_LISTS = {"snapshot.list": "snapshot"}


def labels_kept(discovery: Discovery | None) -> dict[str, bool]:
    """Whether the provider keeps the labels of `image`s and `snapshot`s: false when any class
    states `router` for the kind (the field means the same for every class of a provider)."""
    classes = discovery.classes if discovery is not None else ()
    return {
        "image": not any(item.image_labels_kept_by == "router" for item in classes),
        "snapshot": not any(item.snapshot_labels_kept_by == "router" for item in classes),
    }


def _without_label_assertions(test: Test, kept: Mapping[str, bool]) -> Test:
    """`test` without what it asserts about labels of a kind the provider does not keep: the
    `labels` that a read expects back, and a snapshot list by labels alone (a list by
    `sandbox_id` stays, as does an image list, which the driver makes without the filter)."""
    steps: list[dict[str, Any]] = []
    for step in test.steps:
        operation = str(step.get("op"))
        kind = LABEL_READS.get(operation)
        if kind is not None and not kept[kind]:
            equals = dict(step.get("expect", {}).get("equals", {}))
            if "labels" in equals:
                del equals["labels"]
                expect = {**step["expect"], "equals": equals}
                if not equals:
                    del expect["equals"]
                step = {**step, "expect": expect}
        kind = LABEL_LISTS.get(operation)
        if kind is not None and not kept[kind]:
            given = step.get("in", {})
            if "labels" in given and "sandbox_id" not in given:
                continue
        steps.append(step)
    return dataclasses.replace(test, steps=tuple(steps))


def snapshot_cost_unavailable(discovery: Discovery | None) -> bool:
    """Whether some class states `snapshot_cost: unavailable`: the provider cannot report what a
    snapshot costs, so `snapshot.cost` answers `unsupported` and its test is left out."""
    return discovery is not None and any(
        item.snapshot_cost == "unavailable" for item in discovery.classes
    )


def image_delete_blocked(discovery: Discovery | None) -> bool:
    """Whether some class states `image_delete_in_use: conflict`: a delete of an image waits for
    the sandboxes made from it."""
    return discovery is not None and any(
        item.image_delete_in_use == "conflict" for item in discovery.classes
    )


def _destroy_before_image_delete(test: Test) -> Test:
    """`test` with each sandbox that it created destroyed before its image is deleted: the
    provider cannot delete an image that a sandbox still runs from (rule
    `provider-api/image-delete-in-use`). A sandbox is destroyed once."""
    steps: list[dict[str, Any]] = []
    boxes: list[str] = []
    for step in test.steps:
        if step.get("op") == "create" and "as" in step:
            boxes.append(str(step["as"]))
        if step.get("op") == "image.delete":
            steps.extend({"op": "destroy", "target": box} for box in boxes)
            boxes = []
        steps.append(step)
    return dataclasses.replace(test, steps=tuple(steps))


def cost_offered(discovery: Discovery | None) -> bool:
    """Whether discovery states `cost_final_within_seconds`, which is how a provider offers cost."""
    return discovery is not None and discovery.limits.cost_final_within_seconds is not None


def cost_required(discovery: Discovery | None) -> bool:
    """Whether discovery states a `spec_version` of 1.1 or later, which requires `cost` (contract
    sections 10 and 13). A version that does not parse is held to the newest rules."""
    if discovery is None:
        return False
    try:
        return int(discovery.spec_version.split(".", 1)[1]) >= 1
    except (IndexError, ValueError):
        return True


_UNRESOLVED = object()


def _resolved(test: Test, value: object, fixtures: Mapping[str, object]) -> object:
    """A proof's value with its `$runner.<name>` parts read from the run's fixtures and the values
    the run derives from them; `_UNRESOLVED` when one cannot be read (the claim is then not met)."""
    if isinstance(value, str) and value.startswith("$runner."):
        try:
            known = {**fixtures, **proof_fixtures(test, fixtures)}
        except NotRun:
            return _UNRESOLVED
        return known.get(value.removeprefix("$runner."), _UNRESOLVED)
    if isinstance(value, dict):
        parts = {key: _resolved(test, item, fixtures) for key, item in value.items()}
        return _UNRESOLVED if _UNRESOLVED in parts.values() else parts
    return value


def _implied(test: Test, knob: str, allowed: tuple[str, ...]) -> str | None:
    """The preview `knob` value that the test's own create step asks for, when it names one."""
    for step in test.steps:
        if step.get("op") != "create":
            continue
        requirements = (step.get("in") or {}).get("requirements")
        previews = requirements.get("previews") if isinstance(requirements, dict) else None
        value = previews.get(knob) if isinstance(previews, dict) else None
        if value in allowed:
            return str(value)
    return None


def _floor(value: object) -> int | float | None:
    """The number a count claim promises: itself, or the `at_least` of `{at_least: N}`."""
    if isinstance(value, dict) and set(value) == {"at_least"}:
        value = value["at_least"]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value


def _reaches(claimed: object, wanted: object) -> bool:
    """Whether a claimed count meets a test's `{at_least: N}`: a number or `{at_least: M}` with
    M of N or more (a provider that claims four ports meets a test that needs two)."""
    if not (isinstance(wanted, dict) and set(wanted) == {"at_least"}):
        return False
    have, need = _floor(claimed), _floor(wanted)
    return have is not None and need is not None and have >= need


def _consistent(
    test: Test,
    gates: Mapping[str, list[Mapping[str, object]]],
    fixtures: Mapping[str, object] | None = None,
) -> bool:
    """A test of a section variant runs only when one claimed variant has every knob value that the
    test proves for that section (and, for previews, the access its sandbox asks for)."""
    known = fixtures or {}
    knobs: dict[str, list[tuple[str, object, bool]]] = {}
    for proof in test.proves:
        if "gate" not in proof:
            continue
        gate = str(proof["gate"])
        if gate not in gates:
            return False
        if "knob" in proof:
            # A count that the test names itself (`{at_least: 2}`) is a floor that a larger claim
            # meets; one that its fixtures set (`{at_least: $runner.max_allow_count}`) is what the
            # fixtures prove, so the claim must equal it.
            fixed = "$runner" not in repr(proof["value"])
            knobs.setdefault(gate, []).append(
                (str(proof["knob"]), _resolved(test, proof["value"], known), fixed)
            )
    access = _implied(test, "access", ("public", "private"))
    credential = _implied(test, "credential", ("link", "header"))

    def holds(variant: Mapping[str, object], knob: str, value: object, fixed: bool) -> bool:
        claimed = variant.get(knob)
        if value is _UNRESOLVED:
            return False
        return (
            claimed == value
            or (isinstance(claimed, list) and value in claimed)
            or (fixed and _reaches(claimed, value))
        )

    def listed_or_open(variant: Mapping[str, object], knob: str, wanted: str | None) -> bool:
        listed = variant.get(knob)
        return (
            wanted is None
            or listed is None
            or listed == wanted
            or (isinstance(listed, list) and wanted in listed)
        )

    def offers(variant: Mapping[str, object]) -> bool:
        return listed_or_open(variant, "access", access) and listed_or_open(
            variant, "credential", credential
        )

    if (access or credential) and "previews" in gates and "previews" not in knobs:
        # A test that proves no preview knob still needs a variant for the link it asks for.
        knobs["previews"] = []
    return all(
        any(
            all(holds(variant, knob, value, fixed) for knob, value, fixed in wanted)
            and (gate != "previews" or offers(variant))
            for variant in gates[gate]
        )
        for gate, wanted in knobs.items()
    )


def _alone(discovery: Discovery, item: SandboxClass) -> Discovery:
    return dataclasses.replace(discovery, classes=[item])


def _gates_needed(test: Test, discovery: Discovery) -> set[str]:
    """The gates a test needs its class to claim: those it proves, and its own section's."""
    head = test.id.split(".", 1)[0]
    needed = {str(proof["gate"]) for proof in test.proves if "gate" in proof}
    if head in claimed_gates(discovery):
        needed.add(head)
    return needed


def _claims(
    discovery: Discovery,
    item: SandboxClass,
    test: Test,
    fixtures: Mapping[str, object] | None = None,
) -> bool:
    """Whether this one class claims what the test needs: its gates and knob values, the
    operations (or group of operations) that turn its section on."""
    own = _alone(discovery, item)
    gates = claimed_gates(own)
    if not _gates_needed(test, discovery) <= set(gates) or not _consistent(test, gates, fixtures):
        return False
    group = OPERATION_GROUPS.get(test.id.split(".", 1)[0])
    if group is not None and not set(group) <= set(item.operations):
        return False
    return test.id not in OPERATION_CLAIMS or test.id not in unsupported_operations(own)


def _needs_a_claim(test: Test, discovery: Discovery) -> bool:
    head = test.id.split(".", 1)[0]
    return bool(
        _gates_needed(test, discovery) or head in OPERATION_GROUPS or test.id in OPERATION_CLAIMS
    )


def snapshot_keeps(item: SandboxClass) -> str | None:
    """What a snapshot of this class keeps, for the tests that take one without naming a variant:
    `files_only` when the class's `snapshots` variants list it, else the first value they list."""
    listed: list[str] = []
    for variant in _variants(item.gates, "snapshots"):
        value = variant.get("keeps")
        listed += (
            [str(v) for v in value] if isinstance(value, list) else [str(value)] if value else []
        )
    if "files_only" in listed or not listed:
        return None  # the test's own default is files_only
    return listed[0]


def default_class(discovery: Discovery) -> str:
    """The class that the baseline runs on: `default`, else the first class."""
    names = [item.id for item in discovery.classes]
    return "default" if "default" in names else names[0]


def class_for_test(
    test: Test, discovery: Discovery, fixtures: Mapping[str, object] | None = None
) -> str:
    """The class that runs a test: the default class when the test claims nothing, else the first
    class in discovery order that claims what it needs (the default class when none does alone)."""
    if _needs_a_claim(test, discovery):
        for item in discovery.classes:
            if _claims(discovery, item, test, fixtures):
                return item.id
    return default_class(discovery)


def _pinned(discovery: Discovery, name: str) -> Discovery:
    for item in discovery.classes:
        if item.id == name:
            return _alone(discovery, item)
    known = ", ".join(item.id for item in discovery.classes)
    raise CannotRun(f"the provider has no class {name!r} (its classes: {known})")


def shared_suite() -> Suite:
    """Every shared test: `suite.yaml` and `coverage.yaml`, under the digest that covers both."""
    core = read_suite()
    coverage = read_suite(suite_path().with_name("coverage.yaml"))
    known = {test.id for test in core.tests}
    extra = tuple(test for test in coverage.tests if test.id not in known)
    return Suite(coverage.digest, core.tests + extra, coverage.baseline_ids)


def _section(test: Test) -> str:
    """The section a test belongs to: `coverage.<section>.<name>` rows belong to their section, so a
    row for a knob value that the class does not claim stays out of an explicit selection."""
    head, _, rest = test.id.partition(".")
    return rest.partition(".")[0] if head == "coverage" else head


def _claimed_section(test: Test, gates: Mapping[str, object]) -> bool:
    """Whether the class claims the section of `test` or a gate that it proves, so that an explicit
    selection leaves the test out when the claim lacks a knob value that it proves."""
    return _section(test) in gates or any(proof.get("gate") in gates for proof in test.proves)


def _coverage_only(test: Test, sections: set[str], heads: set[str]) -> bool:
    """Whether `test` is a `coverage.<section>.` row of a claimed section that no other test
    covers: a gate with only coverage rows (`tcp_ports`, `desktop`, `docker`) would otherwise
    report its section `not_run` with no test selected."""
    section = _section(test)
    return test.id.startswith("coverage.") and section in sections and section not in heads


def select_tests(suite: Suite, discovery: Discovery | None, options: TestOptions) -> Suite:
    """The baseline tests, every `contract.` test, and the tests of each claimed section."""
    gates = claimed_gates(discovery) if discovery is not None else {}
    sections = set(claimed_sections(discovery))
    unsupported = unsupported_operations(discovery) if discovery is not None else {}
    chosen: list[Test] = []
    heads = {test.id.split(".", 1)[0] for test in suite.tests}
    for test in suite.tests:
        head = test.id.split(".", 1)[0]
        if options.tests:
            wanted = any(test.id.startswith(prefix) for prefix in options.tests) and (
                not _claimed_section(test, gates) or _consistent(test, gates, options.fixtures)
            )
        elif test.id in OPERATION_CLAIMS:
            # A test named for an operation that a claim turns on runs only when it is claimed.
            wanted = discovery is not None and test.id not in unsupported
        elif head in {"baseline", "contract"}:
            wanted = True
        else:
            wanted = (head in sections or _coverage_only(test, sections, heads)) and _consistent(
                test, gates, options.fixtures
            )
        if wanted and test.id in CLAIMED_TESTS and discovery is not None:
            # Left out unless the class lists its operation; a test named by its whole id stays.
            wanted = CLAIMED_TESTS[test.id] not in unsupported or test.id in options.tests
        if (
            wanted
            and not options.tests
            and discovery is not None
            and not cost_offered(discovery)
            and not cost_required(discovery)
        ):
            wanted = not test.id.startswith(COST_TESTS)
        if wanted and not options.tests and snapshot_cost_unavailable(discovery):
            wanted = test.id != SNAPSHOT_COST_TEST
        if wanted and not options.tests and discovery is not None:
            if "cost.capture" in claimed_operations(discovery):
                wanted = test.id not in CAPTURE_EXEMPT
        if wanted and not (options.quick and test.id in QUICK_SKIPS):
            chosen.append(test)
    if not chosen:
        raise ValueError("no shared tests match the selection")
    if image_delete_blocked(discovery):
        chosen = [_destroy_before_image_delete(test) for test in chosen]
    kept = labels_kept(discovery)
    if not all(kept.values()):
        chosen = [_without_label_assertions(test, kept) for test in chosen]
    return Suite(suite.digest, tuple(chosen), suite.baseline_ids)


def _applies(row: Mapping[str, Any]) -> bool:
    """Whether a test result counts: a `not_run` with a reason from `NOT_APPLICABLE` does not."""
    return not (row["result"] == "not_run" and row.get("reason") in NOT_APPLICABLE)


def _shown(row: Mapping[str, Any]) -> str:
    """The status a summary line prints: a test that a claim leaves out reads `not_claimed`."""
    return "not_claimed" if row.get("reason") == LIFETIME_NOT_CLAIMED else str(row["result"])


def _worst(statuses: Sequence[str]) -> str:
    return next((status for status in SEVERITY if status in statuses), "not_run")


def _source_revision() -> str:
    """The commit of a clean spec checkout, or the development marker when there is none."""
    try:
        return revision(suite_path().parents[1])
    except (ValueError, subprocess.CalledProcessError, OSError):
        return DEVELOPMENT_REVISION


def _subject_discovery(provider: Provider, live: Discovery | None) -> Discovery | None:
    """The discovery a report is bound to: the provider's static discovery where it states one,
    else the live document."""
    try:
        return type(provider).static_discovery()
    except NotImplementedError:
        return live


def _probe_cost(driver: ProviderDriver, discovery: Discovery | None) -> str:
    """Create a sandbox, read its cost, destroy it: the one operation no baseline test uses. A
    1.0 provider that does not offer cost has `unsupported`; one that states 1.1 or later
    `differs`, because 1.1 requires it."""
    if discovery is not None and not cost_offered(discovery):
        return "differs" if cost_required(discovery) else "unsupported"
    created = None
    try:
        created = driver.wait(
            driver.api.create(
                CreateRequest(
                    sandbox_class=driver.sandbox_class, labels={"sps.test.run": driver.run_id}
                ),
                idempotency_key=str(uuid4()),
            )
        )
        driver.wait(driver.api.cost(created.id))
        return "passed"
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
    lines = [f"{row['id']} {_shown(row)}" for row in results]
    by_operation: dict[str, list[str]] = {name: [] for name in OPERATIONS}
    by_section: dict[str, list[str]] = {name: [] for name in sorted(gates)}
    for row in results:
        head = TEST_SECTION.get(str(row["id"])) or str(row["id"]).split(".", 1)[0]
        if head in by_section and _applies(row):
            by_section[head].append(str(row["result"]))
        if head != "baseline":
            continue
        for step in row["steps"]:
            operation = STEP_OPERATION.get(str(step.get("operation")))
            if operation is not None:
                by_operation[operation].append(str(row["result"]))
    by_operation["discovery"].append(discovery_status)
    by_operation["cost"].append(cost_status)
    by_operation["cost"] += [
        str(row["result"]) for row in results if str(row["id"]).startswith("contract.cost")
    ]
    lines += [f"operation {name} {_worst(by_operation[name])}" for name in OPERATIONS]
    lines += [f"section {name} {_worst(by_section[name])}" for name in by_section]
    return lines


def _class_line(name: str, results: Sequence[Mapping[str, Any]]) -> str:
    own = [str(row["result"]) for row in results if row["class"] == name and _applies(row)]
    return f"class {name} {_worst(own)}"


def _run_by_class(
    driver: ProviderDriver,
    suite: Suite,
    discovery: Discovery | None,
    fixtures: dict[str, object],
) -> tuple[list[dict[str, object]], list[str]]:
    """Run each test on its class, one run of the runner per class, and label every result with
    the class that ran it. Results come back in the suite's order, the classes in order of use."""
    if discovery is None:
        results = run_suite(driver, suite, fixtures)
        for row in results:
            row["class"] = driver.sandbox_class
        return results, [driver.sandbox_class]
    groups: dict[str, list[Test]] = {}
    for test in suite.tests:
        groups.setdefault(class_for_test(test, discovery, fixtures), []).append(test)
    by_id: dict[str, dict[str, object]] = {}
    for name, tests in groups.items():
        driver.sandbox_class = name
        driver.not_claimed = not_claimed_tests(discovery, name)
        item = next(item for item in discovery.classes if item.id == name)
        keeps = snapshot_keeps(item)
        own = {**fixtures, "snapshot_keeps": keeps} if keeps else fixtures
        for row in run_suite(driver, Suite(suite.digest, tuple(tests), suite.baseline_ids), own):
            row["class"] = name
            by_id[str(row["id"])] = row
    return [by_id[test.id] for test in suite.tests], list(groups)


def run_tests(provider: Provider, options: TestOptions | None = None) -> Report:
    """Run the tests against `provider` and return the report. The sandboxes it creates are
    labelled `sps.test.run=<run id>`, and every one is deleted before this returns."""
    options = options or TestOptions()
    subject = provider
    if options.two_instances:
        if options.new_client is None:
            raise CannotRun("two provider objects need a way to make a second one (new_client)")
        provider = two_instances(provider, options.new_client())
    driver = ProviderDriver(provider, new_client=options.new_client)
    started = now()
    try:
        discovery: Discovery | None
        try:
            discovery = driver.wait(provider.discovery())
            discovery_status = "passed"
        except NativeFailure as error:
            if error.code in CANNOT_RUN:
                raise CannotRun(CANNOT_RUN[error.code]) from None
            discovery, discovery_status = None, "error"
        except Exception:  # pylint: disable=broad-exception-caught
            discovery, discovery_status = None, "error"
        if discovery is not None and options.sandbox_class is not None:
            discovery = _pinned(discovery, options.sandbox_class)
        if discovery is not None:
            driver.provider = discovery.provider.id
            driver.sandbox_class = default_class(discovery)
            missing = unsupported_operations(discovery)
            driver.unsupported = {
                **driver.unsupported,
                **{name: why for name, why in missing.items() if name not in COMMAND_FALLBACK},
            }
            driver.command_fallback = set(COMMAND_FALLBACK) & set(missing)
            driver.oci_layout = OCI_LAYOUT in claimed_operations(discovery)
            driver.not_claimed = not_claimed_tests(discovery)
            kept = labels_kept(discovery)
            driver.image_labels_kept = kept["image"]
            driver.snapshot_labels_kept = kept["snapshot"]
        suite = select_tests(shared_suite(), discovery, options)
        # The 1 GiB transfer of `contract.files_1gib_roundtrip` is a requirement of the contract,
        # so a run allows it unless the caller says otherwise.
        fixtures = {
            "file_stream_large": True,
            **options.fixtures,
            "reachable_url": options.reachable_url,
        }
        results, used = _run_by_class(driver, suite, discovery, fixtures)
        if discovery is not None:
            driver.sandbox_class = default_class(discovery)
        cost_status = _probe_cost(driver, discovery)
        if cost_status == "passed" and not any(
            str(row["id"]).startswith("contract.cost") for row in results
        ):
            cost_status = "not_run"  # the read worked, but no test checked the cost
        leftovers = driver.sweep_run()
        if leftovers and results:
            cast("list[Any]", results[-1].setdefault("cleanup", [])).extend(leftovers)
        document = Report(
            report(
                driver,
                suite,
                results,
                spec_revision=_source_revision(),
                started_at=started,
                discovery=_subject_discovery(subject, discovery),
            )
        )
        if options.sandbox_class is not None:
            # A run pinned to one class says so, as a report of a native driver does: a declaration
            # that names its class accepts only a report of that class as evidence.
            document["class"] = options.sandbox_class
        sections: dict[str, list[str]] = {name: [] for name in claimed_sections(discovery)}
        document.lines = _summary(results, discovery_status, cost_status, sections)
        if len(used) > 1 or options.sandbox_class is not None:
            document.lines += [_class_line(name, results) for name in used]
        document.all_passed = (
            discovery_status == "passed"
            and cost_status in ("passed", "unsupported", "not_run")
            and all(row["result"] == "passed" for row in results if _applies(row))
        )
        return document
    finally:
        driver.close()
