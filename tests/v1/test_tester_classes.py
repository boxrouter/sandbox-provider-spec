# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The tester runs each test on a class that claims what the test proves, and `--class` pins one."""

from __future__ import annotations

import dataclasses
import json
from typing import Any

import jsonschema
import pytest
from test_tester import LocalProvider, example

from sandbox_provider_spec.cli import main
from sandbox_provider_spec.v1 import CreateRequest, Discovery, Sandbox
from sandbox_provider_spec.v1.tester import (
    CannotRun,
    TestOptions,
    class_for_test,
    default_class,
    run_tests,
    select_tests,
    shared_suite,
)

PAUSE = {"pause_resume": [{"keeps": "files_only"}]}


def classed(**gates: Any) -> Discovery:
    """A discovery with one class per keyword (in order); its value is that class's gates."""
    base = example(Discovery)
    template = dataclasses.replace(base.classes[0], operations=())
    return dataclasses.replace(
        base,
        classes=[
            dataclasses.replace(template, id=name, name=name, gates=value)
            for name, value in gates.items()
        ],
    )


class ClassedProvider(LocalProvider, manifest=False):
    """Claims what `discovery_document` says, and remembers the class of each create."""

    discovery_document: Discovery = classed(default=None, vm=PAUSE)

    def __init__(self) -> None:
        super().__init__()
        self.created_in: list[str] = []

    async def discovery(self) -> Discovery:
        return self.discovery_document

    async def create(self, request: CreateRequest, *, idempotency_key: str) -> Sandbox:
        self.created_in.append(request.sandbox_class)
        return await super().create(request, idempotency_key=idempotency_key)

    async def pause(self, sandbox_id: str) -> Sandbox:
        box = dataclasses.replace(await self.get(sandbox_id), state="paused")
        self.boxes[sandbox_id] = box
        return box

    async def resume(self, sandbox_id: str) -> Sandbox:
        box = dataclasses.replace(await self.get(sandbox_id), state="running")
        self.boxes[sandbox_id] = box
        return box


def classes_of(report: Any) -> dict[str, str]:
    return {str(row["id"]): str(row["class"]) for row in report["tests"]}


def test_a_gate_that_only_a_non_default_class_claims_runs_on_that_class() -> None:
    provider = ClassedProvider()
    report = run_tests(
        provider, TestOptions(tests=("baseline.create_env", "pause_resume.files_only"))
    )
    assert classes_of(report) == {
        "baseline.create_env": "default",
        "pause_resume.files_only": "vm",
    }
    assert provider.created_in[0] == "default" and "vm" in provider.created_in
    assert provider.created_in.count("vm") == 1  # the claiming test, nothing else
    assert "class default passed" in report.lines
    assert any(line.startswith("class vm ") for line in report.lines)
    jsonschema.validate(
        json.loads(json.dumps(report)),
        json.loads(
            (
                __import__("pathlib").Path(__file__).resolve().parents[2]
                / "spec"
                / "report-schema.json"
            ).read_text()
        ),
    )


def test_the_first_claiming_class_in_discovery_order_runs_the_test() -> None:
    document = classed(default=None, second=PAUSE, first=PAUSE)
    test = next(t for t in shared_suite().tests if t.id == "pause_resume.files_only")
    assert class_for_test(test, document) == "second"
    reordered = dataclasses.replace(document, classes=list(reversed(document.classes)))
    assert class_for_test(test, reordered) == "first"
    assert default_class(reordered) == "default"


def test_a_test_that_claims_nothing_runs_on_default_even_when_it_is_not_first() -> None:
    document = classed(vm=PAUSE, default=None)
    baseline = next(t for t in shared_suite().tests if t.id == "baseline.create_env")
    assert class_for_test(baseline, document) == "default"
    assert default_class(classed(a=None, b=None)) == "a"  # no `default` class: the first


def test_a_default_that_claims_the_gate_too_runs_it_when_it_comes_first() -> None:
    document = classed(default=PAUSE, vm=PAUSE)
    test = next(t for t in shared_suite().tests if t.id == "pause_resume.files_only")
    assert class_for_test(test, document) == "default"


def test_a_pinned_class_runs_every_test_on_that_class() -> None:
    provider = ClassedProvider()
    report = run_tests(
        provider, TestOptions(tests=("baseline.create_env", "pause_resume."), sandbox_class="vm")
    )
    assert set(classes_of(report).values()) == {"vm"}
    assert "pause_resume.files_only" in classes_of(report)
    assert set(provider.created_in) == {"vm"}
    assert any(line.startswith("class vm ") for line in report.lines)

    other = ClassedProvider()
    report = run_tests(
        other, TestOptions(tests=("baseline.create_env", "pause_resume."), sandbox_class="default")
    )
    assert set(classes_of(report).values()) == {"default"}  # a pin overrides the claiming class
    assert set(other.created_in) == {"default"}


def test_a_pinned_class_that_does_not_exist_is_refused_with_the_class_names() -> None:
    with pytest.raises(CannotRun, match=r"no class 'nope' \(its classes: default, vm\)"):
        run_tests(ClassedProvider(), TestOptions(sandbox_class="nope"))


def test_selection_by_gate_is_unchanged_for_the_union_of_classes() -> None:
    chosen = {
        t.id
        for t in select_tests(shared_suite(), classed(default=None, vm=PAUSE), TestOptions()).tests
    }
    assert "pause_resume.files_only" in chosen and "baseline.create_env" in chosen


def test_the_test_command_takes_a_class(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main(["test", "--help"])
    assert "--class NAME" in capsys.readouterr().out
