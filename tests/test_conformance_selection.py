# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Supplementary evidence cannot silently replace or establish the frozen baseline."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from sandbox_provider_spec import conformance
from sandbox_provider_spec import drivers as drivers_package
from sandbox_provider_spec.driver import Driver
from sandbox_provider_spec.opt_in import select_tests
from sandbox_provider_spec.suite import Suite, read_suite, suite_path
from sandbox_provider_spec.suite import Test as Scenario


def test_an_unfamiliar_installed_driver_module_is_enumerated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    extra = tmp_path / "drivers"
    extra.mkdir()
    (extra / "zzz.py").write_text("# sidecar\n")
    monkeypatch.setattr(drivers_package, "__path__", [*drivers_package.__path__, str(extra)])
    names = conformance.installed_drivers()
    assert "zzz" in names
    assert "e2b" in names


def test_cli_keeps_core_as_the_default() -> None:
    parser = argparse.ArgumentParser()
    conformance.arguments(parser)
    arguments = ["e2b", "--output", "report.json"]
    assert parser.parse_args(arguments).suite == "core"
    assert parser.parse_args([*arguments, "--suite", "coverage"]).suite == "coverage"


@pytest.mark.parametrize("selection", ["core", "coverage"])
def test_report_binds_only_the_selected_suite(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, selection: str
) -> None:
    paths: list[Path | None] = []
    core = Scenario("baseline.example", "baseline", (), ())
    additional = Scenario("coverage.example", "supplement", (), ())
    candidate = Scenario("baseline.candidate", "candidate", (), ())
    digest = "sha256:" + ("1" if selection == "core" else "2") * 64

    def selected(path: Path | None = None) -> Suite:
        paths.append(path)
        return (
            Suite(digest, (core,), (core.id, candidate.id))
            if path is None
            else Suite(digest, (core, additional, candidate), (core.id, candidate.id))
        )

    driver = Driver()
    driver.provider = "e2b"
    driver.sdk_versions = {"example-sdk": "1.0.0"}

    def factory(**_kwargs: Any) -> Driver:
        return driver

    monkeypatch.setattr(conformance, "read_suite", selected)
    monkeypatch.setattr(conformance, "suite_path", lambda: tmp_path / "conformance/suite.yaml")
    monkeypatch.setattr(conformance, "revision", lambda _root: "0" * 40)
    monkeypatch.setattr(
        conformance, "import_module", lambda _name: SimpleNamespace(make_driver=factory)
    )
    output = tmp_path / "report.json"
    args = argparse.Namespace(
        provider="e2b",
        execution_class="default",
        live=True,
        suite=selection,
        test=[],
        fixtures=None,
        output=output,
    )
    assert conformance.run(args) == 0
    document = json.loads(output.read_text())
    assert document["suite_digest"] == digest
    assert document["selected_tests"] == (
        [core.id] if selection == "core" else [core.id, additional.id, candidate.id]
    )
    assert document["baseline"] == ("not_run" if selection == "core" else "passed")
    assert paths == [None if selection == "core" else tmp_path / "conformance/coverage.yaml"]


def test_focused_run_retains_digest_without_selecting_baseline() -> None:
    suite = read_suite(suite_path().with_name("coverage.yaml"))
    focused = select_tests(suite, ["coverage.docker."])
    assert [test.id for test in focused.tests] == ["coverage.docker.host"]
    assert focused.digest == suite.digest
    assert focused.baseline_ids == suite.baseline_ids


def test_cli_takes_the_streamed_transfer_opt_in() -> None:
    parser = argparse.ArgumentParser()
    conformance.arguments(parser)
    arguments = ["e2b", "--output", "report.json"]
    assert parser.parse_args(arguments).opt_in == []
    assert parser.parse_args([*arguments, "--opt-in", "streamed_transfer"]).opt_in == [
        "streamed_transfer"
    ]
    with pytest.raises(SystemExit):
        parser.parse_args([*arguments, "--opt-in", "everything"])


@pytest.mark.parametrize("opt_in", [[], ["streamed_transfer"]])
def test_a_run_reports_the_streamed_transfer_checks_only_when_opted_in(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, opt_in: list[str]
) -> None:
    ordinary = Scenario("baseline.example", "baseline", (), ())
    streamed = Scenario("files.stream.v1.write.1gib", "stream", (), ())
    links = Scenario("file_links.v1.read_exact", "links", (), ())
    suite = Suite("sha256:" + "3" * 64, (ordinary, streamed, links), (ordinary.id,))
    driver = Driver()
    driver.provider = "e2b"
    driver.sdk_versions = {"example-sdk": "1.0.0"}
    monkeypatch.setattr(conformance, "read_suite", lambda _path=None: suite)
    monkeypatch.setattr(conformance, "suite_path", lambda: tmp_path / "conformance/suite.yaml")
    monkeypatch.setattr(conformance, "revision", lambda _root: "0" * 40)
    monkeypatch.setattr(
        conformance,
        "import_module",
        lambda _name: SimpleNamespace(make_driver=lambda **_kwargs: driver),
    )
    monkeypatch.setattr(
        conformance,
        "run_suite",
        lambda _driver, chosen, _fixtures: [
            {"id": test.id, "result": "not_run"} for test in chosen.tests
        ],
    )
    output = tmp_path / "report.json"
    args = argparse.Namespace(
        provider="e2b",
        execution_class="default",
        live=True,
        suite="coverage",
        test=[],
        opt_in=opt_in,
        fixtures=None,
        output=output,
    )
    conformance.run(args)
    document = json.loads(output.read_text())
    assert document["selected_tests"] == (
        [ordinary.id] if not opt_in else [ordinary.id, streamed.id, links.id]
    )
    assert document["suite_digest"] == suite.digest
