# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Both suite files bind supplementary evidence and its complete baseline."""

from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import tarfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

import pytest
import yaml

from sandbox_provider_spec.driver import Driver, Inputs, NativeFailure, Observation
from sandbox_provider_spec.runner import Runner
from sandbox_provider_spec.suite import Test as Scenario
from sandbox_provider_spec.suite import read_suite, read_suite_at, suite_path


def write_suite(path: Path, identifiers: list[str]) -> None:
    path.write_text(
        yaml.safe_dump(
            {
                "spec": "sandbox-provider-spec/0.1",
                "tests": [
                    {"id": name, "title": name, "rules": [], "proves": [], "steps": []}
                    for name in identifiers
                ],
            }
        )
    )


def test_supplement_selects_baseline_and_new_tests_and_binds_both_files(tmp_path: Path) -> None:
    core, coverage = tmp_path / "suite.yaml", tmp_path / "coverage.yaml"
    write_suite(core, ["baseline.core", "existing.gate"])
    write_suite(coverage, ["baseline.candidate", "coverage.gate"])
    original = read_suite(core)
    combined = read_suite(coverage)
    assert original.digest == "sha256:" + hashlib.sha256(core.read_bytes()).hexdigest()
    assert [test.id for test in original.tests] == ["baseline.core", "existing.gate"]
    assert original.baseline_ids == combined.baseline_ids == ("baseline.core", "baseline.candidate")
    assert [test.id for test in combined.tests] == [
        "baseline.core",
        "baseline.candidate",
        "coverage.gate",
    ]
    write_suite(core, ["baseline.core", "another.existing.gate"])
    read_suite_at.cache_clear()
    assert read_suite(coverage).digest != combined.digest
    combined = read_suite(coverage)
    write_suite(coverage, ["baseline.candidate", "coverage.another"])
    read_suite_at.cache_clear()
    assert read_suite(coverage).digest != combined.digest


@pytest.mark.parametrize("selection", ["suite.yaml", "coverage.yaml"])
def test_duplicate_ids_across_files_fail_before_native_allocation(
    tmp_path: Path, selection: str
) -> None:
    for name in ["suite.yaml", "coverage.yaml"]:
        write_suite(tmp_path / name, ["baseline.duplicate"])
    with pytest.raises(ValueError, match="duplicate test id across suites"):
        read_suite(tmp_path / selection)


def test_each_resolved_path_is_parsed_once(tmp_path: Path) -> None:
    write_suite(tmp_path / "suite.yaml", ["baseline.core"])
    read_suite_at.cache_clear()
    first = read_suite(tmp_path / "suite.yaml")
    assert read_suite(tmp_path / "." / "suite.yaml") is first
    assert read_suite_at.cache_info().misses == 1
    assert read_suite(tmp_path / "suite.yaml").baseline_ids == ("baseline.core",)
    read_suite()
    read_suite(suite_path())
    assert read_suite_at.cache_info().misses == 2


def test_updated_suite_at_same_path_refreshes_baseline(tmp_path: Path) -> None:
    suite = tmp_path / "suite.yaml"
    write_suite(suite, ["baseline.core"])
    first = read_suite(suite)
    write_suite(suite, ["baseline.core", "baseline.new"])
    updated = read_suite(suite)
    assert updated.baseline_ids == ("baseline.core", "baseline.new")
    assert updated.digest != first.digest


def test_suite_cache_is_bounded(tmp_path: Path) -> None:
    suite = tmp_path / "suite.yaml"
    read_suite_at.cache_clear()
    for index in range(12):
        write_suite(suite, [f"baseline.{index}"])
        read_suite(suite)
    assert read_suite_at.cache_info().currsize <= 8


def test_every_bash_script_in_both_suite_files_is_text() -> None:
    """YAML reads an unquoted `true` as a bool, which no driver can run as a command."""
    root = Path(__file__).resolve().parents[1] / "conformance"
    for name in ("suite.yaml", "coverage.yaml"):
        tests = yaml.safe_load((root / name).read_text())["tests"]
        for test in tests:
            for step in test.get("steps", []):
                given = step.get("in")
                if isinstance(given, dict) and "bash_script" in given:
                    assert isinstance(given["bash_script"], str), (name, test["id"])


def test_custom_image_requirements_do_not_repeat_the_top_level_image() -> None:
    root = Path(__file__).resolve().parents[1] / "conformance"
    for name in ("suite.yaml", "coverage.yaml"):
        tests = yaml.safe_load((root / name).read_text())["tests"]
        for test in tests:
            for step in test.get("steps", []):
                given = step.get("in")
                requirements = given.get("requirements") if isinstance(given, dict) else None
                custom_images = (
                    requirements.get("custom_images") if isinstance(requirements, dict) else None
                )
                assert not isinstance(custom_images, dict) or "image" not in custom_images, (
                    name,
                    test["id"],
                )


DISTRO_ROW = "coverage.custom_images.prepare.dockerfile_distro"
DISTRO_DOCKERFILE = "FROM ubuntu:24.04\nRUN printf sps-distro-prepared >/opt/sps-image-marker\n"
DISTRO_MARKER = "/opt/sps-image-marker"
DISTRO_CONTENT = b"sps-distro-prepared"


def test_prepared_distro_dockerfile_row_proves_only_source_and_prepared() -> None:
    root = Path(__file__).resolve().parents[1] / "conformance"
    tests = yaml.safe_load((root / "coverage.yaml").read_text())["tests"]
    test = next(t for t in tests if t["id"] == DISTRO_ROW)
    assert test["proves"] == [
        {"gate": "custom_images", "knob": "source", "value": "dockerfile"},
        {"gate": "custom_images", "knob": "prepared", "value": True},
    ]
    prepare = next(step for step in test["steps"] if step.get("op") == "image.prepare")
    given = prepare["in"]
    assert set(given) == {"source", "dockerfile"}
    instructions = [
        line.split(None, 1)[0] for line in given["dockerfile"].strip().splitlines() if line.strip()
    ]
    assert instructions == ["FROM", "RUN"]
    assert given["dockerfile"] == DISTRO_DOCKERFILE
    create = next(step for step in test["steps"] if step.get("op") == "create")
    assert create["in"]["requirements"] == {
        "custom_images": {"source": "dockerfile", "prepared": True}
    }
    assert create["in"]["lifetime_seconds"] <= 300
    marker = next(step for step in test["steps"] if step.get("op") == "files.read_bytes")
    assert marker["expect"]["equals"]["data"] == {"utf8": "sps-distro-prepared"}


class DistroPreparedDriver(Driver):
    """A faithful fake: the runner's own prepare -> create -> marker dispatch, no provider."""

    def __init__(self, marker: bytes | None = DISTRO_CONTENT) -> None:
        super().__init__()
        self.marker = marker
        self.calls: list[str] = []
        self.prepare_inputs: dict[str, object] = {}
        self.create_inputs: dict[str, object] = {}
        self.read_inputs: dict[str, object] = {}
        self.prepared: dict[str, object] = {}

    def image_prepare(self, target: object, inputs: Inputs) -> Observation:
        del target
        self.calls.append("image.prepare")
        self.prepare_inputs = dict(inputs)
        self.prepared = {
            "resource": self.own("image", object(), lambda: {"result": "deleted"}),
            "key": "0" * 64,
            "identity": "boxrouter-img-offline",
            "resources": {},
        }
        return self.prepared

    def create(self, target: object, inputs: Inputs) -> Observation:
        del target
        self.calls.append("create")
        self.create_inputs = dict(inputs)
        box = {"identity": "box"}
        self.own("sandbox", box, lambda: {"result": "deleted"})
        return box

    def files_read_bytes(self, target: object, inputs: Inputs) -> Observation:
        del target
        self.calls.append("files.read_bytes")
        self.read_inputs = dict(inputs)
        if self.marker is None:
            raise NativeFailure("files_read_failed")
        return {"data": self.marker}


def _distro_row() -> Scenario:
    suite = read_suite(suite_path().with_name("coverage.yaml"))
    return next(test for test in suite.tests if test.id == DISTRO_ROW)


def test_prepared_distro_row_dispatches_prepare_create_and_marker() -> None:
    driver = DistroPreparedDriver()
    outcome = Runner(driver).run_test(_distro_row())
    assert outcome["result"] == "passed"
    assert driver.calls == ["image.prepare", "create", "files.read_bytes"]
    assert driver.prepare_inputs == {"source": "dockerfile", "dockerfile": DISTRO_DOCKERFILE}
    assert driver.create_inputs["image"] is driver.prepared
    assert driver.create_inputs["requirements"] == {
        "custom_images": {"source": "dockerfile", "prepared": True}
    }
    assert driver.create_inputs["lifetime_seconds"] == 300
    assert driver.read_inputs == {"path": DISTRO_MARKER}
    cleanup = cast(list[dict[str, object]], outcome["cleanup"])
    assert {item["kind"] for item in cleanup} == {"image", "sandbox"}


@pytest.mark.parametrize(("marker", "result"), [(b"unexpected", "differs"), (None, "error")])
def test_prepared_distro_row_fails_on_bad_or_missing_marker(
    marker: bytes | None, result: str
) -> None:
    outcome = Runner(DistroPreparedDriver(marker)).run_test(_distro_row())
    assert outcome["result"] == result


DISTRO_CONTEXT_ROW = "coverage.custom_images.prepare.dockerfile_distro_context"
DISTRO_CONTEXT_DOCKERFILE = (
    "FROM ubuntu:24.04\n"
    "COPY copied.txt /opt/sps-copy\n"
    "COPY binary.bin /opt/sps-binary\n"
    "ADD added.txt /opt/sps-added\n"
    "ADD bundle.bin /opt/sps-bundle/\n"
)
DISTRO_CONTEXT_TEXT = {
    "copied.txt": "sps-distro-context-copy",
    "added.txt": "sps-distro-context-add",
}
DISTRO_CONTEXT_BINARY = bytes(range(16))
DISTRO_CONTEXT_MARKER = b"sps-distro-context-unpacked"
DISTRO_CONTEXT_MARKER_PATH = "/opt/sps-bundle/nested/marker.txt"
DISTRO_CONTEXT_READS = (
    "/opt/sps-copy",
    "/opt/sps-binary",
    "/opt/sps-added",
    DISTRO_CONTEXT_MARKER_PATH,
)


def _distro_context_row() -> dict[str, Any]:
    root = Path(__file__).resolve().parents[1] / "conformance"
    tests = yaml.safe_load((root / "coverage.yaml").read_text())["tests"]
    return next(t for t in tests if t["id"] == DISTRO_CONTEXT_ROW)


def _bundle_members(archive: bytes) -> dict[str, tarfile.TarInfo]:
    with tarfile.open(fileobj=io.BytesIO(archive)) as bundle:
        return {member.name: member for member in bundle.getmembers()}


def test_prepared_distro_context_row_proves_only_source_prepared_and_context() -> None:
    test = _distro_context_row()
    assert test["proves"] == [
        {"gate": "custom_images", "knob": "source", "value": "dockerfile"},
        {"gate": "custom_images", "knob": "prepared", "value": True},
        {"gate": "custom_images", "knob": "build_context", "value": True},
    ]
    prepare = next(step for step in test["steps"] if step.get("op") == "image.prepare")
    given = prepare["in"]
    assert set(given) == {"source", "dockerfile", "context"}
    assert given["dockerfile"] == DISTRO_CONTEXT_DOCKERFILE
    instructions = [line.split(None, 1)[0] for line in given["dockerfile"].strip().splitlines()]
    assert instructions == ["FROM", "COPY", "COPY", "ADD", "ADD"]
    context = given["context"]
    assert {name: context[name] for name in DISTRO_CONTEXT_TEXT} == DISTRO_CONTEXT_TEXT
    assert set(context) == {*DISTRO_CONTEXT_TEXT, "binary.bin", "bundle.bin"}
    binary = base64.b64decode(context["binary.bin"]["base64"], validate=True)
    assert binary == DISTRO_CONTEXT_BINARY
    archive = base64.b64decode(context["bundle.bin"]["base64"], validate=True)
    assert archive[:2] == b"\x1f\x8b"
    members = _bundle_members(gzip.decompress(archive))
    assert set(members) == {"nested", "nested/marker.txt"}
    for member in members.values():
        assert (member.uid, member.gid, member.uname, member.gname) == (0, 0, "root", "root")
        assert member.mtime == 1767225600
    with tarfile.open(fileobj=io.BytesIO(gzip.decompress(archive))) as bundle:
        extracted = bundle.extractfile("nested/marker.txt")
        assert extracted is not None
        assert extracted.read() == DISTRO_CONTEXT_MARKER
    create = next(step for step in test["steps"] if step.get("op") == "create")
    assert create["in"]["requirements"] == {
        "custom_images": {"source": "dockerfile", "prepared": True, "build_context": True}
    }
    assert create["in"]["lifetime_seconds"] <= 300
    reads = [step for step in test["steps"] if step.get("op") == "files.read_bytes"]
    assert [read["in"]["path"] for read in reads] == list(DISTRO_CONTEXT_READS)
    assert reads[-1]["expect"]["equals"]["data"] == {"utf8": DISTRO_CONTEXT_MARKER.decode()}


class DistroContextDriver(Driver):
    """A faithful fake: applies the shipped Dockerfile to its context, no provider."""

    def __init__(self, tamper: str | None = None, drop: str | None = None) -> None:
        super().__init__()
        self.tamper = tamper
        self.drop = drop
        self.calls: list[str] = []
        self.prepare_inputs: dict[str, object] = {}
        self.create_inputs: dict[str, object] = {}
        self.read_inputs: list[dict[str, object]] = []
        self.prepared: dict[str, object] = {}
        self.files: dict[str, bytes] = {}

    def image_prepare(self, target: object, inputs: Inputs) -> Observation:
        del target
        self.calls.append("image.prepare")
        self.prepare_inputs = dict(inputs)
        context: dict[str, bytes] = {}
        given = cast(Mapping[str, object], inputs["context"])
        for name, content in given.items():
            if isinstance(content, Mapping) and set(content) == {"base64"}:
                context[name] = base64.b64decode(str(content["base64"]), validate=True)
            else:
                context[name] = str(content).encode()
        for line in str(inputs["dockerfile"]).strip().splitlines():
            parts = line.strip().split(None, 2)
            if len(parts) != 3 or parts[0] not in {"COPY", "ADD"}:
                continue
            source, destination = parts[1], parts[2]
            data = b"unexpected" if source == self.tamper else context[source]
            if parts[0] == "ADD" and data[:2] == b"\x1f\x8b":
                data = gzip.decompress(data)
            if parts[0] == "ADD" and destination.endswith("/"):
                try:
                    with tarfile.open(fileobj=io.BytesIO(data)) as bundle:
                        for member in bundle.getmembers():
                            if member.isfile():
                                extracted = bundle.extractfile(member)
                                assert extracted is not None
                                self.files[destination + member.name] = extracted.read()
                        continue
                except tarfile.TarError:
                    pass
            self.files[destination] = data
        if self.drop is not None:
            self.files.pop(self.drop, None)
        self.prepared = {
            "resource": self.own("image", object(), lambda: {"result": "deleted"}),
            "key": "0" * 64,
            "identity": "boxrouter-img-offline",
            "resources": {},
        }
        return self.prepared

    def create(self, target: object, inputs: Inputs) -> Observation:
        del target
        self.calls.append("create")
        self.create_inputs = dict(inputs)
        box = {"identity": "box"}
        self.own("sandbox", box, lambda: {"result": "deleted"})
        return box

    def files_read_bytes(self, target: object, inputs: Inputs) -> Observation:
        del target
        self.calls.append("files.read_bytes")
        self.read_inputs.append(dict(inputs))
        path = str(inputs["path"])
        if path not in self.files:
            raise NativeFailure("files_read_failed")
        return {"data": self.files[path]}


def _distro_context_scenario() -> Scenario:
    suite = read_suite(suite_path().with_name("coverage.yaml"))
    return next(test for test in suite.tests if test.id == DISTRO_CONTEXT_ROW)


def test_prepared_distro_context_row_dispatches_prepare_create_and_reads() -> None:
    driver = DistroContextDriver()
    outcome = Runner(driver).run_test(_distro_context_scenario())
    assert outcome["result"] == "passed"
    assert driver.calls == ["image.prepare", "create"] + ["files.read_bytes"] * len(
        DISTRO_CONTEXT_READS
    )
    assert driver.prepare_inputs == {
        "source": "dockerfile",
        "dockerfile": DISTRO_CONTEXT_DOCKERFILE,
        "context": _distro_context_row()["steps"][0]["in"]["context"],
    }
    assert driver.create_inputs["image"] is driver.prepared
    assert driver.create_inputs["requirements"] == {
        "custom_images": {"source": "dockerfile", "prepared": True, "build_context": True}
    }
    assert driver.create_inputs["lifetime_seconds"] == 300
    assert [read["path"] for read in driver.read_inputs] == list(DISTRO_CONTEXT_READS)
    cleanup = cast(list[dict[str, object]], outcome["cleanup"])
    assert {item["kind"] for item in cleanup} == {"image", "sandbox"}


@pytest.mark.parametrize(
    ("tamper", "result"),
    [
        ("copied.txt", "differs"),
        ("binary.bin", "differs"),
        ("added.txt", "differs"),
        ("bundle.bin", "error"),
    ],
)
def test_prepared_distro_context_row_fails_on_bad_or_missing_bytes(
    tamper: str, result: str
) -> None:
    outcome = Runner(DistroContextDriver(tamper)).run_test(_distro_context_scenario())
    assert outcome["result"] == result


@pytest.mark.parametrize("drop", ["/opt/sps-added", DISTRO_CONTEXT_MARKER_PATH])
def test_prepared_distro_context_row_fails_on_a_dropped_file(drop: str) -> None:
    driver = DistroContextDriver(drop=drop)
    outcome = Runner(driver).run_test(_distro_context_scenario())
    assert outcome["result"] == "error"


def test_preserved_coverage_suite_entry_is_only_the_prior_suite() -> None:
    history = json.loads(
        (suite_path().parent / "historical-suite-rules.json").read_text(encoding="utf-8")
    )
    preserved = history["sha256:d229e95a248ef8035340670f82bbeb53a55f4d557050a28c5cbc58decaadf295"]
    suite = read_suite(suite_path().with_name("coverage.yaml"))
    live = {test.id: list(test.rules) for test in suite.tests}
    assert set(live) - set(preserved) == {DISTRO_ROW, DISTRO_CONTEXT_ROW}
    for identifier in set(live) & set(preserved):
        assert preserved[identifier] == live[identifier], identifier
