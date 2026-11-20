# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The tester: the Driver over a `Provider`, test selection, the report and the `test` command.

These tests run the shared suite's own baseline tests against a provider that executes commands
in a local subprocess, so they need no Docker and no network.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import fcntl
import itertools
import json
import os
import shutil
import stat
from collections.abc import AsyncIterable, AsyncIterator, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, ClassVar, TypeVar

import jsonschema
import pytest

from sandbox_provider_spec import cost_checks
from sandbox_provider_spec.cli import main
from sandbox_provider_spec.driver import NativeFailure, NotRun, Unsupported, resource
from sandbox_provider_spec.v1 import (
    Cost,
    CreateRequest,
    CredentialField,
    DestroyResult,
    DirectoryEntry,
    DirectoryPage,
    Discovery,
    FileInfo,
    FileStream,
    OutputChunk,
    OutputPage,
    PathInfo,
    Process,
    ProcessStartRequest,
    Provider,
    RunRequest,
    RunResult,
    Sandbox,
    SandboxPage,
    Snapshot,
    SnapshotDeleteResult,
    SnapshotPage,
    SnapshotRequest,
    SpsError,
    from_json,
)
from sandbox_provider_spec.v1 import tester as tester_module
from sandbox_provider_spec.v1.suite_driver import RUN_LABEL, ProviderDriver
from sandbox_provider_spec.v1.tester import (
    QUICK_SKIPS,
    Report,
    TestOptions,
    claimed_gates,
    run_tests,
    select_tests,
    shared_suite,
    unsupported_operations,
)

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "spec" / "provider-api-1.0-examples"
T = TypeVar("T")
MIB = 1024 * 1024

# Baseline tests that need only commands: no files outside the test's own directory, no network.
COMMAND_TESTS = (
    "baseline.create_env",
    "baseline.get",
    "baseline.list",
    "baseline.destroy",
    "baseline.run_output",
    "baseline.run_exit_code",
    "baseline.run_separate_streams",
    "baseline.run_env",
)


def example(cls: type[T]) -> T:
    return from_json(cls, json.loads((EXAMPLES / f"{cls.__name__}.json").read_text("utf-8")))


class LocalProvider(Provider, manifest=False):
    """Runs each command as a local subprocess. A sandbox is only a record."""

    provider_id = "local"
    name = "Local"
    spec_version = "1.0"
    credential_fields: ClassVar[tuple[CredentialField, ...]] = (CredentialField("api_key"),)

    def __init__(self, credentials: Mapping[str, str] | None = None) -> None:
        super().__init__(credentials or {"api_key": "k"})
        self.boxes: dict[str, Sandbox] = {}
        self.counter = itertools.count(1)
        self.created_labels: list[Mapping[str, str]] = []
        self.environment: dict[str, str] = {}
        self.processes: dict[str, Any] = {}
        self.closed = False

    async def aclose(self) -> None:
        self.closed = True

    async def discovery(self) -> Discovery:
        return example(Discovery)

    async def create(self, request: CreateRequest, *, idempotency_key: str) -> Sandbox:
        self.created_labels.append(dict(request.labels))
        box = dataclasses.replace(
            example(Sandbox),
            id=f"box-{next(self.counter)}",
            state="running",
            labels=dict(request.labels),
        )
        self.boxes[box.id] = box
        self.environment = dict(request.env)
        return box

    async def get(self, sandbox_id: str) -> Sandbox:
        if sandbox_id not in self.boxes:
            raise SpsError("not_found", "no such sandbox")
        return self.boxes[sandbox_id]

    async def list(
        self,
        *,
        labels: Mapping[str, str] | None = None,
        cursor: str | None = None,
        limit: int = 100,
    ) -> SandboxPage:
        found = [
            box
            for box in self.boxes.values()
            if box.state == "running"
            and all(box.labels.get(key) == value for key, value in (labels or {}).items())
        ]
        return SandboxPage(sandboxes=found, next_cursor=None)

    async def destroy(self, sandbox_id: str) -> DestroyResult:
        box = await self.get(sandbox_id)
        self.boxes[sandbox_id] = dataclasses.replace(box, state="destroyed")
        return DestroyResult(sandbox_id=sandbox_id, state="destroyed")

    async def run(self, sandbox_id: str, request: RunRequest) -> RunResult:
        await self.get(sandbox_id)
        process = await asyncio.create_subprocess_exec(
            *request.argv,
            cwd=request.cwd,
            env={**os.environ, **self.environment, **request.env},
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, err = await process.communicate()
        return RunResult(exit_code=process.returncode, stdout=out.decode(), stderr=err.decode())

    async def files_read(self, sandbox_id: str, path: str) -> FileStream:
        await self.get(sandbox_id)
        try:
            data = Path(path).read_bytes()
        except FileNotFoundError:
            raise SpsError("not_found", "no such file") from None

        async def chunks() -> AsyncIterator[bytes]:
            for start in range(0, len(data), MIB):
                yield data[start : start + MIB]

        return FileStream(size=len(data), chunks=chunks())

    async def files_write(
        self, sandbox_id: str, path: str, data: AsyncIterable[bytes], *, size: int
    ) -> FileInfo:
        await self.get(sandbox_id)
        written = 0
        with Path(path).open("wb") as handle:
            async for chunk in data:
                written += handle.write(chunk)
        return FileInfo(path=path, size=written)

    async def process_start(self, sandbox_id: str, request: ProcessStartRequest) -> Process:
        await self.get(sandbox_id)
        process = await asyncio.create_subprocess_exec(
            *request.argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        process_id = f"proc-{next(self.counter)}"
        self.processes[process_id] = process
        return Process(id=process_id, sandbox_id=sandbox_id, started_at=datetime.now(UTC))

    async def process_output(
        self, sandbox_id: str, process_id: str, *, cursor: str | None = None, wait_ms: int = 0
    ) -> OutputPage:
        """Output arrives once, when the process has exited; a later read finds it empty."""
        process = self.processes[process_id]
        try:
            out, err = await asyncio.wait_for(process.communicate(), max(wait_ms, 1) / 1000)
        except TimeoutError:
            return OutputPage([], "c", False, False, False, "running", None)
        chunks = [OutputChunk("stdout", out.decode()), OutputChunk("stderr", err.decode())]
        return OutputPage(
            [chunk for chunk in chunks if chunk.data],
            "c",
            False,
            True,
            True,
            "exited",
            process.returncode,
        )

    async def cost(self, sandbox_id: str) -> Cost:
        box = await self.get(sandbox_id)
        return dataclasses.replace(
            example(Cost),
            sandbox_id=sandbox_id,
            status="final" if box.state == "destroyed" else "accruing",
            as_of=datetime.now(UTC),
        )


class SnapshotProvider(LocalProvider, manifest=False):
    """Keeps snapshots as records; a restore is a create that names one."""

    def __init__(self) -> None:
        super().__init__()
        self.snapshots: dict[str, Snapshot] = {}
        self.deleted: set[str] = set()
        self.keys: dict[str, str] = {}
        self.restored_from: list[str | None] = []
        self.states: list[str] = ["saving", "ready"]
        self.expires_at: datetime | None = None

    async def create(self, request: CreateRequest, *, idempotency_key: str) -> Sandbox:
        if request.snapshot is not None and request.snapshot not in self.snapshots:
            raise SpsError("not_found", "no such snapshot")
        self.restored_from.append(request.snapshot)
        return await super().create(request, idempotency_key=idempotency_key)

    async def snapshot_create(
        self, sandbox_id: str, request: SnapshotRequest, *, idempotency_key: str
    ) -> Snapshot:
        box = await self.get(sandbox_id)
        if idempotency_key in self.keys:
            return self.snapshots[self.keys[idempotency_key]]
        snapshot = dataclasses.replace(
            example(Snapshot),
            id=f"snap-{next(self.counter)}",
            sandbox_id=sandbox_id,
            sandbox_class=box.sandbox_class,
            state="saving",
            labels=dict(request.labels),
            expires_at=self.expires_at,
        )
        self.snapshots[snapshot.id] = snapshot
        self.keys[idempotency_key] = snapshot.id
        return snapshot

    async def snapshot_get(self, snapshot_id: str) -> Snapshot:
        if snapshot_id not in self.snapshots:
            raise SpsError("not_found", "no such snapshot")
        snapshot = self.snapshots[snapshot_id]
        if self.states:
            snapshot = dataclasses.replace(snapshot, state=self.states.pop(0))  # type: ignore[arg-type]
        return snapshot

    async def snapshot_list(
        self,
        *,
        labels: Mapping[str, str] | None = None,
        sandbox_id: str | None = None,
        cursor: str | None = None,
        limit: int = 100,
    ) -> SnapshotPage:
        found = [
            item
            for item in self.snapshots.values()
            if item.id not in self.deleted
            and (sandbox_id is None or item.sandbox_id == sandbox_id)
            and all(item.labels.get(key) == value for key, value in (labels or {}).items())
        ]
        return SnapshotPage(snapshots=found, next_cursor=None)

    async def snapshot_delete(self, snapshot_id: str) -> SnapshotDeleteResult:
        if snapshot_id not in self.snapshots:
            raise SpsError("not_found", "no such snapshot")
        self.deleted.add(snapshot_id)
        return SnapshotDeleteResult(snapshot_id, "deleted")

    async def snapshot_cost(self, snapshot_id: str) -> Cost:
        snapshot = await self.snapshot_get(snapshot_id)
        return dataclasses.replace(
            example(Cost),
            sandbox_id=snapshot.sandbox_id,
            snapshot_id=snapshot_id,
            lines=[],
            as_of=datetime.now(UTC),
        )


@pytest.fixture(name="snapshot_driver")
def snapshot_driver_fixture() -> Any:
    driver = ProviderDriver(SnapshotProvider(), run="run-1")
    yield driver
    driver.close()


def test_snapshot_take_waits_for_ready_and_labels_the_snapshot(
    snapshot_driver: ProviderDriver,
) -> None:
    box = snapshot_driver.call("create", None, {})
    snap = snapshot_driver.call("snapshot.take", box, {"keeps": "files_only"})
    provider: Any = snapshot_driver.api
    assert provider.states == []  # it read the snapshot until it was ready
    stored = provider.snapshots[str(snap["identity"])]
    assert dict(stored.labels) == {RUN_LABEL: "run-1"}
    info = snapshot_driver.call("snapshot.get", snap, {})
    assert (info["labels"], info["sandbox_id"]) == ({}, box["identity"])


def test_snapshot_take_of_a_failed_snapshot_is_a_failure_and_is_cleaned_up(
    snapshot_driver: ProviderDriver,
) -> None:
    provider: Any = snapshot_driver.api
    provider.states = ["failed"]
    box = snapshot_driver.call("create", None, {})
    with pytest.raises(NativeFailure) as failure:
        snapshot_driver.call("snapshot.take", box, {})
    assert failure.value.code == "snapshot_failed"
    assert provider.deleted == set()
    snapshot_driver.sweep_run()
    assert len(provider.deleted) == 1


def test_snapshot_restore_creates_from_the_snapshot_in_its_class(
    snapshot_driver: ProviderDriver,
) -> None:
    box = snapshot_driver.call("create", None, {})
    snap = snapshot_driver.call("snapshot.take", box, {})
    again = snapshot_driver.call("snapshot.restore", snap, {"labels": {"k": "v"}})
    provider: Any = snapshot_driver.api
    assert provider.restored_from == [None, snap["identity"]]
    assert snapshot_driver.call("get", again, {"size": True})["size"] == {
        "cpu": 2,
        "memory_mib": 2048,
        "disk_mib": 20480,
    }
    assert snapshot_driver.call("get", again, {})["labels"] == {"k": "v"}
    for progress in ("snapshot.restore_begin", "snapshot.restore_wait"):
        with pytest.raises(NotRun, match="no progress handle"):
            snapshot_driver.call(progress, snap, {})
    snapshot_driver.release(resource(again))


def test_snapshot_delete_twice_and_unknown_ids(snapshot_driver: ProviderDriver) -> None:
    box = snapshot_driver.call("create", None, {})
    snap = snapshot_driver.call("snapshot.take", box, {})
    assert snapshot_driver.call("snapshot.delete", snap, {})["result"] == "deleted"
    assert snapshot_driver.call("snapshot.delete_again", snap, {}) == {
        "native_delete_attempted": True,
        "state": "deleted",
    }
    with pytest.raises(NativeFailure) as failure:
        snapshot_driver.call("snapshot.get", None, {"unknown": True})
    assert failure.value.code == "not_found"


def test_snapshot_create_keyed_owns_one_snapshot_however_often_a_key_returns_it(
    snapshot_driver: ProviderDriver,
) -> None:
    box = snapshot_driver.call("create", None, {})
    first = snapshot_driver.call("snapshot.create_keyed", box, {"idempotency_key": "k1"})
    second = snapshot_driver.call("snapshot.create_keyed", box, {"idempotency_key": "k1"})
    assert first == second
    other = snapshot_driver.call("snapshot.create_keyed", box, {"idempotency_key": "k2"})
    assert other != first
    assert len([r for r in snapshot_driver.resources if r.kind == "snapshot"]) == 2
    listed = snapshot_driver.call("snapshot.list", None, {"sandbox_id": box["identity"]})
    assert listed["count"] == 2


def test_snapshot_retention_is_not_run_without_an_expiry(snapshot_driver: ProviderDriver) -> None:
    provider: Any = snapshot_driver.api
    box = snapshot_driver.call("create", None, {})
    snap = snapshot_driver.call("snapshot.take", box, {})
    with pytest.raises(NotRun):
        snapshot_driver.call("snapshot.retention", snap, {})
    provider.snapshots[str(snap["identity"])] = dataclasses.replace(
        provider.snapshots[str(snap["identity"])],
        expires_at=provider.snapshots[str(snap["identity"])].created_at + timedelta(days=7),
    )
    assert snapshot_driver.call("snapshot.retention", snap, {}) == {"retention_seconds": 604800}


def test_snapshot_cost_checks_identities_and_items(snapshot_driver: ProviderDriver) -> None:
    box = snapshot_driver.call("create", None, {})
    snap = snapshot_driver.call("snapshot.take", box, {})
    assert snapshot_driver.call("snapshot.cost", snap, {}) == {
        "status": "final",
        "snapshot_matches": True,
        "sandbox_matches": True,
        "only_snapshot_lines": True,
    }


def test_the_sweep_deletes_the_runs_snapshots_and_a_provider_without_them_has_none(
    snapshot_driver: ProviderDriver, driver: ProviderDriver
) -> None:
    box = snapshot_driver.call("create", None, {})
    snapshot_driver.call("snapshot.take", box, {})
    results = snapshot_driver.sweep_run()
    assert {row["kind"] for row in results} == {"sandbox", "snapshot"}
    assert snapshot_driver.snapshot_leftovers() == []
    assert driver.snapshot_leftovers() == []  # LocalProvider has no snapshots: nothing to sweep


def test_every_snapshot_operation_needs_the_snapshots_gate() -> None:
    missing = unsupported_operations(example(Discovery))
    wanted = {
        "snapshot.create",
        "snapshot.get",
        "snapshot.list",
        "snapshot.delete",
        "snapshot.cost",
    }
    assert wanted <= set(missing)
    claimed = unsupported_operations(with_gates({"snapshots": {"keeps": "files_only"}}))
    assert not wanted & set(claimed)


def test_an_explicit_selection_still_drops_the_tests_of_a_knob_value_not_claimed() -> None:
    claimed = with_gates(
        {
            "snapshots": {
                "keeps": "files_only",
                "original_after": "briefly_paused",
                "deletable": True,
            }
        }
    )
    chosen = {
        test.id
        for test in select_tests(
            shared_suite(), claimed, TestOptions(tests=["snapshots."], quick=True)
        ).tests
    }
    assert "snapshots.keeps.files_only" in chosen
    assert "snapshots.original_after.briefly_paused" in chosen
    assert "snapshots.keeps.files_and_memory" not in chosen
    assert "snapshots.original_after.terminated" not in chosen
    assert "snapshots.deletable.false" not in chosen
    assert {test_id for test_id in chosen if test_id.startswith("snapshots.v1.")} == {
        "snapshots.v1.outlives_source",
        "snapshots.v1.completed_writes",
        "snapshots.v1.get_and_list",
        "snapshots.v1.idempotent_create",
        "snapshots.v1.restore_rules",
        "snapshots.v1.deleted_not_found",
    }  # `snapshots.v1.cost` waits for a final cost, which --quick leaves out


@pytest.fixture(name="driver")
def driver_fixture() -> Any:
    driver = ProviderDriver(LocalProvider(), run="run-1")
    yield driver
    driver.close()


def with_gates(
    gates: Mapping[str, object], resources: Mapping[str, object] | None = None
) -> Discovery:
    discovery = example(Discovery)
    first = dataclasses.replace(
        discovery.classes[0],
        gates=dict(gates),
        resources={**discovery.classes[0].resources, **(resources or {})},
        operations=(),
    )
    return dataclasses.replace(discovery, classes=[first, *discovery.classes[1:]])


def test_driver_creates_labelled_sandboxes_and_destroys_them(driver: ProviderDriver) -> None:
    made = driver.call("create", None, {"environment": {"A": "b"}})
    assert driver.api.created_labels == [{RUN_LABEL: "run-1"}]  # type: ignore[attr-defined]
    assert driver.call("get", made, {}) == {"state": "active", "labels": {}}
    assert driver.call("list", None, {}) == {
        "sandboxes": [{"identity": made["identity"]}],
        "count": 1,
    }
    driver.call("destroy", made, {})
    assert driver.call("get", made, {})["state"] == "destroyed"
    assert driver.leftovers() == []
    driver.release(resource(made))  # already released: nothing is destroyed twice


def test_driver_runs_a_bash_script_as_argv(driver: ProviderDriver) -> None:
    made = driver.call("create", None, {})
    result = driver.call("run", made, {"bash_script": "printf out; printf err >&2; exit 3"})
    assert result == {"stdout": b"out", "stderr": b"err", "exit_code": 3, "timed_out": False}


def test_driver_maps_unsupported_and_other_errors(driver: ProviderDriver) -> None:
    made = driver.call("create", None, {})
    with pytest.raises(Unsupported):
        driver.call("pause", made, {})
    with pytest.raises(Unsupported):
        driver.call("create", None, {"volumes": []})
    with pytest.raises(NativeFailure) as failure:
        driver.call("files.read_bytes", {"resource": made["resource"]}, {"path": "/nonexistent/x"})
    assert failure.value.code != "unsupported"  # a plain error is not an absence
    driver.call("destroy", made, {})
    assert driver.call("get", made, {})["state"] == "destroyed"


def test_driver_reports_an_sps_error_code(driver: ProviderDriver) -> None:
    async def refuse(*args: Any, **kwargs: Any) -> Any:
        raise SpsError("quota_exceeded", "account is full")

    driver.api.create = refuse  # type: ignore[method-assign]
    with pytest.raises(NativeFailure) as failure:
        driver.call("create", None, {})
    assert failure.value.code == "quota_exceeded"
    assert "account is full" not in str(failure.value)


def test_driver_streams_files_in_both_directions(driver: ProviderDriver, tmp_path: Path) -> None:
    made = driver.call("create", None, {})
    path = str(tmp_path / "big")
    chunks = (bytes([index]) * MIB for index in range(3))
    written = driver.call(
        "files.write_stream", made, {"path": path, "size": 3 * MIB, "chunks": chunks}
    )
    assert written == {"written_bytes": 3 * MIB}
    received = driver.call("files.read_stream", made, {"path": path})
    sizes = [len(chunk) for chunk in received["chunks"]]  # type: ignore[attr-defined]
    assert sum(sizes) == 3 * MIB
    assert max(sizes) <= MIB
    assert driver.call("files.exists", made, {"path": path}) == {"exists": True}
    assert driver.call("files.exists", made, {"path": path + "-no"}) == {"exists": False}


def test_driver_runs_a_background_process_to_its_exit(driver: ProviderDriver) -> None:
    made = driver.call("create", None, {})
    started = driver.call("process.start", made, {"bash_script": "printf hi; exit 5"})
    assert driver.call("process.wait", started, {"timeout_ms": 10000}) == {"exit_code": 5}
    assert driver.call("process.status", started, {}) == {"state": "exited", "exit_code": 5}
    assert driver.call("process.output", started, {}) == {"stdout": b"hi", "stderr": b""}
    with pytest.raises(Unsupported):  # SPS 1.0 has no reattach
        driver.call("process.reattach", started, {})


def test_unsupported_operations_follow_the_claims() -> None:
    assert set(unsupported_operations(with_gates({}))) >= {
        "files.link",
        "pause",
        "resume",
        "preview.link",
        "tcp.link",
        "lifetime.extend",
        "process.write_stdin",
        "process.cancel",
    }
    claimed = unsupported_operations(
        with_gates(
            {
                "pause_resume": [{"keeps": "files_only"}],
                "processes": [{"input": True, "cancel": False}],
                "file_links": [{"operations": ["read"]}],
            },
            {"extendable_lifetime": True},
        )
    )
    assert "pause" not in claimed
    assert "files.link" not in claimed
    assert "lifetime.extend" not in claimed
    assert "process.write_stdin" not in claimed
    assert "process.close_stdin" not in claimed
    assert "process.cancel" in claimed
    assert "preview.link" in claimed


def test_selection_is_the_baseline_plus_claimed_sections() -> None:
    suite = shared_suite()
    plain = {test.id for test in select_tests(suite, with_gates({}), TestOptions()).tests}
    assert plain
    assert all(test_id.startswith(("baseline.", "contract.")) for test_id in plain)
    assert "baseline.destroy" in plain

    claimed = with_gates({"processes": [{"input": True, "cancel": False}]})
    chosen = {test.id for test in select_tests(suite, claimed, TestOptions()).tests}
    assert "processes.input.true" in chosen
    assert "processes.cancel.false" in chosen
    assert "processes.input.false" not in chosen  # that variant is not the one claimed
    assert "processes.cancel.true" not in chosen
    assert not any(test_id.startswith("snapshots.") for test_id in chosen)
    assert set(claimed_gates(claimed)) == {"processes"}


def test_a_selection_names_tests_by_prefix_and_quick_skips_the_slow_ones() -> None:
    suite = shared_suite()
    one = select_tests(suite, None, TestOptions(tests=["baseline.run_"]))
    assert {test.id for test in one.tests} >= {"baseline.run_output", "baseline.run_cwd"}
    with pytest.raises(ValueError, match="no shared tests"):
        select_tests(suite, None, TestOptions(tests=["nothing."]))
    assert QUICK_SKIPS == {
        "contract.files_1gib_roundtrip",
        "contract.cost_final",
        "contract.cost_closed_lines",
        "snapshots.v1.cost",
        "terminal.v1.idle_kept",
    }


def test_run_tests_passes_reports_and_cleans_up() -> None:
    provider = LocalProvider()
    report = run_tests(provider, TestOptions(tests=COMMAND_TESTS))
    jsonschema.validate(
        json.loads(json.dumps(report)),
        json.loads((ROOT / "spec" / "report-schema.json").read_text()),
    )
    assert report.all_passed
    assert [row["result"] for row in report["tests"]] == ["passed"] * len(COMMAND_TESTS)
    assert report["provider"] == "example"  # the id that the provider's own discovery names
    assert report["clean"] is True
    assert provider.closed
    assert len({labels[RUN_LABEL] for labels in provider.created_labels}) == 1
    assert all(box.state == "destroyed" for box in provider.boxes.values())
    lines = report.lines
    assert lines[0] == "baseline.create_env passed"
    assert "operation create passed" in lines
    assert "operation cost passed" in lines
    assert "operation files.read not_run" in lines  # no selected test reads a file
    sections = [line for line in lines if line.startswith("section ")]
    assert sections  # the example discovery claims some
    assert all(line.endswith(" not_run") for line in sections)  # and no selected test covers them


def test_a_failing_test_fails_the_run() -> None:
    class Wrong(LocalProvider, manifest=False):
        async def run(self, sandbox_id: str, request: RunRequest) -> RunResult:
            return RunResult(exit_code=0, stdout="", stderr="")

    report = run_tests(Wrong(), TestOptions(tests=["baseline.run_output"]))
    assert not report.all_passed
    assert report["tests"][0]["result"] == "differs"
    assert report.lines[0] == "baseline.run_output differs"


def test_run_tests_deletes_what_a_failed_test_left_behind() -> None:
    class Stubborn(LocalProvider, manifest=False):
        """Its destroy fails once, so the runner's cleanup cannot end the first sandbox."""

        refused = False

        async def destroy(self, sandbox_id: str) -> DestroyResult:
            if not self.refused:
                type(self).refused = True
                raise SpsError("unavailable", "try again")
            return await super().destroy(sandbox_id)

    provider = Stubborn()
    run_tests(provider, TestOptions(tests=["baseline.get"]))
    assert all(box.state == "destroyed" for box in provider.boxes.values())


def fake_report(passed: bool) -> Report:
    report = Report()
    report["tests"] = []
    report.lines, report.all_passed = ["baseline.get passed"], passed
    return report


@pytest.mark.parametrize(
    ("cost_fails", "cost_status", "code"),
    [(False, "passed", 0), (True, "error", 1)],
)
def test_the_command_exit_code_includes_the_cost_probe(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    cost_fails: bool,
    cost_status: str,
    code: int,
) -> None:
    class CostFailure(LocalProvider, manifest=False):
        async def cost(self, sandbox_id: str) -> Cost:
            raise SpsError("unavailable", "cost is unavailable")

    provider_class = CostFailure if cost_fails else LocalProvider
    monkeypatch.setattr(
        "sandbox_provider_spec.cli._load_provider_class",
        lambda _provider_id, _command: provider_class,
    )
    monkeypatch.setenv("SPS_TEST_TOKEN", "test-token")
    output = tmp_path / "report.json"

    result = main(
        [
            "test",
            "local",
            "--credential",
            "api_key=SPS_TEST_TOKEN",
            "--test",
            "baseline.create_env",
            "--output",
            str(output),
        ]
    )

    assert result == code
    assert f"operation cost {cost_status}" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("passed", "extra", "code"),
    [(True, [], 0), (True, ["--quick"], 3), (False, [], 1), (False, ["--quick"], 1)],
)
def test_the_command_exit_codes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    passed: bool,
    extra: list[str],
    code: int,
) -> None:
    seen: list[TestOptions] = []

    def fake_run(provider: Provider, options: TestOptions) -> Report:
        seen.append(options)
        return fake_report(passed)

    monkeypatch.setattr(tester_module, "run_tests", fake_run)
    monkeypatch.setenv("SPS_TEST_TOKEN", "secret-token-value")
    output = tmp_path / "out" / "report.json"
    result = main(
        [
            "test",
            "http://127.0.0.1:9",
            "--credential",
            "token=SPS_TEST_TOKEN",
            "--test",
            "baseline.",
            "--output",
            str(output),
            *extra,
        ]
    )
    assert result == code
    assert json.loads(output.read_text()) == {"tests": []}
    assert seen[0].tests == ["baseline."]
    assert seen[0].reachable_url == "https://example.com"
    assert seen[0].quick == bool(extra)
    streams = capsys.readouterr()
    assert streams.out == "baseline.get passed\n"
    assert "secret-token-value" not in streams.out + streams.err


def test_the_command_refuses_bad_credentials_and_targets(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("SPS_NOT_SET", raising=False)
    assert main(["test", "http://127.0.0.1:9", "--credential", "token=SPS_NOT_SET"]) == 1
    assert "SPS_NOT_SET is not set" in capsys.readouterr().err
    assert main(["test", "http://127.0.0.1:9", "--credential", "token"]) == 1
    monkeypatch.setenv("SPS_SET", "x")
    assert main(["test", "http://127.0.0.1:9", "--credential", "key=SPS_SET"]) == 1
    assert "takes one credential" in capsys.readouterr().err
    assert main(["test", "no-such-provider", "--credential", "api_key=SPS_SET"]) == 1
    assert "no installed provider" in capsys.readouterr().err


# --- the contract tests ----------------------------------------------------------------------


class ContractProvider(LocalProvider, manifest=False):
    """A provider that keeps every promise of the contract that `contract.` tests check.

    Each flag turns one promise off, so a test can show that its `contract.` test notices.
    """

    def __init__(self, credentials: Mapping[str, str] | None = None) -> None:
        super().__init__(credentials)
        self.keys: dict[str, tuple[str, str]] = {}
        self.replay_creates = True
        self.filter_labels = True
        self.repeat_destroy = True
        self.kill_group = True

    async def create(self, request: CreateRequest, *, idempotency_key: str) -> Sandbox:
        if request.image not in (None, "base") or float(request.resources.get("cpu_min", 0)) > 4:  # type: ignore[arg-type]
            raise SpsError("unsupported", "no class meets the request")
        body = json.dumps(
            [dict(request.env), dict(request.labels), request.image, dict(request.resources)],
            sort_keys=True,
        )
        known = self.keys.get(idempotency_key)
        if known is not None and self.replay_creates:
            if known[0] != body:
                raise SpsError("conflict", "the key was used with another body")
            return self.boxes[known[1]]
        box = await super().create(request, idempotency_key=idempotency_key)
        self.keys[idempotency_key] = (body, box.id)
        return box

    async def list(
        self,
        *,
        labels: Mapping[str, str] | None = None,
        cursor: str | None = None,
        limit: int = 100,
    ) -> SandboxPage:
        kept = labels if self.filter_labels else {RUN_LABEL: (labels or {})[RUN_LABEL]}
        return await super().list(labels=kept, cursor=cursor, limit=limit)

    async def destroy(self, sandbox_id: str) -> DestroyResult:
        if not self.repeat_destroy and (await self.get(sandbox_id)).state == "destroyed":
            raise SpsError("conflict", "already destroyed")
        return await super().destroy(sandbox_id)

    async def run(self, sandbox_id: str, request: RunRequest) -> RunResult:
        await self.get(sandbox_id)
        if request.cwd is not None and not Path(request.cwd).is_dir():
            raise SpsError("not_found", "no such directory")
        process = await asyncio.create_subprocess_exec(
            *request.argv,
            cwd=request.cwd,
            env={**os.environ, **self.environment, **request.env},
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        out, err = bytearray(), bytearray()

        async def read(stream: asyncio.StreamReader | None, into: bytearray) -> None:
            while stream is not None and (chunk := await stream.read(4096)):
                into.extend(chunk)

        readers = [
            asyncio.ensure_future(read(process.stdout, out)),
            asyncio.ensure_future(read(process.stderr, err)),
        ]
        try:
            await asyncio.wait_for(process.wait(), request.timeout_ms / 1000)
            await asyncio.gather(*readers)
            timed_out = False
        except TimeoutError:
            if self.kill_group:
                os.killpg(process.pid, 9)
                await asyncio.gather(*readers)
                await process.wait()
            else:
                process.kill()  # the command's children keep running
                for reader in readers:
                    reader.cancel()
                # Python 3.11 resolves wait() only when the pipes close;
                # a left-behind child holds them.
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(process.wait(), 1)
            timed_out = True
        return RunResult(
            exit_code=None if timed_out else process.returncode,
            stdout=out.decode(),
            stderr=err.decode(),
            timed_out=timed_out,
        )


CONTRACT_TESTS = (
    "contract.discovery_valid",
    "contract.idempotent_create_same_body",
    "contract.idempotent_create_other_body",
    "contract.list_label_filter",
    "contract.not_found_codes",
    "contract.unsupported_unclaimed",
    "contract.run_timeout_ends_command",
    "contract.destroy_repeat",
    "contract.cost_final",
    "contract.cost_revision",
    "contract.cost_as_of",
    "contract.cost_closed_lines",
)  # every contract test but the 1 GiB transfer, which a live run covers


def results(provider: Provider, tests: tuple[str, ...] = CONTRACT_TESTS) -> dict[str, str]:
    report = run_tests(provider, TestOptions(tests=tests))
    return {str(row["id"]): str(row["result"]) for row in report["tests"]}


def test_there_are_fourteen_contract_tests_and_the_tester_selects_each_by_default() -> None:
    suite = shared_suite()
    ids = {test.id for test in suite.tests if test.id.startswith("contract.")}
    assert ids == {
        *CONTRACT_TESTS,
        "contract.files_1gib_roundtrip",
        "contract.files_write_missing_parent",
    }
    chosen = {test.id for test in select_tests(suite, None, TestOptions()).tests}
    assert ids <= chosen
    quick = {test.id for test in select_tests(suite, None, TestOptions(quick=True)).tests}
    assert ids - quick == {test_id for test_id in QUICK_SKIPS if test_id.startswith("contract.")}


def test_a_provider_that_keeps_the_contract_passes_every_contract_test() -> None:
    provider = ContractProvider()
    assert results(provider) == {test_id: "passed" for test_id in CONTRACT_TESTS}
    assert all(box.state == "destroyed" for box in provider.boxes.values())


@pytest.mark.parametrize(
    ("flag", "failing"),
    [
        (
            "replay_creates",
            ["contract.idempotent_create_same_body", "contract.idempotent_create_other_body"],
        ),
        ("filter_labels", ["contract.list_label_filter"]),
        ("repeat_destroy", ["contract.destroy_repeat"]),
    ],
)
def test_a_provider_that_breaks_a_promise_fails_its_contract_test(
    flag: str, failing: list[str]
) -> None:
    provider = ContractProvider()
    setattr(provider, flag, False)
    found = results(provider)
    assert sorted(test_id for test_id, result in found.items() if result != "passed") == sorted(
        failing
    )
    assert all(found[test_id] in {"differs", "error"} for test_id in failing)


def test_a_provider_that_leaves_the_commands_children_running_fails_the_timeout_test() -> None:
    provider = ContractProvider()
    provider.kill_group = False
    try:
        assert results(provider, ("contract.run_timeout_ends_command",)) == {
            "contract.run_timeout_ends_command": "differs"
        }
    finally:  # the children that the provider left behind
        child = Path("/tmp/sps-timeout-child")
        if child.is_file():
            os.system(f"kill -9 {int(child.read_text())} 2>/dev/null")  # noqa: S605


def test_a_provider_that_creates_on_an_unsupported_request_fails_its_test() -> None:
    class Eager(ContractProvider, manifest=False):
        async def create(self, request: CreateRequest, *, idempotency_key: str) -> Sandbox:
            return await LocalProvider.create(self, request, idempotency_key=idempotency_key)

    assert results(Eager(), ("contract.unsupported_unclaimed",)) == {
        "contract.unsupported_unclaimed": "differs"
    }


def test_a_provider_that_answers_not_found_with_another_code_fails_its_test() -> None:
    class Wrong(ContractProvider, manifest=False):
        async def destroy(self, sandbox_id: str) -> DestroyResult:
            try:
                return await super().destroy(sandbox_id)
            except SpsError:
                raise SpsError("conflict", "no such sandbox") from None

    found = results(Wrong(), ("contract.not_found_codes", "contract.destroy_repeat"))
    assert found["contract.not_found_codes"] == "error"
    assert found["contract.destroy_repeat"] == "error"


@pytest.mark.parametrize(
    "change",
    [
        {"status": "accruing"},  # never final inside the window
        {"total_usd": "9.99"},  # does not add up
    ],
)
def test_the_cost_test_needs_a_final_cost_that_adds_up(
    monkeypatch: pytest.MonkeyPatch, change: dict[str, str]
) -> None:
    class Costly(ContractProvider, manifest=False):
        async def cost(self, sandbox_id: str) -> Cost:
            base = await super().cost(sandbox_id)
            return dataclasses.replace(
                base,
                **{
                    key: (value if key == "status" else type(base.total_usd)(value))
                    for key, value in change.items()
                },  # type: ignore[arg-type]
            )

    monkeypatch.setattr("sandbox_provider_spec.cost_checks.final_wait_seconds", lambda *_: 0.001)
    found = results(Costly(), ("contract.cost_final",))
    assert found == {"contract.cost_final": "not_run" if "status" in change else "differs"}


def test_the_cost_final_wait_is_what_discovery_promises_plus_a_grace() -> None:
    driver = ProviderDriver(ContractProvider(), run="run-1")
    promised = example(Discovery).limits.cost_final_within_seconds
    assert cost_checks.final_wait_seconds(driver, {}) == promised + 30
    assert cost_checks.final_wait_seconds(driver, {"timeout_ms": 5000}) == 5
    assert cost_checks.poll_seconds(10) == 2 and cost_checks.poll_seconds(604800) == 30
    driver.close()


def test_revision_that_goes_down_or_is_not_a_positive_integer_differs() -> None:
    class Falling(ContractProvider, manifest=False):
        reads = 0

        async def cost(self, sandbox_id: str) -> Cost:
            base = await super().cost(sandbox_id)
            type(self).reads += 1
            return dataclasses.replace(base, revision=10 - type(self).reads)

    class Zero(ContractProvider, manifest=False):
        async def cost(self, sandbox_id: str) -> Cost:
            return dataclasses.replace(await super().cost(sandbox_id), revision=0)

    assert results(Falling(), ("contract.cost_revision",)) == {"contract.cost_revision": "differs"}
    assert results(Zero(), ("contract.cost_revision",)) == {"contract.cost_revision": "differs"}


def test_as_of_older_than_sixty_seconds_on_a_running_sandbox_differs() -> None:
    class Stale(ContractProvider, manifest=False):
        async def cost(self, sandbox_id: str) -> Cost:
            base = await super().cost(sandbox_id)
            if base.status == "final":
                return base
            return dataclasses.replace(base, as_of=datetime.now(UTC) - timedelta(seconds=61))

    assert results(Stale(), ("contract.cost_as_of",)) == {"contract.cost_as_of": "differs"}


def test_a_running_sandbox_whose_cost_is_final_differs_on_the_cost_as_of_test() -> None:
    class Early(ContractProvider, manifest=False):
        async def cost(self, sandbox_id: str) -> Cost:
            return dataclasses.replace(await super().cost(sandbox_id), status="final")

    assert results(Early(), ("contract.cost_as_of",)) == {"contract.cost_as_of": "differs"}


@pytest.mark.parametrize("change", ["end_after_as_of", "lines_change"])
def test_a_line_that_ends_after_as_of_or_changes_between_reads_differs(change: str) -> None:
    class Open(ContractProvider, manifest=False):
        reads = 0

        async def cost(self, sandbox_id: str) -> Cost:
            base = await super().cost(sandbox_id)
            if base.status != "final":
                return base
            type(self).reads += 1
            line = base.lines[0]
            if change == "end_after_as_of":
                line = dataclasses.replace(line, end=base.as_of + timedelta(seconds=5))
            elif type(self).reads > 1:
                line = dataclasses.replace(line, quantity=line.quantity + 1)
            return dataclasses.replace(base, lines=[line])

    assert results(Open(), ("contract.cost_closed_lines",)) == {
        "contract.cost_closed_lines": "differs"
    }


def test_lines_that_change_with_a_correction_are_the_same_lines_when_revision_rose() -> None:
    class Corrected(ContractProvider, manifest=False):
        reads = 0

        async def cost(self, sandbox_id: str) -> Cost:
            base = await super().cost(sandbox_id)
            if base.status != "final":
                return base
            type(self).reads += 1
            line = dataclasses.replace(
                base.lines[0], quantity=base.lines[0].quantity + type(self).reads
            )
            return dataclasses.replace(base, lines=[line], revision=type(self).reads)

    assert results(Corrected(), ("contract.cost_closed_lines",)) == {
        "contract.cost_closed_lines": "passed"
    }


# --- directory operations ---------------------------------------------------------------------

FOUR_OPERATIONS = ("files.list", "files.mkdir", "files.remove", "files.exists")


def with_operations(operations: tuple[str, ...]) -> Discovery:
    discovery = example(Discovery)
    first = dataclasses.replace(discovery.classes[0], operations=operations)
    return dataclasses.replace(discovery, classes=[first, *discovery.classes[1:]])


class DirectoryProvider(ContractProvider, manifest=False):
    """Serves the four directory operations from the local file system, as commands would."""

    def __init__(self, credentials: Mapping[str, str] | None = None) -> None:
        super().__init__(credentials)
        self.follow_links_in_exists = False
        self.unsorted = False

    async def discovery(self) -> Discovery:
        return with_operations(FOUR_OPERATIONS)

    @staticmethod
    def _kind(mode: int) -> Any:
        if stat.S_ISREG(mode):
            return "file"
        if stat.S_ISDIR(mode):
            return "directory"
        return "symlink" if stat.S_ISLNK(mode) else "other"

    async def files_write(
        self, sandbox_id: str, path: str, data: AsyncIterable[bytes], *, size: int
    ) -> FileInfo:
        if not Path(path).parent.is_dir():  # one of the two behaviors that the contract allows
            raise SpsError("not_found", "no parent directory")
        return await super().files_write(sandbox_id, path, data, size=size)

    async def files_list(
        self, sandbox_id: str, path: str, *, cursor: str | None = None, limit: int = 100
    ) -> Any:
        await self.get(sandbox_id)
        target = Path(path)
        if not target.exists():
            raise SpsError("not_found", "no such directory")
        if not target.is_dir():
            raise SpsError("invalid_request", "not a directory")
        names = sorted(item.name for item in target.iterdir())
        if self.unsorted:
            names.reverse()
        if cursor is not None:
            names = [name for name in names if name > cursor]
        page, more = names[:limit], len(names) > limit
        entries = []
        for name in page:
            info = (target / name).lstat()
            entries.append(DirectoryEntry(name, self._kind(info.st_mode), info.st_size))
        return DirectoryPage(entries, page[-1] if more else None)

    async def files_mkdir(self, sandbox_id: str, path: str, *, parents: bool = False) -> None:
        await self.get(sandbox_id)
        target = Path(path)
        for ancestor in [target, *target.parents]:
            if ancestor.is_symlink() or ancestor.exists():
                if not ancestor.is_dir():
                    raise SpsError("conflict", "an entry that is not a directory is in the way")
                break
            if ancestor == target and not parents and not target.parent.exists():
                raise SpsError("not_found", "no parent")
        if not parents and not target.parent.is_dir():
            raise SpsError("not_found", "no parent")
        target.mkdir(parents=parents, exist_ok=True)

    async def files_remove(self, sandbox_id: str, path: str, *, recursive: bool = False) -> None:
        await self.get(sandbox_id)
        if path == "/":
            raise SpsError("invalid_request", "never the root")
        target = Path(path)
        if not target.is_symlink() and not target.exists():
            raise SpsError("not_found", "no such entry")
        if target.is_dir() and not target.is_symlink():
            if any(target.iterdir()) and not recursive:
                raise SpsError("conflict", "the directory is not empty")
            shutil.rmtree(target)
        else:
            target.unlink()

    async def files_exists(self, sandbox_id: str, path: str) -> Any:
        await self.get(sandbox_id)
        target = Path(path)
        if self.follow_links_in_exists and not target.exists():
            return PathInfo(False, None)
        if not target.is_symlink() and not target.exists():
            return PathInfo(False, None)
        return PathInfo(True, self._kind(target.lstat().st_mode))


LOCAL_PATHS = tuple(
    Path("/tmp") / name
    for name in (
        "sps-d", "sps-p", "sps-m", "sps-r", "sps-e", "sps-np", "sps-list-file",
    )
)  # fmt: skip


@pytest.fixture(name="local_paths")
def local_paths_fixture() -> Any:
    """The directory tests run their commands on this machine, at fixed paths: one at a time,
    from a clean start, leaving nothing behind."""

    def clean() -> None:
        for path in LOCAL_PATHS:
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
            elif path.is_symlink() or path.exists():
                path.unlink()

    with Path("/tmp/sps-directory-tests.lock").open("w", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        clean()
        try:
            yield
        finally:
            clean()


DIRECTORY_TESTS = (
    "directories.list",
    "directories.list_paging",
    "directories.list_errors",
    "directories.mkdir",
    "directories.remove",
    "directories.exists",
    "contract.files_write_missing_parent",
)


def test_the_four_operations_are_claimed_together_and_select_the_directories_section() -> None:
    suite = shared_suite()
    claimed = {
        test.id
        for test in select_tests(suite, with_operations(FOUR_OPERATIONS), TestOptions()).tests
    }
    assert {test.id for test in suite.tests if test.id.startswith("directories.")} <= claimed
    assert "contract.files_write_missing_parent" in claimed
    bare = {test.id for test in select_tests(suite, with_operations(()), TestOptions()).tests}
    assert not any(test_id.startswith("directories.") for test_id in bare)
    assert "contract.files_write_missing_parent" in bare  # a contract test: every provider runs it
    assert (
        unsupported_operations(with_operations(FOUR_OPERATIONS)).keys().isdisjoint(FOUR_OPERATIONS)
    )
    assert set(unsupported_operations(with_operations(()))) >= set(FOUR_OPERATIONS)


@pytest.mark.usefixtures("local_paths")
def test_a_provider_that_does_the_commands_work_passes_the_directories_section() -> None:
    provider = DirectoryProvider()
    report = run_tests(
        provider, TestOptions(tests=("directories.", "contract.files_write_missing"))
    )
    assert {str(row["id"]): str(row["result"]) for row in report["tests"]} == {
        test_id: "passed" for test_id in DIRECTORY_TESTS
    }
    assert "section directories passed" in report.lines
    assert all(box.state == "destroyed" for box in provider.boxes.values())


@pytest.mark.usefixtures("local_paths")
def test_a_provider_that_does_not_claim_the_operations_has_them_unsupported() -> None:
    class Unclaimed(ContractProvider, manifest=False):
        async def discovery(self) -> Discovery:
            return with_operations(())

    report = run_tests(Unclaimed(), TestOptions(tests=("directories.",)))
    assert {row["result"] for row in report["tests"]} == {"unsupported"}
    assert not any(line.startswith("section directories") for line in report.lines)


def test_exists_runs_the_command_until_the_operation_is_claimed(driver: ProviderDriver) -> None:
    # No discovery yet: nothing is claimed, so `files.exists` is `test -e`.
    made = driver.call("create", None, {})
    assert driver.call("files.exists", made, {"path": "/tmp"}) == {"exists": True}
    with pytest.raises(Unsupported):
        driver.call("files.exists", made, {"path": "/tmp", "native": True})


@pytest.mark.usefixtures("local_paths")
@pytest.mark.parametrize(
    ("flag", "failing"),
    [
        ("follow_links_in_exists", ["directories.exists"]),
        ("unsorted", ["directories.list", "directories.list_paging"]),
    ],
)
def test_a_provider_that_breaks_a_directory_rule_fails_its_test(
    flag: str, failing: list[str]
) -> None:
    provider = DirectoryProvider()
    setattr(provider, flag, True)
    found = results(provider, ("directories.",))
    assert sorted(test_id for test_id, result in found.items() if result != "passed") == sorted(
        failing
    )


@pytest.mark.usefixtures("local_paths")
def test_a_write_under_a_missing_parent_may_create_or_refuse_but_nothing_else() -> None:
    class Refuses(DirectoryProvider, manifest=False):
        async def files_write(
            self, sandbox_id: str, path: str, data: AsyncIterable[bytes], *, size: int
        ) -> FileInfo:
            if not Path(path).parent.exists():
                raise SpsError("not_found", "no parent")
            return await super().files_write(sandbox_id, path, data, size=size)

    class Creates(DirectoryProvider, manifest=False):
        async def files_write(
            self, sandbox_id: str, path: str, data: AsyncIterable[bytes], *, size: int
        ) -> FileInfo:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            return await super().files_write(sandbox_id, path, data, size=size)

    class Half(DirectoryProvider, manifest=False):
        async def files_write(
            self, sandbox_id: str, path: str, data: AsyncIterable[bytes], *, size: int
        ) -> FileInfo:
            Path(path).parent.parent.mkdir(parents=True, exist_ok=True)
            raise SpsError("not_found", "no parent")

    test = ("contract.files_write_missing_parent",)
    for cls, expected, text in (
        (Refuses, "passed", "refused_not_found"),
        (Creates, "passed", "created_parents"),
        (Half, "differs", None),
    ):
        report = run_tests(cls(), TestOptions(tests=test))
        row = report["tests"][0]
        assert row["result"] == expected, cls.__name__
        if text is not None:
            assert text in json.dumps(row), cls.__name__
        shutil.rmtree("/tmp/sps-np", ignore_errors=True)
