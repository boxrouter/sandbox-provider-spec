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
import itertools
import json
import os
from collections.abc import AsyncIterable, AsyncIterator, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar, TypeVar

import jsonschema
import pytest

from sandbox_provider_spec.cli import main
from sandbox_provider_spec.driver import NativeFailure, Unsupported, resource
from sandbox_provider_spec.v1 import (
    Cost,
    CreateRequest,
    CredentialField,
    DestroyResult,
    Discovery,
    FileInfo,
    FileStream,
    OutputChunk,
    OutputPage,
    Process,
    ProcessStartRequest,
    Provider,
    RunRequest,
    RunResult,
    Sandbox,
    SandboxPage,
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
        await self.get(sandbox_id)
        return dataclasses.replace(example(Cost), sandbox_id=sandbox_id, as_of=datetime.now(UTC))


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
    assert QUICK_SKIPS == {"contract.files_1gib_roundtrip", "contract.cost_final"}


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
)  # every contract test but the 1 GiB transfer, which a live run covers


def results(provider: Provider, tests: tuple[str, ...] = CONTRACT_TESTS) -> dict[str, str]:
    report = run_tests(provider, TestOptions(tests=tests))
    return {str(row["id"]): str(row["result"]) for row in report["tests"]}


def test_there_are_ten_contract_tests_and_the_tester_selects_each_by_default() -> None:
    suite = shared_suite()
    ids = {test.id for test in suite.tests if test.id.startswith("contract.")}
    assert ids == {*CONTRACT_TESTS, "contract.files_1gib_roundtrip"}
    chosen = {test.id for test in select_tests(suite, None, TestOptions()).tests}
    assert ids <= chosen
    quick = {test.id for test in select_tests(suite, None, TestOptions(quick=True)).tests}
    assert ids - quick == QUICK_SKIPS


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

    monkeypatch.setattr("sandbox_provider_spec.v1.suite_driver._COST_WAIT_MS", 1)
    found = results(Costly(), ("contract.cost_final",))
    assert found == {"contract.cost_final": "not_run" if "status" in change else "differs"}
