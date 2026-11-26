# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""What a run can be told (`--fixture`, `--fixtures`), and three tester gaps that stopped provider
lanes from claiming sections: the prepared-image check through `sh`, `resume` returning the
sandbox, and `processes.reattach` through a fresh client."""

from __future__ import annotations

import asyncio
import dataclasses
import fcntl
import json
import re
from pathlib import Path
from typing import Any

import pytest
from test_images import ImageProvider, outcome
from test_tester import LocalProvider, example, with_gates

from sandbox_provider_spec import fixtures as fixtures_module
from sandbox_provider_spec.cli import main
from sandbox_provider_spec.driver import resource
from sandbox_provider_spec.fixtures import DERIVED, FIXTURES, FixtureError, read_fixtures
from sandbox_provider_spec.v1 import (
    CreateRequest,
    Discovery,
    OutputChunk,
    OutputPage,
    Process,
    ProcessStartRequest,
    RunRequest,
    RunResult,
    Sandbox,
)
from sandbox_provider_spec.v1.suite_driver import ProviderDriver
from sandbox_provider_spec.v1.tester import TestOptions, run_tests

ROOT = Path(__file__).resolve().parents[2]
DIGEST = "sha256:" + "a" * 64


def reasons(report: Any) -> dict[str, str]:
    return {str(row["id"]): str(row.get("reason", "")) for row in report["tests"]}


@pytest.fixture(name="images")
def images_fixture() -> Any:
    ImageProvider.reset()
    yield ImageProvider()
    ImageProvider.reset()


# --- --fixture and --fixtures ---------------------------------------------------------------


def test_a_supplied_fixture_makes_its_test_run_and_a_missing_one_stays_not_run(
    images: ImageProvider,
) -> None:
    options = TestOptions(tests=("custom_images.oci",))
    missing = run_tests(images, options)
    assert outcome(missing) == {"custom_images.oci": "not_run"}
    assert reasons(missing) == {"custom_images.oci": "fixture_missing"}

    given = {"oci_image": f"docker.io/library/alpine@{DIGEST}", "image_marker": "Alpine Linux"}
    supplied = run_tests(ImageProvider(), TestOptions(tests=("custom_images.oci",), fixtures=given))
    assert outcome(supplied) == {"custom_images.oci": "passed"}
    assert len(ImageProvider.seen) == 1  # the test reached the provider


def test_one_missing_fixture_among_those_supplied_keeps_the_test_not_run(
    images: ImageProvider,
) -> None:
    only_the_image = {"oci_image": f"docker.io/library/alpine@{DIGEST}"}
    report = run_tests(images, TestOptions(tests=("custom_images.oci",), fixtures=only_the_image))
    assert reasons(report) == {"custom_images.oci": "fixture_missing"}
    assert not ImageProvider.seen  # nothing was prepared


def test_a_value_is_json_when_it_is_json_and_text_otherwise() -> None:
    got = read_fixtures(
        ["max_mounts=3", 'allowed_domains=["a.example","b.example"]', "oci_image=alpine@x"]
    )
    assert got == {
        "max_mounts": 3,
        "allowed_domains": ["a.example", "b.example"],
        "oci_image": "alpine@x",
    }


def test_env_values_come_from_the_environment_and_are_never_printed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("SPS_TEST_PASSWORD", "hunter2")
    monkeypatch.setenv("SPS_TEST_JSON", "[1, 2]")  # an env value is text, never parsed
    path = tmp_path / "fixtures.yaml"
    path.write_text(
        "private_oci_username: robot\n"
        "private_oci_password: env:SPS_TEST_PASSWORD\n"
        "egress_proxy:\n  addresses:\n    http: env:SPS_TEST_PASSWORD\n",
        encoding="utf-8",
    )
    got = read_fixtures(["private_oci_image=env:SPS_TEST_JSON"], [str(path)])
    assert got["private_oci_password"] == "hunter2"
    assert got["egress_proxy"] == {"addresses": {"http": "hunter2"}}
    assert got["private_oci_image"] == "[1, 2]"
    monkeypatch.delenv("SPS_TEST_PASSWORD")
    with pytest.raises(FixtureError, match="SPS_TEST_PASSWORD, not set") as raised:
        read_fixtures(["private_oci_password=env:SPS_TEST_PASSWORD"])
    assert "hunter2" not in str(raised.value)


def test_a_file_is_yaml_or_json_and_a_flag_wins_over_it(tmp_path: Path) -> None:
    as_json = tmp_path / "f.json"
    as_json.write_text(json.dumps({"max_mounts": 2, "volume_kind": "bucket"}), encoding="utf-8")
    as_yaml = tmp_path / "f.yaml"
    as_yaml.write_text("max_mounts: 5\n", encoding="utf-8")
    assert read_fixtures([], [str(as_json)]) == {"max_mounts": 2, "volume_kind": "bucket"}
    assert read_fixtures(["max_mounts=9"], [str(as_json), str(as_yaml)])["max_mounts"] == 9


@pytest.mark.parametrize(
    ("pair", "message"),
    [
        ("nonsense=1", "unknown fixture 'nonsense'"),
        ("reachable_url=https://x", "use --reachable-url"),
        ("run_nonce=1", "the run generates it"),
        ("test_size_value=1", "derived from test_size"),
        ("max_mounts", "needs NAME=VALUE"),
    ],
)
def test_a_bad_flag_is_one_plain_line(pair: str, message: str) -> None:
    with pytest.raises(FixtureError, match=re.escape(message)):
        read_fixtures([pair])


def test_a_file_that_is_not_a_map_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "f.yaml"
    path.write_text("- a\n- b\n", encoding="utf-8")
    with pytest.raises(FixtureError, match="expected a map"):
        read_fixtures([], [str(path)])
    with pytest.raises(FixtureError, match="--fixtures"):
        read_fixtures([], [str(tmp_path / "absent.yaml")])


def test_the_test_command_takes_fixtures_and_lists_every_name(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit):
        main(["test", "--help"])
    shown = capsys.readouterr().out
    assert "--fixture NAME=VALUE" in shown and "--fixtures FILE" in shown
    assert all(name in shown for name in (*FIXTURES, *DERIVED))


def test_the_test_command_refuses_a_bad_fixture_before_it_connects(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["test", "http://localhost:9", "--fixture", "nonsense=1"]) == 1
    assert "unknown fixture 'nonsense'" in capsys.readouterr().err


def test_every_fixture_the_suites_name_is_documented() -> None:
    names: set[str] = set()
    for path in (ROOT / "conformance").glob("*.yaml"):
        names |= set(re.findall(r"\$runner\.([a-z_0-9]+)", path.read_text(encoding="utf-8")))
    for path in (ROOT / "src" / "sandbox_provider_spec").glob("*.py"):
        found = re.findall(r"fixtures(?:\.get\(|\[)\s*[\"']([a-z_0-9]+)", path.read_text("utf-8"))
        names |= set(found)
    names -= {"run_nonce", "sps_task_id"}  # set by the run, or a driver's own
    known = set(FIXTURES) | set(DERIVED)
    assert names <= known, sorted(names - known)
    assert set(DERIVED.values()) <= set(FIXTURES)
    assert "reachable_url" in FIXTURES and "reachable_url" in fixtures_module.RESERVED


# --- the prepared-image check runs through sh -----------------------------------------------


class RecordingImages(ImageProvider, manifest=False):
    commands: list[list[str]] = []

    async def run(self, sandbox_id: str, request: RunRequest) -> RunResult:
        type(self).commands.append(list(request.argv))
        return await super().run(sandbox_id, request)


def test_the_prepared_oci_check_runs_through_sh_and_the_other_tests_keep_bash() -> None:
    ImageProvider.reset()
    RecordingImages.commands = []
    report = run_tests(RecordingImages(), TestOptions(tests=("images.v1.prepare_oci",)))
    assert outcome(report) == {"images.v1.prepare_oci": "passed"}
    assert RecordingImages.commands == [["sh", "-c", "cat /etc/os-release"]]
    driver = ProviderDriver(LocalProvider(), run="run-1")
    try:
        box = driver.call("create", None, {})
        driver.call("run", box, {"bash_script": "true"})
    finally:
        driver.close()
    ImageProvider.reset()


class PlainOciProvider(ImageProvider, manifest=False):
    """A provider whose plain OCI image has `sh` and no `bash`, like Alpine."""

    async def run(self, sandbox_id: str, request: RunRequest) -> RunResult:
        if request.argv[0] == "bash":
            return RunResult(127, "", "timeout: can't execute bash")
        return await super().run(sandbox_id, request)


def test_a_plain_oci_image_without_bash_passes_the_prepared_image_test() -> None:
    ImageProvider.reset()
    report = run_tests(PlainOciProvider(), TestOptions(tests=("images.v1.prepare_oci",)))
    assert outcome(report) == {"images.v1.prepare_oci": "passed"}
    ImageProvider.reset()


# --- resume returns the sandbox -------------------------------------------------------------


class PausableProvider(LocalProvider, manifest=False):
    async def discovery(self) -> Discovery:
        return with_gates({"pause_resume": [{"keeps": "files_and_memory"}]})

    async def pause(self, sandbox_id: str) -> Sandbox:
        box = dataclasses.replace(await self.get(sandbox_id), state="paused")
        self.boxes[sandbox_id] = box
        return box

    async def resume(self, sandbox_id: str, *, lifetime_seconds: int | None = None) -> Sandbox:
        del lifetime_seconds
        box = dataclasses.replace(await self.get(sandbox_id), state="running")
        self.boxes[sandbox_id] = box
        return box


def test_resume_returns_the_sandbox_so_a_step_can_bind_and_use_it() -> None:
    driver = ProviderDriver(PausableProvider(), run="run-1")
    try:
        box = driver.call("create", None, {})
        driver.call("pause", box, {})
        again = driver.call("resume", box, {})
        assert again["state"] == "active"
        assert again["identity"] == box["identity"]
        assert resource(again) is resource(box)
        assert driver.call("run", again, {"bash_script": "true"})["exit_code"] == 0
    finally:
        driver.close()


def test_pause_resume_files_and_memory_binds_the_resumed_sandbox() -> None:
    # Multiple CI slots share the host's /tmp, and this suite intentionally uses fixed absolute
    # paths. Serialize same-host copies so one run cannot unlink another run's marker files.
    with Path("/tmp/sps-pause-resume-files-and-memory.lock").open("a") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        for name in ("sps-marker", "sps-pid", "sps-release", "sps-result"):
            Path("/tmp", name).unlink(missing_ok=True)
        try:
            report = run_tests(
                PausableProvider(), TestOptions(tests=("pause_resume.files_and_memory",))
            )
        finally:
            for name in ("sps-marker", "sps-pid", "sps-release", "sps-result"):
                Path("/tmp", name).unlink(missing_ok=True)
    assert outcome(report) == {"pause_resume.files_and_memory": "passed"}, report["tests"]


# --- reattach is a fresh client reading from cursor 0 ---------------------------------------


class Shared:
    """What every client of one provider shares: the process and what it printed."""

    def __init__(self) -> None:
        self.output: dict[str, str] = {}
        self.exited: set[str] = set()
        self.clients: list[ReattachProvider] = []


class ReattachProvider(LocalProvider, manifest=False):
    """Output is kept by the provider, so a client that reads from no cursor gets all of it."""

    def __init__(self, shared: Shared | None = None) -> None:
        super().__init__()
        self.shared = shared or Shared()
        self.shared.clients.append(self)
        self.processes = {}

    async def discovery(self) -> Discovery:
        return with_gates({"processes": [{"reattach": True}]})

    async def create(self, request: CreateRequest, *, idempotency_key: str) -> Sandbox:
        box = await super().create(request, idempotency_key=idempotency_key)
        return box

    async def get(self, sandbox_id: str) -> Sandbox:
        return example(Sandbox) if sandbox_id.startswith("box-") else await super().get(sandbox_id)

    async def process_start(self, sandbox_id: str, request: ProcessStartRequest) -> Process:
        process = await super().process_start(sandbox_id, request)
        asyncio.get_running_loop().create_task(self._collect(process.id))
        return process

    async def _collect(self, process_id: str) -> None:
        process = self.processes[process_id]
        out, _ = await process.communicate()
        self.shared.output[process_id] = out.decode()
        self.shared.exited.add(process_id)

    async def process_output(
        self, sandbox_id: str, process_id: str, *, cursor: str | None = None, wait_ms: int = 0
    ) -> OutputPage:
        await asyncio.sleep(min(wait_ms, 300) / 1000)
        done = process_id in self.shared.exited
        text = self.shared.output.get(process_id, "") if cursor != "c" else ""
        chunks = [OutputChunk("stdout", text)] if text else []
        cursor_after = "c" if text else "0"  # a read from "0" or no cursor starts at the start
        return OutputPage(
            chunks,
            cursor_after,
            False,
            done,
            done,
            "exited" if done else "running",
            0 if done else None,
        )


def test_reattach_reads_the_existing_process_through_a_new_client_from_the_start() -> None:
    shared = Shared()
    provider = ReattachProvider(shared)
    driver = ProviderDriver(provider, run="run-1", new_client=lambda: ReattachProvider(shared))
    try:
        box = driver.call("create", None, {})
        started = driver.call("process.start", box, {"bash_script": "printf one; sleep 0.3"})
        first = driver.call("process.output", started, {})
        assert first["stdout"] == b"one"
        driver.call("process.disconnect", started, {})
        again = driver.call("process.reattach", box, {"identity": started["identity"]})
        assert again["identity"] == started["identity"]
        assert driver.call("process.output", again, {})["stdout"] == b"one"  # from cursor 0
        assert len(shared.clients) == 2 and shared.clients[1] is not provider
    finally:
        driver.close()
    assert shared.clients[1].closed  # the fresh client is closed with the run


def test_reattach_without_a_way_to_make_a_client_reads_through_the_same_one() -> None:
    shared = Shared()
    driver = ProviderDriver(ReattachProvider(shared), run="run-1")
    try:
        box = driver.call("create", None, {})
        started = driver.call("process.start", box, {"bash_script": "printf one"})
        driver.call("process.output", started, {})
        again = driver.call("process.reattach", box, {"identity": started["identity"]})
        assert driver.call("process.output", again, {})["stdout"] == b"one"
        assert len(shared.clients) == 1
    finally:
        driver.close()


def test_the_reattach_test_passes_through_the_tester() -> None:
    for name in ("sps-reattach-release",):
        Path("/tmp", name).unlink(missing_ok=True)
    shared = Shared()
    try:
        report = run_tests(
            ReattachProvider(shared),
            TestOptions(
                tests=("processes.reattach.true",), new_client=lambda: ReattachProvider(shared)
            ),
        )
    finally:
        Path("/tmp/sps-reattach-release").unlink(missing_ok=True)
    assert outcome(report) == {"processes.reattach.true": "passed"}, report["tests"]
    assert len(shared.clients) == 2


def test_disconnect_needs_a_process() -> None:
    driver = ProviderDriver(LocalProvider(), run="run-1")
    try:
        box = driver.call("create", None, {})
        with pytest.raises(ValueError, match="requires a process"):
            driver.call("process.disconnect", box, {})
    finally:
        driver.close()


def test_the_conformance_page_lists_every_fixture_with_the_same_sentence() -> None:
    page = (ROOT / "spec" / "conformance.md").read_text(encoding="utf-8")
    for name, what in FIXTURES.items():
        assert f"| `{name}` | {what} |" in page, name
    for name, source in DERIVED.items():
        assert f"| `{name}` | `{source}` |" in page, name
