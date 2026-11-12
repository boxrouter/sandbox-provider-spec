# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Per-check digests are deterministic, isolated per test and bound to shared execution."""

from __future__ import annotations

import ast
import json
import os
import re
import time
from dataclasses import replace
from importlib import import_module
from pathlib import Path
from typing import Any

import pytest

from sandbox_provider_spec import check_digests as digests
from sandbox_provider_spec import conformance
from sandbox_provider_spec.check import spec_dir
from sandbox_provider_spec.driver import Driver
from sandbox_provider_spec.lifetime import DEFAULT_LIFETIME_SECONDS
from sandbox_provider_spec.load import load
from sandbox_provider_spec.report import report
from sandbox_provider_spec.suite import Suite, read_suite, suite_path
from sandbox_provider_spec.suite import Test as Scenario

loader = import_module("sandbox_provider_spec.document_cache")

PACKAGE = Path(digests.__file__).parent


def _suite() -> Suite:
    return read_suite(suite_path().with_name("coverage.yaml"))


def test_digests_are_deterministic_and_keyed_by_selected_id() -> None:
    suite = _suite()
    first = digests.check_digests(suite.tests)
    assert first == digests.check_digests(suite.tests)
    assert list(first) == [test.id for test in suite.tests]
    assert len(set(first.values())) == len(first)


@pytest.mark.parametrize(
    "identifier",
    (
        "lifetime_timer.at_end.paused",
        "snapshots.original_after.terminated",
        "edge.previews.public_under_lockdown",
    ),
)
def test_historical_rule_labels_preserve_only_unchanged_checks(identifier: str) -> None:
    tests = {test.id: test for suite in (read_suite(), _suite()) for test in suite.tests}
    test = tests[identifier]
    history = json.loads((suite_path().parent / "historical-suite-rules.json").read_text())
    historical_suite = next(
        digest for digest, rules in history.items() if rules.get(identifier) == []
    )
    old = replace(test, rules=())
    expected = digests.check_digest(old, load(spec_dir() / "catalog.yaml"), digests.shared_digest())

    assert digests.historical_check_digest(test, historical_suite) == expected
    assert (
        digests.historical_check_digest(
            replace(test, title=test.title + " changed"), historical_suite
        )
        != expected
    )
    assert digests.historical_check_digest(test, "sha256:" + "0" * 64) is None


SUITE_BEFORE_0_3_182 = "sha256:f79f539d8db867cdbb548aec6cd92dafd7b340feb5ca370b768dae6d4894d53b"


def _named_lifetime(test: Scenario, seconds: int) -> Scenario:
    return replace(
        test,
        steps=tuple(
            {**step, "in": {**step.get("in", {}), "lifetime_seconds": seconds}}
            if step.get("op") == "create"
            else step
            for step in test.steps
        ),
    )


@pytest.mark.parametrize(
    ("identifier", "named"),
    (
        ("coverage.facts.size_is_ceiling.true", 300),
        ("coverage.custom_images.prepare.registry", 300),
        ("coverage.network_lockdown.switchable.true", 600),
    ),
)
def test_a_dropped_create_lifetime_counts_only_when_the_run_sends_it(
    identifier: str, named: int
) -> None:
    """SPS 0.3.182 stopped naming these lifetimes; the run's default now fills them in.

    A report of the earlier definition still stands where the caller's driver sends that
    same number for a create that names none, and nowhere else.
    """
    test = {test.id: test for test in _suite().tests}[identifier]
    history = json.loads((suite_path().parent / "historical-suite-rules.json").read_text())
    rules = tuple(history[SUITE_BEFORE_0_3_182][identifier])
    earlier = _named_lifetime(replace(test, rules=rules), named)
    expected = digests.check_digest(
        earlier, load(spec_dir() / "catalog.yaml"), digests.shared_digest()
    )

    assert (
        digests.historical_check_digest(test, SUITE_BEFORE_0_3_182, create_lifetime=named)
        == expected
    )
    for other in (None, 120, named + 1):
        assert (
            digests.historical_check_digest(test, SUITE_BEFORE_0_3_182, create_lifetime=other)
            != expected
        )
    assert (
        digests.historical_check_digest(test, "sha256:" + "0" * 64, create_lifetime=named) is None
    )


@pytest.mark.parametrize(
    ("report_path", "identifier"),
    (
        (
            "providers/blaxel/reports/adapter-default-size-ceiling.json",
            "coverage.facts.size_is_ceiling.true",
        ),
        (
            "providers/e2b/reports/native-default-registry.json",
            "coverage.custom_images.prepare.registry",
        ),
        ("providers/e2b/reports/native-default-coverage.json", "coverage.desktop.live_view"),
    ),
)
def test_committed_reports_of_a_dropped_lifetime_still_stand(
    report_path: str, identifier: str
) -> None:
    """Reports run before SPS 0.3.182 named 300 s; a run now sends the same 300 s default."""
    recorded = json.loads((PACKAGE.parents[1] / report_path).read_text())
    test = {test.id: test for test in _suite().tests}[identifier]
    assert recorded["check_digests"][identifier] != digests.check_digests((test,))[identifier]

    assert (
        digests.historical_check_digest(
            test, recorded["suite_digest"], create_lifetime=DEFAULT_LIFETIME_SECONDS
        )
        == recorded["check_digests"][identifier]
    )


def test_recorded_create_lifetimes_name_only_creates_that_now_name_none() -> None:
    recorded = json.loads((suite_path().parent / "historical-create-lifetimes.json").read_text())
    tests = {test.id: test for suite in (read_suite(), _suite()) for test in suite.tests}
    for identifier, seconds in recorded.items():
        creates = [step for step in tests[identifier].steps if step.get("op") == "create"]
        assert creates, identifier
        assert all("lifetime_seconds" not in step.get("in", {}) for step in creates), identifier
        assert isinstance(seconds, int) and seconds > 0, identifier


def test_check_digests_resolves_each_dependency_once(monkeypatch: pytest.MonkeyPatch) -> None:
    tests = _suite().tests
    dependencies = {name for test in tests for name in digests.test_dependencies(test)}
    expected = dependencies | set(digests.SHARED_MODULES)
    calls: list[str] = []
    real = digests.file_digest

    def record(name: str) -> str:
        calls.append(name)
        return real(name)

    monkeypatch.setattr(digests, "file_digest", record)
    digests.check_digests(tests)
    assert set(calls) == expected
    assert len(calls) == len(expected)


def test_changing_one_test_leaves_other_digests_stable() -> None:
    suite = _suite()
    before = digests.check_digests(suite.tests)
    changed = (replace(suite.tests[0], title="Another title"), *suite.tests[1:])
    after = digests.check_digests(changed)
    assert after[changed[0].id] != before[changed[0].id]
    assert {k: v for k, v in after.items() if k != changed[0].id} == {
        k: v for k, v in before.items() if k != changed[0].id
    }


def test_catalog_change_reaches_only_tests_that_prove_the_entry() -> None:
    suite = _suite()
    catalog = load(spec_dir() / "catalog.yaml")
    proving = next(t for t in suite.tests if any("knob" in p for p in t.proves))
    other = next(t for t in suite.tests if not t.proves)
    gate, knob = proving.proves[0]["gate"], proving.proves[0]["knob"]
    execution = digests.shared_digest()
    edited: dict[str, Any] = {**catalog, "gates": {**catalog["gates"]}}
    edited["gates"][gate] = {**catalog["gates"][gate], "settings": {"x-edited": {}}}
    assert digests.check_digest(other, edited, execution) == digests.check_digest(
        other, catalog, execution
    )
    knobs = {**catalog["gates"][gate].get("knobs", {}), knob: {"kind": "yes_no", "edited": True}}
    edited["gates"][gate] = {**catalog["gates"][gate], "knobs": knobs}
    assert digests.check_digest(proving, edited, execution) != digests.check_digest(
        proving, catalog, execution
    )


def test_shared_execution_change_invalidates_every_check() -> None:
    catalog = load(spec_dir() / "catalog.yaml")
    test = _suite().tests[0]
    assert digests.check_digest(test, catalog, "sha256:" + "0" * 64) != digests.check_digest(
        test, catalog, "sha256:" + "1" * 64
    )


@pytest.mark.parametrize("name", ["coverage_v3.py", "fixtures/idle_activity.py"])
def test_gate_specific_change_reaches_only_its_checks(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    suite = _suite()
    users = [t for t in suite.tests if name in digests.test_dependencies(t)]
    others = [t for t in suite.tests if name not in digests.test_dependencies(t)]
    assert users and others
    before = digests.check_digests(suite.tests)
    real = digests.file_digest
    monkeypatch.setattr(digests, "file_digest", lambda n: "edited" if n == name else real(n))
    after = digests.check_digests(suite.tests)
    assert all(after[t.id] != before[t.id] for t in users)
    assert all(after[t.id] == before[t.id] for t in others)


def _rewrite_until_ctime_ticks(path: Path, original: os.stat_result, content: bytes) -> None:
    """Rewrite `path` to `content` with `original`'s times until its ctime moves on.

    A rewrite inside the filesystem's coarse ctime tick keeps the old ctime, and the
    stat-keyed digest cache then cannot observe the change (~1-in-thousands CI flake).
    """
    for _ in range(100):
        path.write_bytes(content)
        os.utime(path, ns=(original.st_atime_ns, original.st_mtime_ns))
        if path.stat().st_ctime_ns != original.st_ctime_ns:
            return
        time.sleep(0.01)
    pytest.skip("the filesystem's ctime clock did not tick within a second")


def test_file_digest_observes_same_size_same_mtime_rewrite(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / "dependency.txt"
    path.write_bytes(b"first\n")
    original = path.stat()
    monkeypatch.setattr(digests, "_location", lambda _name: path)
    digests._file_digest_at.cache_clear()
    try:
        before = digests.file_digest("fixtures/dependency.txt")
        _rewrite_until_ctime_ticks(path, original, b"other\n")
        assert path.stat().st_size == original.st_size
        assert path.stat().st_mtime_ns == original.st_mtime_ns
        assert digests.file_digest("fixtures/dependency.txt") != before
    finally:
        digests._file_digest_at.cache_clear()


def test_file_digest_cache_is_bounded(tmp_path: Path) -> None:
    path = tmp_path / "dependency.txt"
    path.write_bytes(b"dependency\n")
    digests._file_digest_at.cache_clear()
    try:
        for index in range(600):
            digests._file_digest_at(path, index, index)
        info = digests._file_digest_at.cache_info()
        assert info.maxsize == 512
        assert info.currsize == 512
    finally:
        digests._file_digest_at.cache_clear()


def test_siblings_and_fixtures_named_in_source_are_dependencies() -> None:
    closure = digests.dependency_closure(["coverage_docker.py"])
    assert "coverage_network.py" in closure  # imported sibling
    assert "fixtures/docker_workload.sh" in closure  # named in source
    assert "fixtures/coverage_http.py" in closure  # named by the imported sibling


def test_address_family_operation_dependencies_are_scoped_to_its_rows() -> None:
    tests = {test.id: test for test in _suite().tests}
    address_rows = [
        test
        for test in tests.values()
        if "outbound_ip_families" in test.id or "ipv4_destination_reach" in test.id
    ]
    generic_rows = [
        test
        for test in tests.values()
        if test.id.startswith("coverage.facts.") and test not in address_rows
    ]
    assert len(address_rows) == 3
    assert generic_rows
    for test in address_rows:
        assert set(digests.OPERATION_DEPENDENCIES["fixture.address_families"]) <= set(
            digests.test_dependencies(test)
        )
    for test in generic_rows:
        assert "coverage_address_families.py" not in digests.test_dependencies(test)


def test_unmapped_operation_fails_closed() -> None:
    unknown = Scenario("x.unknown", "t", ({"op": "fixture.brand_new"},), ())
    with pytest.raises(ValueError, match="no declared dependencies"):
        digests.test_dependencies(unknown)
    with pytest.raises(ValueError, match="no declared dependencies"):
        digests.check_digests((unknown,))


def test_every_suite_operation_is_classified_once() -> None:
    used = {op for t in _suite().tests for op in digests.step_operations(t.steps)}
    mapped, shared = set(digests.OPERATION_DEPENDENCIES), digests.SHARED_OPERATIONS
    assert used <= mapped | shared
    assert not mapped & shared


def test_runner_dispatch_matches_the_declared_map() -> None:
    """Each operation branch in the runner reaches only what the map declares for it."""
    source = (PACKAGE / "runner.py").read_text()
    function = next(
        n
        for n in ast.walk(ast.parse(source))
        if isinstance(n, ast.FunctionDef) and n.name == "_test_operation"
    )
    siblings = {p.name for p in PACKAGE.glob("*.py")} - set(digests.SHARED_MODULES)
    for node in function.body:
        if not (isinstance(node, ast.If) and isinstance(node.test, ast.Compare)):
            continue
        comparator = node.test.comparators[0]
        if not isinstance(comparator, ast.Constant):
            continue
        text = ast.get_source_segment(source, node) or ""
        used = {n.id + ".py" for n in ast.walk(node) if isinstance(n, ast.Name)} & siblings
        used |= {f"fixtures/{m}" for m in re.findall(r"fixtures/([\w.-]+)", text)}
        operation = str(comparator.value)
        if operation in digests.SHARED_OPERATIONS:
            assert not used, operation
        else:
            declared = digests.dependency_closure(digests.OPERATION_DEPENDENCIES[operation])
            assert used <= set(declared), operation


def test_every_unshared_file_is_claimed_or_declared_unexecuted() -> None:
    roots = [f for files in digests.OPERATION_DEPENDENCIES.values() for f in files]
    claimed = set(digests.dependency_closure(roots))
    fixtures = suite_path().parent / "fixtures"
    for path in fixtures.rglob("*"):
        relative = path.relative_to(fixtures).as_posix()
        if path.is_file() and not relative.startswith(digests.NON_EXECUTION_FIXTURES):
            assert f"fixtures/{relative}" in claimed, relative
    for path in PACKAGE.glob("coverage_*.py"):
        assert path.name in claimed, path.name


def test_report_records_digests_for_selected_tests_only() -> None:
    suite = conformance.select(_suite(), ["coverage.docker."])
    driver = Driver()
    driver.provider = "e2b"
    driver.sdk_versions = {"example-sdk": "1.0.0"}
    results = [
        {"id": t.id, "result": "not_run", "steps": [], "cleanup": [], "rules": [], "proves": []}
        for t in suite.tests
    ]
    document = report(driver, suite, results, spec_revision="0" * 40, started_at="t")
    assert list(document["check_digests"]) == document["selected_tests"]  # type: ignore[call-overload]
    assert document["suite_digest"] == suite.digest


def test_import_candidates_parse_each_source_once(monkeypatch: pytest.MonkeyPatch) -> None:
    digests._import_candidates.cache_clear()
    parses: list[str] = []
    real = ast.parse

    def record_parse(source: str) -> ast.AST:
        parses.append(source)
        return real(source)

    monkeypatch.setattr(ast, "parse", record_parse)
    source = "from sandbox_provider_spec import coverage_network\n"
    for _ in range(3):
        assert digests._sibling_imports(source) == {"coverage_network.py"}
    assert parses == [source]


def test_changed_source_reparses_and_changes_the_closure() -> None:
    before = "import os\n"
    after = before + "import sandbox_provider_spec.coverage_network\n"
    assert digests._sibling_imports(before) == set()
    assert digests._sibling_imports(after) == {"coverage_network.py"}
    assert digests._sibling_imports(before) == set()


def test_sibling_file_presence_is_checked_on_every_call(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(digests, "PACKAGE", tmp_path)
    source = "from sandbox_provider_spec.brand_new_sibling import x\n"
    assert digests._sibling_imports(source) == set()
    (tmp_path / "brand_new_sibling.py").write_text("x = 1\n")
    assert digests._sibling_imports(source) == {"brand_new_sibling.py"}
    (tmp_path / "brand_new_sibling.py").unlink()
    assert digests._sibling_imports(source) == set()


def test_closure_reads_current_source_even_with_candidates_cached(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(digests, "PACKAGE", tmp_path)
    root, mid, leaf = (tmp_path / f"{n}.py" for n in ("root", "mid", "leaf"))
    root.write_text("x = 1\n")
    mid.write_text("y = 1\n")
    leaf.write_text("z = 1\n")
    assert digests.dependency_closure(["root.py"]) == ("root.py",)
    root.write_text("from sandbox_provider_spec import mid\n")
    assert digests.dependency_closure(["root.py"]) == ("mid.py", "root.py")
    mid.write_text("import sandbox_provider_spec.leaf\n")
    assert digests.dependency_closure(["root.py"]) == ("leaf.py", "mid.py", "root.py")
    mid.write_text("y = 1\n")
    assert digests.dependency_closure(["root.py"]) == ("mid.py", "root.py")
    root.write_text("x = 1\n")
    assert digests.dependency_closure(["root.py"]) == ("root.py",)


def test_mutating_a_returned_set_cannot_poison_the_cache() -> None:
    source = "import sandbox_provider_spec.coverage_network\n"
    first = digests._sibling_imports(source)
    first.add("poison.py")
    first.clear()
    assert digests._sibling_imports(source) == {"coverage_network.py"}
    assert isinstance(digests._import_candidates(source), tuple)


def test_closure_digests_equal_with_cold_and_warm_import_cache() -> None:
    suite = _suite()
    digests._import_candidates.cache_clear()
    cold = digests.check_digests(suite.tests)
    assert digests._import_candidates.cache_info().hits > 0
    assert digests.check_digests(suite.tests) == cold


def test_import_candidate_cache_is_bounded() -> None:
    assert digests._import_candidates.cache_info().maxsize == 128
    digests._import_candidates.cache_clear()
    for index in range(300):
        digests._import_candidates(f"x = {index}\n")
    assert digests._import_candidates.cache_info().currsize == 128


def _catalog_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, text: str) -> Path:
    monkeypatch.setattr(digests, "spec_dir", lambda: tmp_path)
    loader._document_texts.clear()
    path = tmp_path / "catalog.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def _count_parses(monkeypatch: pytest.MonkeyPatch) -> list[bytes]:
    parses: list[bytes] = []
    real = loader._parse

    def record(suffix: str, content: bytes) -> Any:
        parses.append(content)
        return real(suffix, content)

    monkeypatch.setattr(loader, "_parse", record)
    return parses


def test_catalog_is_parsed_once_across_repeated_digest_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    loader._document_texts.clear()
    parses = _count_parses(monkeypatch)
    suite = _suite()
    first = digests.check_digests(suite.tests)
    for _ in range(4):
        assert digests.check_digests(suite.tests) == first
    assert parses == [(spec_dir() / "catalog.yaml").read_bytes()]


def test_same_size_same_mtime_rewrite_is_observed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    base = (spec_dir() / "catalog.yaml").read_text(encoding="utf-8")
    path = _catalog_dir(monkeypatch, tmp_path, base)
    suite = _suite()
    proving = next(t for t in suite.tests if any("knob" in p for p in t.proves))
    before = digests.check_digests((proving,))
    gate, knob = proving.proves[0]["gate"], proving.proves[0]["knob"]
    catalog = load(path)
    kind = catalog["gates"][gate]["knobs"][knob]["kind"]
    assert base.count(kind) >= 1
    swapped = kind[:-1] + ("x" if kind[-1] != "x" else "y")
    stat = path.stat()
    edited = base.replace(kind, swapped)
    assert len(edited.encode()) == stat.st_size
    _rewrite_until_ctime_ticks(path, stat, edited.encode())
    assert path.stat().st_mtime_ns == stat.st_mtime_ns and path.stat().st_size == stat.st_size
    assert digests.check_digests((proving,)) != before
    path.write_text(base, encoding="utf-8")
    assert digests.check_digests((proving,)) == before


def test_deleted_and_replaced_catalog_follow_the_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    base = (spec_dir() / "catalog.yaml").read_text(encoding="utf-8")
    path = _catalog_dir(monkeypatch, tmp_path, base)
    tests = (next(t for t in _suite().tests if any("knob" in p for p in t.proves)),)
    before = digests.check_digests(tests)
    path.unlink()
    with pytest.raises(FileNotFoundError):
        digests.check_digests(tests)
    path.write_text("baseline_result: {}\ngates: {}\n", encoding="utf-8")
    assert digests.check_digests(tests) != before


def test_invalid_and_duplicate_key_catalogs_still_refuse_and_are_not_cached(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    base = (spec_dir() / "catalog.yaml").read_text(encoding="utf-8")
    path = _catalog_dir(monkeypatch, tmp_path, base + "\nbaseline_result: {}\n")
    tests = _suite().tests[:2]
    for _ in range(2):
        with pytest.raises(ValueError, match="duplicate key"):
            digests.check_digests(tests)
    path.write_text("a: [unclosed\n", encoding="utf-8")
    with pytest.raises(Exception, match="expected"):
        digests.check_digests(tests)
    assert len(loader._document_texts) == 0


def test_digest_calls_do_not_mutate_the_cached_catalog(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    base = (spec_dir() / "catalog.yaml").read_text(encoding="utf-8")
    path = _catalog_dir(monkeypatch, tmp_path, base)
    tests = _suite().tests
    digests.check_digests(tests)
    (cached,) = loader._document_texts.values()
    assert json.loads(cached) == load(path)


def test_catalog_cache_is_bounded_and_evicts_least_recently_used(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = _catalog_dir(monkeypatch, tmp_path, "n: 0\n")
    parses = _count_parses(monkeypatch)
    for index in range(loader._DOCUMENT_TEXTS + 3):
        path.write_text(f"n: {index}\n", encoding="utf-8")
        assert loader.cached_load(path) == {"n": index}
    assert len(loader._document_texts) == loader._DOCUMENT_TEXTS
    parsed = len(parses)
    path.write_text(f"n: {loader._DOCUMENT_TEXTS + 2}\n", encoding="utf-8")
    loader.cached_load(path)
    assert len(parses) == parsed
    path.write_text("n: 0\n", encoding="utf-8")
    loader.cached_load(path)
    assert len(parses) == parsed + 1


def test_file_changed_and_restored_during_a_parse_cannot_poison_the_cache(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = _catalog_dir(monkeypatch, tmp_path, "n: 1\n")
    real = loader._parse

    def aba(suffix: str, content: bytes) -> Any:
        path.write_text("n: 2\n", encoding="utf-8")
        parsed = real(suffix, content)
        path.write_text("n: 1\n", encoding="utf-8")
        return parsed

    monkeypatch.setattr(loader, "_parse", aba)
    assert loader.cached_load(path) == {"n": 1}
    monkeypatch.setattr(loader, "_parse", real)
    assert loader.cached_load(path) == {"n": 1}
    path.write_text("n: 2\n", encoding="utf-8")
    assert loader.cached_load(path) == {"n": 2}


def test_refusals_match_the_strict_loader(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    base = (spec_dir() / "catalog.yaml").read_text(encoding="utf-8")
    path = _catalog_dir(monkeypatch, tmp_path, base)
    for text in (base + "\nbaseline_result: {}\n", "a: [unclosed\n", "a: &x [*y]\n"):
        path.write_text(text, encoding="utf-8")
        with pytest.raises(Exception) as direct:  # noqa: PT011
            load(path)
        with pytest.raises(type(direct.value)) as cached:
            digests.check_digests(_suite().tests[:1])
        assert str(cached.value) == str(direct.value)
        assert len(loader._document_texts) == 0
