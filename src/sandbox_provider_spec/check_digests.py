# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Per-check digests: what a single test's result depends on, listed explicitly.

A check digest binds three inputs, each hashed as canonical JSON:

- `definition`: the selected test's id, title, steps, proves and rules;
- `catalog`: only the catalog entries its `proves` targets name, plus the result vocabulary;
- `execution`: the shared runner semantics (`SHARED_MODULES`, the suite format version) that
  every check depends on, and the dependencies of the operations this test's steps use.

An operation's dependencies come from `OPERATION_DEPENDENCIES`: the module that implements it,
every sibling module that module imports (transitively), and every `fixtures/<file>` its source
names. Editing a gate-specific module or fixture changes only the checks that use it; editing
`SHARED_MODULES` changes every check. A step operation that is in neither `OPERATION_DEPENDENCIES`
nor `SHARED_OPERATIONS` raises instead of being skipped, so a new dependency can never be missed.

A digest is computed when a report is written; existing reports are never given one.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
import tempfile
import threading
from collections import OrderedDict
from collections.abc import Iterable, Mapping
from dataclasses import replace
from functools import lru_cache
from pathlib import Path
from typing import Any

from sandbox_provider_spec.check import spec_dir
from sandbox_provider_spec.load import load
from sandbox_provider_spec.suite import SPEC, Test, suite_path

PACKAGE = Path(__file__).resolve().parent

# Code every check's result depends on: step execution, proof judgement and suite loading.
SHARED_MODULES = (
    "driver.py",
    "hostnames.py",
    "load.py",
    "proofs.py",
    "runner.py",
    "suite.py",
    "timestamps.py",
)

# Operations implemented inside the shared runner or driver, so `SHARED_MODULES` covers them.
SHARED_OPERATIONS = frozenset(
    {
        "allocation.observe", "bindings.compare", "clock.observe", "clock.start", "create",
        "desktop.live_link", "destroy", "environment.observe", "files.exists",
        "files.read_bytes", "files.write", "get", "idle.select_duration", "image.delete",
        "image.prepare", "image.state", "lifetime.extend", "lifetime.observe_paused_countdown",
        "list", "long_running.observe", "native.operation_absent", "pause", "preview.link",
        "preview.revoke", "probe.http", "process.cancel", "process.disconnect",
        "process.output", "process.reattach", "process.start", "process.wait",
        "process.write_stdin", "resume", "run", "run.as_root", "run.each_url", "secret.create",
        "snapshot.delete", "snapshot.delete_again", "snapshot.restore",
        "snapshot.restore_begin", "snapshot.restore_wait", "snapshot.retention",
        "snapshot.take", "tcp.link", "terminal.disconnect", "terminal.open",
        "terminal.output", "terminal.reattach", "terminal.write", "volume.create",
        "volume.create_many", "volume.observe_kind", "volume.observe_mounts",
    }
)  # fmt: skip

# Operation -> the module (relative to the package) or fixture (`fixtures/<file>`) that is its
# own implementation. Sibling imports and fixtures named in module source are added from source.
OPERATION_DEPENDENCIES: Mapping[str, tuple[str, ...]] = {
    "http.buffered": ("coverage_http_buffered.py",),
    "fixture.fuse_mount": ("fuse_mount.py", "fuse_mount_identity.py", "fixtures/fuse_mount.py"),
    "fixture.fuse_mount_provider_terminal_handover": ("fuse_mount_handover.py",),
    "fixture.fuse_mount_provider_terminal_handover_read": ("fuse_mount_handover_read.py",),
    "fixture.fuse_mount_provider_terminal_handover_shared": ("fuse_mount_handover_shared.py",),
    "fixture.fuse_mount_provider_terminal_handover_130": ("fuse_mount_handover_130.py",),
    "fixture.fuse_mount_provider_terminal_handover_read_130": ("fuse_mount_handover_read_130.py",),
    "fixture.fuse_mount_provider_terminal_handover_shared_130": (
        "fuse_mount_handover_shared_130.py",
    ),
    "fixture.fuse_mount_provider_terminal_branch_fork": ("fuse_mount_handover_branch_131.py",),
    "fixture.fuse_mount_provider_terminal_handover_env_132": ("fuse_mount_handover_env_132.py",),
    "fixture.fuse_mount_provider_terminal_handover_read_env_132": (
        "fuse_mount_handover_env_132.py",
    ),
    "fixture.fuse_mount_provider_terminal_handover_shared_env_132": (
        "fuse_mount_handover_env_132.py",
    ),
    "fixture.fuse_mount_provider_terminal_branch_fork_env_132": ("fuse_mount_handover_env_132.py",),
    "fixture.coverage_active_lifetime": ("coverage_lifecycle.py",),
    "fixture.coverage_allowlist": ("coverage_v2.py",),
    "fixture.coverage_connection_closed": ("coverage_v3.py",),
    "fixture.coverage_connection_update": ("coverage_v3.py",),
    "fixture.coverage_deny_wins": ("coverage_v2.py",),
    "fixture.coverage_denylist": ("coverage_network.py",),
    "fixture.coverage_desktop": ("coverage_desktop.py",),
    "fixture.coverage_docker": ("coverage_docker.py",),
    "fixture.coverage_docker_create": ("coverage_docker.py",),
    "fixture.coverage_domain_traffic": ("coverage_v2.py",),
    "fixture.coverage_egress_proxy": ("coverage_v5.py",),
    "fixture.coverage_fact": ("coverage_probe.py",),
    "fixture.address_families": (
        "coverage_address_families.py",
        "fixtures/address_families.py",
        "fixtures/address_families.example.json",
        "fixtures/address_families.schema.json",
        "fixtures/address_families.md",
    ),
    "fixture.guest_reserved_tcp_ports": (
        "coverage_guest_reserved_tcp_ports.py",
        "fixtures/guest_reserved_tcp_ports.py",
        "fixtures/guest_reserved_tcp_ports.schema.json",
        "fixtures/guest_reserved_tcp_ports.md",
    ),
    "fixture.file_links": ("coverage_file_transfer.py",),
    "fixture.file_stream": ("coverage_file_transfer.py",),
    "fixture.regular_write_usability": (
        "coverage_regular_write.py",
        "fixtures/regular_write_usability.py",
        "fixtures/regular_write_usability.schema.json",
        "fixtures/regular_write_usability.md",
    ),
    "fixture.coverage_harness_health": ("coverage_v2.py",),
    "fixture.coverage_http_rule_deny": ("coverage_v2.py",),
    "fixture.coverage_http_rules": ("coverage_v2.py",),
    "fixture.coverage_identity_token": ("coverage_v5.py",),
    "fixture.coverage_kernel_feature": ("coverage_v6.py",),
    "fixture.coverage_network_checks": ("coverage_network.py",),
    "fixture.coverage_open_connection": ("coverage_v3.py",),
    "fixture.coverage_outbound_traffic": ("coverage_v6.py",),
    "fixture.coverage_policy_change": ("coverage_network.py",),
    "fixture.coverage_private_network": ("coverage_v6.py",),
    "fixture.coverage_reserved_ports": ("coverage_ports.py",),
    "fixture.coverage_secret": ("coverage_secrets.py",),
    "fixture.coverage_secret_body": ("coverage_v4.py",),
    "fixture.coverage_secret_header": ("coverage_v4.py",),
    "fixture.coverage_secret_hosts": ("coverage_v4.py",),
    "fixture.coverage_secret_wildcard": ("coverage_v4.py",),
    "fixture.coverage_server": ("coverage_probe.py",),
    "fixture.process_eof": ("process_eof.py",),
    "fixture.process_state": ("fixtures/process_state.py",),
    "fixture.root_attack": ("fixtures/root_attack.py",),
    "fixture.secret_receiver": ("fixtures/secret_receiver.py",),
    "fixture.snapshot_ticker_observe": ("snapshot_ticker.py",),
    "fixture.snapshot_ticker_start": ("snapshot_ticker.py",),
    "fixture.volume_visibility": ("volume_visibility.py",),
    "probe.desktop_browser": ("coverage_desktop.py",),
    "probe.ssh": ("coverage_ssh.py",),
    "probe.tcp": ("protocol_probe.py",),
    "probe.websocket": ("protocol_probe.py",),
}

# Fixture files that no step executes: deployment assets for the hosted endpoints.
NON_EXECUTION_FIXTURES = ("endpoints/", "endpoints-worker/")

_IMPORT = re.compile(r"sandbox_provider_spec(?:\.(\w+))?")
_FIXTURE = re.compile(r"fixtures/([\w.-]+)")


def _is_string_statement(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    )


def _canonical(node: object) -> str:
    """Canonical syntax tree independent of absent fields on different Python versions."""
    if isinstance(node, ast.AST):
        fields = []
        for name in sorted(node._fields):
            value: Any = getattr(node, name, None)
            if isinstance(value, list):
                value = [item for item in value if not _is_string_statement(item)]
            if value is None or value == []:
                continue
            fields.append(f"{name}={_canonical(value)}")
        return f"{type(node).__name__}({','.join(fields)})"
    if isinstance(node, list):
        return f"[{','.join(_canonical(item) for item in node)}]"
    return repr(node)


@lru_cache(maxsize=512)
def normalized_module(source: bytes) -> bytes:
    """Hash Python syntax without docstrings, comments or formatting differences."""
    return _canonical(ast.parse(source)).encode("utf-8")


def _digest(value: object) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "sha256:" + hashlib.sha256(data.encode()).hexdigest()


def _location(name: str) -> Path:
    if name.startswith("fixtures/"):
        return suite_path().parent / name
    return PACKAGE / name


@lru_cache(maxsize=512)
def _file_digest_at(path: Path, ctime_ns: int, size: int) -> str:
    del ctime_ns, size
    content = path.read_bytes()
    if path.suffix == ".py" and path.parent == PACKAGE:
        content = normalized_module(content)
    elif path.suffix == ".py":
        lines = content.splitlines(keepends=True)
        content = b"".join(
            line
            for index, line in enumerate(lines)
            if index >= 2
            or not line.startswith((b"# SPDX-FileCopyrightText:", b"# SPDX-License-Identifier:"))
        )
    return hashlib.sha256(content).hexdigest()


def file_digest(name: str) -> str:
    """Digest of one dependency; a module's comments, docstrings and formatting are ignored."""
    path = _location(name)
    stat = path.stat()
    return _file_digest_at(path, stat.st_ctime_ns, stat.st_size)


@lru_cache(maxsize=128)
def _import_candidates(source: str) -> tuple[str, ...]:
    """Sibling `module.py` names the source's imports could mean; the file check is separate."""
    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        names: list[str] = []
        if isinstance(node, ast.ImportFrom) and node.module:
            names = [node.module, *(f"{node.module}.{alias.name}" for alias in node.names)]
            # `from sandbox_provider_spec import coverage_x` names the module as an alias.
            if node.module == "sandbox_provider_spec":
                found.update(f"{alias.name}.py" for alias in node.names)
        elif isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        for name in names:
            match = _IMPORT.fullmatch(name)
            if match and match.group(1):
                found.add(f"{match.group(1)}.py")
    return tuple(sorted(found))


def _sibling_imports(source: str) -> set[str]:
    """Sibling modules the source imports, as `module.py` names."""
    return {name for name in _import_candidates(source) if (PACKAGE / name).is_file()}


def dependency_closure(roots: Iterable[str]) -> tuple[str, ...]:
    """The roots, the unshared sibling modules they import, and the fixtures their source names."""
    pending, seen = list(roots), set()
    while pending:
        name = pending.pop()
        if name in seen or name in SHARED_MODULES:
            continue
        seen.add(name)
        if name.startswith("fixtures/"):
            continue
        source = _location(name).read_text(encoding="utf-8")
        pending.extend(_sibling_imports(source))
        pending.extend(f"fixtures/{match}" for match in _FIXTURE.findall(source))
    return tuple(sorted(seen))


def step_operations(value: object) -> Iterable[str]:
    if isinstance(value, dict):
        if isinstance(value.get("op"), str):
            yield value["op"]
        for item in value.values():
            yield from step_operations(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from step_operations(item)


def test_dependencies(test: Test) -> tuple[str, ...]:
    """Unshared files this test's steps use. An unclassified operation is an error."""
    roots: list[str] = []
    for operation in sorted(set(step_operations(test.steps))):
        if operation in OPERATION_DEPENDENCIES:
            roots.extend(OPERATION_DEPENDENCIES[operation])
        elif operation not in SHARED_OPERATIONS:
            raise ValueError(f"{test.id}: operation {operation} has no declared dependencies")
    return dependency_closure(roots)


def shared_digest() -> str:
    """Digest of the runner, proof and suite code every check result depends on."""
    files = {name: file_digest(name) for name in SHARED_MODULES}
    return _digest({"spec": SPEC, "files": files})


def catalog_inputs(test: Test, catalog: Mapping[str, Any]) -> dict[str, Any]:
    """The catalog entries the test's proof targets name, and nothing else."""
    entries: dict[str, Any] = {"baseline_result": catalog["baseline_result"]}
    for proof in test.proves:
        if "fact" in proof:
            fact = str(proof["fact"])
            if fact.startswith("lifetime_timer."):
                entries["lifetime_timer"] = catalog["lifetime_timer"]
            else:
                name = fact.split(".", 1)[1]
                entries.setdefault("declaration_resources", {})[name] = catalog[
                    "declaration_resources"
                ].get(name)
            continue
        gate = catalog["gates"].get(proof["gate"], {})
        bucket = entries.setdefault("gates", {}).setdefault(proof["gate"], {})
        if "knob" not in proof:
            bucket["gate"] = {
                key: value for key, value in gate.items() if key not in {"knobs", "description"}
            }
            continue
        knob = proof["knob"]
        knob_spec = dict(gate.get("knobs", {}).get(knob, {}))
        knob_spec.pop("description", None)
        bucket.setdefault("knobs", {})[knob] = {
            "knob": knob_spec,
            "declaration_only": gate.get("declaration_only", {}).get(knob),
            "limit": knob in gate.get("limits", []),
        }
    return entries


def check_digest(test: Test, catalog: Mapping[str, Any], shared: str) -> str:
    dependencies = test_dependencies(test)
    file_digests = {name: file_digest(name) for name in dependencies}
    return _check_digest_with_dependencies(test, catalog, shared, dependencies, file_digests)


def historical_rule_digest(test: Test, suite_digest: object) -> str | None:
    """Digest this check with only its rule labels from a recognized earlier suite.

    Rule labels classify coverage; they do not change the operation or proof. Equality with
    a recorded check digest still proves every other input, including executable code,
    catalog entries, steps and proof targets, is unchanged.
    """
    if not isinstance(suite_digest, str):
        return None
    try:
        history = json.loads(
            (suite_path().parent / "historical-suite-rules.json").read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    suites = history.get(suite_digest) if isinstance(history, dict) else None
    rules = suites.get(test.id) if isinstance(suites, dict) else None
    if (
        not isinstance(rules, list)
        or any(not isinstance(rule, str) for rule in rules)
        or tuple(rules) == test.rules
    ):
        return None
    catalog = _catalog_document(spec_dir() / "catalog.yaml")
    return check_digest(replace(test, rules=tuple(rules)), catalog, shared_digest())


def _check_digest_with_dependencies(
    test: Test,
    catalog: Mapping[str, Any],
    shared: str,
    dependencies: tuple[str, ...],
    file_digests: Mapping[str, str],
) -> str:
    definition = {
        "id": test.id,
        "title": test.title,
        "steps": list(test.steps),
        "proves": list(test.proves),
        "rules": list(test.rules),
    }
    return _digest(
        {
            "definition": definition,
            "catalog": catalog_inputs(test, catalog),
            "execution": {
                "shared": shared,
                "dependencies": {name: file_digests[name] for name in dependencies},
            },
        }
    )


_CATALOG_ENTRIES = 4
_catalogs: OrderedDict[str, Any] = OrderedDict()
_catalogs_lock = threading.Lock()


def _catalog_document(path: Path) -> Any:
    """The strictly loaded catalog, parsed once per distinct file content.

    The file is read on every call and keyed by the SHA-256 of its bytes, so a rewrite of the
    same size and modification time still reparses. On a miss the strict loader parses a private
    copy of exactly those bytes, so a parse can never be stored under the key of other content,
    even if the file changes and changes back meanwhile. The document stays internal: callers only
    hash entries of it. A parse that raises is never stored.
    """
    content = path.read_bytes()
    key = hashlib.sha256(content).hexdigest()
    with _catalogs_lock:
        if key in _catalogs:
            _catalogs.move_to_end(key)
            return _catalogs[key]
    with tempfile.TemporaryDirectory() as private:
        copy = Path(private) / path.name
        copy.write_bytes(content)
        document = load(copy)
    with _catalogs_lock:
        _catalogs[key] = document
        _catalogs.move_to_end(key)
        while len(_catalogs) > _CATALOG_ENTRIES:
            _catalogs.popitem(last=False)
    return document


def check_digests(tests: tuple[Test, ...]) -> dict[str, str]:
    """Digest of each selected test, keyed by id."""
    catalog = _catalog_document(spec_dir() / "catalog.yaml")
    shared = shared_digest()
    dependencies = tuple(test_dependencies(test) for test in tests)
    names = {name for test_dependencies in dependencies for name in test_dependencies}
    file_digests = {name: file_digest(name) for name in sorted(names)}
    return {
        test.id: _check_digest_with_dependencies(
            test, catalog, shared, test_dependencies, file_digests
        )
        for test, test_dependencies in zip(tests, dependencies, strict=True)
    }
