# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Load shared declarative tests independently of provider declarations."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from sandbox_provider_spec.check import spec_dir
from sandbox_provider_spec.load import load

SPEC = "sandbox-provider-spec/0.1"
OBSERVATIONS = frozenset(
    {
        "get",
        "list",
        "files.read_bytes",
        "files.exists",
        "files.list",
        "process.output",
        "process.wait",
        "terminal.output",
        "probe.http",
        "probe.websocket",
        "probe.tcp",
        "fixture.process_state",
    }
)


@dataclass(frozen=True)
class Test:
    id: str
    title: str
    steps: tuple[dict[str, Any], ...]
    proves: tuple[dict[str, Any], ...]
    rules: tuple[str, ...] = ()


@dataclass(frozen=True)
class Suite:
    digest: str
    tests: tuple[Test, ...]
    baseline_ids: tuple[str, ...] = ()


def suite_path() -> Path:
    root = spec_dir()
    source = root.parent / "conformance" / "suite.yaml"
    return source if source.is_file() else root / "conformance" / "suite.yaml"


def read_suite(path: Path | None = None) -> Suite:
    """Unknown versions, duplicate ids and mutation retries fail before any allocation.

    Each unchanged set of suite files is parsed once per process. File signatures in the
    cache key make updates at the same path visible to the matcher.
    """
    chosen = (path or suite_path()).resolve()
    sources: tuple[Path, ...] = (
        (chosen.with_name("suite.yaml"), chosen) if chosen.name == "coverage.yaml" else (chosen,)
    )
    additional = chosen.with_name("coverage.yaml")
    if additional.is_file() and additional not in sources:
        sources += (additional,)
    signatures = tuple(
        (source, source.stat().st_mtime_ns, source.stat().st_size) for source in sources
    )
    return read_suite_at(chosen, signatures)


# The next change that alters the shared check digest anyway should also parse these files through
# document_cache.cached_load (an AST edit here or in load.py makes every report's digests stale).
@lru_cache(maxsize=8)
def read_suite_at(chosen: Path, signatures: tuple[tuple[Path, int, int], ...] = ()) -> Suite:
    # File signatures participate in the bounded cache key, not suite parsing.
    del signatures
    additional = chosen.with_name("coverage.yaml")
    sources = (
        (chosen.with_name("suite.yaml"), chosen) if chosen.name == "coverage.yaml" else (chosen,)
    )
    documents = {source: load(source) for source in sources}
    if additional.is_file() and additional not in documents:
        documents[additional] = load(additional)
    if any(document.get("spec") != SPEC for document in documents.values()):
        raise ValueError("unknown suite spec version")
    baseline = tuple(
        test["id"]
        for document in documents.values()
        for test in document["tests"]
        if test["id"].startswith("baseline.")
    )
    identifiers = [test["id"] for document in documents.values() for test in document["tests"]]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("duplicate test id across suites")
    catalog = load(spec_dir() / "catalog.yaml")
    tests: list[Test] = []
    seen: set[str] = set()
    for source, raw in (
        (file_path, test) for file_path in sources for test in documents[file_path]["tests"]
    ):
        identifier = raw["id"]
        if chosen.name == "coverage.yaml" and source == sources[0]:
            if not identifier.startswith("baseline."):
                continue
        if identifier in seen:
            raise ValueError(f"duplicate test id: {identifier}")
        seen.add(identifier)
        for step in raw["steps"]:
            if "eventually_ms" in step.get("expect", {}) and step.get("op") not in OBSERVATIONS:
                raise ValueError(f"{identifier}: cannot retry a mutation")
        rules = raw.get("rules", [])
        proofs = raw.get("proves", [])
        if (
            not isinstance(rules, list)
            or any(not isinstance(r, str) or not r for r in rules)
            or len(rules) != len(set(rules))
        ):
            raise ValueError(f"{identifier}: invalid rule targets")
        if not isinstance(proofs, list):
            raise ValueError(f"{identifier}: invalid proof targets")
        for proof in proofs:
            if not isinstance(proof, dict) or "value" not in proof:
                raise ValueError(f"{identifier}: invalid proof target")
            if set(proof) == {"fact", "value"}:
                fact = proof["fact"]
                if fact not in {
                    "lifetime_timer.at_end",
                    "lifetime_timer.enforced_by",
                    "lifetime_timer.counts_paused_time",
                } and not (
                    isinstance(fact, str)
                    and fact.startswith("resources.")
                    and fact.split(".", 1)[1] in catalog["declaration_resources"]
                ):
                    raise ValueError(f"{identifier}: unknown fact proof")
                continue
            if set(proof) == {"gate", "value"}:
                if proof["gate"] not in catalog["gates"] or proof["value"] is not True:
                    raise ValueError(f"{identifier}: invalid presence proof")
                continue
            if set(proof) != {"gate", "knob", "value"}:
                raise ValueError(f"{identifier}: invalid gate proof")
            gate, knob = proof["gate"], proof["knob"]
            knobs = catalog["gates"].get(gate, {}).get("knobs", {})
            limits = catalog["gates"].get(gate, {}).get("limits", [])
            declaration_only = catalog["gates"].get(gate, {}).get("declaration_only", {})
            if knob in limits:
                continue
            if knob in declaration_only:
                knobs = {**knobs, **declaration_only}
            if knob not in knobs:
                raise ValueError(f"{identifier}: unknown gate proof")
            definition = knobs[knob]
            value = proof["value"]
            if definition["kind"] == "pick" and value not in definition["values"]:
                raise ValueError(f"{identifier}: unknown knob value")
            if definition["kind"] == "yes_no" and not isinstance(value, bool):
                raise ValueError(f"{identifier}: invalid boolean knob value")
            if definition["kind"] == "all_of" and (
                not isinstance(value, list)
                or not value
                or any(item not in definition["values"] for item in value)
                or len(value) != len(set(value))
            ):
                raise ValueError(f"{identifier}: invalid all-of knob value")
        tests.append(
            Test(
                identifier,
                raw["title"],
                tuple(raw["steps"]),
                tuple(raw.get("proves", [])),
                tuple(raw.get("rules", [])),
            )
        )
    payload = (
        chosen.read_bytes()
        if len(sources) == 1
        else b"".join(
            source.name.encode() + b"\0" + source.read_bytes() + b"\0" for source in sources
        )
    )
    digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    return Suite(digest, tuple(tests), baseline)
