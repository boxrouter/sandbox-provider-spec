# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""What a report is bound to: the provider package's files and the discovery it tested.

A report records `subject` (`report_subject`), so a reader can tell that the code and the discovery
it reads are the ones a test passed on. The functions are pure reads of installed files and of a
`Discovery`; the reader of a report calls the same ones and compares."""

from __future__ import annotations

import hashlib
import json
import sys
from collections.abc import Mapping
from functools import cache
from importlib.metadata import EntryPoints, entry_points, packages_distributions, version
from pathlib import Path

from sandbox_provider_spec.v1.types import Discovery
from sandbox_provider_spec.v1.wire import to_json

__all__ = ["discovery_digest", "package_digest", "report_subject"]

# The per-class fields that state availability right now, left out of a discovery digest: a flip
# changes nothing that a report or a price version proved.
VOLATILE_CLASS_FIELDS = ("ready", "unavailable_regions")


def discovery_digest(discovery: Discovery) -> str:
    """`sha256:` and the hex digest of the discovery's canonical JSON (sorted keys, no spacing),
    without `ready` and `unavailable_regions`. Equal to the digest that Cloud's prober records for
    a document, so that both ask the same question."""
    document = dict(to_json(discovery))
    document["classes"] = [
        {key: value for key, value in item.items() if key not in VOLATILE_CLASS_FIELDS}
        for item in document["classes"]
    ]
    text = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _top_package(cls: type) -> tuple[str, Path] | None:
    top = cls.__module__.split(".")[0]
    module = sys.modules.get(top)
    where = getattr(module, "__file__", None)
    return None if where is None else (top, Path(where).resolve().parent)


@cache
def _distributions() -> Mapping[str, list[str]]:
    """The environment's package-to-distribution map: process-static, but a full filesystem
    scan, so the roster's per-provider subjects share one read instead of one scan each."""
    return packages_distributions()


@cache
def _spec_entries() -> EntryPoints:
    """The installed `sandbox_provider_spec.providers` entry points: process-static."""
    return entry_points(group="sandbox_provider_spec.providers")


def _distribution_names(top: str) -> list[str]:
    """The distributions that hold the top-level package `top`. An editable install does not
    list its package, so a provider's own entry point names it too."""
    names = list(_distributions().get(top, ()))
    for entry in _spec_entries():
        if entry.dist is not None and entry.value.split(".")[0].split(":")[0] == top:
            names.append(entry.dist.name)
    return names


def package_digest(cls: type) -> str | None:
    """`sha256:` and the hex digest of the files of the Python package that defines `cls`: each
    file's path (relative, `/` separated) and content, sorted, without bytecode. None when the
    class has no package directory. Read from the files themselves, so it holds for a wheel and for
    an editable install alike."""
    found = _top_package(cls)
    if found is None:
        return None
    _, root = found
    outer = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if "__pycache__" in relative.parts or path.suffix == ".pyc" or not path.is_file():
            continue
        outer.update(relative.as_posix().encode() + b"\0")
        outer.update(hashlib.sha256(path.read_bytes()).digest())
    return "sha256:" + outer.hexdigest()


def report_subject(cls: type, discovery: Discovery | None = None) -> dict[str, str] | None:
    """The `subject` a report records: the distribution that holds `cls` (`package`, `version`),
    the digest of its files (`package_digest`) and `discovery_digest` of `discovery` when given.
    None where `cls` belongs to no installed distribution."""
    found = _top_package(cls)
    names = _distribution_names(found[0]) if found else None
    # An HTTP client names the spec's own package, not the provider it talks to.
    if not names or cls.__module__ == "sandbox_provider_spec.v1.http_client":
        return None
    digest = package_digest(cls)
    if digest is None:
        return None
    subject = {"package": names[0], "version": version(names[0]), "package_digest": digest}
    if discovery is not None:
        subject["discovery_digest"] = discovery_digest(discovery)
    return subject
