# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Validate providers' brand and publication files and build their release JSON.

`providers/<id>/brand.yaml` (chart colour, logo, mark, mark_colours, launched),
`providers/<id>/publication.yaml` (hidden, candidate or published) and `providers/<id>/notes.yaml`
(the provider's sentences) are optional. `sandbox-provider-spec provider-assets --out DIR` writes
`brand.json`, `publication.json` and `notes.json`, each self-contained.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
from pathlib import Path
from typing import Any

import yaml

from sandbox_provider_spec.check import spec_dir

BRAND_SCHEMA = "sandbox-provider-spec.brand/1"
PUBLICATION_SCHEMA = "sandbox-provider-spec.publication/1"
NOTES_SCHEMA = "sandbox-provider-spec.notes/1"
NOTE_KEY = re.compile(r"[a-z0-9][a-z0-9_.-]*")
STATES = ("hidden", "candidate", "published")
IMAGE_SUFFIXES = (".svg", ".png", ".webp")
BRAND_KEYS = ("color", "launched", "logo", "mark", "mark_colours", "order")
RECEIPT_KEYS = ("approved_by", "reference", "content_sha256")
SHA256 = re.compile(r"[0-9a-f]{64}")
COLOR = re.compile(r"#[0-9A-Fa-f]{6}")


def _load(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a mapping")
    return value


def _nonblank(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def brand(folder: Path) -> dict[str, Any] | None:
    """The folder's brand as release JSON, or None without a `brand.yaml`."""
    source = folder / "brand.yaml"
    if not source.is_file():
        return None
    declared = _load(source)
    unknown = sorted(set(declared) - set(BRAND_KEYS))
    if unknown:
        raise ValueError(f"{source}: unknown keys {unknown}")
    result: dict[str, Any] = {}
    if "color" in declared:
        if not (isinstance(declared["color"], str) and COLOR.fullmatch(declared["color"])):
            raise ValueError(f"{source}: color must be #RRGGBB")
        result["color"] = declared["color"]
    if "order" in declared:
        order = declared["order"]
        if not isinstance(order, int) or isinstance(order, bool) or order < 0:
            raise ValueError(f"{source}: order must be a non-negative integer")
        result["order"] = order
    if "launched" in declared:
        if declared["launched"] is not True:
            raise ValueError(f"{source}: launched must be true; omit it before launch")
        result["launched"] = True
    if "mark_colours" in declared:
        if declared["mark_colours"] != "own":
            raise ValueError(f"{source}: mark_colours must be 'own'; omit it for a one-colour mark")
        if "mark" not in declared:
            raise ValueError(f"{source}: mark_colours needs a mark")
        result["mark_colours"] = "own"
    for kind, suffix in (("logo", ""), ("mark", "-mark")):
        if kind not in declared:
            continue
        relative = declared[kind]
        file = (folder / relative).resolve() if isinstance(relative, str) else None
        if file is None or not file.is_relative_to(folder.resolve()) or not file.is_file():
            raise ValueError(f"{source}: {kind} must name a file inside the provider folder")
        if file.suffix not in IMAGE_SUFFIXES:
            raise ValueError(f"{source}: {kind} must be one of {', '.join(IMAGE_SUFFIXES)}")
        result[kind] = {
            "file": f"{folder.name}{suffix}{file.suffix}",
            "base64": base64.b64encode(file.read_bytes()).decode("ascii"),
        }
    return result


def publication_receipt(
    provider: str,
    execution_class: str | None,
    reason: str,
    reference: str,
    *,
    default_class: str | None = None,
) -> dict[str, str]:
    """Encode an authorized maintainer decision bound to its exact scope and content.

    The identity schema preserves existing approval hashes. Computing a receipt never
    grants publication authority; the reference records the preceding authorization.
    """
    identity = {
        "schema": "sandbox-provider-spec.publication-decision/1",
        "provider": provider,
        "class": execution_class,
        "approved": True,
        "reason": reason,
        "approved_by": "maintainer",
        "reference": reference,
        "default_class": default_class if execution_class is None else None,
    }
    content = json.dumps(identity, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return {
        "approved_by": "maintainer",
        "reference": reference,
        "content_sha256": hashlib.sha256(content.encode()).hexdigest(),
    }


def _bound_receipt(
    source: Path,
    provider: str,
    execution_class: str | None,
    decision: dict[str, Any],
    default_class: str | None,
) -> None:
    if decision["state"] != "published":
        return
    proof = decision["receipt"]
    expected = publication_receipt(
        provider,
        execution_class,
        decision["reason"],
        proof["reference"],
        default_class=default_class,
    )
    if proof != expected:
        scope = "provider" if execution_class is None else f"class {execution_class}"
        raise ValueError(f"{source}: {scope} receipt differs from its scope or content")


def _receipt(source: Path, where: str, value: object) -> None:
    if not isinstance(value, dict) or set(value) != set(RECEIPT_KEYS):
        raise ValueError(f"{source}: {where} receipt needs exactly {', '.join(RECEIPT_KEYS)}")
    if not _nonblank(value["approved_by"]) or not _nonblank(value["reference"]):
        raise ValueError(f"{source}: {where} receipt names its approver and reference")
    if not (isinstance(value["content_sha256"], str) and SHA256.fullmatch(value["content_sha256"])):
        raise ValueError(f"{source}: {where} receipt content_sha256 must be 64 hex digits")


def _state(source: Path, where: str, entry: dict[str, Any]) -> None:
    if entry.get("state") not in STATES:
        raise ValueError(f"{source}: {where} state must be one of {', '.join(STATES)}")
    if entry["state"] == "published":
        if not _nonblank(entry.get("reason")):
            raise ValueError(f"{source}: published {where} needs a reason")
        _receipt(source, where, entry.get("receipt"))


def publication(folder: Path) -> dict[str, Any]:
    """The folder's publication as release JSON; no file means hidden."""
    source = folder / "publication.yaml"
    if not source.is_file():
        return {"state": "hidden", "classes": {}}
    declared = _load(source)
    _state(source, "provider", declared)
    classes = declared.get("classes")
    if not isinstance(classes, dict) or not all(
        isinstance(name, str) and isinstance(entry, dict) for name, entry in classes.items()
    ):
        raise ValueError(f"{source}: classes must map class names to entries")
    for name, entry in classes.items():
        _state(source, f"class {name}", entry)
    default = declared.get("default_class")
    if declared["state"] != "hidden" and default not in classes:
        raise ValueError(f"{source}: default_class must be one of the declared classes")
    _bound_receipt(source, folder.name, None, declared, default)
    for name, entry in classes.items():
        _bound_receipt(source, folder.name, name, entry, default)
    return declared


def notes(folder: Path) -> dict[str, str] | None:
    """The folder's provider sentences (`notes.yaml`), or None; keys say what each is about."""
    source = folder / "notes.yaml"
    if not source.is_file():
        return None
    declared = _load(source)
    for key, sentence in declared.items():
        if not (isinstance(key, str) and NOTE_KEY.fullmatch(key)):
            raise ValueError(
                f"{source}: note key {key!r} must be lower-case words joined by . _ or -"
            )
        if not _nonblank(sentence):
            raise ValueError(f"{source}: note {key} must be a non-empty sentence")
    return {str(key): str(value).strip() for key, value in declared.items()}


def providers_dir() -> Path:
    """The `providers` folder beside the spec, from source or an installed wheel."""
    source = spec_dir().parent / "providers"
    return source if source.is_dir() else spec_dir() / "providers"


def providers(root: Path | None = None) -> list[Path]:
    base = root / "providers" if root else providers_dir()
    return sorted(path for path in base.iterdir() if path.is_dir())


def build(root: Path | None = None) -> dict[str, dict[str, Any]]:
    """Both release documents, validated; every provider folder appears in publication."""
    brands = {}
    for folder in providers(root):
        declared = brand(folder)
        if declared is not None:
            brands[folder.name] = declared
    sentences = {}
    for folder in providers(root):
        found = notes(folder)
        if found is not None:
            sentences[folder.name] = found
    return {
        "brand.json": {"schema": BRAND_SCHEMA, "providers": brands},
        "notes.json": {"schema": NOTES_SCHEMA, "providers": sentences},
        "publication.json": {
            "schema": PUBLICATION_SCHEMA,
            "providers": {folder.name: publication(folder) for folder in providers(root)},
        },
    }


def arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--out", type=Path, help="write brand.json, publication.json and notes.json here"
    )


def run(args: argparse.Namespace) -> int:
    documents = build()
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        for name, document in documents.items():
            (args.out / name).write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    print(f"provider assets: ok ({len(documents['publication.json']['providers'])} providers)")
    return 0
