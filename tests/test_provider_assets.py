# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Brand and publication files are validated and packaged for consumers."""

from __future__ import annotations

import base64
import copy
from pathlib import Path
from typing import Any

import pytest
import yaml

from sandbox_provider_spec import provider_assets

RECEIPT = provider_assets.publication_receipt(
    "sixth", None, "approved", "decision", default_class="default"
)
CLASS_RECEIPT = provider_assets.publication_receipt("sixth", "default", "approved", "decision")
PUBLISHED = {
    "state": "published",
    "default_class": "default",
    "reason": "approved",
    "receipt": RECEIPT,
    "classes": {
        "default": {"state": "published", "reason": "approved", "receipt": CLASS_RECEIPT},
        "vm": {"state": "hidden", "reason": "not approved"},
    },
}


def provider(tmp_path: Path, name: str, **files: Any) -> Path:
    folder = tmp_path / "providers" / name
    folder.mkdir(parents=True)
    for filename, content in files.items():
        target = folder / filename.replace("__", "/")
        target.parent.mkdir(exist_ok=True)
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(yaml.safe_dump(content) if not isinstance(content, str) else content)
    return folder


def test_shipped_providers_build_both_documents() -> None:
    documents = provider_assets.build()
    brands = documents["brand.json"]["providers"]
    states = documents["publication.json"]["providers"]
    assert set(brands) <= set(states)
    for declared in brands.values():
        assert declared["color"].startswith("#")
        for kind in ("logo", "mark"):
            assert base64.b64decode(declared[kind]["base64"])
    for declared in states.values():
        assert declared["state"] in provider_assets.STATES


def test_missing_files_mean_hidden_and_no_brand(tmp_path: Path) -> None:
    provider(tmp_path, "sixth")
    documents = provider_assets.build(tmp_path)
    assert documents["publication.json"]["providers"]["sixth"] == {"state": "hidden", "classes": {}}
    assert documents["brand.json"]["providers"] == {}


def test_brand_embeds_the_named_assets(tmp_path: Path) -> None:
    provider(
        tmp_path,
        "sixth",
        **{
            "brand.yaml": {
                "order": 2,
                "color": "#112233",
                "logo": "brand/logo.svg",
                "mark": "brand/mark.png",
            },
            "brand__logo.svg": "<svg/>",
            "brand__mark.png": b"\x89PNG",
        },
    )
    declared = provider_assets.build(tmp_path)["brand.json"]["providers"]["sixth"]
    assert declared["color"] == "#112233"
    assert declared["order"] == 2
    assert declared["logo"]["file"] == "sixth.svg"
    assert declared["mark"]["file"] == "sixth-mark.png"
    assert base64.b64decode(declared["logo"]["base64"]) == b"<svg/>"


@pytest.mark.parametrize(
    "brand",
    [
        {"color": "red"},
        {"order": -1},
        {"order": "first"},
        {"logo": "../escape.svg"},
        {"logo": "missing.svg"},
        {"logo": "brand/logo.gif"},
        {"unknown": 1},
    ],
)
def test_bad_brand_is_refused(tmp_path: Path, brand: dict[str, Any]) -> None:
    provider(
        tmp_path, "sixth", **{"brand.yaml": brand, "brand__logo.gif": b"GIF", "escape.svg": "x"}
    )
    with pytest.raises(ValueError):
        provider_assets.build(tmp_path)


def test_published_needs_receipts_at_both_levels(tmp_path: Path) -> None:
    provider(tmp_path, "sixth", **{"publication.yaml": PUBLISHED})
    assert (
        provider_assets.build(tmp_path)["publication.json"]["providers"]["sixth"]["state"]
        == "published"
    )
    for path in (("receipt",), ("classes", "default", "receipt"), ("reason",)):
        broken = copy.deepcopy(PUBLISHED)
        node: Any = broken
        for key in path[:-1]:
            node = node[key]
        del node[path[-1]]
        other = tmp_path / "other"
        provider(other, "sixth", **{"publication.yaml": broken})
        with pytest.raises(ValueError):
            provider_assets.build(other)
        (other / "providers/sixth/publication.yaml").unlink()
        (other / "providers/sixth").rmdir()


def test_candidate_and_hidden_need_no_receipt(tmp_path: Path) -> None:
    candidate = {
        "state": "candidate",
        "default_class": "default",
        "classes": {"default": {"state": "candidate"}},
    }
    provider(tmp_path, "sixth", **{"publication.yaml": candidate})
    provider(tmp_path, "seventh", **{"publication.yaml": {"state": "hidden", "classes": {}}})
    states = provider_assets.build(tmp_path)["publication.json"]["providers"]
    assert states["sixth"]["state"] == "candidate"
    assert states["seventh"]["state"] == "hidden"


@pytest.mark.parametrize(
    "change",
    [
        {"state": "live"},
        {"default_class": "absent"},
        {"classes": ["default"]},
        {"receipt": {**RECEIPT, "content_sha256": "short"}},
    ],
)
def test_bad_publication_is_refused(tmp_path: Path, change: dict[str, Any]) -> None:
    provider(tmp_path, "sixth", **{"publication.yaml": {**PUBLISHED, **change}})
    with pytest.raises(ValueError):
        provider_assets.build(tmp_path)


def test_notes_are_packaged_and_checked(tmp_path: Path) -> None:
    provider(
        tmp_path, "sixth", **{"notes.yaml": {"fact.open_source": "Sixth publishes its runtime."}}
    )
    provider(tmp_path, "seventh")
    documents = provider_assets.build(tmp_path)
    assert documents["notes.json"]["providers"] == {
        "sixth": {"fact.open_source": "Sixth publishes its runtime."}
    }
    for bad in ({"Bad Key": "x"}, {"fact.open_source": " "}, {"fact.open_source": 3}):
        other = tmp_path / "other"
        provider(other, "sixth", **{"notes.yaml": bad})
        with pytest.raises(ValueError):
            provider_assets.build(other)
        (other / "providers/sixth/notes.yaml").unlink()
        (other / "providers/sixth").rmdir()


@pytest.mark.parametrize(
    "path,value",
    [
        (("reason",), "another decision"),
        (("receipt", "reference"), "another authority"),
        (("receipt", "approved_by"), "another approver"),
        (("classes", "default", "reason"), "another class decision"),
        (("classes", "default", "receipt"), RECEIPT),
        (("default_class",), "vm"),
    ],
)
def test_changed_publication_content_is_refused(
    tmp_path: Path, path: tuple[str, ...], value: Any
) -> None:
    changed = copy.deepcopy(PUBLISHED)
    node: Any = changed
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    provider(tmp_path, "sixth", **{"publication.yaml": changed})
    with pytest.raises(ValueError, match="receipt differs"):
        provider_assets.build(tmp_path)


def test_publication_receipt_cannot_be_reused_for_another_provider(tmp_path: Path) -> None:
    provider(tmp_path, "seventh", **{"publication.yaml": PUBLISHED})
    with pytest.raises(ValueError, match="receipt differs"):
        provider_assets.build(tmp_path)
