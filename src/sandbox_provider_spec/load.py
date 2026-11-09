# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The strict YAML and JSON loader. A duplicate key is an error."""

from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Any

import yaml


class DuplicateKeyError(ValueError):
    """A mapping repeated a key."""


class _UniqueKeyLoader(yaml.SafeLoader):
    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> Any:
        seen: set[Any] = set()
        for key_node, _value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in seen:
                raise DuplicateKeyError(f"duplicate key: {key}")
            seen.add(key)
        return super().construct_mapping(node, deep)


def _json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise DuplicateKeyError(f"duplicate key: {key}")
        document[key] = value
    return document


def _plain(value: Any) -> str:
    """YAML dates are citations, not objects. Anything else cannot be stored."""
    if isinstance(value, datetime.date):
        return value.isoformat()
    raise TypeError(f"unsupported YAML value: {type(value).__name__}")


def load(path: str | Path) -> Any:
    """Load one YAML or JSON document. Duplicate keys raise DuplicateKeyError."""
    file = Path(path)
    text = file.read_text(encoding="utf-8")
    if file.suffix == ".json":
        return json.loads(text, object_pairs_hook=_json_pairs)
    document = yaml.load(text, Loader=_UniqueKeyLoader)
    return json.loads(json.dumps(document, default=_plain))
