# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""One bounded parse owner for the catalog and exact-byte report evidence."""

import hashlib
import json
import threading
from collections import OrderedDict
from pathlib import Path
from typing import Any

import yaml

from sandbox_provider_spec.load import load

_DOCUMENT_TEXTS = 4
_document_texts: OrderedDict[tuple[str, bool, str], str] = OrderedDict()
_document_texts_lock = threading.Lock()


def cached_load(path: Path, *, yaml_content: bytes | None = None) -> Any:
    """Reuse a bounded JSON parse by exact bytes and parser; return fresh caller data.

    Evidence supplies the bytes whose digest it checked and keeps its safe-YAML parser.
    The catalog uses the strict loader. Non-JSON values retain their original types and
    are not stored. A file changed during parsing is returned but not stored.
    """
    strict = yaml_content is None
    source = path.read_bytes() if yaml_content is None else yaml_content
    key = (path.suffix, strict, hashlib.sha256(source).hexdigest())
    with _document_texts_lock:
        if key in _document_texts:
            _document_texts.move_to_end(key)
            return json.loads(_document_texts[key])
    document = load(path) if strict else yaml.safe_load(source)
    try:
        text = json.dumps(document)
        restored = json.loads(text)
    except (TypeError, ValueError):
        return document
    if restored != document or (strict and path.read_bytes() != source):
        return document
    with _document_texts_lock:
        _document_texts[key] = text
        _document_texts.move_to_end(key)
        while len(_document_texts) > _DOCUMENT_TEXTS:
            _document_texts.popitem(last=False)
    return restored
