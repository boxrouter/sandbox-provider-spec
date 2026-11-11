# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""One bounded strict parse per exact file content, shared by the catalog, digest and evidence
readers."""

import hashlib
import json
import threading
from collections import OrderedDict
from pathlib import Path
from typing import Any

import yaml

from sandbox_provider_spec.load import _json_pairs, _plain, _UniqueKeyLoader

_DOCUMENT_TEXTS = 4
_document_texts: OrderedDict[tuple[str, str], str] = OrderedDict()
_document_texts_lock = threading.Lock()

_FastLoader: type[_UniqueKeyLoader] = _UniqueKeyLoader
if yaml.__with_libyaml__:

    class _CUniqueKeyLoader(yaml.CSafeLoader, _UniqueKeyLoader):
        """libyaml's parser with the strict loader's constructors and duplicate-key refusal."""

    _FastLoader = _CUniqueKeyLoader


def _parse(suffix: str, content: bytes) -> Any:
    """The document `load` returns for a file with these bytes, parsed by libyaml when present."""
    text = content.decode("utf-8")
    if suffix == ".json":
        return json.loads(text, object_pairs_hook=_json_pairs)
    try:
        document = yaml.load(text, Loader=_FastLoader)
    except yaml.YAMLError:
        # libyaml words syntax errors differently; raise the pure-Python parser's error.
        document = yaml.load(text, Loader=_UniqueKeyLoader)
    return json.loads(json.dumps(document, default=_plain))


def cached_load(path: Path, *, content: bytes | None = None) -> Any:
    """`load(path)`'s document, parsed once per exact content; each caller gets its own copy.

    A caller that checked a digest passes the bytes it hashed as `content`; otherwise the file is
    read on every call. The cache key is the file suffix and the SHA-256 of the bytes parsed, so
    a rewrite of the same size and modification time still reparses. A parse that raises, or a
    document JSON cannot round-trip (a NaN), is not stored.
    """
    source = path.read_bytes() if content is None else content
    key = (path.suffix, hashlib.sha256(source).hexdigest())
    with _document_texts_lock:
        if key in _document_texts:
            _document_texts.move_to_end(key)
            return json.loads(_document_texts[key])
    document = _parse(path.suffix, source)
    text = json.dumps(document)
    restored = json.loads(text)
    if restored != document:
        return document
    with _document_texts_lock:
        _document_texts[key] = text
        _document_texts.move_to_end(key)
        while len(_document_texts) > _DOCUMENT_TEXTS:
            _document_texts.popitem(last=False)
    return restored
