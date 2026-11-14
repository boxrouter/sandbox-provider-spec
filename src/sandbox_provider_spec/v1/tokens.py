# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The bearer token of a served provider that declares several credential fields.

The token is `sps1.` followed by the unpadded base64url encoding of a JSON object that maps
every declared field name to its value. A provider with one field uses the value itself.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Mapping, Sequence

from sandbox_provider_spec.v1.errors import SpsError

PREFIX = "sps1."


def encode(fields: Mapping[str, str]) -> str:
    """The token for these credential fields."""
    for name, value in fields.items():
        if not isinstance(value, str):
            raise TypeError(f"credential field {name!r} must be a string")
    body = json.dumps(dict(fields), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return PREFIX + base64.urlsafe_b64encode(body.encode("utf-8")).rstrip(b"=").decode("ascii")


def decode(token: str, field_names: Sequence[str]) -> dict[str, str]:
    """The credential fields in a token. Raises `unauthenticated` unless the token decodes to
    exactly the declared fields. The error never repeats any part of the token."""
    bad = SpsError("unauthenticated", "The token is not valid for this provider")
    if not token.startswith(PREFIX):
        raise bad
    encoded = token[len(PREFIX) :]
    if not encoded.isascii() or "=" in encoded:
        raise bad
    try:
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        value = json.loads(raw.decode("utf-8"))
    except (binascii.Error, UnicodeDecodeError, ValueError):
        raise bad from None
    if not isinstance(value, dict) or set(value) != set(field_names):
        raise bad
    if not all(isinstance(item, str) for item in value.values()):
        raise bad
    return {name: value[name] for name in field_names}
