# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Public Core binding identities used by the SPS 0.3.130 handover checks."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping

_FIELDS = ("native_id", "incarnation", "created_at_ms", "session_id")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


def public_core_binding_digest(  # pylint: disable=too-many-boolean-expressions
    binding: Mapping[str, object],
) -> tuple[str, list[str]]:
    """Hash all actual public Core binding fields and return their captured-value basis."""
    if not isinstance(binding, Mapping) or set(binding) != set(_FIELDS):
        raise ValueError("A complete public Core SandboxBinding is required")
    native_id, incarnation, created_at_ms, session_id = (binding[name] for name in _FIELDS)
    if (
        not isinstance(native_id, str)
        or not native_id
        or (incarnation is not None and (not isinstance(incarnation, str) or not incarnation))
        or (
            created_at_ms is not None
            and (isinstance(created_at_ms, bool) or not isinstance(created_at_ms, int))
        )
        or (session_id is not None and (not isinstance(session_id, str) or not session_id))
    ):
        raise ValueError("Public Core SandboxBinding fields are invalid")
    basis = [name for name in _FIELDS if name == "native_id" or binding[name] is not None]
    encoded = json.dumps(
        {name: binding[name] for name in _FIELDS},
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return "sha256:" + hashlib.sha256(encoded.encode()).hexdigest(), basis


def public_core_binding_identity_valid(digest: object, basis: object) -> bool:
    """Validate the closed, ordered identity basis and digest syntax in a typed report."""
    return (
        isinstance(digest, str)
        and _DIGEST.fullmatch(digest) is not None
        and isinstance(basis, list)
        and bool(basis)
        and all(isinstance(field, str) for field in basis)
        and len(basis) == len(set(basis))
        and basis[0] == "native_id"
        and basis == [field for field in _FIELDS if field in basis]
    )


def public_core_binding_identity_matches(
    binding: Mapping[str, object], digest: object, basis: object
) -> bool:
    """Reject a digest/basis pair that differs from the actual captured Core binding."""
    try:
        expected_digest, expected_basis = public_core_binding_digest(binding)
    except (TypeError, ValueError):
        return False
    return (
        public_core_binding_identity_valid(digest, basis)
        and digest == expected_digest
        and basis == expected_basis
    )
