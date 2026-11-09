# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Predicates used to compare a request with declared knob grants."""

from __future__ import annotations

from typing import Any, TypedDict


class GrantedValue(TypedDict):
    value: Any


class KnobGrant(TypedDict):
    """The values a chosen variant grants, or None where an unasked knob is unknown."""

    values: list[GrantedValue] | None


def _granted(grant: KnobGrant | None, value: Any) -> bool:
    """The grant holds the value, or with a tuple of values, one of them."""
    wanted = value if isinstance(value, tuple) else (value,)
    return (
        grant is not None
        and grant["values"] is not None
        and any(granted["value"] in wanted for granted in grant["values"])
    )


def _any_granted(grants: dict[str, KnobGrant], conditions: tuple[tuple[str, Any], ...]) -> bool:
    return any(_granted(grants.get(knob), value) for knob, value in conditions)
