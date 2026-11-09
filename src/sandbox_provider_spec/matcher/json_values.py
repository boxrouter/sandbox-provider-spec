# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""JSON value equality shared by report identity and extension matching."""

from __future__ import annotations

from typing import Any


def same_value(offered: Any, asked: Any) -> bool:
    """Compare JSON values without treating booleans as numbers."""
    if isinstance(offered, bool) or isinstance(asked, bool):
        return type(offered) is type(asked) and offered == asked
    if isinstance(offered, dict) and isinstance(asked, dict):
        return offered.keys() == asked.keys() and all(
            same_value(offered[key], value) for key, value in asked.items()
        )
    if isinstance(offered, list) and isinstance(asked, list):
        return len(offered) == len(asked) and all(
            same_value(left, right) for left, right in zip(offered, asked, strict=True)
        )
    return bool(offered == asked)
