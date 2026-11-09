# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Shared timestamp parsing helpers."""

from __future__ import annotations

from datetime import datetime


def parse_aware_datetime(value: object) -> datetime | None:
    """Parse an ISO 8601 timestamp only when it carries an explicit UTC offset."""
    if not isinstance(value, str):
        return None
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        return None
    return timestamp
