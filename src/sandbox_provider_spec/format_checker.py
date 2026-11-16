# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The JSON Schema formats SPS validates, independent of optional packages."""

from __future__ import annotations

import re
from datetime import date

from jsonschema import FormatChecker

_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", re.ASCII)
_DATE_TIME = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]"
    r"(?:\.[0-9]+)?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])",
    re.ASCII,
)


def _valid_date(value: object) -> bool:
    if not isinstance(value, str):
        return True
    return bool(_DATE.fullmatch(value) and date.fromisoformat(value))


def _valid_date_time(value: object) -> bool:
    if not isinstance(value, str):
        return True
    normalized = value.upper()
    if not _DATE_TIME.fullmatch(normalized):
        return False
    return _valid_date(normalized[:10])


def sps_format_checker() -> FormatChecker:
    """Check SPS date formats only; URI formats are deliberately not validated."""
    checker = FormatChecker(formats=())
    checker.checks("date", raises=ValueError)(_valid_date)
    checker.checks("date-time", raises=ValueError)(_valid_date_time)
    return checker
