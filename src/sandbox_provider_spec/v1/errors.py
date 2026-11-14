# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The twelve error codes of the 1.0 provider API and the exception that carries them."""

from __future__ import annotations

from typing import Literal, get_args

ErrorCode = Literal[
    "invalid_request",
    "unauthenticated",
    "forbidden",
    "not_found",
    "conflict",
    "too_large",
    "unsupported",
    "quota_exceeded",
    "rate_limited",
    "unavailable",
    "timeout",
    "provider_error",
]
Outcome = Literal["failed", "unknown"]
Fault = Literal["caller", "provider"]

# Each code with the HTTP status that mirrors it and the party at fault. The code is
# authoritative; the status only mirrors it.
ERROR_TABLE: dict[ErrorCode, tuple[int, Fault]] = {
    "invalid_request": (400, "caller"),
    "unauthenticated": (401, "caller"),
    "forbidden": (403, "caller"),
    "not_found": (404, "caller"),
    "conflict": (409, "caller"),
    "too_large": (413, "caller"),
    "unsupported": (422, "caller"),
    "quota_exceeded": (402, "caller"),
    "rate_limited": (429, "caller"),
    "unavailable": (503, "provider"),
    "timeout": (504, "provider"),
    "provider_error": (500, "provider"),
}
PROVIDER_FAULT: frozenset[ErrorCode] = frozenset(
    code for code, (_, fault) in ERROR_TABLE.items() if fault == "provider"
)

assert set(ERROR_TABLE) == set(get_args(ErrorCode))


class SpsError(Exception):
    """An operation failed. `str()` is `<code>: <message>`.

    `outcome` says whether the operation had any effect: "failed" means none, "unknown" means
    that it may have taken effect. A caller-fault code always has outcome "failed".
    """

    code: ErrorCode
    message: str
    outcome: Outcome
    retry_after_seconds: int | None

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        *,
        outcome: Outcome = "failed",
        retry_after_seconds: int | None = None,
    ) -> None:
        if code not in ERROR_TABLE:
            raise ValueError(f"unknown error code: {code!r}")
        if outcome not in ("failed", "unknown"):
            raise ValueError(f"unknown outcome: {outcome!r}")
        if outcome == "unknown" and ERROR_TABLE[code][1] == "caller":
            raise ValueError(f"{code} is a caller fault, so its outcome is always 'failed'")
        if retry_after_seconds is not None and retry_after_seconds < 0:
            raise ValueError("retry_after_seconds cannot be negative")
        super().__init__(code, message)
        self.code = code
        self.message = message
        self.outcome = outcome
        self.retry_after_seconds = retry_after_seconds

    @property
    def http_status(self) -> int:
        return ERROR_TABLE[self.code][0]

    @property
    def fault(self) -> Fault:
        return ERROR_TABLE[self.code][1]

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"
