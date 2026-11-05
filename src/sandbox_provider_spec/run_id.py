# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""One run id per live run, carried by every native resource the run creates.

Provider accounts are shared: several runs may use one account at the same time. A run
therefore names or labels everything it creates with its own id, deletes only that, and
proves cleanup by showing that nothing with its id remains. Other runs' resources are
never compared, adopted or deleted.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import time
from uuid import uuid4

#: The environment variable that fixes the run id, for example `shared-accounts-1`.
ENVIRONMENT = "SPS_RUN_ID"

#: Names that carry a run: `sps-r<8 hex>-<minutes since the epoch in base 36>-<unique part>`.
#: Nothing else is a run's resource; the stamp lets a sweeper age a resource by its name alone.
TOKEN_PATTERN = re.compile(r"(?<![0-9A-Za-z-])sps-(r[0-9a-f]{8})-([0-9a-z]{5})-")

#: This process's run id, fixed on first use.
_RUN: str | None = None


def run_id() -> str:
    """`SPS_RUN_ID` if set, else `<lane>-<UTC YYYYMMDDTHHMMSSZ>-<4 hex>`; fixed per run."""
    global _RUN  # pylint: disable=global-statement
    if _RUN is None:
        configured = os.environ.get(ENVIRONMENT, "").strip()
        _RUN = configured or (
            f"{os.environ.get('SPS_LANE', 'run')}-"
            f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{secrets.token_hex(2)}"
        )
    return _RUN


def token(identity: str | None = None) -> str:
    """The short, name-safe form of the run id: `r` and eight hex digits."""
    digest = hashlib.sha256((identity or run_id()).encode()).hexdigest()
    return f"r{digest[:8]}"


def _base36(number: int) -> str:
    digits = ""
    while number:
        number, digit = divmod(number, 36)
        digits = "0123456789abcdefghijklmnopqrstuvwxyz"[digit] + digits
    return digits.rjust(5, "0")


def native_name(unique: int = 32, *, middle: str = "") -> str:
    """A unique native name that carries this run: `sps-<token>-<stamp>[-<middle>]-<hex>`."""
    infix = f"-{middle}" if middle else ""
    stamp = _base36(int(time.time() // 60))
    return f"sps-{token()}-{stamp}{infix}-{uuid4().hex[:unique]}"


def created_by_a_run(name: str) -> tuple[str, float] | None:
    """The run token and creation time (epoch seconds) a native name carries, else None.

    None means no run of this suite made the resource, so no run may delete it.
    """
    found = TOKEN_PATTERN.search(name)
    return (found.group(1), int(found.group(2), 36) * 60.0) if found else None


def own_run(name: str) -> bool:
    """Whether this process's run created the named resource."""
    found = created_by_a_run(name)
    return found is not None and found[0] == token()


def stale(name: str, ttl_seconds: float, *, now: float | None = None) -> bool:
    """Whether a run's resource is older than the TTL. Anything else is never stale."""
    found = created_by_a_run(name)
    return found is not None and (time.time() if now is None else now) - found[1] > ttl_seconds
