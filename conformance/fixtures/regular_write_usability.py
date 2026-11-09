# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Guest observer for regular-file write usability. Emits bounded JSON only."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys

ARGUMENTS = "SPS_REGULAR_WRITE_ARGUMENTS"


def observe(path: str) -> dict[str, object]:
    try:
        info = os.lstat(path)
    except OSError as error:
        return {"exists": False, "errno": int(error.errno or 0)}
    mode = stat.S_IMODE(info.st_mode)
    return {
        "exists": True,
        "size": int(info.st_size),
        "mode": oct(mode),
        "uid": int(info.st_uid),
        "gid": int(info.st_gid),
        "readable": os.access(path, os.R_OK),
        "writable": os.access(path, os.W_OK),
        "executable": os.access(path, os.X_OK),
        "sha256": _digest(path) if stat.S_ISREG(info.st_mode) else None,
    }


def _digest(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    raw = os.environ.get(ARGUMENTS, "")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        print("invalid_arguments", file=sys.stderr)
        return 2
    path = payload.get("path")
    if not isinstance(path, str) or not path.startswith("/"):
        print("invalid_path", file=sys.stderr)
        return 2
    print(json.dumps(observe(path), separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
