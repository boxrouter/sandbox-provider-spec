# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Guest-only observations of a real remote FUSE mount and a retained writer descriptor."""

import errno
import hashlib
import json
import os
import sys
import time
from pathlib import Path


def mounted(path: Path) -> bool:
    """Require this exact mountpoint to be a FUSE filesystem, not a local directory."""
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        left, right = line.split(" - ", 1)
        fields = left.split()
        mountpoint = fields[4].replace("\\040", " ").replace("\\134", "\\")
        if mountpoint == str(path) and right.split()[0].startswith("fuse"):
            return True
    return False


def write(path: Path, value: bytes) -> None:
    with path.open("wb") as handle:
        handle.write(value)
        handle.flush()
        os.fsync(handle.fileno())


def observe(mode: str, mount: Path, control: Path, nonce: str) -> dict[str, object]:
    target = mount / ("sps-fuse-" + nonce)
    first = (nonce + ":initial").encode()
    edited = (nonce + ":edited").encode()
    successor = (nonce + ":successor").encode()
    if mode == "hold":
        with target.open("r+b", buffering=0) as handle:
            # A successful write/fsync on this same descriptor precedes fencing.
            handle.seek(0)
            handle.write(edited)
            os.fsync(handle.fileno())
            control.write_text("ready")
            deadline = time.monotonic() + 90
            while control.read_text() != "fence-complete":
                if time.monotonic() >= deadline:
                    raise TimeoutError("fencing was not requested")
                time.sleep(0.05)
            try:
                handle.seek(0)
                handle.write((nonce + ":stale").encode())
                os.fsync(handle.fileno())
            except OSError as error:
                return {
                    "fenced": error.errno in {errno.EIO, errno.EROFS, errno.ESTALE},
                    "errno": error.errno,
                }
            return {"fenced": False, "errno": 0}
    if not mounted(mount):
        raise RuntimeError("fixture path is not an exact FUSE mount")
    if mode == "write":
        write(target, first)
    elif mode == "edit":
        if target.read_bytes() != first:
            raise RuntimeError("initial data mismatch")
        write(target, edited)
    elif mode == "resume":
        if target.read_bytes() != edited:
            raise RuntimeError("checkpoint data mismatch")
        write(target, successor)
    elif mode == "verify":
        if target.read_bytes() != successor:
            raise RuntimeError("stale writer changed successor data")
    else:
        raise ValueError("unknown phase")
    return {
        "verified": True,
        "uid": os.getuid(),
        "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
    }


if __name__ == "__main__":
    print(json.dumps(observe(sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4])))
