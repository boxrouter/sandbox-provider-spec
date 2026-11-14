# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""A smoke check for the template adapter against a running Example Cloud.

Creates a sandbox, runs `echo hi`, writes and reads a file, destroys the
sandbox and reads its cost, then prints `smoke ok`.

    python template/scripts/smoke.py --endpoint http://127.0.0.1:18080 --api-key dev
"""

from __future__ import annotations

import argparse
import asyncio
from collections.abc import AsyncIterator

from sandbox_provider_spec.v1 import CreateRequest, RunRequest

from sps_provider_example import ExampleProvider


async def _one(data: bytes) -> AsyncIterator[bytes]:
    yield data


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--api-key", default="dev")
    args = parser.parse_args()

    provider = ExampleProvider({"api_key": args.api_key, "endpoint": args.endpoint})
    box = await provider.create(CreateRequest(lifetime_seconds=300), idempotency_key="smoke-run-1")

    result = await provider.run(box.id, RunRequest(argv=["echo", "hi"]))
    assert result.stdout.strip() == "hi", result.stdout

    await provider.files_write(box.id, "/tmp/smoke.txt", _one(b"hello smoke"), size=11)
    stream = await provider.files_read(box.id, "/tmp/smoke.txt")
    read = b"".join([part async for part in stream.chunks])
    assert read == b"hello smoke", read

    await provider.destroy(box.id)
    cost = await provider.cost(box.id)
    assert cost.status == "final" and cost.source == "calculated", cost

    await provider.aclose()
    print("smoke ok")


if __name__ == "__main__":
    asyncio.run(main())
