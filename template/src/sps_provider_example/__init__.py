# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The template adapter: a 1.0 `Provider` over Example Cloud (`template/fake_cloud/`).

Example Cloud's API is deliberately not shaped like the standard, so each method shows a real
translation; a comment above it names the Example Cloud call it maps. Example Cloud returns no
labels or sizes on a machine, so the adapter keeps them in a JSON file inside the machine
(`META_PATH`); a provider whose API stores machine metadata would read that instead. Example
Cloud lists only running machines, so a replayed create is found only while the first machine runs.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterable, AsyncIterator, Mapping
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import httpx
from sandbox_provider_spec.v1 import (
    ERROR_TABLE,
    Cost,
    CostLine,
    CreateRequest,
    DestroyResult,
    Discovery,
    FileInfo,
    FileStream,
    OutputChunk,
    OutputPage,
    Process,
    ProcessStartRequest,
    Provider,
    RunRequest,
    RunResult,
    Sandbox,
    SandboxPage,
    Size,
    SpsError,
)

from sps_provider_example.create_spec import fingerprint, plan_create
from sps_provider_example.facts import (
    CLASS,
    IMAGE,
    LIMITS,
    LIST_LIMIT,
    MAX_RUN_S,
    MAX_WAIT_S,
    META_PATH,
    PRICE_CPU,
    PRICE_MEM,
    REGION,
    TAG_BODY,
    TAG_IDEM,
    TAG_LABEL,
    build_discovery,
)


def _stamp(text: str) -> datetime:
    return datetime.fromisoformat(text)


class ExampleProvider(Provider):
    """A 1.0 provider over Example Cloud's machine API."""

    def __init__(
        self, credentials: Mapping[str, str], *, transport: httpx.AsyncBaseTransport | None = None
    ) -> None:
        super().__init__(credentials)
        endpoint = self.credentials.get("endpoint", "https://api.example.test")
        self._http = httpx.AsyncClient(
            base_url=endpoint.rstrip("/"),
            headers={"X-Api-Key": self.credentials["api_key"]},
            transport=transport,
            timeout=httpx.Timeout(60.0, connect=10.0),
        )

    # -- transport ------------------------------------------------------------

    @staticmethod
    def _check(resp: httpx.Response) -> None:
        """Map an Example Cloud error body to an `SpsError`; a provider fault is `unknown`."""
        if resp.status_code < 400:
            return
        try:
            body = resp.json()["error"]
            code, message = body["code"], body["message"]
            if code not in ERROR_TABLE:
                raise KeyError(code)
        except (ValueError, KeyError, TypeError):
            raise SpsError(
                "provider_error",
                f"Example Cloud answered HTTP {resp.status_code}",
                outcome="unknown",
            ) from None
        raise SpsError(
            code,
            message[:1024],
            outcome="unknown" if ERROR_TABLE[code][1] == "provider" else "failed",
        )

    async def _req(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        try:
            resp = await self._http.request(method, path, **kwargs)
        except httpx.TimeoutException:
            raise SpsError("timeout", "Example Cloud did not answer", outcome="unknown") from None
        except httpx.HTTPError:
            raise SpsError(
                "unavailable", "Example Cloud is unreachable", outcome="unknown"
            ) from None
        self._check(resp)
        return resp

    async def _json(self, method: str, path: str, **kwargs: Any) -> Any:
        return (await self._req(method, path, **kwargs)).json()

    async def _machines(self, *tags: tuple[str, str], **params: Any) -> dict[str, Any]:
        query: list[tuple[str, str]] = [("tag", f"{k}:{v}") for k, v in tags]
        query += [(k, str(v)) for k, v in params.items()]
        return await self._json("GET", "/machines", params=query)

    async def _read_meta(self, machine_id: str) -> dict[str, Any] | None:
        try:
            resp = await self._req("GET", f"/machines/{machine_id}/fs", params={"path": META_PATH})
        except SpsError as error:
            if error.code == "not_found":
                return None
            raise
        return json.loads(resp.content)

    async def _to_sandbox(self, machine: dict[str, Any]) -> Sandbox:
        mid = machine["machine_id"]
        meta = await self._read_meta(mid)
        if meta is not None:
            size = Size(cpu=meta["size"]["cpu"], memory_mib=meta["size"]["memory_mib"])
            labels = dict(meta["labels"])
        else:
            # The meta file is gone with the container; usage records outlive it.
            usage = await self._json("GET", f"/machines/{mid}/usage")
            size = Size(cpu=usage["cpu"], memory_mib=usage["memory_mb"])
            labels = {}
        ends = _stamp(machine["expires"]) if machine.get("expires") else None
        return Sandbox(
            id=mid,
            sandbox_class=CLASS,
            state="running" if machine["status"] == "running" else "destroyed",
            size=size,
            region=REGION,
            image=IMAGE,
            labels=labels,
            created_at=_stamp(machine["created"]),
            ends_at=ends,
            at_end="destroyed" if ends else None,
        )

    # -- operations ------------------------------------------------------------

    async def discovery(self) -> Discovery:
        # No Example Cloud call returns these facts; listing machines proves the key.
        await self._machines(limit=1)
        return build_discovery()

    async def create(self, request: CreateRequest, *, idempotency_key: str) -> Sandbox:
        # GET /machines?tag=sps.idem:<key> finds a replay, then POST /machines.
        # A provider with unique names would instead send the key as the name at
        # no extra call: `POST /machines {name: idempotency_key, ...}` and map
        # the API's name-conflict error to the replay path.
        spec, meta = plan_create(request)
        spec["tags"].update({TAG_IDEM: idempotency_key, TAG_BODY: fingerprint(request)})
        page = await self._machines((TAG_IDEM, idempotency_key), limit=1)
        if page["machines"]:
            same = await self._machines(
                (TAG_IDEM, idempotency_key), (TAG_BODY, spec["tags"][TAG_BODY]), limit=1
            )
            if not same["machines"]:
                raise SpsError("conflict", "Idempotency-Key was used with a different body")
            return await self._to_sandbox(same["machines"][0])
        machine = await self._json("POST", "/machines", json=spec)
        try:
            raw = json.dumps(meta).encode()
            await self._req(
                "PUT",
                f"/machines/{machine['machine_id']}/fs",
                params={"path": META_PATH},
                content=raw,
                headers={"Content-Length": str(len(raw))},
            )
        except SpsError as error:
            if error.code != "not_found":
                raise
        return await self._to_sandbox(machine)

    async def get(self, sandbox_id: str) -> Sandbox:
        # GET /machines/{id}, with the meta file (or the usage record) for the rest.
        return await self._to_sandbox(await self._json("GET", f"/machines/{sandbox_id}"))

    async def list(
        self,
        *,
        labels: Mapping[str, str] | None = None,
        cursor: str | None = None,
        limit: int = 100,
    ) -> SandboxPage:
        # GET /machines?tag=l.<k>:<v>&page_token= filters on the server where a
        # label fits a tag; "/" keys never became tags and are checked locally.
        tags: list[tuple[str, str]] = []
        local: dict[str, str] = {}
        for key, value in dict(labels or {}).items():
            if "/" in key:
                local[key] = value
            else:
                tags.append((f"{TAG_LABEL}{key}", value))
        params: dict[str, Any] = {"limit": min(limit, LIST_LIMIT)}
        if cursor:
            params["page_token"] = cursor
        page = await self._machines(*tags, **params)
        boxes = [await self._to_sandbox(item) for item in page["machines"]]
        if local:
            boxes = [b for b in boxes if all(b.labels.get(k) == v for k, v in local.items())]
        return SandboxPage(sandboxes=boxes, next_cursor=page["next_page_token"])

    async def destroy(self, sandbox_id: str) -> DestroyResult:
        # DELETE /machines/{id}; usage records outlive the machine, so cost stays
        # readable and the result carries no final cost.
        await self._req("DELETE", f"/machines/{sandbox_id}")
        return DestroyResult(sandbox_id=sandbox_id, state="destroyed", cost=None)

    async def run(self, sandbox_id: str, request: RunRequest) -> RunResult:
        # POST /machines/{id}/exec. A missing workdir is a generic failure there,
        # so a cwd is probed first to give the standard's not_found.
        if request.cwd is not None:
            probe = [
                "python3",
                "-c",
                "import os,sys;sys.exit(not os.path.isdir(sys.argv[1]))",
                request.cwd,
            ]
            check = {"cmd": probe, "timeout_s": 30}
            if (await self._json("POST", f"/machines/{sandbox_id}/exec", json=check))["code"]:
                raise SpsError("not_found", f"No such directory: {request.cwd}")
        body: dict[str, Any] = {
            "cmd": list(request.argv),
            "env": dict(request.env),
            "timeout_s": request.timeout_ms / 1000,
        }
        if request.cwd is not None:
            body["dir"] = request.cwd
        res = await self._json(
            "POST",
            f"/machines/{sandbox_id}/exec",
            json=body,
            timeout=httpx.Timeout(min(body["timeout_s"], MAX_RUN_S) + 60, connect=10.0),
        )
        limit = request.output_limit_bytes
        if not 0 <= limit <= LIMITS.output_bytes:
            raise SpsError("invalid_request", f"output_limit_bytes over {LIMITS.output_bytes}")
        out, err = res["out"].encode(), res["err"].encode()
        return RunResult(
            exit_code=None if res["killed"] else res["code"],
            stdout=out[:limit].decode("utf-8", "replace"),
            stderr=err[:limit].decode("utf-8", "replace"),
            stdout_truncated=len(out) > limit,
            stderr_truncated=len(err) > limit,
            timed_out=bool(res["killed"]),
        )

    async def files_read(self, sandbox_id: str, path: str) -> FileStream:
        # GET /machines/{id}/fs?path= streams the raw bytes.
        ctx = self._http.stream("GET", f"/machines/{sandbox_id}/fs", params={"path": path})
        resp = await ctx.__aenter__()
        if resp.status_code >= 400:
            await resp.aread()
            await ctx.__aexit__(None, None, None)
            self._check(resp)

        async def chunks() -> AsyncIterator[bytes]:
            try:
                async for part in resp.aiter_bytes(1 << 16):
                    yield part
            finally:
                await ctx.__aexit__(None, None, None)

        length = resp.headers.get("content-length")
        return FileStream(size=int(length) if length else None, chunks=chunks())

    async def files_write(
        self, sandbox_id: str, path: str, data: AsyncIterable[bytes], *, size: int
    ) -> FileInfo:
        # PUT /machines/{id}/fs?path= streams the body with the declared length.
        resp = await self._req(
            "PUT",
            f"/machines/{sandbox_id}/fs",
            params={"path": path},
            content=data,
            headers={"Content-Length": str(size)},
            timeout=httpx.Timeout(None, connect=10.0),
        )
        return FileInfo(path=resp.json()["path"], size=resp.json()["size"])

    async def process_start(self, sandbox_id: str, request: ProcessStartRequest) -> Process:
        # POST /machines/{id}/jobs; a job is a detached exec with a retained log.
        if request.stdin:
            raise SpsError("unsupported", "Example Cloud jobs take no stdin")
        body: dict[str, Any] = {"cmd": list(request.argv), "env": dict(request.env)}
        if request.cwd is not None:
            body["dir"] = request.cwd
        job = await self._json("POST", f"/machines/{sandbox_id}/jobs", json=body)
        return Process(id=job["job_id"], sandbox_id=sandbox_id, started_at=datetime.now(UTC))

    async def process_output(
        self, sandbox_id: str, process_id: str, *, cursor: str | None = None, wait_ms: int = 0
    ) -> OutputPage:
        # GET /machines/{id}/jobs/{job}/log?offset=&wait= long-polls the retained log.
        params: dict[str, Any] = {"wait": min(wait_ms / 1000, MAX_WAIT_S)}
        if cursor:
            params["offset"] = cursor
        log = await self._json(
            "GET",
            f"/machines/{sandbox_id}/jobs/{process_id}/log",
            params=params,
            timeout=httpx.Timeout(MAX_WAIT_S + 30, connect=10.0),
        )
        chunks = [
            OutputChunk(s, log[k]) for s, k in (("stdout", "out"), ("stderr", "err")) if log[k]
        ]
        # The log keeps only the newest window; the server never says where it
        # starts, so a discarded span shows as a shorter answer than requested.
        gap = False
        if cursor:
            req_out, req_err = (int(part) for part in cursor.split("."))
            end_out, end_err = (int(part) for part in log["offset"].split("."))
            gap = (
                len(log["out"].encode()) < end_out - req_out
                or len(log["err"].encode()) < end_err - req_err
            )
        done = bool(log["done"])
        return OutputPage(
            chunks=chunks,
            next_cursor=log["offset"],
            gap=gap,
            stdout_closed=done,
            stderr_closed=done,
            state="exited" if done else "running",
            exit_code=log["code"] if done else None,
        )

    async def cost(self, sandbox_id: str) -> Cost:
        # GET /machines/{id}/usage; the price list in discovery prices the record.
        usage = await self._json("GET", f"/machines/{sandbox_id}/usage")
        start = _stamp(usage["started"])
        end = _stamp(usage["ended"]) if usage["ended"] else datetime.now(UTC)
        seconds = Decimal(str(max((end - start).total_seconds(), 0.0)))
        cpu_q = Decimal(str(usage["cpu"])) * seconds
        mem_q = Decimal(str(usage["memory_mb"])) / 1024 * seconds
        lines = (
            CostLine("cpu", cpu_q, "vcpu_second", cpu_q * PRICE_CPU, start, end),
            CostLine("memory", mem_q, "gib_second", mem_q * PRICE_MEM, start, end),
        )
        return Cost(
            sandbox_id=sandbox_id,
            status="final" if usage["ended"] else "accruing",
            total_usd=sum(line.amount_usd for line in lines),
            source="calculated",
            lines=lines,
            as_of=datetime.now(UTC),
        )

    async def aclose(self) -> None:
        await self._http.aclose()
