<!-- SPDX-FileCopyrightText: BoxRouter, Inc. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Example Cloud

Example Cloud is a small fake machine provider. It serves a plain HTTP API
that runs every machine as a local Docker container, so tools can exercise a
provider-shaped API end to end without a real account. It keeps its own
usage records in SQLite, so cost and usage data outlive each machine.

It is deliberately **not** shaped like the provider contract this repository
defines: the template adapter next to it shows a real translation between an
existing provider API and the standard.

## Requirements

- Python 3.11+, with `docker` (the `docker` extra of this package) and `uvicorn`
- A local Docker daemon
- The machine image, pulled once:

  ```console
  $ docker pull python:3.13-slim@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f
  ```

  The image is pinned by digest and provides `bash` and `python3`. Override
  it with `--image <ref>`.

## Run

```console
$ python template/fake_cloud/server.py --port 18080 --state-dir /tmp/example-cloud
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--host` | `127.0.0.1` | Bind address |
| `--port` | (required) | Bind port |
| `--state-dir` | (required) | Directory for the SQLite usage database |
| `--owner` | `example-<pid>` | Label namespace for this server's machines |
| `--image` | the pinned image above | Machine image |

Every request needs a non-empty `X-Api-Key` header; any value is accepted
and a missing or empty one gets `401`. `GET /healthz` is unauthenticated.

## API

| Call | Request → result |
| --- | --- |
| `POST /machines` | `{cpu, memory_mb, ttl_seconds, env, tags}` → `{machine_id, status, created, expires}` |
| `GET /machines/{id}` | → the same object; `status` is `running` or `ended` |
| `GET /machines?tag=<k>:<v>&page_token=&limit=` | → `{machines: [...], next_page_token}`; lists only running machines, `tag` may repeat |
| `DELETE /machines/{id}` | → `{status}`; repeating on an ended machine still succeeds |
| `POST /machines/{id}/exec` | `{cmd: [...], dir, env, timeout_s}` → `{code, out, err, killed}`; `killed` means the timeout ended the command |
| `GET` and `PUT /machines/{id}/fs?path=` | raw bytes in both directions, streamed; `PUT` needs `Content-Length` and the parent directory must exist |
| `POST /machines/{id}/jobs` | `{cmd: [...], dir, env}` → `{job_id}`; a job keeps running after the call returns |
| `GET /machines/{id}/jobs/{job_id}/log?offset=&wait=` | → `{out, err, offset, done, code}`; `offset` is `<stdout_pos>.<stderr_pos>`, `wait` long-polls up to 60 s |
| `GET /machines/{id}/usage` | → `{cpu, memory_mb, started, ended}`; `ended` is null while the machine runs |

Errors look like `{"error": {"code": "not_found", "message": "..."}}` with a
matching HTTP status.

## How machines work

- A machine is a container named `ec-<machine_id>` running `sleep
  <ttl_seconds>` (`sleep infinity` for a null ttl) with `auto_remove`, so
  Docker ends it when its lifetime runs out even if this server has stopped.
- `cpu` and `memory_mb` become the container's CPU and memory limits. `env`
  becomes the container environment; `exec` and `jobs` add theirs per call.
- `tags` become container labels `example.tag.<k>`, alongside
  `example.owner`, `example.machine_id`, `example.created` and
  `example.expires`.
- Usage records (`usage.db` in the state directory) are kept for 30 days
  after a machine ends and are pruned lazily.

## Limits of the fake

- `exec` keeps at most 16 MiB of output per stream; a job's log keeps the
  newest 4 MiB per stream. An offset older than the kept window reads from
  the window's start.
- `exec` output is capped in memory; `fs` is the only truly streamed
  operation. File reads and writes stream raw bytes through the Docker
  archive API in both directions, so a multi-gigabyte file never sits in
  memory.
- A job's record is kept for ten minutes after it exits; then `log`
  returns `not_found`.
- There is one account, one region and no TLS; `X-Api-Key` only checks
  presence.

## Tests

```console
$ uv run --locked pytest template/fake_cloud/tests -q
```

The tests start the server on a loopback port and create real containers.
They skip with a stated reason when no local Docker daemon is reachable.
