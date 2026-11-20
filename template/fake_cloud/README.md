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
| `GET` and `PUT /machines/{id}/fs?path=` | raw bytes in both directions, streamed; `PUT` needs `Content-Length`; a missing parent directory is `404` and nothing is created |
| `GET /machines/{id}/fs?op=ls&path=&after=&max=` | → `{items: [{name, kind, bytes}], after}`; `kind` is `file`, `dir`, `link` or `other`, `bytes` is the entry's own size, items are sorted by name, `max` is 1 to 1000 (default 100), `after` is an opaque token that continues the listing (null at the end) |
| `GET /machines/{id}/fs/stat?path=` | → `{found, kind}`; a final link is not followed |
| `POST /machines/{id}/fs/mkdir` | `{path, parents}` → `{}`; `409` when a non-directory is in the way, `404` for a missing parent without `parents` |
| `POST /machines/{id}/fs/rm` | `{path, recursive}` → `{}`; a link is removed, never followed; `409` for a non-empty directory without `recursive`; `400` for `/` |
| `POST /machines/{id}/jobs` | `{cmd: [...], dir, env}` → `{job_id}`; a job keeps running after the call returns |
| `GET /machines/{id}/jobs/{job_id}/log?offset=&wait=` | → `{out, err, offset, done, code}`; `offset` is `<stdout_pos>.<stderr_pos>`, `wait` long-polls up to 60 s |
| `POST /machines/{id}/tty` | `{cmd: [...] or null, dir, env, cols, rows, term}` → `{tty_id, ws}`; starts the program (`bash -l` when `cmd` is null) on a pseudo-terminal, and `ws` is the path of its WebSocket |
| `WebSocket /machines/{id}/tty/{tty_id}` | binary frames carry the terminal's bytes in both directions; when the program ends, one text frame `{"exit": <code or null>}` and a close. It connects once, needs `X-Api-Key`, and closing it hangs up on the program's process group (a kill follows 5 seconds later) |
| `POST /machines/{id}/tty/{tty_id}/resize` | `{cols, rows}` → `{}` |
| `GET /machines/{id}/usage` | → `{cpu, memory_mb, started, ended, as_of, revision}`; `ended` is null while the machine runs and then counts up to `as_of`, the time of the read; `revision` is 1 (nothing is ever corrected) |
| `POST /machines/{id}/images` | `{tags, pause}` → `{image_id, machine_id, status, created, cpu, memory_mb, size_bytes, tags}`; saves the machine's files as an image, ready when the call returns; `pause` (default true) freezes the machine meanwhile, `false` lets it run |
| `POST /machines` with `image_id` | as above, starting from an image's files at its `cpu` and `memory_mb` (unless the call names its own); the new machine has its own `env` and `tags` |
| `GET /images?tag=<k>:<v>&machine=&page_token=&limit=` | → `{images: [...], next_page_token}`; `tag` may repeat; lists images that are not deleted |
| `GET /images/{id}` | → the same image object |
| `DELETE /images/{id}` | → `{status: "deleted"}`; repeating still succeeds, an unknown id is `404`; a deleted image can no longer start a machine |
| `GET /images/{id}/usage` | → `{machine_id, records: [{size_bytes, from, until}], as_of, revision}`; `until` is null while the image is stored; records outlive the image |

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
- A terminal is a Docker exec with a TTY. A terminal that nobody connects to within a minute
  is ended, and the machine's lifetime ends every terminal on it.
- Usage records (`usage.db` in the state directory) are kept for 90 days
  after a machine ends and are pruned lazily.
- An image is `docker commit` of the machine's container, tagged
  `example-cloud-image:<image_id>` and labelled `example.snapshot=1` and
  `example.owner`, so `docker images --filter label=example.snapshot=1` lists
  what Example Cloud holds. A machine started from an image gets its own `env`
  and `tags`: the saved machine's are blanked, because Docker keeps them in the
  image. Deleting an image removes its Docker image as soon as no machine
  uses it; a machine that was started from it keeps running until it ends.

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
