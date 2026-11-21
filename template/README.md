<!-- SPDX-FileCopyrightText: BoxRouter, Inc. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Template: an SPS 1.0 provider adapter

This is the adapter a new provider starts from. `sps_provider_example` implements every
required 1.0 operation, and the optional `snapshots` section, by calling Example Cloud
(`fake_cloud/`), a small fake provider API that runs each sandbox as a local Docker container. The API is deliberately not
shaped like the standard, so `src/sps_provider_example/__init__.py` shows a real
translation: a comment above each method names the Example Cloud call it maps.
It also implements two optional sections: the directory operations and a terminal
(`terminal_open`, over Example Cloud's own WebSocket), and claims both in discovery.
It does not claim three additions that a provider with the means may add: running as a named
user (`user_selection`), exact output bytes (`run.base64`) and prepared images (`image.prepare`
and its three companions); `docs/implement.md` says how.

To ship a real provider, copy this directory and rename its Python package and distribution
in `pyproject.toml`. Set the provider entry-point key there and `provider_id` in
`src/<package>/sps-provider.yaml` to the same id, and set the display name in that manifest.
Discovery reads its provider id and name from the manifest. Replace each Example Cloud call
with your own API's. An adapter contributed to
[sandbox-provider-adapters](https://github.com/boxrouter/sandbox-provider-adapters) carries that
repository's licence, the PolyForm Shield License 1.0.0: set `license = "LicenseRef-PolyForm-Shield-1.0.0"`
in `pyproject.toml` (that repository's `providers/example/` has it already). A provider keeps
ownership of its adapter and may use it anywhere.

## Run it

Every command below runs from the root of the cloned repository
(`git clone https://github.com/boxrouter/sandbox-provider-spec`). Example Cloud needs a local Docker
daemon:

```console
$ uv run --extra docker --extra http python template/fake_cloud/server.py --port 18080 --state-dir /tmp/example-cloud &
```

Every request needs a non-empty `X-Api-Key`; any value works, for example `dev`.

## Smoke check

```console
$ uv run --no-project --with '.[http]' --with ./template python template/scripts/smoke.py \
    --endpoint http://127.0.0.1:18080 --api-key dev
smoke ok
```

It creates a sandbox, runs `echo hi`, writes and reads a file, destroys the sandbox
and reads its cost.

## Snapshots

A snapshot is an Example Cloud image: `docker commit` of the sandbox's container, which the
adapter takes without pausing it, so discovery declares `original_after: continues`, with
`keeps: files_only` and `deletable: true`. A restore is a `create` that names `snapshot`; Example
Cloud starts a machine from the image's files. Each image's stored size is a usage record that the
adapter prices as the `snapshot` item in `gib_month`. After a tester run, no image is left:

```console
$ export EXAMPLE_API_KEY=dev EXAMPLE_ENDPOINT=http://127.0.0.1:18080
$ uv run --no-project --with '.[http]' --with ./template sandbox-provider-spec test example \
    --credential api_key=EXAMPLE_API_KEY --credential endpoint=EXAMPLE_ENDPOINT --test snapshots.
$ docker images --filter label=example.snapshot=1 -q | wc -l
0
```

## Run the tester

```console
$ export EXAMPLE_API_KEY=dev EXAMPLE_ENDPOINT=http://127.0.0.1:18080
$ uv run --no-project --with '.[http]' --with ./template sandbox-provider-spec test example \
    --credential api_key=EXAMPLE_API_KEY --credential endpoint=EXAMPLE_ENDPOINT
```

A full run takes a few minutes: it moves a 1 GiB file, waits for a final cost and waits for a
60-second lifetime to end. Add `--quick` to skip those while you iterate.

Or serve the adapter over the standard HTTP API and test it as a native provider. A served adapter
with several credential fields takes one token: `sps1.` and the unpadded base64url encoding of a
JSON object that maps each field to its value.

```console
$ uv run --no-project --with '.[http]' --with ./template sandbox-provider-spec serve example --port 18431 &
$ export SPS_TOKEN=$(python3 -c 'import base64, json; print("sps1." + base64.urlsafe_b64encode(json.dumps({"api_key": "dev", "endpoint": "http://127.0.0.1:18080"}).encode()).decode().rstrip("="))')
$ uv run --no-project --with '.[http]' sandbox-provider-spec test http://127.0.0.1:18431 --credential token=SPS_TOKEN
```

## Offline tests

```console
$ uv run --no-project --with '.[http]' --with ./template --with pytest==9.1.1 pytest template/tests -q -o addopts=""
```

They replay recorded Example Cloud responses and need no Docker daemon.
