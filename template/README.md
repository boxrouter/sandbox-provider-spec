<!-- SPDX-FileCopyrightText: BoxRouter, Inc. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Template: an SPS 1.0 provider adapter

This is the adapter a new provider starts from. `sps_provider_example` implements every
required 1.0 operation by calling Example Cloud (`fake_cloud/`), a small fake provider
API that runs each sandbox as a local Docker container. The API is deliberately not
shaped like the standard, so `src/sps_provider_example/__init__.py` shows a real
translation: a comment above each method names the Example Cloud call it maps.

To ship a real provider, copy this directory and rename its Python package and distribution
in `pyproject.toml`. Set the provider entry-point key there and `provider_id` in
`src/<package>/sps-provider.yaml` to the same id, and set the display name in that manifest.
Discovery reads its provider id and name from the manifest. Replace each Example Cloud call
with your own API's. An adapter contributed to
[`boxrouter/sandbox-providers`](https://github.com/boxrouter/sandbox-providers) carries that
repository's licence, the PolyForm Shield License 1.0.0: set `license = "LicenseRef-PolyForm-Shield-1.0.0"`
in `pyproject.toml` (that repository's `providers/example/` has it already). A provider keeps
ownership of its adapter and may use it anywhere.

## Run it

Example Cloud needs a local Docker daemon.

```console
$ uv run --locked python template/fake_cloud/server.py --port 18080 --state-dir /tmp/example-cloud &
```

Every request needs a non-empty `X-Api-Key`; any value works, for example `dev`.

## Smoke check

From `packages/sandbox-provider-spec`:

```console
$ uv run --locked --package sps-provider-example python template/scripts/smoke.py \
    --endpoint http://127.0.0.1:18080 --api-key dev
smoke ok
```

It creates a sandbox, runs `echo hi`, writes and reads a file, destroys the sandbox
and reads its cost.

## Run the tester

```console
$ export EXAMPLE_API_KEY=dev EXAMPLE_ENDPOINT=http://127.0.0.1:18080
$ uv run --locked --extra http sandbox-provider-spec test example \
    --credential api_key=EXAMPLE_API_KEY --credential endpoint=EXAMPLE_ENDPOINT
```

Or serve the adapter over the standard HTTP API and test it as a native provider:

```console
$ uv run --locked --extra http sandbox-provider-spec serve example --port 18431 &
$ export SPS_TOKEN=$(uv run --locked python -c \
    "from sandbox_provider_spec.v1.tokens import encode; print(encode({'api_key': 'dev', 'endpoint': 'http://127.0.0.1:18080'}))")
$ uv run --locked --extra http sandbox-provider-spec test http://127.0.0.1:18431 --credential token=SPS_TOKEN
```

## Offline tests

```console
$ uv run --locked --package sps-provider-example pytest template/tests -q
```

(Run it from `packages/sandbox-provider-spec`. uv does not treat `template/` as a workspace member
when it is the current directory, so name the package instead of changing into it.)

They replay recorded Example Cloud responses and need no Docker daemon.
