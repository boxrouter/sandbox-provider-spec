# Implement SPS 1.0

The Sandbox Provider Spec (SPS) is an open standard interface for sandboxes. A provider that
implements SPS 1.0 works with any consumer that speaks it: an SDK, an agent framework, an
evaluation harness, or a router. This page is everything you need to implement it. The
[OpenAPI file](../spec/provider-api-1.0.openapi.yaml) defines every request and result, and the
[rules page](../spec/provider-api.md) holds the rules that span several operations.

## Two Ways To Conform

| | Adapter | Native API |
| --- | --- | --- |
| What you build | A Python package with one `Provider` subclass and an `sps-provider.yaml` manifest | The SPS HTTP API, served at an HTTPS base URL that you choose |
| Who runs it | The consumer installs and runs it, so you host nothing | You do; the consumer calls your base URL |
| Credentials | Your declared credential fields, passed to the constructor | `Authorization: Bearer <token>`, where the token is your account's own API token |
| Start from | The template adapter in [`template/`](../template/) | The OpenAPI file; `sandbox-provider-spec serve` shows a working server |
| Test with | `sandbox-provider-spec test <provider_id>` | `sandbox-provider-spec test <base URL>` |

Both ways carry the same operations, fields, and rules, and pass the same tests. An operation's
Python method and OpenAPI `operationId` are its dotted name with underscores (`files.read` is
`files_read`). Any adapter can be served over the HTTP API unchanged, so you can start with an
adapter and move to a native API later.

## Required Operations

Every provider implements these ten operations, and may offer an eleventh, `cost` (see [Cost](#cost)). Paths are relative to your base URL.

| Operation | HTTP | What it does |
| --- | --- | --- |
| `discovery` | `GET /v1/discovery` | Says what this account can create, and the prices |
| `create` | `POST /v1/sandboxes` | Creates a sandbox; safe to retry with the same `Idempotency-Key` |
| `get` | `GET /v1/sandboxes/{sandbox_id}` | Reads one sandbox |
| `list` | `GET /v1/sandboxes` | Lists the sandboxes that have not ended, filtered by labels |
| `destroy` | `DELETE /v1/sandboxes/{sandbox_id}` | Ends a sandbox and returns once the request is accepted |
| `run` | `POST /v1/sandboxes/{sandbox_id}/run` | Runs a command and returns its exit code and output |
| `files.read` | `GET /v1/sandboxes/{sandbox_id}/files?path=` | Reads a file as a byte stream of at least 1 GiB |
| `files.write` | `PUT /v1/sandboxes/{sandbox_id}/files?path=` | Writes a file from a byte stream of at least 1 GiB |
| `process.start` | `POST /v1/sandboxes/{sandbox_id}/processes` | Starts a background process |
| `process.output` | `GET /v1/sandboxes/{sandbox_id}/processes/{process_id}/output` | Reads a process's output and exit status |

Inside a sandbox, commands and the file operations see the same filesystem. A sandbox created
without an image has `bash` and `python3` on its path, outbound HTTPS works, and sandbox code
cannot reach instance metadata or host credentials. These rules most often catch implementers:

- **Credentials.** The bearer token is the only credential, and it decides the account. Never put
  it in a result, an error message, or a log line, and never send it to another host.
- **Unknown fields.** Refuse a request field that the contract does not define, with
  `invalid_request`. Add result fields only with the prefix `x-<provider_id>-`.
- **Formats and ids.** Times are RFC 3339 strings in UTC with a `Z` suffix, and money is a decimal
  string such as `"0.000014"`. You choose each id and never reuse it for another sandbox or process.
- **Idempotent create.** Within 24 hours, a repeated `create` with the same `Idempotency-Key`
  returns the first sandbox. A repeat with a different body, or one sent while the first create is
  still in progress, gets `conflict`.
- **Lifetime and destroy.** End the sandbox in its `at_end` state no later than `lifetime_seconds`
  (default 300) after `create` returns, even if the consumer has gone away. Return from `destroy`
  once you have accepted the request; a repeated destroy succeeds.
- **Commands.** `run` takes `argv` and runs it without a shell. A nonzero exit code or a timeout is
  a result, not an error. At the timeout, end the command and every process that it started.
- **Files and processes.** Move the whole file or fail: a read whose connection ends early has
  failed and never yields a short file. When the parent directory of a write is missing, either
  create every missing directory on the path, as `mkdir -p` would, and write the file, or refuse
  with `not_found` and create nothing; a consumer relies on neither. A process has exited only
  when `state` is `exited` with an `exit_code`; closed output streams do not mean that it exited.

Discovery's `limits` object states your limits, and each has a floor that you must meet: `file_bytes`
1 GiB, `run_timeout_ms` 60000, `output_bytes` 16 MiB, `wait_ms` 30000, `process_output_bytes` 1 MiB,
`process_retention_seconds` 600, and `list_limit` 100. `cost_final_within_seconds` is your own statement
and has no floor (see [Cost](#cost)).

## Discovery And Prices

`GET /v1/discovery` needs the same token as every other request, because two accounts on different
plans may see different classes, regions, and sizes. Prices are list prices: a plan or discount on
an account never changes them. A class is a wholesale different kind
of sandbox, such as a container or a microVM; the main class has the id `default`.

```json
{
  "spec_version": "1.0",
  "provider": {"id": "example", "name": "Example Cloud"},
  "limits": {"file_bytes": 5368709120, "run_timeout_ms": 600000, "output_bytes": 16777216, "wait_ms": 60000,
             "process_output_bytes": 4194304, "process_retention_seconds": 3600, "list_limit": 1000,
             "cost_final_within_seconds": 3600},
  "classes": [{
    "id": "default", "name": "Linux container", "ready": true,
    "resources": {"regions": ["example:us-east"], "located_in": ["US"],
                  "sizes": [{"cpu": 2, "memory_mib": 2048}],
                  "default_size": {"cpu": 2, "memory_mib": 2048}, "max_lifetime_seconds": 86400},
    "lifetime_timer": {"enforced_by": "provider", "at_end": ["destroyed"], "counts_paused_time": false},
    "gates": {"file_links": [{"operations": ["read", "write"], "link_lifetime_seconds": 3600}]},
    "images": [{"id": "base", "default": true, "description": "Ubuntu 24.04 with bash and python3"}],
    "prices": [
      {"item": "cpu", "price_usd": "0.000014", "unit": "vcpu_second", "basis": "allocated"},
      {"item": "memory", "price_usd": "0.0000045", "unit": "gib_second", "basis": "allocated"},
      {"item": "egress", "price_usd": "0", "unit": "gb", "basis": "used", "included": true}
    ]
  }]
}
```

`resources`, `lifetime_timer`, and `gates` use the [SPS vocabulary](../spec/vocabulary.md) and the
[declaration schema](../spec/declaration-schema.json); `gates` lists the
[optional sections](#optional-sections) that you claim. `ready: false` means that the class takes no
new sandboxes now, while existing sandboxes keep working.

**Prices.** You can write your price list in minutes by copying your own price page. Each item has
four required fields:

- `item` is what is charged: `cpu`, `memory`, `disk`, `gpu`, `machine` (a whole fixed-size machine),
  `create` (each sandbox), `egress`, `snapshot`, `volume`, `start` (each start or resume), `request`,
  or `feature` (a recurring fee for an enabled feature).
- `price_usd` is the price of one unit in US dollars, as a decimal string.
- `unit` is the unit as you state it, such as `vcpu_second`, `gib_hour`, `gb`, `each`, or `month`. A
  `month` is 730 hours, and a `gb` is 10^9 bytes (write `gib` if you bill binary gigabytes).
- `basis` is what is measured: `allocated`, `used`, `max_allocated_used`, `fixed`, or `count`.

Optional fields cover billed states, increments, minimums, allowances, and prices for one size,
region, GPU model, or variant. An item that you do not list has an unknown price, never a zero
price, so list a free item with `"price_usd": "0"` and `"included": true`.

## Cost

`cost` is optional: state `limits.cost_final_within_seconds` in discovery to offer `GET /v1/sandboxes/{sandbox_id}/cost`, or leave it out and `cost` answers `unsupported`. If you offer it:

1. Answer in every state, also after the sandbox ends (`get` reports `destroyed`, or it is gone), and keep the cost readable at least until it is `final`. Take quantities from your own records, never from a clock in the consumer or an adapter.
2. Each line has an `item` and an `amount_usd`, and a `quantity` and `unit` when `source` is `calculated` (what the amount was priced from: `"240"` and `"vcpu_second"`, or `"1"` and `"each"` for a flat fee) or `usage` (what the line reports, with `amount_usd` null). `total_usd` is the sum of the lines, and null for `usage`. A line with `start` and `end` both null covers no period, as a fee does; `start` set and `end` null is open, and only while `accruing`. A line's `start` and `end` may be a billing period, such as an hour, that contains the usage.
3. `as_of` is the time up to which your figures count usage. It may be earlier than the time of the read, if your records lag.
4. `final` means that the figures will not change. Make the cost `final` within `cost_final_within_seconds` after the sandbox ends, or after storage that outlives it ends (you choose the number; the tester waits at most 7 days). A `final` cost has no open line, and a `total_usd` unless its `source` is `usage`.
5. Amounts are US dollars, as decimal strings, at your published list price when the usage happened, before any plan, free tier, trial, credit or discount. `source` is `reported` when your records state those amounts, `usage` when you state only the quantities from your usage records (no amount, `total_usd` null) and leave the pricing to the consumer, and `calculated` when you multiply quantities from your usage records by your prices. `usage` is the simplest: your adapter holds no copy of your prices beyond the list prices in discovery. The tester checks that a `calculated` line's amount is its quantity times the price in your discovery for that item and unit, to the decimal places that the amount states.
6. While `accruing` and nothing is metered yet, `total_usd` may be null and `lines` empty. `"0"` is a true zero, never "not counted yet". A free sandbox returns one line with the amount `"0"`.

```json
{"sandbox_id": "sbx-17", "status": "final", "total_usd": "0.00444", "source": "calculated",
 "lines": [{"item": "cpu", "quantity": "240", "unit": "vcpu_second", "amount_usd": "0.00336",
            "start": "2026-11-13T10:00:00Z", "end": "2026-11-13T10:02:00Z"},
           {"item": "memory", "quantity": "240", "unit": "gib_second", "amount_usd": "0.00108",
            "start": "2026-11-13T10:00:00Z", "end": "2026-11-13T10:02:00Z"}],
 "as_of": "2026-11-13T10:05:00Z"}
```

A router that bills from your figures publishes what it asks of a provider on [its own page](https://boxrouter.ai/docs/providers/cost). A snapshot's own cost is `snapshot.cost` in the optional `snapshots` section.

## Errors

Every error has one of twelve codes, and each code is fixed as the caller's fault or yours. A
consumer treats the fault as fixed by the code, whatever the message says.

```json
{"error": {"code": "not_found", "message": "No sandbox sbx-17", "outcome": "failed", "retry_after_seconds": null}}
```

| Code | HTTP | Fault | When |
| --- | --- | --- | --- |
| `invalid_request` | 400 | caller | The request is malformed, has an unknown field, or has a value out of range |
| `unauthenticated` | 401 | caller | The token is missing, wrong, or expired |
| `forbidden` | 403 | caller | The token is valid but may not do this |
| `not_found` | 404 | caller | The sandbox, process, file, or directory does not exist |
| `conflict` | 409 | caller | The sandbox's state forbids the operation, or an `Idempotency-Key` was reused |
| `too_large` | 413 | caller | A file or body is over a declared limit |
| `unsupported` | 422 | caller | The request names a class, region, size, image, section, or value that you do not offer |
| `quota_exceeded` | 402 | caller | The account reached its plan, spending, or concurrency limit |
| `rate_limited` | 429 | caller | The account sent too many requests |
| `unavailable` | 503 | provider | You cannot serve a valid request now: no capacity, or maintenance |
| `timeout` | 504 | provider | You did not finish the operation in time |
| `provider_error` | 500 | provider | Any other failure on your side |

`outcome` is `failed` when the operation had no effect and `unknown` when it may have taken effect.
Set `retry_after_seconds`, and the same value in a `Retry-After` header, when retrying later can
work. Keep `message` under 1024 characters, with no credentials and no other system's response
body. An adapter raises `SpsError(code, message)`; any other exception, like any response without a
valid error body, counts as `provider_error` with outcome `unknown`.

## Get Started

### 1. Copy The Template Or Start Your Endpoint

The tester and a reference server ship in the `sandbox-provider-spec` package. The package and the
template are in the [GitHub repository](https://github.com/boxrouter/sandbox-provider-spec); the
commands below run the package straight from it, so there is nothing else to install. Add `@` and
a release tag after the URL (`git+https://github.com/boxrouter/sandbox-provider-spec@<tag>`) to pin a release.
The contract that you implement is SPS 1.0; the package's own version numbers the tools, not the contract.

**Adapter.** The template is a complete adapter for Example Cloud, a small fake provider API that
runs each sandbox as a local Docker container. Example Cloud is deliberately not shaped like SPS,
so each method shows a real translation. Copy the template, rename the package and the provider id
in `pyproject.toml` and `src/<package>/sps-provider.yaml`, and replace each Example Cloud call with
yours. [`template/README.md`](../template/README.md) shows how to run it on your machine.

```console
git clone https://github.com/boxrouter/sandbox-provider-spec
cp -r sandbox-provider-spec/template my_adapter
```

To try the template as it is, start Example Cloud in another terminal (it needs Docker):

```console
uv run --project sandbox-provider-spec --extra docker --extra http python sandbox-provider-spec/template/fake_cloud/server.py --port 18080 --state-dir /tmp/example-cloud
```

Each method translates one operation to your API and raises `SpsError` for an error:

```python
from sandbox_provider_spec.v1 import Provider, RunRequest, RunResult, SpsError


class ExampleProvider(Provider):  # __init__ makes self._http from self.credentials
    async def run(self, sandbox_id: str, request: RunRequest) -> RunResult:
        resp = await self._http.post(
            f"/machines/{sandbox_id}/exec",
            json={"cmd": list(request.argv), "timeout_s": request.timeout_ms / 1000},
        )
        if resp.status_code == 404:
            raise SpsError("not_found", f"No sandbox {sandbox_id}")
        body = resp.json()
        return RunResult(exit_code=body["code"], stdout=body["out"], stderr=body["err"])
```

**Native API.** Serve the ten operations under your base URL, as the OpenAPI file defines them.
To see a working server, serve the template adapter over the HTTP API. The `serve` command serves
any installed adapter, and it needs the `http` extra:

```console
uvx --from 'sandbox-provider-spec[http] @ git+https://github.com/boxrouter/sandbox-provider-spec' --with ./my_adapter sandbox-provider-spec serve example --port 18431
```

Use your own provider id in place of `example` after you rename the template. A served adapter takes
its credentials from the bearer token. With one credential field, the token is the value itself; with
several, it is `sps1.` and the unpadded base64url encoding of a JSON object that maps each field to its value.

### 2. Write The Manifest (Adapter Only)

The adapter's Python package holds `sps-provider.yaml`. Tools read it without importing your code,
and the `Provider` class reads it when your subclass is defined
([schema](../spec/sps-provider.schema.json)).

```yaml
provider_id: example          # a-z 0-9 -, 2 to 32 characters; also the entry point's name
name: Example Cloud
spec_version: "1.0"
credential_fields:
  - {name: api_key, secret: true, description: "API key from the Example Cloud console"}
api_domains: [api.example.com]
```

Register the class under the entry-point group `sandbox_provider_spec.providers` in
`pyproject.toml` (`example = "sps_provider_example:ExampleProvider"`), and declare several
credential fields when your API needs several values, such as a key and a team id. The adapter
calls only the hosts in `api_domains` (an exact name, or a suffix such as `.example.com`), with
only the credentials that it was given. It reads no environment variables, no files outside its
package, and no global state, and its dependencies are your own SDK and `httpx`. It never logs or
returns a credential, and it keeps nothing that a later call needs, because a consumer may make a
new instance for every call.

### 3. Run The Tester

Run the tester against your own test account. It reads each credential from the environment
variable that you name, never from the command line.

```console
# Adapter: the provider id from your manifest, and one --credential for each field of your manifest
export EXAMPLE_API_KEY=dev EXAMPLE_ENDPOINT=http://127.0.0.1:18080
uvx --from git+https://github.com/boxrouter/sandbox-provider-spec --with ./my_adapter sandbox-provider-spec test example --credential api_key=EXAMPLE_API_KEY --credential endpoint=EXAMPLE_ENDPOINT

# Native API: your base URL (the URL form needs the http extra)
uvx --from 'sandbox-provider-spec[http] @ git+https://github.com/boxrouter/sandbox-provider-spec' sandbox-provider-spec test \
  https://api.example.com/sps --credential token=EXAMPLE_TOKEN
```

The first command tests the template against Example Cloud from step 1. To test the template served
as a native API, serve it as in step 1, make its token, and test its URL:

```console
export SPS_TOKEN=$(python3 -c 'import base64, json; print("sps1." + base64.urlsafe_b64encode(json.dumps({"api_key": "dev", "endpoint": "http://127.0.0.1:18080"}).encode()).decode().rstrip("="))')
uvx --from 'sandbox-provider-spec[http] @ git+https://github.com/boxrouter/sandbox-provider-spec' sandbox-provider-spec test http://127.0.0.1:18431 --credential token=SPS_TOKEN
```

The tester runs the baseline and contract tests, then the tests of every optional section that
your discovery claims, and deletes every sandbox that it created. It prints one line per test, then
one per required operation, one for `cost` (`operation cost unsupported` when discovery states no
`cost_final_within_seconds`) and one per claimed section, such as `operation create passed`; a status is
`passed`, `differs`, `unsupported`, `not_run`, or `error`. It writes a JSON report
(`sps-report.json`) and exits 0 only when every test that it ran passed, `cost` included when you offer it.
A full run also waits for a final cost, up to your `cost_final_within_seconds` after it destroys a
sandbox, and for a sandbox to end at the lifetime that it asked for (60 seconds, plus up to 30). `--quick`
skips the 1 GiB round trip and those waits while you iterate, and prints `not_run` for what it did
not test; a quick pass exits 3, never 0. If the tester cannot reach `https://example.com` from a
sandbox, pass `--reachable-url` with an HTTPS URL that your sandboxes can reach. A consumer runs the same tester. To state that you conform, name the spec version,
the class, and the passing report ([GOVERNANCE.md](../GOVERNANCE.md#conformance-claims)).

## Optional Sections

An optional section is a feature from the SPS vocabulary that you claim in discovery's `gates` (or
in `resources`, for a resource fact). A claim alone turns nothing on: a section is on only when the
tester passes it. Refuse a request for a section that you do not offer with `unsupported`; in an
adapter, each optional method raises `unsupported` until you implement it.

| Section | Operations | What it adds |
| --- | --- | --- |
| `file_links` | `files.link` | A URL that you sign, which moves a file's bytes directly, without the consumer's credential |
| `pause_resume` | `pause`, `resume` | Pause and resume, keeping what you claim (`keeps`) |
| `extendable_lifetime` | `lifetime.extend` | Lets a sandbox run longer; never shortens its lifetime |
| `processes` with `input` | `process.write_stdin`, `process.close_stdin` | Input to a running process |
| `processes` with `cancel` | `process.cancel` | Ends a process and its children |
| `previews` | `preview.link`, and with `revocable` `preview.revoke` | An HTTPS URL that reaches a port in the sandbox; `preview.link` may ask for `access` (`public` or `private`) and a `lifetime_seconds`, and returns the link's `id`, `access` and `credential`; `preview.revoke` stops one link |
| `tcp_ports` | `tcp.link` | A host and port that reach a TCP port in the sandbox |
| `terminal` | `terminal.open` | A terminal over one WebSocket: input, output, resize and the exit status |
| `snapshots` | `snapshot.create`, `snapshot.get`, `snapshot.list`, `snapshot.delete`, `snapshot.cost`, and `create` with `snapshot` | Save a sandbox and start new sandboxes from the save |

### Directory operations

Four operations list, make, test and remove paths: `files.list`, `files.mkdir`, `files.remove` and
`files.exists`. They are a fast path for what every program can already do with commands such as
`ls -A`, `mkdir -p`, `rm -rf` and `test -e`, so they are not an SPS section and no request can ask
for them: commands give the same result on every provider, and a consumer that finds the operations
off runs the commands instead. You claim all four, or none, in the `operations` list of a class in
discovery (`classes[].operations`), and they turn on when the tester passes its `directories.` tests.
Each result must be the one that the equivalent commands, run as the class's default user at the
same moment, would give: `files.list` returns the immediate entries sorted by the bytes of their
names and never follows a symbolic link, `files.remove` removes a link and never its target, and
`files.exists` reports a dangling link as existing.

`labels.update` is a separate operation of the same kind: list it in `operations` and the tester's
`labels.` test runs. It sets the labels that it is given, removes those given as the empty string,
and leaves the rest, so that a reaper or a caller can mark a sandbox after it was created.

### Prepared images

Four operations prepare an image ahead of creation: `image.prepare`, `image.get`, `image.list` and
`image.delete`. A provider that can build an image from an OCI image, a private OCI image or a
Dockerfile lists all four, or none, in `classes[].operations`, claims `custom_images` knob
`prepared`, and states `limits.image_context_bytes` (at least 512 MiB). They turn on when the tester
passes its `images.` tests.

- **The request.** `image.prepare` is one `multipart/form-data` request with an `Idempotency-Key`.
  The part `request` comes first and holds the `source`, optional `resources` and `labels`. A
  Dockerfile that copies files is followed by the part `context`, a tar archive. In Python you get
  `context` as an async stream of bytes (and `context_size` when the caller knows it): read it once,
  and never hold it whole.
- **No registry.** `digest` and `config` (environment, working directory, user, entrypoint, command)
  come from the caller, who resolved them. Apply `config` as the defaults of every sandbox made from
  the image, and reach no registry. Registry credentials are write-only: never return or log them.
- **Every image alike.** Make any OCI image or Dockerfile runnable, and never treat one image
  differently by its name or reference. What you need to run an arbitrary image (an entrypoint, an
  init wrapper) is part of your own build.
- **The result.** A `PreparedImage` in state `preparing`, `ready` or `failed` (with an `error` body).
  A consumer reads `image.get` until `ready`, then creates with
  `image: {"provider_artifact": "<id>"}`. `image.delete` returns on acceptance, and afterwards the
  id is `not_found`; a sandbox already made from the image is not affected.

### Run as a named user, exact output bytes

Two optional additions change `run`, `process.start` and `files.write`; a provider that skips them
is still a valid 1.0 provider.

- **A named user.** `run` and `process.start` take `user` in the request, and `files.write` takes
  a `user` query parameter. Omitted or null means the class's default user. A provider claims it
  with the `user_selection` section and its knobs `commands`, `process_start` and `files_write`.
  A user that the sandbox does not have is `not_found` (the command does not run), and a class
  that does not claim the knob answers `unsupported`. A written file is owned by that user from
  its creation.
- **Exact bytes.** `run` takes `output`, `text` (the default) or `base64`. With `base64` the
  result carries `stdout_base64` and `stderr_base64`, the exact bytes of each stream, and
  `stdout` and `stderr` are empty. A provider claims it by listing `run.base64` in the
  `operations` of a class, beside the directory operations or alone.

The tester runs `run.user`, `files.write.user`, `process.start.user` and `run.base64` only when the
claim is made. Your Python `Provider` receives `RunRequest.user` and `RunRequest.output`,
`ProcessStartRequest.user` and, only when a user is named, a `user` keyword on `files_write`.

Other sections are set at create, with no operation of their own: `custom_images`,
`network_lockdown`, `idle_shutdown`, `hidden_secrets`, and resource asks such as `arch`, `cpu_min`,
`memory_min_mib`, `region`, and `gpu_model`. Desktops and volumes wait for later 1.x releases.

## Versioning

SPS follows semantic versioning. The URL path carries the major version (`/v1`), and the
`spec_version` in discovery and in the manifest carries `major.minor`. A 1.x release only adds
optional operations, optional request fields, result fields, and vocabulary. The twelve error codes
stay fixed for all of 1.x, so nothing that a 1.0 provider does becomes wrong in a later 1.x. A
consumer sends only the fields of the minor that you declare. A 2.0 would be a new path, `/v2`.
