# Installed HTTP reference and starter

The SPS wheel includes a reusable reference endpoint and native `Backend` protocol.
It lets a provider implement its native handlers and compose them with the PP1 wire
boundary without a source checkout or imports from examples or tooling. This is
an onboarding starter, not hosted admission, a complete SPS baseline report, proof
that HTTP v0.1 satisfies every contract guarantee, a general-purpose client or a
production server.
The [binding](../spec/binding-http.md) and its
[schema](../spec/http-binding.schema.json) are authoritative. The reference and
fixture runner use `sandbox_provider_spec.http_binding_validation`, the validator
included in the SPS wheel. It resolves schemas through the package's `spec_dir()`
lookup; callers do not need to copy schema files or import tooling modules.
`BindingValidationError` is a `ValueError` with a machine-readable `code` mapped
by `STATUS`.

Construct `Endpoint` with the operator's externally advertised HTTPS origin as
`endpoint_origin`. The reference validates it with `validate_discovery()` before
opening its state database and returns that exact origin in authenticated discovery.
This syntax check does not admit public origins or establish reachability.

## Run the proof

Install SPS and the HTTPX test dependency in a clean Python environment, then
import `Backend` and `Endpoint` from `sandbox_provider_spec.http_reference`.
The optional native Docker implementation is separately installed with
`sandbox-provider-spec[docker]`; importing the endpoint does not import Docker.
No HTTP server starts during import or construction.

The deterministic proof uses the SPS package dev environment (`uv sync` in a
checkout creates `.venv`). Run the commands below from the checkout root; a clean
checkout of this repository holds `src/sandbox_provider_spec/` and
`conformance/suite.yaml` at its root, the layout Adapter Kit's `--spec-checkout`
accepts:

```sh
.venv/bin/python tooling/http_binding/validate.py
.venv/bin/python -m pytest -q -n 0 \
  -o 'markers=live: opt-in local Docker proof' \
  tests/test_http_binding_reference.py
```

These commands run offline package checks and create no
provider resources. They are not an Adapter Kit `spec_run`. Kit's `--spec-checkout`
requires a separate clean SPS checkout root with `src/sandbox_provider_spec/` and
`conformance/suite.yaml` at that root; a directory that merely contains the
checkout fails the same checks. Run Kit `spec_run` only when this
provider also has an existing Core `SandboxProvider` and configured
`DriverFactory`. The HTTP `HttpConformanceDriver` is not a Kit `CoreDriver`; this
starter provides no generic `make_driver` factory. An HTTP-only provider uses
`boxrouter-http`'s separate SPS HTTP consumer and report.

The default run uses an explicitly named deterministic test backend. It executes
no commands and provides no isolation. Five native tests are skipped. HTTPX's
WSGI transport delivers actual method/path/header/body/status values in-process;
no HTTP listener, public endpoint or provider account is used. The fixture's
synthetic bearer values authorize only those test instances.

For an unfamiliar endpoint, an operator first provisions and verifies the provider
account, chooses the provider's native account/namespace and offering, and creates
a persistent state location. The operator stores the bearer-token-to-account
mapping in the deployment's approved secret manager and grants the service identity
read access to that secret. The author supplies the factory import paths, state path,
and exact advertised HTTPS origin through deployment configuration; credentials do
not belong in source, shell history, command arguments, reports, or logs. The operator
installs the package, starts an existing WSGI server configured for the factory, then
registers the endpoint through the authorized enrollment flow with only actual reports.
Registration remains an operator action; this guide does not enable customer
self-enrollment or change credential policy.

For the native tests, first verify that a local Docker Engine and a cached image
already exist. The proof does not pull an image, install a daemon or use a remote
Docker host:

```sh
docker info --format '{{.ServerVersion}}'
docker image inspect python:3.12-slim --format '{{.Id}}'
SPS_HTTP_DOCKER=1 .venv/bin/python -m pytest -q -n 0 \
  -o 'markers=live: opt-in local Docker proof' \
  tests/test_http_binding_reference.py
```

The environment flag is the local opt-in. Where an installed adapter-conformance
Kit supplies its live-test network policy, the same marked tests also need its
`--live=docker_engine` selection. An unavailable socket or missing image is a
missing prerequisite, not a passed test.
Containers have a unique owner label, no host mounts or privileged mode, dropped
capabilities, disabled networking, and CPU/memory/PID limits. Cleanup removes only
that exact owner label and checks that no matching containers or reader threads
remain. Images are retained. No other sandbox account or resource is touched.

## Compose native handlers

[`Backend`, `Endpoint`, `Failure`, and `Output`](../src/sandbox_provider_spec/http_reference/__init__.py)
are the installed imports. The endpoint supplies the WSGI
boundary, authentication/account checks, strict PP1 validation, allocation-key
store, identity fencing, pagination and output buffer. Construct `Endpoint` with
an implementation of its `Backend` protocol, an owned SQLite path, the configured
`endpoint_origin`, and the operator's credential-to-account mapping. Supply
credentials through approved configuration; never use the test fixture's tokens
for a deployed endpoint.

| Handler | Native responsibility |
| --- | --- |
| `create` | Allocate in the selected account for the supplied identity and initial environment; return `None` only after readiness is established. |
| `get`, `destroy` | Address the exact incarnation; distinguish actual absence, accepted deletion, confirmed deletion and lookup failure. |
| `run` | Preserve argv, cwd and environment; return separate complete text streams and an observed integer exit. |
| `run_buffered` | For POSIX commands on Linux/Python images, use the public `buffered_runner_argv` and `decode_buffered_runner_result` helper by default; native execution controls may implement the same contract directly. |
| `read`, `write` | Use the native file API for exact bytes in an existing guest directory. |
| `start` | Return a native process identity and a native execution-state observer; feed the supplied output buffer while the process runs. |

`list` enumerates this reference account's recorded allocations and observes their
native state. Its opaque cursors are bound to account and offering. Production
providers must inventory their actual account scope; failed native lookup is
never an empty inventory. The default 0.1 example admits only its fixed unverified
offering and an empty requirements request. Additional requirements are refused
before allocation; implement admission with the existing SPS checker/matcher and
current evidence before supporting them. The 0.3 backend contract below is a separate
explicit path.

## The installed backend interfaces

The interfaces below are those of the SPS 0.3.126 wheel, read from
[`endpoint.py`](../src/sandbox_provider_spec/http_reference/endpoint.py) and its dispatch
sites. `Backend` has existed since 0.3.87, `BufferedCommandBackend` since 0.3.93 and
`AdmissionBackend` since 0.3.98; a wheel older than the one that introduced an interface
does not import it. They are `typing.Protocol` classes: a backend satisfies one by having
the methods, not by inheriting. Request arguments are the endpoint's already validated
wire dictionaries, so the [schema](../spec/http-binding.schema.json) is the full field
list for each request and result; this page names only what a backend reads or returns.
`kind`, `authority` and `sdks` are backend class attributes. `identity` is the complete
five-field `SandboxIdentity` (`provider_id`, `account_id`,
`offering_id`, `sandbox_id`, `incarnation`). The endpoint generates it, and a backend
must bind its native resource to exactly that identity (for example a native name or
label) so a later call can find the same incarnation.

| Method | Receives | Returns |
| --- | --- | --- |
| `create(identity, env)` | the identity and the create request's `env` mapping | `None`. Raise `Failure` to refuse. The endpoint, not the backend, returns the identity. |
| `get(identity)` | the identity | one of `active`, `paused`, `destroyed`, `absent`, `unknown`. A sandbox that can resume is `paused`; one that cannot is `destroyed`. |
| `destroy(identity)` | the identity | `accepted`, `destroyed` or `absent`. |
| `run(request, *, deadline)` | the `run` request (`sandbox`, `argv`, `cwd` or `None`, `env`, `observation_timeout_ms`, `encoding`); `deadline` is a `time.monotonic()` value | a dictionary with `stdout` and `stderr` (complete text), integer `exit_code` and `output_complete` set to `True`. A result that is not complete is a `Failure`, never `False`. |
| `read(request)` | `sandbox`, absolute guest `path`, `limit_bytes` | the whole file as `bytes`. Refuse a file larger than `limit_bytes`; never return a prefix. |
| `write(request, data)` | `sandbox`, absolute guest `path`, the decoded `bytes` | `None`. The endpoint reports `written_bytes`; a partial write is a `Failure`. |
| `start(request, output)` | the `process.start` request and an `Output` | a pair: the native process ID (a string that is a valid identifier) and an observer callable. |

`get` reports `absent` only for an authoritative native absence. A failed lookup is
raised, as a `Failure` or any exception (the endpoint reports an exception that is not a
`Failure` as `provider_error` with unknown outcome); it is never `absent`, `destroyed`
or an empty state. `list` calls `get` for each recorded allocation, omits `absent`
ones and pages the rest. A client asks for a page with the request's `page_size`
(1 to 1000; discovery advertises its own `page_size` of 100), plus `cursor` and an
optional `offering_id`; a backend implements no pagination. `destroy` returns
`accepted` when deletion has been requested but not observed, and `destroyed` only after
the backend has observed it.

In operation request dictionaries, `request["sandbox"]` is the complete five-field sandbox
identity described above, not a sandbox ID string. The observation deadline bounds how long the
caller waits. If it passes after a native observation may have taken effect, raise
`Failure("timeout", "unknown")`; use `not_dispatched` only when the backend can establish that
it did not issue the native request.

`start` returns `(process_id, observe)`. `observe()` returns `("running", None)`,
`("exited", code)` with an integer code, or `("unknown", None)` when the native state
cannot be read. While the process runs, the backend feeds `output.feed("stdout", text)`
and `output.feed("stderr", text)` with decoded text. `output.close()` records that the
native streams closed (EOF); `output.close(lost=True)` records that observation was
lost, which clients see as `output_unavailable`. EOF and exit are separate facts: close
the output when the native stream ends and report `exited` only from the native exit
status, in either order. Closing the output never implies an exit code.

`Failure(code, outcome="not_dispatched", exit_code=None)` classifies a result. `code` is
one of the schema's error codes (`provider_error`, `timeout`, `limit_exceeded`,
`unsupported_mode`, `conflict` and the others) and `outcome` one of `not_dispatched`,
`failed`, `unknown` or `completed`. Use `unknown` whenever the native call may have taken
effect. The endpoint never discloses an exception's text.

### Optional extensions

`BufferedCommandBackend` adds `run_buffered(request, *, execution_limit_ms)`. Its
request also carries `output_limit_bytes`; it returns `mode` (`buffered_commands_v1`),
`encoding` (`base64`), canonical `stdout_base64` and `stderr_base64`, `stdout_bytes` and
`stderr_bytes` equal to the decoded lengths, `stdout_truncated` and `stderr_truncated`
(booleans), `exit_code` and `output_complete=True`, with no UTF-8 `stdout` or `stderr` fields.
A stream longer than `output_limit_bytes` is not an error: return its first
`output_limit_bytes` bytes with its flag `true`. See [buffered commands](#opt-in-to-buffered-commands).

`AdmissionBackend` (binding 0.3 only) adds `offerings(account)`, which returns a list of
offering dictionaries (`offering_id`, `declaration_id`, `declaration`). The backend computes
`declaration_id` itself: `sha256:` plus the SHA-256 of canonical JSON (sorted keys, no
spaces) of everything the selection promises, at least the declaration and the binding
(the Docker reference also binds its image and network), and changes it whenever any of
them changes;
`create_admitted(identity, request, env, labels, admission)`, which returns an
observation `{"state", "labels", "lifetime"}` with state `active` or `ready`; and
`observe_admitted(identity)`, which returns the same shape for any state in the
schema's `GetResult03` and reports `absent` as `{"state": "absent", "labels": {},
"lifetime": {"ready_at": None, "ends_at": None}}`. Its `labels` are the public label
map only. See [binding 0.3](#opt-in-to-http-binding-03).

### Result mapping for `run_buffered`

`buffered_runner_argv` returns one frame, decoded by `decode_buffered_runner_result` into a
state, an exit code, the two streams and their truncated flags. Map it to the endpoint's reply the way
`DockerBackend.run_buffered` does:

| Runner state or fault | `run_buffered` does |
| --- | --- |
| `completed` | Return the result dictionary with base64 streams, `stdout_truncated`, `stderr_truncated` and `exit_code`. The runner already cut each stream to `output_limit_bytes`; a stream still longer than that is a defect (`provider_error`, `unknown`). |
| `terminated` (E expired and the TERM-to-KILL obligation settled) | `raise Failure("timeout", "completed", result.exit_code)` |
| `unknown` (the runner could not establish the outcome) | `raise Failure("provider_error", "unknown")` |
| Exec failed, runner exit status not 0, anything on the exec's stderr, a frame that is truncated, malformed or larger than `buffered_runner_frame_limit` | `raise Failure("provider_error", "unknown")` |

Never return `completed` for a terminated or unknown run, and never retry the command.

### Failure codes for file and state errors

The binding names no dedicated not-found code, and the suites check none of the three cases
below. Use the reference convention so clients see the same thing from every endpoint:

| Case | Raise |
| --- | --- |
| The sandbox is not `active` (paused, destroyed or absent) for `run`, `read`, `write` or `start` | `Failure("conflict")` before touching the native API |
| `read` of a file that does not exist | `Failure("conflict")` once the native call has reported the path missing and returned nothing |
| `write` into a directory that does not exist (the binding implies no automatic parent creation) | `Failure("conflict")`, with nothing written |
| A native call that may have changed state before failing | `Failure("provider_error", "unknown")` |
| A file larger than `limit_bytes` | `Failure("limit_exceeded", "completed")`, never a prefix |

`conflict` carries `not_dispatched` by default, which the binding requires of conflict errors.
Any other exception is reported as `provider_error` with unknown outcome.

After a destroy, binding 0.1 and 0.2 `get` may report `absent` (the consumer reports it as
destroyed); `destroy` returns `accepted`, `destroyed` or `absent`. Binding 0.3 `get` must report
`destroyed` for an ended incarnation.

### Identity, authority and credentials

Three attributes name the backend and are part of what the endpoint advertises:

- `kind` is the provider identifier. It is the `provider_id` in discovery and in every
  sandbox identity and the `provider` in the declaration. A request for an identity
  whose `provider_id` differs is forbidden.
- `authority` is a stable string naming the native credential, account scope or
  namespace the backend operates in. The endpoint writes `[kind, authority]` into its
  SQLite store when the store is first opened and refuses to open that store with a
  different pair. Change it only with a new store: a different authority could hide
  allocations the old one created.
- `sdks` maps each native client name to its version string. It becomes
  `verified.sdks` in the advertised 0.1/0.2 declaration, so a new version changes
  `declaration_id`. A 0.3 backend writes its own declarations: their `verified.sdks` must
  be the SDK set of the reports the values rest on, which for an HTTP endpoint is the
  conformance consumer's client packages at the versions the run used (the report's
  `sdk_versions`), not the backend's native SDK. Matching refuses a baseline report with
  another SDK set. Legacy 0.1 limitation: the reference's declaration
  carries the endpoint's current date in `verified.date`, and the 0.1 `declaration_id` is
  a hash of that declaration. A new create whose retained `declaration_id` predates a
  date change is refused as `conflict` before dispatch. The reference adds no refresh;
  a caller that sees this establishes a new discovery by explicit client setup.

The operator supplies `tokens`, a mapping from bearer token to account ID. The direction
is token to account: the endpoint authenticates the header, resolves its account, and
refuses a request whose `account_id` differs from it. Discovery names the token's account, so a
client configured with a different account ID rejects it. One endpoint and store
serve all of its accounts, while one `authority` names the single native scope behind
them; a provider that gives each account its own native credentials needs a backend that
selects the credential from `identity["account_id"]`.

### Isolation, guest paths and optional capabilities

The endpoint validates, authenticates and records. It provides no isolation. Whatever
isolates one sandbox from another and from the host is the native backend, and the
declaration must say only what that backend establishes. Paths in `read`, `write`, `run`
and `start` are absolute paths inside the guest; a backend must never resolve one against
the host file system or hand it to a host process.

`TestBackend`, the packaged deterministic double, is not a sandbox. It stores bytes in
memory, returns scripted output and starts no process, so it claims no baseline and no
isolation, and its legacy 0.1 declaration has empty `gates` and `evidence`. Do not copy it as a
provider or use it to mean "the baseline passes".

A method that exists does not establish the capability behind it. The endpoint
advertises no optional gate in the legacy 0.1 example; a 0.3 backend supplies its own
offering declarations and owns the truth of what they say. Either way an unknown
capability stays `unknown`, and a backend that
cannot do something honestly raises `Failure("unsupported_mode")` rather than
approximating it. Declare a capability only with the evidence the
[declaration](../spec/declarations.md) rules require; backend methods alone are not
evidence.

## Opt in to HTTP binding 0.3

Binding 0.3 is an explicit reference-control-plane configuration. Set
`EndpointSettings(binding_version="0.3")` or `SPS_HTTP_BINDING_VERSION=0.3` in
the starter. It also enables the bounded buffered-command envelope, so configure
the existing output and execution caps. Bootstrap GET responses use the fixed
4 MiB protocol ceiling and `SPS_HTTP_CONTROL_RESPONSE_BYTES` local ceiling (default
4 MiB). The starter's 0.3 profile publishes execution and observation limits of 60 seconds
(`SPS_HTTP_EXECUTION_MS` changes only the execution cap) and 16 MiB buffered output, the
envelope Core admission requires; the profile is a configuration default, not native proof.
The default remains 0.1; the existing
buffered-command option remains 0.2 when no explicit version is selected.

A 0.3 backend must implement the installed `AdmissionBackend` extension as well as
`BufferedCommandBackend`. `offerings(account)` supplies the current real offerings
and declarations. `create_admitted(identity, request, env, labels, admission)` must
fulfil the complete accepted request and establish the native lifetime policy before
returning ready. `observe_admitted(identity)` reports the actual state, labels and
lifetime. The endpoint performs the strict current declaration fit before reserving
or dispatching a new create, and stores the resulting admission with the allocation.
The extension's method names alone do not prove native support for request semantics,
default-principal file access, or a provider-enforced lifetime timer.

The 0.3 endpoint owns an explicit managed namespace: allocations accepted and
reserved by that endpoint for the authenticated account. Its list operation observes
every known identity in that namespace and paginates the complete result; resources
created outside it are not adopted or represented as a complete account inventory.
An observation failure fails the page rather than turning into absence. Stored
admission is recovered for get and create replay after restart even when the current
offering disappears or current caps shrink. Existing allocation databases with rows
that lack retained 0.3 admission are rejected at startup; use a separate database
rather than assigning them invented metadata.

`DockerBackend` remains the legacy 0.1/0.2 backend. The separate
`DockerBackend03` source implementation supplies requestful offerings and creation
for one configured immutable cached image on an existing operator-selected
Docker network. It uses a finite native `sleep` command and Docker auto-removal for
accepted lifetime, preserving the native `StartedAt` clock across endpoint recovery.
File reads and writes use native `cat` and `tee` exec streams under the image's
default principal, bounded to 16 MiB with whole-file overflow refusal. Its SDK-fake
tests exercise create JSON, discovery, file transfer, create/get and recovery without
starting Docker. This source implementation is not native fulfillment evidence or
hosted eligibility; network enforcement, image authority and the remaining 0.3
contract still require a separately reviewed native proof.

For the example starter, set `SPS_HTTP_BACKEND_FACTORY` to
`sandbox_provider_spec.http_reference.docker_backend_03:backend_from_environment`,
and configure `SPS_HTTP_DOCKER_IMAGE` with a cached `@sha256:` image reference,
`SPS_HTTP_DOCKER_NETWORK` with an existing non-internal bridge network, and
`SPS_HTTP_DOCKER_OWNER` with a stable 12-hex namespace. These are operator settings;
create-request environment values go only to Docker's container configuration.

[`DockerBackend`](../src/sandbox_provider_spec/http_reference/docker_backend.py) uses
Docker exec/create/inspect and archive APIs. Its baseline process reader lives in
the provider control plane. It never uploads a helper, writes persistent PID/output
files or runs a requested program on the host. Keep the configured owner namespace stable
when reopening the backend: changing that namespace could hide existing live
allocations. The native test reopens both the SDK and allocation store with the
same namespace and recovers the original identity. The store binds that native
authority at initialization; a changed namespace fails before any native lookup.

Docker archive operations use the daemon's native file authority, independent of
the command image's default user. This proof supplies no selected-user file mode
or guarantee that a separately configured user has equivalent file access.
Commands inherit the cached image's user; the tests do not grant a new
user-selection capability.

## Opt in to buffered commands

The default `EndpointSettings` keeps binding 0.1, empty `core_modes`, the existing
UTF-8 `run` result and the existing one-megabyte request/response caps. A backend
must separately implement the optional `BufferedCommandBackend.run_buffered`
extension. Set `buffered_commands=True` and provide positive
`buffered_command_output_bytes` (at most 16 MiB per stream) and `execution_ms`
(at most 30 seconds) to enable binding 0.2. Configuration fails closed if the
backend has no method. Discovery advertises the mode only in this configuration;
its selection token binds the declaration, binding, modes and limits.

The starter exposes the same explicit switch with
`SPS_HTTP_BUFFERED_COMMANDS=1`; optional decimal caps are
`SPS_HTTP_BUFFERED_COMMAND_OUTPUT_BYTES` (default 16777216) and
`SPS_HTTP_EXECUTION_MS` (default 30000). Do not set the switch until the native
backend implementation is verified for the declared caps.

For 0.2 allocations, the SQLite ownership row keeps the selected offering, binding,
modes and limits beside its response. Replays are resolved before current offering
admission. Existing 0.1 rows without that selection record are treated as baseline
only and cannot gain buffered-mode claims after a restart or configuration change.
For `run_buffered`, the installed
[`buffered_runner_argv`](../src/sandbox_provider_spec/http_reference/buffered_runner.py)
helper wraps a command such as `["sh", "-c", script]` with the canonical execution timer,
TERM, five-second grace and original-process-group KILL. It sends the wrapper source with
native exec; it does not upload or install a supervisor. Read its single framed stdout result
with `decode_buffered_runner_result`. The target needs Python 3, Linux `memfd_create` and
`/proc` process-group inspection; a backend with native termination can use its native
implementation instead. The helper starts its `E` timer once the child has been spawned and
sends TERM `E` plus `BUFFERED_RUNNER_TERM_ALLOWANCE_S` (0.25 s) after that: `E` runs from
dispatch, so TERM is never early, and the allowance covers the guest's startup so that
`execution_term` and `group_kill` can prove a correct TERM time. Do not add your own pad. This
helper does not change the starter or Endpoint into a generic
cancellation layer: authors must opt in from their `run_buffered` implementation.

The `DockerBackend` extension calls the same `buffered_runner_argv` through native Docker exec
and decodes its frame with the public helper in the cached image. It captures stdout and stderr
separately in per-execution anonymous files capped at 32 MiB each, snapshots at most `L+1` bytes
from each stream immediately when the foreground child completes, and closes its own descriptors.
Inherited guest descriptors can write until they close; the kernel releases each
capture file after the last descriptor closes. Later writes cannot change the
captured result or leave a persistent path. Each active command reserves at most
64 MiB of private capture storage (32 MiB per stream), within the existing 128 MiB
container memory ceiling. The runner reads at most `L+1` bytes per stream to decide
the output limit. This independent finite capture ceiling applies only to captured
stdout/stderr; it does not set a guest filesystem limit or terminate the workload.
If a guest writes beyond a stream's 32 MiB private capture ceiling, further writes
to that captured stream can fail. The shared inline runner uses
the cached image's Python standard library, Linux `memfd_create`, and `/proc`
process-group inspection; it adds no package or uploaded helper. The `/proc` scan
runs at most every 10 ms during the five-second TERM grace, bounded by the
container's 32-process limit.
The runner returns canonical base64, starts its independent
E timer when the guest child exists (TERM follows `E` by the fixed 0.25 s allowance), and retains the operation slot while a late
result or TERM-to-KILL obligation settles. Normal foreground completion snapshots
output without waiting for inherited stream EOF; ordinary background work remains
in the sandbox. These source semantics still require the separately reviewed finite
local Docker proof before they count as native evidence.

The installed composition factory is
`sandbox_provider_spec.http_reference.starter:create_application`; importing the module
reads no configuration. It takes
explicit `module:factory` import paths for the provider's native `Backend` factory
and operator-owned credential mapping, plus a persistent SQLite path and
`SPS_HTTP_ENDPOINT_ORIGIN`. An existing WSGI server that supports application factories
can load that factory, which fails closed unless all values are configured.
[`examples/http-binding/starter.py`](../examples/http-binding/starter.py) remains a
compatibility wrapper that builds `application` from the same factory for servers
configured with `starter:application`. Supply credentials through the operator's secret
configuration, never source code or logs. It does not start a server. WSGI transport
in tests calls the app in-process and does not establish HTTPS; deployment must use
the operator's existing server and HTTPS termination.

## The starter variables

`sandbox_provider_spec.http_reference.starter:create_application` reads these when it is
called, and fails closed when a required one is missing:

| Variable | Meaning |
| --- | --- |
| `SPS_HTTP_BACKEND_FACTORY` | Required. `module:factory`, a zero-argument callable that returns your `Backend`. |
| `SPS_HTTP_STATE_PATH` | Required. The SQLite file for allocation keys, replay records and identity fencing. Put it on persistent storage owned by the operator; it is bound to the backend's `kind` and `authority`, so a new `authority` needs a new file. |
| `SPS_HTTP_ENDPOINT_ORIGIN` | Required. The exact HTTPS origin the endpoint advertises. |
| `SPS_HTTP_ACCOUNT_TOKENS_FACTORY` | Required. `module:factory`, a zero-argument callable that returns the mapping from bearer token to account ID. Read the tokens from the operator's secret store inside it; never put them in source, arguments or logs. The mapping must not be empty. |
| `SPS_HTTP_BUFFERED_COMMANDS` | `1` enables binding 0.2 buffered commands (requires `run_buffered`); default `0`. |
| `SPS_HTTP_BUFFERED_COMMAND_OUTPUT_BYTES` | Per-stream output cap, default 16777216. |
| `SPS_HTTP_EXECUTION_MS` | Execution cap, default 30000 (60000 for 0.3). The conformance suites need at least 30000. |
| `SPS_HTTP_BINDING_VERSION` | `0.1`, `0.2` or `0.3`. |
| `SPS_HTTP_CONTROL_RESPONSE_BYTES` | 0.3 control-plane response ceiling, default 4 MiB. |

[Run the HTTP conformance suites](how-to/run-http-conformance.md) builds the same configuration
for you, in process.

## Check buffered-command semantics

The starter and `Endpoint` do **not** impose an execution timer or kill an author's native
process. For ordinary 0.1 `run`, `deadline` is an observation deadline only. For advertised
`buffered_commands_v1` in 0.2/0.3, the author backend's `run_buffered` must implement the
binding's independent execution limit: TERM at E, then KILL after five seconds if the original
group remains, and no completed result before settlement. The reference Docker backend
already implements this method with an inline runner in the target container, and
`DockerBackend03` inherits it. A Docker-backed author can reuse that command implementation
while supplying its own native allocation and lifecycle methods. Its inline runner sends TERM at
E and KILL after the five-second grace to the original process group, and returns only after
settlement. Other execution backends need their own native process-group controls. The endpoint
cannot add termination safely because it has no native process-group authority; observation
timeout must not cancel dispatched work.

Run the canonical HTTP conformance consumer against the installed SPS `coverage` suite and
select all `http.buffered.` rows. The canonical consumer is `boxrouter-http`'s
`run_http_suite`; its `HttpConformanceDriver` implements the public `http.buffered` and
`http.buffered_run` hooks, while the installed SPS module owns the workloads, witnesses and
judgments. The `boxrouter-http-suite` command in
[Run the HTTP conformance suites](how-to/run-http-conformance.md) runs them, with provenance,
against your backend in process:

```sh
boxrouter-http-suite --backend my_backend:create_backend \
  --sps-artifacts sps-artifacts --suite buffered --out reports/buffered
```

The `http.buffered_run` hook returns `{"ok": True, "stdout": bytes, "stderr": bytes,
"exit_code": int, "stdout_truncated": bool, "stderr_truncated": bool}` for a success (the
two flags come from the wire result) or `{"ok": False, "code": str, "outcome": str}` for a
typed error. `http.buffered.output_limit` checks that output over the limit is such a success.
A consumer that omits the hook or endpoint mode reports `not_run`, which is not a pass.
The normal Kit Core suite is separate and applies only when a real Core adapter and its
existing Kit `DriverFactory` are available. `HttpConformanceDriver` is not that factory;
the HTTP starter does not invent one. Kit's `--spec-checkout` must point to a standalone
SPS checkout root with `src/sandbox_provider_spec/` and `conformance/suite.yaml` — a clean
checkout of this repository; a directory that merely contains it fails Kit's
`checkout_root` layout checks. These diagnostics and baseline remain HTTP SPS reports,
not a synthetic Kit Core pass.

The causal rows catch a backend that ignores execution expiry (`execution_term`), returns
before termination settles, fails to keep the TERM-to-KILL obligation after its leader exits
(`group_kill`), terminates work at observation expiry instead of leaving it live until E
(`observation_versus_execution`), or waits for inherited stream EOF instead of returning live
foreground output while background work survives (`background_survives`). The bytes row also
checks exact per-stream bytes and ordinary nonzero exits. These are behavioral diagnostics,
not baseline requirements or universal 0.3 certification. Timing intervals crossing a required
boundary, missing witnesses, or late TERM/KILL remain unproven/errors; a correct endpoint can
be unproven when guest timing cannot establish the exact boundary. Disconnect/lost-reply and
full 16 MiB native storage require separate checks. Escaped process groups are outside the
guarantee.

## Exercise the endpoint with the canonical client in process

[`examples/http-binding/in_process_client.py`](../examples/http-binding/in_process_client.py)
drives the packaged `Endpoint` and `TestBackend` through `boxrouter_http`'s
`SyncBindingClient` and `AsyncBindingClient`, the canonical client, with no listener,
DNS lookup or host command. Install `boxrouter-http` beside SPS; it is a separate
distribution that brings HTTPX and Core (see [where to get it](how-to/run-http-conformance.md#install)). Both client faces take an asynchronous HTTPX
transport, and `httpx.WSGITransport` is synchronous, so the example's
`WsgiAsyncTransport` adapts it: it reads the request body, runs the WSGI call in a worker
thread, drains and closes the synchronous response, and returns a response backed by an
in-memory stream that the async client reads and closes. The example is test scaffolding,
not a production transport. Do not use it, or `WSGITransport`, against a deployed
endpoint.

```sh
python examples/http-binding/in_process_client.py
```

A client performs one authenticated discovery at explicit setup and keeps that context
for its exchanges; the example does not rediscover per request, and neither the client
nor the endpoint retries or refreshes after a mutation or an `unknown` outcome. Binding
0.3 recovers its retained admission for `get` and create replay after restart, as
described above. This recipe covers the baseline 0.1 path only and makes no claim about
buffered commands or 0.3.

It prints one line per face (`sync ... active destroyed absent` and the async
equivalent) and exits nonzero if a check fails. Each run performs authenticated
discovery, a create, a get, a destroy and a second get, checks that an unknown token and
another account's token are refused, and confirms that its temporary SQLite directory is
gone. The `https://` origin only has to equal the `endpoint_origin` the endpoint
advertises, which the client checks; it is not evidence of TLS, DNS or a reachable
endpoint. The bearer values are synthetic. This does not run conformance, produce a
report or establish any capability; the backend executes nothing.

The invariant is that `Endpoint` drains its native work before the backend is closed
or the SQLite state is removed: `Endpoint.close()` refuses new work and waits for native
calls in flight, and a backend must not be closed while it still owns work. Closing a
client only disposes its local HTTP resources and never destroys a remote sandbox; it has
no required order against the server. In the example each face closes its client after
all its exchanges have settled, then `reference_endpoint` closes `Endpoint`, would close a
backend that holds native resources (`TestBackend` holds none), and only then removes the
state directory, which it asserts is gone.

## Handle uncertainty and output honestly

The SQLite reservation commits before native create. Duplicate keys and concurrent
requests return the same identity or `unknown`; changed bytes conflict. Persist
exact request bytes and digest on the caller. The reference retains reservations
and a monotone UTC floor so expiry cannot be undone by clock rollback. A known
destroyed allocation replays as `unavailable`, preserving its identity.
An accepted native create whose identity was lost remains unknown after restart;
it is never submitted again. A production provider needs native reconciliation
and recovery/cleanup for that case, plus durable storage backup and fail-closed
handling if its key store is lost. The example does not implement that recovery.

Run, start, write and destroy have no request-ID deduplication. The tests inject
an HTTP read failure after dispatch and verify that the transport does not retry.
An explicit second dispatch is another native operation. Resolve the first
operation's outcome before deciding what to do next; closing a client is not
remote destruction.

A separate native stream reader retains at most 64 KiB of text per process for up
to 60 seconds, evicting oldest frames. UTF-8 replacement decoding is incremental
per stream. Assigned sequences are stable on replay; lost prefixes report `gap`.
A next frame that cannot fit the requested byte limit fails without moving the
cursor. Process handles and cursors are endpoint-lifetime state: loss is reported,
not replaced with an empty successful history. Native stream closure supplies EOF;
Docker exec metadata supplies exit. Neither implies the other.

The fixed Docker tests establish output before exit, environment/cwd/argv mapping,
separate streams, nonzero exit, split UTF-8 decoding, exact binary/empty files,
limits, allocation replay and owned cleanup. Deterministic tests additionally
cover EOF while running, retention eviction, expiry/rollback, malformed input,
corrupted/replayed replies, concurrent create and lost replies. Known-content
checks detect merged streams and corrupt file bytes that JSON shape validation
alone cannot detect. The existing SPS evidence checker rejects an unproven
terminal declaration.

## What is unfinished

For the legacy default 0.1 and opt-in 0.2 paths, discovery keeps empty facts,
gates and evidence. `verified` records the source version; it is not a baseline
pass. Binding 0.1 claims no optional capability or exact command bytes. The 0.2
source implementation does not establish cross-client compatibility or provider
eligibility. Declaration and 0.2 selection identities change with their bound
content. Binding 0.3 discovery uses backend offerings and its requestful control
plane and `DockerBackend03` source are covered by fake-SDK tests. The Docker backend
still requires native proof of its image, network, lifetime, file and execution
behavior before any fulfillment claim.

This is not a hardened network service. HTTPS termination, origin/DNS/redirect
policy, ingress framing/deadlines, deployment-wide admission and external disconnects
are untested. After request validation, the endpoint uses one monotonic deadline
across SQLite authority/key storage, scheduling, native dispatch, inspection and
buffer waiting. Requests without an observation field use a local five-second
operation budget (`operation_timeout_ms`); this adds no wire field. Its shared eight-call
admission limit rejects saturation as `provider_error/not_dispatched`; a timed-out
store or native call retains its slot until completion or failure. `run` and `process.start`
return `timeout/unknown` after admitted work stalls. They never retry or kill the
native process. A start finishing after timeout can leave a native process without
a returned handle; the caller must not retry that mutation.

Output inspection consumes the same budget as the subsequent local buffer wait.
An inspection timeout yields unknown execution state; genuine retained frames and
native EOF remain available, and late inspection cannot advance the caller's
cursor. A deadline does not establish a command execution limit or guaranteed
continuation. Tests release every injected stall and drain endpoint observations
before Docker cleanup. Embedders must call `endpoint.close()` before closing their
backend; shutdown reports still-owned work rather than silently abandoning it.

The deterministic deadline regression now passes. Native tests stall SDK calls
after actual Docker exec acceptance and during exec inspection, then establish
actual process continuation, native exit, exact file completion and cursor replay.
These are local SDK fault injections, not a hosted network latency or overload
measurement. HTTP parsing, schema checks, serialization and transport deadlines
remain outside this post-validation operation budget, as does endpoint startup.
SQLite still has its existing 10-second busy timeout; the caller does not wait for
that timeout, and a blocked store call continues owning its admission slot. Identity
read timeout is known not-dispatched. Create timeout can remain unknown while its
admitted transaction completes. Before every native create/replay lookup or inventory
lookup after storage, the worker checks the original deadline; releasing a store
lock cannot dispatch expired work. An outcome that remains unestablished stays
unknown on replay. If the original native create later settles with authoritative
success or refusal, the same key resolves to that result without redispatch; the
first observer's already returned timeout is unchanged. Neither path makes a second
attempt. Tests use real exclusive
SQLite locks to exercise these cases and saturation. This does not claim an OS
scheduling bound or an end-to-end HTTP deadline. Generic deployments still need
bounded ingress and process ownership across endpoint shutdown.

The network-disabled tests for this reference do not establish public HTTPS,
complete isolation/host-metadata resistance, the full SPS suite, hosted
registration/routing, evidence admission, account funding, pricing, billing,
commercial setup or external provider onboarding. They do not establish a native
0.3 backend or provider eligibility. Passing these tests must not admit an endpoint
or rewrite existing provider evidence.
