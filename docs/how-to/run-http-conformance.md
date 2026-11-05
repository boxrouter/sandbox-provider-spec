# Run the HTTP conformance suites

This is the one runnable path for an HTTP provider author: write a `Backend`, run the suites
against it in process, read the reports. It needs no listener, no deployed endpoint and no
provider account. For the backend interfaces see the
[HTTP reference](../http-binding-reference.md#the-installed-backend-interfaces).

## Install

Prerequisites: Bash, Git, Python 3.11 or newer, [uv](https://docs.astral.sh/uv/),
`gh` authenticated to GitHub, and `sha256sum`. `curl` is needed only when checking a
reachable URL. Create and activate the environment using the
[SPS virtual-environment step](../getting-started.md#install):

```sh
uv venv --clear --python 3.11 --seed .venv
. .venv/bin/activate
```

Install the packages below into that environment:

| Package | Where it comes from |
| --- | --- |
| `sandbox-provider-spec` | The SPS release wheel from this repository's releases. Each release (tag `v<version>`) carries the wheel, `SOURCE.json` and `SHA256SUMS`. Until releases are public, a maintainer supplies the same three files. |
| `boxrouter-http` 0.1.37 or newer | The consumer that runs the suites and provides the `boxrouter-http-suite` command. A maintainer supplies its wheel together with the `boxrouter-core` and `boxrouter-operation-timings` wheels it requires; its HTTPX and `anyio` dependencies come from PyPI. |

```bash
set -euo pipefail
mkdir -p sps-artifacts dist

# Pin the version here. The tag is exactly v<version>.
SPS_VERSION=0.3.126

gh release download "v$SPS_VERSION" -R boxrouter/sandbox-provider-spec \
  --dir sps-artifacts \
  --pattern 'sandbox_provider_spec-*.whl' --pattern SOURCE.json --pattern SHA256SUMS
(cd sps-artifacts && sha256sum --check SHA256SUMS)

# Put the supplied consumer wheels in dist/, then:
uv pip install \
  sps-artifacts/sandbox_provider_spec-*.whl \
  dist/boxrouter_operation_timings-*.whl dist/boxrouter_core-*.whl dist/boxrouter_http-*.whl
```

Install the SPS wheel file itself, the one you downloaded into `sps-artifacts`. An editable
or source install differs from the wheel file for file, which fails the check in
[Provenance](#provenance). Use the SPS release pinned above: older helpers cannot pass
`http.buffered.execution_term` and `group_kill`, and the metadata probe can outlast a short
observation window.

## Run

Write a factory that returns your `Backend` (and, for buffered commands, a `run_buffered`).
Then, from the directory that holds your module (both entry points add this directory to
Python's import path):

```sh
boxrouter-http-suite --backend my_backend:create_backend \
  --sps-artifacts sps-artifacts --reachable-url "$SPS_REACHABLE_URL" --out reports/run1
```

`--backend` takes the same `module:factory` path as `SPS_HTTP_BACKEND_FACTORY`, a zero-argument
callable. The command builds the endpoint the way the installed
[starter](../http-binding-reference.md#the-starter-variables) does, drives it through the
canonical `SyncBindingClient` over an in-memory transport, and writes
`<suite>-report.json` and `<suite>-receipt.json` for each suite into `--out`. It runs the
`baseline` suite, and `buffered` as well when the backend has `run_buffered`. Add `--suite
core` or `--suite coverage` for the full suites, and `--fixtures file.json` for fixtures (a
JSON object; `--reachable-url` sets `reachable_url`). To test an application you already
compose, pass `--app module:factory` (a callable that returns a WSGI application, such as
`sandbox_provider_spec.http_reference.starter:create_application`) with `--token-env VAR`,
`--origin` and `--account`.

Other options: `--execution-ms` (default 30000, see [the execution cap](#execution-and-output-caps)),
`--output-bytes`, `--binding-version 0.1|0.2|0.3`, `--no-buffered`.

Binding 0.3 requires the backend to implement the `AdmissionBackend` methods
`offerings`, `create_admitted` and `observe_admitted`, as well as `run_buffered`.
The starter reports a clear startup error if any are missing; implement those methods or select
another binding version.

The exit status is 0 when every row passed, 1 when any row is `differs` or `error`, and 3 when
nothing failed but some rows are `not_run` (not a pass). Each non-passing row is printed with
its reason.

The starter accepts any `kind` that is a valid SPS `Identifier`: 1–128 characters, beginning
with an ASCII letter or digit, followed by ASCII letters, digits, `.`, `_`, `:`, or `-`. It is
the stable provider ID used in discovery and sandbox identities; it is not a fixed list of
provider names.

The suite calls `close()` in a `finally` block after all selected suites finish. It calls the application’s
`close()` when present, then the backend’s `close()` when present (for `--app`, it uses the
application's `backend` attribute). Make shutdown idempotent if both objects close the same
backend.

For the reference backend interfaces, `Output` is constructed as
`Output(capacity: int, retention: float, clock: Callable[[], float] = time.monotonic)`.
`buffered_runner_argv(command, *, execution_limit_ms, output_limit_bytes)` accepts argv as its
positional command and requires both limit values by keyword. Its decoder returns
`BufferedRunnerResult(state, exit_code, stdout, stderr, stdout_truncated, stderr_truncated)`,
whose fields have types `str`, `int`, `bytes`, `bytes`, `bool`, and `bool`. The public helpers are
`decode_buffered_runner_result(frame: bytes) -> BufferedRunnerResult` and
`buffered_runner_frame_limit(output_limit_bytes: int) -> int`. `state` is one of
`completed`, `terminated`, or `unknown`. A completed result holds at most `output_limit_bytes`
of each stream, and a stream's flag is `true` when the command wrote more than that;
see the [HTTP binding reference](../http-binding-reference.md#result-mapping-for-run_buffered)
for how each result maps to the backend response.

## Provenance

A report is certifying only if the SPS code that produced it is the code of a release. The
command checks that before it creates anything: the installed package must match the release
wheel file for file, and `SOURCE.json` must name that wheel and a source revision.

- **Certifying run.** `--sps-artifacts DIR` points at a directory with the wheel
  `sandbox_provider_spec-<installed version>-py3-none-any.whl`, `SOURCE.json` and the release's
  `SHA256SUMS` (the `gh release download` above puts all three there). The hashes come from
  `SHA256SUMS`, which catches a corrupt download. To check against hashes you verified some
  other way, pass `--wheel-sha256` and `--source-sha256` (or set `SPS_WHEEL_SHA256` and
  `SPS_SOURCE_SHA256`); never take them from the endpoint under test. A mismatch stops the run
  and names what differs.
- **Local development run.** `--dev` skips provenance, so it works with an editable or source
  install of SPS. The run is marked non-certifying everywhere: the reports record the null
  source revision (`0000000000000000000000000000000000000000`) and are written as
  `*-report.dev.json`, the receipt carries `"certifying": false`, and SPS refuses a report with
  that revision as evidence (`sandbox-provider-spec check` fails it). A development report can
  be read and compared but never cited in a declaration. Do not hand-edit its revision;
  produce the cited report again with `--sps-artifacts`.

The same two modes exist in Python as `SpsArtifactProvenance` and `LocalDevelopmentProvenance`
for `boxrouter_http.conformance.run_http_suite`.

## What the suites expect of the guest

The baseline and `http.buffered.` rows run ordinary commands and file calls in your sandbox.

- **Tools.** `bash` and `python3` on `PATH`. The buffered helper needs Linux, `memfd_create` and
  `/proc` (see [`buffered_runner_argv`](../http-binding-reference.md#opt-in-to-buffered-commands)).
- **Filesystem.** `/tmp` exists and is writable by both commands and the file API, and the two
  see the same files: bytes written through `write` are readable by a command, and bytes a
  command writes are readable through `read`. Paths are absolute guest paths. A `cwd` of
  `None` means the sandbox's default working directory; `/tmp` must work as an explicit `cwd`.
  `write` needs the parent directory to exist; the binding implies no automatic parent
  creation. Environment values given at create are visible to every command, and a command's
  own `env` overlays them.
- **Background survival.** Work a command leaves running, and a `start`ed process, must outlive
  the call that started it. Anything that kills the sandbox's process tree when one command
  returns breaks `background_survives`, `observation_versus_execution` and `process_stream`: a
  new PID namespace per command (`bwrap --unshare-pid`, `unshare --pid`), `--die-with-parent`,
  a per-command scope or cgroup that is torn down at exit, or an exec session that is reaped on
  return. Run each command inside a long-lived sandbox root, as `docker exec` does in a
  container whose PID 1 is `sleep infinity`.
- **Network.** See below.

For a local backend, give each sandbox its own root and private temporary directory, then reuse
that root for its commands and file operations. For example, on Linux a backend can allocate a
fresh `$root` per sandbox and execute each command with Bubblewrap:

```sh
mkdir -p "$root/tmp"
bwrap --ro-bind / / --bind "$root/tmp" /tmp \
  --proc /proc --dev /dev --chdir /tmp -- "$@"
```

Keep the sandbox's process tree alive after an individual command returns so background work
and started processes remain observable. Do not use a PID namespace (for example,
`--unshare-pid`) or `--die-with-parent`; the backend must provide its own lifecycle cleanup.

### Network

The baseline needs both of these at once, so do not disable the network to pass one of them:

- `outbound_network` needs the sandbox to reach an HTTPS URL that the runner can also reach. The
  suite has no default: pass a `reachable_url` fixture (`--reachable-url`) that you have checked
  from both places. For example, set `SPS_REACHABLE_URL=https://api.github.com` and check it
  with `curl -fsSI "$SPS_REACHABLE_URL"` from the runner and from a command in the sandbox,
  then pass `--reachable-url "$SPS_REACHABLE_URL"`. Use a URL your environment permits. Without
  it the row is `not_run` (`fixture_missing`), never a pass.
- `no_metadata` needs the sandbox not to expose a cloud host's identity or credentials at the
  link-local metadata addresses `169.254.169.254`, `fd00:ec2::254` and `fd20:ce::254`. A shared
  host network passes when those addresses are unreachable or answer nothing identifying. The
  probe bounds its own waiting (an unroutable address is waited on once, concurrently, for about
  two seconds, and the whole probe stops within 3.5 seconds), so it fits inside the shortest
  observation window of five seconds. If the host exposes a real metadata service, block those
  addresses for the sandbox rather than removing all networking.

### Execution and output caps

The suite's longest buffered command runs for 30 seconds, so the endpoint must advertise
`execution_ms` of at least 30000 and `buffered_command_output_bytes` of at least the 65536 bytes
its witnesses read. A lower advertised cap makes those rows `not_run`
(`buffered_execution_limit_ms_above_advertised`). The command and the starter default to 30000
and 16 MiB; the starter's 0.3 profile defaults to 60000.

## Reading the results

- The HTTP consumer reports `not_run` for everything it cannot run or the endpoint does not
  offer: an unmapped operation, a missing fixture, an advertised cap that is too low, an
  operation the backend lacks. It never reports `unsupported`. `unsupported` needs a permitted
  documentation quote, so a `not_run` row says nothing about whether the capability exists.
- `differs` is a definite violation. `error` means the check could not establish its answer,
  for example `http_buffered_unproven_*` (a timing the guest clock cannot place) or a failed
  exchange.
- `http_request_not_dispatched` means the consumer could not send the HTTP request; inspect
  transport setup and endpoint reachability. `create_inputs_unmapped` means the selected
  binding cannot map one or more create inputs; inspect the request fields and binding version.
- Rows whose reason is `fixture_missing`, `driver_unimplemented` or `operation_unmapped` are
  the full core and coverage suites exercising things an HTTP provider does not expose; only
  the baseline and, for buffered commands, the `http.buffered.` rows apply to every endpoint.
- Baseline summary `passed` needs every baseline row to pass; a single `not_run` keeps it
  `not_run`.

The complete baseline is the `baseline.` rows of the coverage suite. Cite only tests that ran
from a committed, clean report made with `--sps-artifacts`.

After a certifying pass, continue with the [provider kit guide](provider-kit.md) to prepare or
update the provider declaration and its evidence.
