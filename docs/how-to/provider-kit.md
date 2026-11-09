# Provider onboarding kit

Start from native handlers, write an honest declaration, and validate it. This kit
does not admit a provider to hosted routing and does not require a hosted account.

## Generate and check a starter

From an environment where this package is installed:

```sh
sandbox-provider-spec scaffold --output declaration.yaml
sandbox-provider-spec check declaration.yaml
```

The generator validates structural defaults against the current catalog before creating a new file.
An existing file is never replaced. Optional gates are omitted, which matching
reads as unknown. The file does not invent processes, PTY, snapshots, or other
optional capabilities. `check` validates structure, vocabulary, and the evidence map.
It is declaration self-assessment: it does not contact a provider, open an HTTP
endpoint, or prove a baseline pass. It is not admission.

```yaml
spec: sandbox-provider-spec/0.1
provider: example
verified:
  date: 2026-10-22
  sdks:
    example-sdk: "0.0.0"
resources:
  kernel: unknown
gates: {}
evidence: {}
```

## Identity and versioning

Replace the generated identity before claiming a run:

| Field | Meaning |
| --- | --- |
| `spec` | `sandbox-provider-spec/0.1`. A tool refuses a version it does not know. |
| `provider` | Lowercase letters, digits, and hyphens. It names the declaration and the `x-<provider>` extension. |
| `verified.date` | Date of the newest run the values rest on, or the date cited documentation was last reviewed when no run exists. A date does not claim a test ran. |
| `verified.sdks` | Client or SDK versions used for that run. Quote them in YAML. Replace `0.0.0` after a real run. `sdks` must not be empty. |

A new SDK version, or a change to a declared value, needs a new full run and an
updated `verified` block. See [the declaration fields](../../spec/declarations.md#the-fields).

## Implement native handlers

Implement the nine required operations against your own control plane:
`create`, `get`, `list`, `destroy`, `run`, `files.read_bytes`, `files.write`,
`process.start`, and `process.output`. Follow the [HTTP binding](../../spec/binding-http.md).
Do not add a guest supervisor.

Reuse the installed `sandbox_provider_spec.http_reference.Endpoint` and
`sandbox_provider_spec.http_reference.Backend`. Construct `Endpoint` with your
`Backend`, an owned state path, credential mapping, and `EndpointSettings`
whose `endpoint_origin` is required. Validate wire messages with
`sandbox_provider_spec.http_binding_validation`; it loads schemas from the
installed package. Do not copy the endpoint, schema, transport, or validator.

The composition steps are the canonical
[`docs/http-binding-reference.md`](../http-binding-reference.md). The installed
application factory is `sandbox_provider_spec.http_reference.starter:create_application`;
[`examples/http-binding/starter.py`](../../examples/http-binding/starter.py) wraps it.
The reference lists the [installed backend method signatures](../http-binding-reference.md#the-installed-backend-interfaces)
and shows how to [exercise the endpoint with the canonical client in process](../http-binding-reference.md#exercise-the-endpoint-with-the-canonical-client-in-process).

Baseline background output is required: a started process must produce observable
output before it exits. Richer process control and PTY need native implementations.
Leave those gates out until the native API does the work.

Implement the binding version and modes your consumer requires. The nine baseline
handlers alone do not establish the stronger buffered-command mode or the 0.3
admission and lifecycle guarantees. Advertise only the versions and modes the
implementation supplies; consumers must refuse an unsupported requirement.

Credentials come from environment variables or approved secret input, never from
command arguments. Record account setup, default-image requirements, and failure
outcomes in evidence once they are proven. Write a second variant only when choosing
one value forces another; a conditional knob belongs only in the variant where it
applies.

## What a consumer's create needs (binding 0.3)

A consumer that creates sandboxes through binding 0.3 admission needs all of the following.
In one place:

- Implement `Backend`, `BufferedCommandBackend.run_buffered` and `AdmissionBackend`, and
  run the starter with `SPS_HTTP_BINDING_VERSION=0.3`.
- Give each declaration a `lifetime_timer` block with `counts_from: ready`,
  `counts_paused_time: false`, integer `step_seconds` and `min_seconds`, and `at_end`.
  `lifetime_timer.at_end` and `lifetime_timer.enforced_by` need test evidence: cite
  `lifetime_timer.at_end.destroyed`. Other values may cite a dated quote of your own
  documentation.
- After a lifetime ends or a destroy, `get` must report `destroyed` for that incarnation,
  not `absent`: keep a record of destroyed identities.
- Set `verified.sdks` to the conformance client's SDK set (see
  [the backend interfaces](../http-binding-reference.md#identity-authority-and-credentials)).
- Produce two reports with the HTTP conformance consumer: the complete baseline, and a
  report that selects only the fact checks you cite (for example
  `lifetime_timer.at_end.destroyed`). Matching reads the newest report that selects the
  whole baseline; a partial report does not displace it. A consumer may refuse a report
  with any `error` row, even from a non-normative diagnostic, so select only the checks you
  cite.

## Honest reporting

A gate left out means nobody has looked (`unknown`). `unsupported` means they looked
and it is not offered; that still needs a permitted documentation quote. A passing
test in a clean committed report proves a value. Do not declare a capability the
native API lacks.

`sandbox-provider-spec check` is declaration self-assessment of the file.
`sandbox-provider-spec run` is native-only: it drives a registered native SDK
driver in this package. See [Run conformance](run-conformance.md). It does not
accept an HTTP endpoint.

A new provider needs no bundled native SPS driver. Adapter or HTTP reports may supply all
of its declaration evidence; native reports are optional. Existing native drivers remain
independent measurement paths. Keep the actual adapter implementation identity, source
digest and installed versions in its reports; Kit validates those bindings in addition
to SPS's declaration and evidence checks.

For a Core adapter, use Adapter Kit's `CoreDriver` and declarative `DriverFactory`; no
provider-specific driver subclass is needed for operations Core already expresses. Run
both suites with its `boxrouter_adapter_kit.spec_run` runner. A configured Core HTTP
adapter uses the same path. See the installed Kit's conformance instructions for setup,
class aliases, fixtures and report provenance. A missing mapping stays `not_run` and
cannot establish that the provider lacks a capability.

HTTP reporting uses `boxrouter-http`, a separately installed consumer, and one command runs
the baseline and buffered suites in process against your backend: `boxrouter-http-suite`. See
[Run the HTTP conformance suites](run-http-conformance.md) for where to get the packages, the
exact command, SPS provenance (a certifying run against the release wheel, or a non-certifying
`--dev` run) and what the guest must provide. `boxrouter-http`'s `run_http_suite` is the same
runner as a Python call. The native CLI does not load that consumer or supply its HTTP client.
The consumer implements the installed `sandbox_provider_spec.driver.Driver` contract and uses
`sandbox_provider_spec.conformance.run_suite` plus `sandbox_provider_spec.report.report` and
`write_report` to emit a standard report. Kit `spec_run` is a separate path and applies only
when the provider also has an existing Core `SandboxProvider` and configured Kit
`DriverFactory`. `HttpConformanceDriver` is an SPS HTTP `Driver`, not a Kit `CoreDriver`; the
HTTP starter supplies no generic `make_driver` factory. Do not substitute a placeholder factory
or claim a Kit run for an HTTP-only provider. When a genuine Core factory exists, Kit keeps
`passed`, `differs`, `error`, `not_run` and `unsupported` rows distinct, and its
`--spec-checkout` must be a standalone clean SPS checkout root with `src/sandbox_provider_spec/`
and `conformance/suite.yaml`. The Cloud workspace root and nested SPS package directory are not
valid roots. Keep HTTP SPS and Kit reports separate; neither claims the other's results.
Constructing an `Endpoint` alone does not run conformance or produce a report.

The HTTP consumer reports `not_run` for every operation it cannot map or the endpoint does not
offer, and never `unsupported` (which needs a permitted documentation quote). A `not_run` row is
not evidence that a capability is absent.

For an HTTP endpoint advertising `buffered_commands_v1`, the same command also runs the
`http.buffered.` rows of the `coverage` suite. Its `HttpConformanceDriver` implements the
diagnostic transport hook; SPS owns the process workloads and causal witnesses. A `not_run` row
means the hook or mode was unavailable, not that execution termination passed. The starter and
Endpoint do not add TERM/KILL to an arbitrary author `Backend`; termination is the backend's
responsibility under the binding, and the public `buffered_runner_argv` helper provides it for a
Linux/Python guest. The diagnostics catch ignored E, missing group KILL settlement, work stopped
by O, and EOF mistaken for foreground completion. They are useful implementation checks, but not
a full binding 0.3 certification.

Matching still needs a clean committed report that selected every
[baseline](../../spec/spec.md#5-baseline) test. Cite only tests that ran. Keep
failed and unclean full-baseline reports; do not hide a newer failure behind an
older pass.

To select the complete baseline for a callable consumer, include the supplementary
suite before filtering. The original suite alone does not select later baseline
checks, although its baseline identity names them:

```python
from sandbox_provider_spec.conformance import select
from sandbox_provider_spec.suite import read_suite, suite_path

baseline = select(read_suite(suite_path().with_name("coverage.yaml")), ["baseline."])
```

`boxrouter-http-suite` selects this for you. The metadata-isolation baseline needs no native
per-command execution limit: its HTTP requests are bounded inside the probe, which finishes
within 3.5 seconds even when the link-local addresses drop packets. The `outbound_network` row
needs a `reachable_url` fixture (see [the network section](run-http-conformance.md#network)). Supplementary fact probes retain
their own execution limits.

Self-assessment is the declaration plus cited reports. Hosted admission is a
separate step. Passing these commands does not route production traffic.

[Unknown values](../explanation/evidence-and-unknown.md) never count as support.
