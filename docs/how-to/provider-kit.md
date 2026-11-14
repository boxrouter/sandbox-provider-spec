# Provider onboarding kit

Write an honest declaration and validate it. This kit
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
It is declaration self-assessment: it does not contact a provider or prove a baseline pass. It is not admission.

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

## Honest reporting

A gate left out means nobody has looked (`unknown`). `unsupported` means they looked
and it is not offered; that still needs a permitted documentation quote. A passing
test in a clean committed report proves a value. Do not declare a capability the
native API lacks.

`sandbox-provider-spec check` is declaration self-assessment of the file.
`sandbox-provider-spec run` is native-only: it drives a registered native SDK
driver in this package. See [Run conformance](run-conformance.md).

A new provider needs no bundled native SPS driver. Adapter reports may supply all
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

Self-assessment is the declaration plus cited reports. Hosted admission is a
separate step. Passing these commands does not route production traffic.

[Unknown values](../explanation/evidence-and-unknown.md) never count as support.
