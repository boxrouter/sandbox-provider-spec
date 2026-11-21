# Sandbox Provider Spec

An open standard for running code in sandboxes and describing what each sandbox provider guarantees.

**Status:** Provider API 1.0 · Capability, declaration, request, and matching formats 0.1 (working draft)

[Implement SPS 1.0](docs/implement.md) · [OpenAPI file](spec/provider-api-1.0.openapi.yaml) · [Rules](spec/provider-api.md) · [Specification index](spec/README.md) · [Tutorial](docs/getting-started.md) · [Changelog](CHANGELOG.md) · [Contribute](CONTRIBUTING.md)

> [!IMPORTANT]
> **This specification is young and open to contribution.** It is published to be used and argued with, and it will keep moving as implementers find gaps. If your sandbox does something that the vocabulary cannot express, or if a rule is stated in a way that you cannot implement or test, please [open an issue](https://github.com/boxrouter/sandbox-provider-spec/issues). You can also propose a new capability or add your provider by following [CONTRIBUTING.md](CONTRIBUTING.md).

## What SPS Is

A **sandbox** is an isolated Linux machine that an agent or a program controls through an API to run commands, read and write files, and run background processes.

Many cloud providers offer sandboxes. At the surface, their interfaces look similar: you create a machine, run a command, copy files in and out, and stop or destroy the machine. Underneath, providers differ in the guarantees that code relies on. On one provider, pausing a sandbox keeps running processes in memory; on another, pausing keeps only the files on disk. One provider's outbound network allowlist accepts domain names; another accepts only IPv4 addresses.

Without a common standard, every tool that supports more than one sandbox provider must maintain a separate integration for each provider and guess which features work from documentation and pricing pages.

The **Sandbox Provider Spec (SPS)** replaces private integrations and guesswork with an open standard that has two parts:

1. **[Provider API 1.0](spec/provider-api.md):** one interface for driving sandboxes, coupled with a conformance tester (`sandbox-provider-spec test`) that checks whether an implementation follows the rules.
2. **[Capability vocabulary and matching (format 0.1)](spec/spec.md):** a shared language for stating what a sandbox provider actually guarantees, backed by test reports, so that a tool can check offline whether a provider fits a workload before creating a sandbox.

### What It Gets You

- **For tools and developers** (agent frameworks, SDKs, evaluation harnesses, and routers): You write against one interface instead of maintaining one integration per provider. You describe what your workload needs in a short file, and you choose or switch providers based on tested guarantees rather than marketing copy.
- **For sandbox providers:** You implement the interface once, either in your own HTTP server or through a small Python adapter over your existing API, and your service works with every tool that speaks SPS. You prove how your runtime behaves with the public tester and describe your real features with evidence.

### SPS at a Glance

Every provider that implements Provider API 1.0 supports ten required operations (`discovery`, `create`, `get`, `list`, `destroy`, `run`, `files.read`, `files.write`, `process.start`, and `process.output`), plus any optional operations that it claims for costs, file links, pause and resume, lifetime extension, process input and cancellation, HTTP previews, TCP ports, interactive terminals, snapshots, directories, and prepared images.

When a program needs specific runtime guarantees, it writes a short request in YAML or JSON:

```yaml
lifetime_seconds: 3600
requirements:
  pause_resume: {keeps: files_and_memory}
  network_lockdown: {policy: allowlist, allow: [api.github.com]}
resources:
  memory_min_mib: 4096
```

SPS checks that request offline against each provider's published capability file and tells you which providers qualify and which exact line fails on the providers that do not.

## For Sandbox Providers

Start with **[Implement SPS 1.0](docs/implement.md)**. It is a single-page guide that covers the two ways to conform, the ten required operations, discovery and price lists, the optional `cost` operation, the twelve error codes, optional feature sections, the template adapter, and the conformance tester.

A provider conforms to Provider API 1.0 in one of two ways:

- **Ship a Python adapter:** Write a small Python package that implements the `Provider` class by translating SPS operations into calls to your existing API. You can start by copying [`template/`](template/), which is a working adapter over a fake provider API.
- **Serve the HTTP API directly:** Serve the operations defined in [`spec/provider-api-1.0.openapi.yaml`](spec/provider-api-1.0.openapi.yaml) at an HTTPS base URL that you choose. Any Python adapter can also be served over HTTP with `sandbox-provider-spec serve`.

```console
git clone https://github.com/boxrouter/sandbox-provider-spec
cp -r sandbox-provider-spec/template my_adapter
# Replace the template's Example Cloud calls with calls to your API, then run the tester.
```

The guide's [Get Started](docs/implement.md#get-started) section has every command, from starting the template's stand-in cloud to running the tester.

The tester runs the same conformance checks that any consumer runs. It prints one result line for each required operation and for each optional section that your discovery response claims, writes a JSON report, and exits 0 only when every test that it ran passes. A provider that serves the HTTP API directly runs the same command against its HTTPS base URL.

## For Tools That Choose A Sandbox

Even when two providers share the same API, their runtimes differ in details that code depends on. SPS defines a vocabulary in [`spec/vocabulary.md`](spec/vocabulary.md) to describe those details without ambiguity:

- A **baseline** is the set of behaviors that every provider must support in the same way, such as running commands with separated standard output and standard error, reading and writing files, starting background processes, providing `bash` and `python3`, allowing outbound HTTPS by default, and blocking access to host cloud metadata.
- A **gate** is an optional feature that a provider either offers or does not offer, such as `pause_resume`, `previews`, `network_lockdown`, `snapshots`, or `terminal`.
- A **knob** is a specific detail of a gate where providers differ and where code depends on the behavior. For example, on `pause_resume`, the `keeps` knob says whether resuming a paused sandbox restores running processes (`files_and_memory`) or only the filesystem (`files_only`). On `network_lockdown`, the `entry_kinds` limit says whether an allowlist accepts host names (`names`), IPv4 addresses (`addresses`), or both.
- A **declaration** ([`spec/declarations.md`](spec/declarations.md)) is a YAML file for a provider class that states which gates, knob values, limits, and resource facts the provider offers. Every declared value other than `unknown` cites evidence: either a passing conformance test in a committed run report or, for a fact that no test can observe from inside a sandbox, a dated quote from the provider's documentation.
- A **request** ([`spec/spec.md`](spec/spec.md)) is a YAML or JSON file that states the gates, knob values, resource minimums, and lifetime that a workload relies on.
- **Matching** ([`spec/matching.md`](spec/matching.md)) compares a request against one or more declarations and decides, with exact reasons, whether each declaration satisfies the request.

The request below describes a coding agent that keeps its sandbox for a day, pauses between sessions with its running processes intact, exposes a development server on port 3000, needs at least 4 GiB of memory, and may connect out only to `api.github.com`:

<!-- sps:example file=coding-agent.yaml -->

```yaml
lifetime_seconds: 86400
at_end: paused
requirements:
  pause_resume: {keeps: files_and_memory}
  previews: {access: public, ports: [3000]}
  network_lockdown: {policy: allowlist, allow: [api.github.com]}
resources:
  memory_min_mib: 4096
```

The `check` command validates a request or declaration against the specification rules offline. An `ok` result means that the file is well formed; it does not prove that any provider satisfies the request:

<!-- sps:example exit=0 stream=stdout -->

```console
$ sandbox-provider-spec check coding-agent.yaml
coding-agent.yaml: ok
```

The `match` command compares the request against provider declarations that ship in the package. When a declaration does not qualify, each refusal line names the requirement that failed and why. In this example, the declaration for a local container engine offers no previews or network lockdown, and it does not state how long a sandbox may live, what an ended sandbox does, or its sizes:

<!-- sps:example exit=1 stream=stdout -->

```console
$ sandbox-provider-spec match coding-agent.yaml --met-need pro_plan "$(sandbox-provider-spec installed-declaration docker-engine)"
docker-engine: not eligible
  - baseline_failed: no newest clean baseline-passing report for this provider, class and SDK set
  - gate_not_listed: previews: this route does not list it, so it is not offered
  - gate_not_listed: network_lockdown: this route does not list it, so it is not offered
  - resource_unknown: lifetime_seconds 86,400: the most a route allows is unknown
  - resource_unknown: at_end: asked paused, declared ['unknown']
  - resource_unknown: sizes: declared unknown, asked {'memory_min_mib': 4096}
```

Matching runs offline without provider credentials and without creating a sandbox. Exit code 0 means that at least one declaration qualifies; exit code 1 means that no declaration qualifies or that an input file is invalid. A `baseline_failed` refusal means that the declaration's cited reports do not establish a clean pass across every baseline test that all providers must pass. The [tutorial](docs/getting-started.md) walks through checking requests and reading refusal reasons in detail.

<!-- sps:counts -->
The vocabulary has 16 gates and 48 knobs; the conformance suite has 284 tests.

## What Is In This Repository

| Part | Where | Who uses it |
| --- | --- | --- |
| Provider API 1.0 | [`spec/provider-api-1.0.openapi.yaml`](spec/provider-api-1.0.openapi.yaml), [`spec/provider-api.md`](spec/provider-api.md) | Providers and consumers |
| Python interface, tester, and reference server | [`src/sandbox_provider_spec/v1/`](src/sandbox_provider_spec/v1/) | Adapter authors and consumers |
| Template adapter and its fake provider | [`template/`](template/) | Adapter authors |
| Capability vocabulary | [`spec/vocabulary.md`](spec/vocabulary.md) | Optional sections, requests, and declarations |
| Requests, declarations, and matching | [`spec/spec.md`](spec/spec.md), [`spec/declarations.md`](spec/declarations.md), [`spec/matching.md`](spec/matching.md) | Tools that choose a sandbox for a workload |
| Conformance suite and reports | [`conformance/`](conformance/), [`spec/conformance.md`](spec/conformance.md) | The tester and anyone who checks a claim |

## Principles

- **Only what code relies on enters the vocabulary.** A gate, knob, or resource fact is added only when leaving it out would allow a program to be matched to a provider that breaks it. Edge cases are covered by conformance tests and rules rather than extra vocabulary words.
- **When in doubt, the answer is no.** `unknown` is a value of its own that means nobody has established the answer yet. Except where a request explicitly says `"any"`, `unknown` never satisfies a requirement.
- **Every claim rests on verifiable evidence.** Every value in a declaration other than `unknown` must cite either a conformance test result in a committed report that anyone can rerun, or a dated quote from the provider's own documentation for facts that no test can reach.
- **Matching is shared, while choosing is not.** Matching is deterministic: any compliant matcher produces the same eligibility answer and refusal reasons for a given request and declaration. How a tool chooses among several eligible providers—for example by price, latency, or live availability—is outside the specification.

## Documentation

| Read | To |
| --- | --- |
| [Implement SPS 1.0](docs/implement.md) | Make a provider conform with an adapter or a native HTTP API |
| [Tutorial](docs/getting-started.md) | Check a request and interpret a match offline without a provider account |
| [Compare providers](docs/how-to/compare-providers.md), [read evidence](docs/how-to/read-evidence.md) | Compare provider declarations and inspect the cited conformance reports |
| [Add a provider](docs/how-to/add-provider.md), [run conformance](docs/how-to/run-conformance.md) | Write a declaration and driver, and produce conformance reports |
| [Specification index](spec/README.md) | Look up the normative baseline, vocabulary, request rules, matching rules, declarations, and JSON schemas |

## Contributing

SPS is open to sandbox providers, tool authors, and developers who run workloads in sandboxes.

Start with a [good first issue](https://github.com/boxrouter/sandbox-provider-spec/issues?q=is%3Aissue%20is%3Aopen%20label%3A%22good%20first%20issue%22)
or [help wanted](https://github.com/boxrouter/sandbox-provider-spec/issues?q=is%3Aissue%20is%3Aopen%20label%3A%22help%20wanted%22).
If a workload requirement cannot be written in the current vocabulary, or if a provider rule is stated in a way that cannot be implemented or verified, [open an issue](https://github.com/boxrouter/sandbox-provider-spec/issues). Documentation fixes, new provider adapters and declarations, updated evidence reports, and vocabulary proposals are all welcome.

- **[CONTRIBUTING.md](CONTRIBUTING.md)** explains how to set up a checkout, sign commits under the Developer Certificate of Origin (`git commit -s`), propose a change to the specification, and add or update a provider declaration.
- **[GOVERNANCE.md](GOVERNANCE.md)** explains how specification changes are reviewed and versioned, how a provider can take review ownership of its declaration while evidence in conformance reports decides every claim, and how to scope public conformance claims.
- **[SECURITY.md](SECURITY.md)** explains how to report a vulnerability privately.
- **[Code of Conduct](CODE_OF_CONDUCT.md)** sets the standards for taking part in this project.

## Development

Python 3.11 or newer with `venv` and `pip` is required. To install the `sandbox-provider-spec` command from source, start in a [checkout](docs/getting-started.md#install):

<!-- The tutorial links here so there is one installation entry point. -->
<!-- sps:install -->

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
```

To work on the specification or the Python package, install [uv](https://docs.astral.sh/uv/) and run `make check` as [CONTRIBUTING.md](CONTRIBUTING.md#setting-up) describes. `make check` runs formatting, linting, type checks, unit tests, declaration validation, link and anchor checks, and the offline README transcripts without needing a provider account.

## License

Licensed under [Apache-2.0](LICENSE). See [NOTICE](NOTICE) for ownership and copyright.
