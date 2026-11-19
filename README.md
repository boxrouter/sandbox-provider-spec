# Sandbox Provider Spec

The open standard interface for sandboxes. A provider implements it once, with an adapter or in
its own API, and then works with every tool that speaks it: SDKs, agent frameworks, evaluation
harnesses, and routers. The interface is shared, and providers compete on the runtime underneath.

**Status: Provider API 1.0.** [Implement SPS 1.0](docs/implement.md) ·
[OpenAPI file](spec/provider-api-1.0.openapi.yaml) · [Rules](spec/provider-api.md) ·
[Changelog](CHANGELOG.md) · [Contribute](CONTRIBUTING.md)

The request, declaration, and matching formats (format 0.1) are a working draft that may still change.

## For Sandbox Providers

Start with **[Implement SPS 1.0](docs/implement.md)**. It is one page that covers the two ways to
conform, the eleven required operations, discovery and prices, cost, errors, the template adapter,
and the tester.

```console
git clone https://github.com/boxrouter/sandbox-provider-spec
cp -r sandbox-provider-spec/template my_adapter
# Replace the template's Example Cloud calls with calls to your API, then run the tester:
uvx --from git+https://github.com/boxrouter/sandbox-provider-spec --with ./my_adapter sandbox-provider-spec test example --credential api_key=EXAMPLE_API_KEY
```

The tester runs the same tests that any consumer runs. It prints one line per required operation
and per optional section that you claim, and it exits 0 only when every test passes. A provider
that serves the API itself runs the same command against its base URL.

## Why A Standard

Every tool that supports more than one provider ends up maintaining its own integration for each
one. SPS replaces those private integrations with one interface and one set of tests, the way SMTP
did for mail. A provider that conforms works with every consumer, and a consumer that speaks SPS
reaches every conforming provider. The interface, the tests, and the template assume nothing about
any one consumer.

## What Is In This Repository

| Part | Where | Who uses it |
| --- | --- | --- |
| Provider API 1.0 | [`spec/provider-api-1.0.openapi.yaml`](spec/provider-api-1.0.openapi.yaml), [`spec/provider-api.md`](spec/provider-api.md) | Providers and consumers |
| Python interface, tester, and reference server | [`src/sandbox_provider_spec/v1/`](src/sandbox_provider_spec/v1/) | Adapter authors and consumers |
| Template adapter and its fake provider | [`template/`](template/) | Adapter authors |
| Capability vocabulary | [`spec/vocabulary.md`](spec/vocabulary.md) | Optional sections, requests, and declarations |
| Requests, declarations, and matching | [`spec/spec.md`](spec/spec.md), [`spec/declarations.md`](spec/declarations.md), [`spec/matching.md`](spec/matching.md) | Tools that choose a sandbox for a workload |
| Conformance suite and reports | [`conformance/`](conformance/), [`spec/conformance.md`](spec/conformance.md) | The tester and anyone who checks a claim |

## For Tools That Choose A Sandbox

Sandbox providers differ in details that code relies on. "Pause" may keep running processes or only
files, and an egress allowlist may take host names or only addresses. A request states what a
workload relies on, a declaration states what a provider offers with evidence for each value, and
matching decides, with reasons, whether the two fit. This request is for a coding agent that keeps
its sandbox for a day, pauses between sessions with its processes intact, shows a dev server on
port 3000, and may reach only `api.github.com`:

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

`check` validates a file against the format, offline. `ok` means that the file is well formed; it
does not prove that any provider satisfies it:

<!-- sps:example exit=0 stream=stdout -->

```console
$ sandbox-provider-spec check coding-agent.yaml
coding-agent.yaml: ok
```

`match` compares the request with declarations that ship in the package. Each refusal names the
line of the request that failed. Here, one provider offers only address allowlists, and the other
pauses without keeping running processes:

<!-- sps:example exit=1 stream=stdout -->

```console
$ sandbox-provider-spec match coding-agent.yaml --met-need pro_plan \
    "$(sandbox-provider-spec installed-declaration e2b)" \
    "$(sandbox-provider-spec installed-declaration vercel)"
e2b: not eligible
  - baseline_failed: no newest clean baseline-passing report for this provider, class and SDK set
  - limit_exceeded: variant 1: entry_kinds ['addresses'] does not cover ['names']; variant 2: policy: asked allowlist, offers deny_all
vercel: not eligible
  - baseline_failed: no newest clean baseline-passing report for this provider, class and SDK set
  - knob_mismatch: variant 1: keeps: asked files_and_memory, offers files_only
  - knob_mismatch: variant 1: policy: asked allowlist, offers deny_all
  - resource_mismatch: at_end: asked paused, declared ['destroyed', 'stopped']
```

Matching is offline. Exit 0 means that at least one declaration qualifies; exit 1 means that none
does or an input is invalid. `baseline_failed` means that the cited reports do not establish the
baseline that every provider must pass. The [tutorial](docs/getting-started.md) walks through more.

<!-- sps:counts -->
The vocabulary has 16 gates and 48 knobs; the conformance suite has 275 tests.

## Principles

Only what code relies on enters the vocabulary. `unknown` is a value of its own, and it never
satisfies a request. Every value rests on evidence: a test that anyone can rerun, or a dated quote of
the provider's own documentation. The specification standardizes behavior, not APIs, and matching is
shared while choosing is not.

## Documentation

| Read | To |
| --- | --- |
| [Implement SPS 1.0](docs/implement.md) | Make a provider conform |
| [Tutorial](docs/getting-started.md) | Check a request and interpret a match without an account |
| [Compare providers](docs/how-to/compare-providers.md), [read evidence](docs/how-to/read-evidence.md) | Compare declarations and read reports |
| [Add a provider](docs/how-to/add-provider.md), [run conformance](docs/how-to/run-conformance.md) | Write a declaration and driver; produce reports |
| [Specification index](spec/README.md) | Look up the baseline, vocabulary, requests, matching, declarations, and schemas |

## Contributing

Start with a [good first issue](https://github.com/boxrouter/sandbox-provider-spec/issues?q=is%3Aissue%20is%3Aopen%20label%3A%22good%20first%20issue%22)
or [help wanted](https://github.com/boxrouter/sandbox-provider-spec/issues?q=is%3Aissue%20is%3Aopen%20label%3A%22help%20wanted%22).
Corrections, new providers and vocabulary proposals are welcome. [CONTRIBUTING.md](CONTRIBUTING.md)
explains setup, DCO and proposals; [GOVERNANCE.md](GOVERNANCE.md) explains decisions. Report
vulnerabilities through [SECURITY.md](SECURITY.md). Follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Development

Python 3.11 or newer with `venv` and `pip` is required. To install the command from source,
start in a [checkout](docs/getting-started.md#install):

<!-- The tutorial links here so there is one installation entry point. -->
<!-- sps:install -->

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
```

To work on the specification or the package, use [uv](https://docs.astral.sh/uv/) and run
`make check` as [CONTRIBUTING.md](CONTRIBUTING.md#setting-up) describes. See [NOTICE](NOTICE) for
ownership and copyright. Licensed under [Apache-2.0](LICENSE).
