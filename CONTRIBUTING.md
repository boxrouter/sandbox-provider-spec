# Contributing

Thank you for helping. Read the [README](README.md) and [the specification](spec/spec.md)
first; [GOVERNANCE.md](GOVERNANCE.md) says how changes are decided.

For a small first contribution, choose a
[good first issue](https://github.com/boxrouter/sandbox-provider-spec/issues?q=is%3Aissue%20is%3Aopen%20label%3A%22good%20first%20issue%22)
or [help wanted](https://github.com/boxrouter/sandbox-provider-spec/issues?q=is%3Aissue%20is%3Aopen%20label%3A%22help%20wanted%22).
Documentation corrections and new example requests are useful starting points.

## Contributing by pull request

Open pull requests on this repository. Maintainers review contributions and merge accepted
changes with their authorship and sign-off preserved.

## Sign your work

This project uses the Developer Certificate of Origin (DCO). Add a `Signed-off-by` trailer
to every commit to certify that you have the right to submit the work under this project's
license. The sign-off name and email must match the commit author:

```text
Signed-off-by: Your Name <you@example.com>
```

Run `git commit -s` to add it automatically. Read the
[Developer Certificate of Origin](https://developercertificate.org/) before signing.

## Setting up

You need [uv](https://docs.astral.sh/uv/). From a checkout:

```console
uv sync --all-extras
make check
```

`uv sync --all-extras` installs every provider's SDK and Playwright, so the first sync takes
a while. `make check` runs everything CI runs: formatting, lint, type checks, the tests, a
check of every declaration, and a build of the package. It needs network access to fetch
packages, but no provider account and no secret.
It also lints Markdown, checks local links and anchors, validates generated formats, and
runs the README transcripts from an empty directory against both source and installed-wheel
commands. `make check-docs` runs just the documentation checks. External website availability
is not required.
`make format` fixes formatting, and `make write` regenerates `spec/catalog.json` from
`spec/catalog.yaml`. Never edit a generated file by hand.

## Changing the specification

Open an issue first for anything larger than a correction. A pull request that changes the
specification brings the text, a test or a waiver for each new rule, the catalog and
schemas, and the declarations it affects, as [GOVERNANCE.md](GOVERNANCE.md#changes) lists.
Use the [normative-change form](.github/ISSUE_TEMPLATE/spec-change.yml) for a new rule or
changed meaning, and the [specification-error form](.github/ISSUE_TEMPLATE/spec-error.yml)
for an ambiguity or incorrect existing rule. Ordinary bug reports may be free form.

Write for a provider or developer who has never seen this repository, in plain, neutral
English. Name a product only as an identifier or an example, never to promote it. An unknown
stays `unknown`; never guess a value.

## Adding a provider

1. **Choose a conformance path.** Use an installed adapter or HTTP consumer runner, or
   optionally add an independent native driver. A declaration may rely entirely on
   adapter-identity reports; adding a native module or CLI registration is not required.
   See [the provider kit](docs/how-to/provider-kit.md#honest-reporting). If adding a bundled
   native driver, follow [Writing a driver](spec/conformance.md#writing-a-driver) for
   its module, SDK extra and loader registration. No path may emulate missing native behavior.
2. **Run the conformance tests** with `--suite core` and
   `--suite coverage`. Review and commit evidence reports to `providers/<provider>/reports/`
   under the [report-selection rules](spec/conformance.md#results-and-reports). Every complete
   full-baseline run belongs in that history, including failures and non-clean runs; a newer
   one displaces an older pass. Focused diagnostics omitting part of the baseline may remain
   separate. Pass `--fixtures` to both runs. The shared fixture tables in the
   [conformance guide](spec/conformance.md#running-the-tests-against-a-provider) and its
   [driver notes](spec/conformance.md#driver-notes) list the values each test needs; a test
   with a missing fixture remains `not_run`. The baseline passes only when a clean report
   selected every baseline test and each passed. Follow
   [declaration writing step 3](spec/declarations.md#writing-one): every value needs evidence
   from a conformance report or an allowed dated documentation quote. Record any condition
   needed to reproduce a value in `needs`. The report records test outcomes and provenance.
3. **Write the declaration** in `providers/<provider>/`, as
   [declarations.md](spec/declarations.md) describes: every value has an entry in its
   `evidence` map, citing conformance results that establish the value or absence of an
   operation, or a dated documentation quote where the declaration rules permit it.
   A new region or GPU identifier you use must be added to the matching registry in the same
   change. Region entries go under the top-level `regions` key in
   `spec/registries/regions.json`, keyed by the identifier, with this shape:
   `{"countries": ["US"], "source": "<url>"}` (`countries` is `null` when unknown). GPU
   entries go under the top-level `gpu_models` key in `spec/registries/gpu-models.json`, keyed
   by the identifier, with `vendor`, `family` and `compute_capability` fields; use `null` for
   unknown family or compute capability. See existing entries in each file for examples.
   `check` does not refuse an identifier the registry lacks, but a tool reads it as `unknown`.
4. **Check it** from the owning Git checkout with
   `uv run sandbox-provider-spec check providers/<provider>/declaration*.yaml`, then `make check`.
   Cited reports must be committed and unmodified. The checker validates their suite and
   check digests; the recorded source revision need not be an ancestor of this checkout's
   `HEAD`. Follow [report verification](spec/conformance.md#results-and-reports); do not
   alter historical reports to make them look current.

A run creates real sandboxes on your account and attempts cleanup after every test.
Unconfirmed cleanup makes the report unclean and leaves resources to reconcile.
Credentials come from each SDK's standard environment variables; never commit a key, an
account id, a workspace name or a local path.

## Correcting a declaration

Open a pull request that changes the value and adds the evidence: a new run report, or a
dated quote of the provider's documentation. If the provider owns the declaration, it
reviews the change; the evidence decides.

A changed declaration file has a new SHA-256, and implementations pin the digest of the
declaration they verified against. A consumer that pins declarations serves them only from the
released package it pins, so merging a change under `providers/**` does not change what it
serves until it repins the new release together with its declaration digests.

## Reporting a vulnerability

Do not open a public issue: follow [SECURITY.md](SECURITY.md).
