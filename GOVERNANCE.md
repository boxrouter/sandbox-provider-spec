# Governance

This page says who decides what the Sandbox Provider Specification says, how changes are
made and versioned, and how a provider takes ownership of its declaration.

## Maintainers

The maintainers decide what lands. The maintainers want the specification
maintained by providers and the implementations that use it. Someone who has contributed
steadily may become a maintainer when the existing maintainers agree.

## Changes

Anyone may propose a change by opening a pull request, or an issue first for a larger one.
A change lands with one maintainer's approval. Any maintainer's objection holds it until
the maintainers agree.

A change to the specification brings, in the same pull request:

- the text, with a rule id on every new **MUST**, **MUST NOT**, **SHOULD** or
  **SHOULD NOT**;
- a test for each new rule, or an entry in [spec/untested.yaml](spec/untested.yaml) saying
  why no test can check it;
- `spec/catalog.yaml`, `spec/catalog.json` and the schemas, updated with the text;
- the declarations and evidence it changes;
- the version change it needs, as [Versioning](#versioning) says.

New vocabulary has to earn its place. A new gate, knob, value or fact names the program
behaviour that relies on it, the providers that differ on it, and the test that tells them
apart, and the provider's own SDK reference or documentation that shows it offers it. A
declaration claims the word only with a passing test, or, for a fact no test can reach, a
dated quote of the provider's documentation. A word enters only when leaving it out would
let a program be matched to a provider that breaks it. Everything else is a test or a
sentence of documentation.

When a release is cut, a word that no declaration in it offers with the evidence the
declaration rules require returns to the known differences in
[section 13 of the specification](spec/spec.md#13-where-the-specification-stops). For a
yes/no knob, offering it means declaring it `true`.

## Versioning

- Every file the specification defines (declarations, conformance tests, run reports)
  carries its version, as major.minor: `spec: sandbox-provider-spec/0.1`. A tool refuses a
  file whose version it does not know. A request carries no version; a tool reads it under
  its own.
- Releases are tagged `v0.1.0`, `v0.1.1` and so on, and the Python package carries the same
  version. The version in `pyproject.toml` changes before the tag.
- A patch release changes no file's meaning. It carries updated declarations and evidence,
  new run reports, new tests for existing values, new registry identifiers, and
  documentation.
- A release that changes a file under `providers/` changes that declaration's SHA-256.
  Implementations pin the digest of the declaration they verified; they adopt a changed
  declaration only by repinning the release and its declaration digests together, so a
  source edit alone changes nothing they serve.
- Anything a checker or a matcher must learn raises the minor version: a new gate, knob,
  value or field, or a changed meaning.
- Below 1.0, a minor release may change what a file means. From 1.0, a minor release only
  adds. [Specification §12](spec/spec.md#12-versioning) defines the internal-tag exception; these rules apply to published versions.

## Provider declarations

Anyone may add a provider or correct a declaration, with evidence: a run report from the
conformance tests, or a dated quote of the provider's documentation for a fact no test can
reach. [CONTRIBUTING.md](CONTRIBUTING.md) says how.

**A provider may own its declaration.** Someone who can show they speak for the provider,
for example as a member of its GitHub organization, asks in an issue. The maintainers then
designate the provider's declaration and driver for review and review every change to those paths.

**Evidence decides, whoever owns the file.** Anyone may open a correction to any
declaration with the evidence that shows the declared value is wrong. The owner reviews
it; if the owner has not answered in 14 days, a maintainer may merge a correction whose
evidence holds. A run report wins over a declared value, and no declaration claims more
than its evidence shows. Every provider and every implementation is held to the same rules,
including any provider or implementation a maintainer works for.

## Implementations

The README lists implementations of the specification on request. A listing says the
implementation exists; it is not an endorsement.

## Conformance claims

Anyone may publish a conformance claim. A claim speaks for its author; it is not a
certification or endorsement by the maintainers. Use "conforms to the Sandbox Provider
Specification" only with a stated scope:

- A provider claim names the specification version, provider and sandbox class, provider SDK
  and version, conformance report, and run date. The report identifies a clean revision and
  suite digest, records a passing complete baseline, and shows passing tests for each claimed
  gate or fact.
- An implementation claim names the implementation and version, its role, the specification
  version, and the report or test vectors and date that support the claim. Identify the exact
  implementation revision and show passing results for the claimed rules.

The cited report or test-vector result must be available for inspection. Report which optional
gates are unsupported, untested, or not run, and disclose any failed or differing results.
Unsupported optional gates do not by themselves disprove conformance to the baseline or to
other gates with passing evidence. A claim must not imply that every provider feature
conforms when the evidence covers only a provider class, SDK version, implementation role,
or subset of rules. Do not use "certified", "approved", or "endorsed" unless a separate
program grants that status.

Anyone may dispute a claim by opening an issue with its cited report or test-vector result,
the specification and SDK versions, and the specific rule or evidence in question. A
reproducible result may support a correction to a declaration, test, or claim. Disputes about
the specification itself follow the change process above; provider owners have the same
evidence and review obligations as other contributors.

## Conduct and security

Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md). Vulnerabilities are
reported as [SECURITY.md](SECURITY.md) describes.
