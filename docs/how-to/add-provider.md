# Add a provider

You can begin with provider documentation and a source checkout; an account is needed
only when you run tests against the provider. Keep facts you cannot establish unknown.

This page adds a native SDK driver to this package. A provider that runs its own endpoint
of the [HTTP binding](../../spec/binding-http.md) needs no driver here: follow the
[provider onboarding kit](provider-kit.md) instead.

1. **Inspect the SDK and vocabulary.** Find the provider behavior your workload depends
   on in the [vocabulary](../../spec/vocabulary.md). Discuss a missing word through a
   [normative-change issue](../../CONTRIBUTING.md#changing-the-specification).
2. **Start a declaration.** Follow the [declaration format and writing steps](../../spec/declarations.md#writing-one).
   You may cite documentation for permitted facts and absent operations before a driver
   exists. Such a declaration cannot pass matching without baseline evidence. Use the
   [verified field definition](../../spec/declarations.md#the-fields) for its review date
   and the provider SDK versions; a date does not claim a conformance run occurred.
3. **Validate the file early.** Run `sandbox-provider-spec check path/to/declaration.yaml`
   while writing it. Use a small request to inspect the matcher's refusal reasons before
   spending time on live tests.
4. **Run conformance and commit evidence.** An adapter or HTTP consumer can produce
   all required reports; a native SPS driver is optional. Follow the
   [provider kit](provider-kit.md#honest-reporting) for that path, or the
   [contribution procedure](../../CONTRIBUTING.md#adding-a-provider) for an independent
   native driver. Keep report identity and versions, run both suites, and check the
   declaration against its cited reports. Follow [Run conformance](run-conformance.md)
   for native-run prerequisites and cleanup.
5. **Add brand and publication (optional).** `providers/<id>/brand.yaml` names a chart
   colour, a logo and a one-colour mark (SVG, PNG or WebP files in the provider folder).
   `providers/<id>/publication.yaml` sets `hidden`, `candidate` or `published` for the provider
   and each class; without it the provider is hidden. `providers/<id>/notes.yaml` holds the
   provider's own published sentences (facts, notes, price and in-development reasons). `make check`
   validates them, and releases ship them as `brand.json`, `publication.json` and `notes.json`.
   A published provider and class each need an authorized, content-bound receipt. The
   `provider_assets.publication_receipt` helper encodes that prior decision; it grants no
   authority. Changing the provider, class, reason, reference or default class invalidates
   the receipt. All consumers read the validated publication artifact.
6. **Submit the complete change.** Include the declaration, cited reports, affected
   tests, and DCO sign-off. Run `make check`. Every complete baseline result belongs in
   the history, including failures; do not hide a newer failure behind an older pass.

An existing provider declaration can be corrected through the same evidence-first pull
request path. Provider ownership and disagreements follow
[Governance](../../GOVERNANCE.md#provider-declarations).
