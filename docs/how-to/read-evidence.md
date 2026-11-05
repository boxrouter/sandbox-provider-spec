# Read a declaration's evidence

You need a declaration and the reports beside it. This inspection needs no account and
does not rerun provider tests.

1. **Validate the files.** For a bundled example:

   ```sh
   declaration=$(sandbox-provider-spec installed-declaration docker-engine)
   sandbox-provider-spec check "$declaration"
   ```

   `ok` means the checker accepts the file and its citations. It does not mean every
   possible workload qualifies. Warnings identify evidence that is no longer current.
2. **Find the claimed value.** Read its entry under `evidence`. Test citations name report
   files relative to the declaration and test IDs inside them. Documentation citations
   name a source URL, read date, and exact quote. Quotes are permitted only for the
   [specified facts](../../spec/declarations.md#writing-one); observable gate behavior
   needs passing tests.
3. **Inspect the report.** Match the provider, execution class, specification, and SDK
   versions to the declaration. Read the cited test's status and any cleanup failure.
   `clean: true` means cleanup was confirmed, and says nothing by itself about test passes.
4. **Check the baseline history.** Matching selects the newest report that included the
   complete baseline before considering its result or SDK set. A newer failure displaces an older
   pass. A focused diagnostic run cannot replace a complete baseline run.
5. **Ask the matcher about your workload.** It combines baseline evidence, the requested
   optional gates, resource facts, and conditions. Read its reasons alongside the cited
   tests rather than inferring eligibility from a declaration's date or a single pass.

The authoritative details are [declaration evidence](../../spec/declarations.md),
[report selection](../../spec/conformance.md#results-and-reports), and
[matching](../../spec/matching.md). Public claims follow
[Governance](../../GOVERNANCE.md#conformance-claims).
