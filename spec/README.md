# Specification reference

This directory holds the working draft for format `sandbox-provider-spec/0.1`.
The linked specification pages define the contract. The [tutorial and task guides](../docs/README.md),
example requests, and driver notes help apply it; they do not define additional obligations.

| Task | Authoritative reference |
| --- | --- |
| Understand the scope and model | [Specification](spec.md): scope, conventions, words, principles, and baseline |
| Express a workload | [Requests](spec.md#8-requests), [vocabulary](vocabulary.md), and [request schema](request-schema.json) |
| Compare providers or implement a matcher | [Matching](matching.md), [matcher test vectors](../tests/matcher/README.md), and [request examples](../examples/requests/) |
| Publish or correct provider facts | [Declarations](declarations.md) and [declaration schema](declaration-schema.json) |
| Verify claims or write a driver | [Conformance](conformance.md), [core suite](../conformance/suite.yaml), [coverage suite](../conformance/coverage.yaml), and [report schema](report-schema.json) |
| Look up the machine-readable vocabulary | [Catalog source](catalog.yaml), [generated catalog](catalog.json), [catalog schema](catalog-schema.json), and [registries](registries/) |
| Understand versions and claims | [Versioning](spec.md#12-versioning), [governance](../GOVERNANCE.md#versioning), [conformance claims](../GOVERNANCE.md#conformance-claims), and [changelog](../CHANGELOG.md) |

Published tags are fixed snapshots; `main` is the changing draft. No public release has
been cut yet. A file-format version and the Python package version serve different
purposes; requests are interpreted by the matcher version that reads them.
