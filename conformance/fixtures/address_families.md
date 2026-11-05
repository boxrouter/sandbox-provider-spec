# Address-family fixture

`address_families.example.json` is an explicit example for `sandbox-provider-spec run
--suite coverage --fixtures <file>`. Fixtures are absent unless the caller supplies a file; this
example is not loaded automatically.

The IPv4 and IPv6 values are Cloudflare's documented literals for TCP 443. Their provenance scope
is a **non-BoxRouter-controlled public anycast fixture**. The conformance runner makes a fresh,
independent TCP control connection for each family, records each exact address tuple, and reads at
most one byte with a bounded timeout. If either control is missing or fails, the observation is
unknown or `not_run`, never a negative capability.

The `nat64_prefix` member is optional and omitted from the example. Add it only when an explicit
prefix and its provenance are available. The probe performs no DNS lookup and has no inferred or
universal prefix.
