# Why evidence and unknown values matter

A feature name hides details a program may rely on. A snapshot may keep files or memory;
an egress allowlist may accept host names or IP addresses. A request expresses the needed
behavior. A declaration states the provider's behavior using the same vocabulary.

The **baseline** is behavior every eligible provider must establish. Optional features
are **gates**; their differing details are **knobs**. Provider-wide properties, such as
sizes, regions, and kernel isolation, are **facts**. A declaration may offer several
variants of a gate, each with its own conditions and conflicts.

The matcher checks evidence before deciding eligibility. Conformance reports record
observed native behavior through an API, SDK, faithful adapter, or HTTP binding. A new
provider does not need a separate native SPS driver; reports keep their actual
implementation identities and versions. Dated documentation quotes support only
the facts for which the specification permits them. Neither a declaration's valid syntax
nor its review date proves a baseline pass.

`unknown` preserves the difference between an absent capability and a capability nobody
has established yet. It cannot satisfy a requirement. Matching also refuses unknown
words, so a misspelled or newer requirement cannot silently become a weaker request.

Choosing among eligible providers is a separate decision. Cost, latency, and reliability
vary with time and account conditions; they are not facts this specification declares.

See the [core model](../../spec/spec.md#3-words),
[deterministic matching rules](../../spec/matching.md), and
[conformance claims policy](../../GOVERNANCE.md#conformance-claims).
