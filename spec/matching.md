# Matching

[Specification index](README.md) · [Documentation](../docs/README.md)

How a matcher decides whether a provider declaration satisfies a request. This is the part
of the [Sandbox Provider Specification](spec.md) that an independent matcher implements;
its test vectors are in [tests/matcher/vectors](../tests/matcher/vectors/), and the
reference matcher is [`sandbox_provider_spec.matcher`](../src/sandbox_provider_spec/matcher/).
The words **MUST**, **SHOULD** and **MAY** are used as [section 2](spec.md#2-conventions)
of the specification says.

## Using the reference matcher

The reference matcher is a Python library; the `sandbox-provider-spec match` command runs it
on files, after checking the request, each declaration and the reports beside it. Its public
entry point is `sandbox_provider_spec.matcher.match(request, declarations, *, reports=(),
registry=None, met_needs=None, mode="create", snapshot=None)`. It accepts parsed request
and declaration mappings. Check the request, each declaration and each report with the
checker before matching; `match` does not run the declaration or report checker or read
declaration evidence. Load the JSON report documents committed beside the declarations and
pass them as `reports`. With the default empty report list, no provider has baseline proof.

Use `load(path)` from `sandbox_provider_spec.load` to load YAML or JSON for Python callers.
It rejects duplicate keys and preserves YAML dates as strings. Another parser must supply
the same JSON-compatible mappings; plain PyYAML's date objects fail the declaration schema.

`mode="create"` is the default request shape for a new sandbox. `mode="restore"` checks a
restored sandbox request, which cannot name an `image` because the snapshot supplies the
environment. `mode="restores_need"` validates the restricted request shape used inside a
create request's `restores_need` field. To match an actual snapshot restore, use the public
`match_restore(request, snapshot, declarations, **kwargs)` entry point. It matches only the
declaration with the snapshot's `provider` and `class`, and uses `mode="restore"`.

The snapshot mapping supplies `provider`, `class`, and `keeps`; use JSON `null` (Python
`None`) for an older snapshot of an unnamed class, or `default` for its resolved route
identity. Both identify the same unnamed route and provider. Named classes still match only
their exact name, and a snapshot must name the owning provider. `source_resources` is optional
and, when known, is the chosen size mapping (for example,
`{"cpu": 2, "memory_mib": 2048, "disk_mib": 4096}`). The
current snapshots variant for that `keeps` value binds the restore: its conflicts apply to
the restore request, and its `resizes_on_restore` value controls whether requested size
minima must fit within the recorded source size. If no source size was recorded, a
size-bearing restore is `resource_unknown` unless that variant permits resizing. Where the
variant cannot resize, the size chosen for a size-bearing restore is the recorded source size,
not a declared size fitted to the minima; a field the source did not record as a number is
left out.

Pass an explicit `Registry` as well. The default is empty, so place and GPU identifiers are
not recognized from the published registries unless the caller loads and supplies them.
Build it with `Registry.from_documents(regions, gpu_models)`, using the pinned
`registries/regions.json` and `registries/gpu-models.json` documents from `spec_dir()`.
The regions document has root members `areas`, `regions`, `countries_source` and `countries`.
`areas` and `regions` map identifiers to entries with `countries` and `source`; `countries`
is an array of country-code strings for an area, and an array or `null` for a region. `source`
and root `countries_source` are strings; root `countries` is an array of country-code strings.
The GPU document has a `gpu_models` map from model identifiers to entries with `vendor`,
`family` and `compute_capability`; their values are strings, except `family` and
`compute_capability` may be `null`. The reference registry uses area and region country lists
and recognizes GPU models by their map keys. A region with `countries: null` has unknown
country coverage: its exact identifier can still be recognized and pinned, but it does not
establish that the region is within a requested area or country.
The complete Python example, including checker calls, is in the
[matcher test README](../tests/matcher/README.md#using-the-python-reference-matcher).

`match` returns a `MatchResult` with `rejected`, `eligible`, `chosen` and `results`. A
request refused before matching has a rejection and no provider results. Otherwise,
`eligible` lists matching declaration names in declaration order and `chosen` is the first
one, or `null` when none match. A declaration name is its provider name, or `provider/class`
when the declaration names a class. `results` maps each declaration name to its
`ProviderResult`: provider identity and SDK versions, `eligible`, selected `gates`, resolved
`resources`, any `restores_need` grant, and `failed` checks (each with a `reason` and
`detail`). For a usable declaration, `class` is always a string: the declared class, or
`default` when the declaration omits `class`. This is the resolved route identity; the result
map key and `name` keep the declaration identity (the bare provider name when `class` is
omitted). An unusable declaration remains ineligible and keeps its raw `class` value,
including `null` when it was omitted. Proof lookup continues to use the raw declaration class,
so reports for an omitted class still use JSON `null`; a report
labelled `default` does not prove that declaration. See the
[reference matcher vectors](../tests/matcher/README.md) for their assertion format.

Call `sandbox_provider_spec.matcher.declared_fit(request, declarations, *, registry=None,
met_needs=None, mode="create", snapshot=None)` when a caller needs declaration
compatibility without a conformance-proof decision. It shares request validation, resource
fitting, gate and condition selection, conflict handling, and recursive `restores_need`
matching with `match`. Its result names `compatible` declarations and each provider result
uses a `compatible` boolean with the same resolved resources and structured failures. It does
not check baseline reports and does not establish runtime availability, account or funding
admission, or `proven_only` eligibility. `match` and `match_restore` continue to require
baseline proof by default.

### Rejections and failed checks

The Python reference matcher's public result shape is specific to
[`sandbox_provider_spec.matcher.match`](../src/sandbox_provider_spec/matcher/matcher.py).
When request validation refuses the input, `rejected` is an object with `code`, `reason`,
`message`, `path`, `fix` and `details`; `eligible` is empty, `chosen` is `null` and `results`
is empty. In that object, `path` and `fix` may be `null`, and `details` holds structured
context. The request-level `reason` values currently emitted are `any_misplaced`,
`empty_list`, `knob_not_named`, `one_value`, `resource_value`, `setting`,
`unknown_as_value`, `unrecognised_word` and `wrong_type`. `code` is `knob_not_named` or
`unrecognised_word` for those reasons, and `invalid_request` for the others. The rejection
and reason definitions are in the [reference request validator](../src/sandbox_provider_spec/matcher/request.py).

For example, a request that gives two values to `network_lockdown.policy` is refused with
`reason: "one_value"` and `code: "invalid_request"`. The reference matcher's `message`,
`path`, `fix` and `details` explain that instance; their exact wording is not a shared
diagnostic format. The checker's `check_request` function instead returns a list of
human-readable strings from its own validation path. Those strings are not the structured
reference-matcher result or a promise of matching prose; for the same two-value request, the
checker may describe the policy as an unknown word. See the [checker](../src/sandbox_provider_spec/check.py)
and the [request vectors](../tests/matcher/vectors/matching.json) for their separate outputs.

When a request is valid but a declaration does not fit, `rejected` is `null`; that
declaration's result contains ordered `failed` checks. Their `reason` values currently
emitted by the reference matcher are:

| Reason | Meaning |
| --- | --- |
| `baseline_failed` | No qualifying passing baseline report was found. |
| `conflict` | A selected variant conflicts with another selected grant or a requested resource. |
| `declaration_unusable` | The declaration cannot be used for matching. |
| `extra_mismatch` | A requested extension is not offered by that declaration. |
| `gate_not_listed` | The declaration does not list a requested gate. |
| `gate_unavailable` | A requested variant or knob value has an account condition not known to be met. |
| `gate_unsupported` | The declaration marks the requested gate unsupported or has no variants. |
| `image_provider_mismatch` | The `provider_artifact` image names another provider. |
| `knob_mismatch` | The declaration's known knob value does not fit the request. |
| `knob_unknown` | The request compares a knob whose value is not established. |
| `limit_exceeded` | A requested setting exceeds a declared limit. |
| `resource_mismatch` | A known resource value does not fit the request. |
| `resource_unknown` | A resource value needed by the request is not established, including when its account condition is not known to be met. |
| `variant_unusable` | A declaration variant cannot be used for matching. |
| `volume_provider_mismatch` | A requested volume belongs to another provider. |

Each failed check also has a `detail` and may include context fields such as `gate`,
`knob`, `resource` or `extra`. These are explanatory fields from the reference matcher;
their exact text is not prescribed. The specification requires the same matching decision
and semantic cause, not identical human-readable prose or a particular library result shape.
The complete reason assertions are in the [vector guide](../tests/matcher/README.md) and
[frozen vectors](../tests/matcher/vectors/matching.json); the current reference logic is in
the [matcher](../src/sandbox_provider_spec/matcher/matching.py).

A declaration satisfies a request when all of these hold:

1. The provider passes the baseline.
2. For every gate the request names, the declaration has a variant whose knobs all fit, and
   whose limits admit the request's settings. For `network_lockdown` with `switchable: true`,
   that same variant's `policy` must include the starting policy and every value in
   `switches_to`.
3. The variants chosen conflict neither with each other nor with the resources requested.
4. Every resource the request names, and its `lifetime_seconds` and `at_end`, fit the
   declared facts.

The result of a match is, for each named gate, the variant chosen and the values it grants
(the values of each knob the request accepts that the variant offers, less those a conflict
removes), the size chosen, the architecture and `egress_ips` value chosen where the request
names them (the first declared one it accepts), the ways to get root it accepts that the
declaration lists, and the region pinned, if any.

```text
match(request, declaration):
    if not passes_baseline(declaration): return no
    if not facts_fit(request, declaration): return no
    gates = the gates the request names, in the order of the gates table (spec.md, section 6)
    return choose(request, declaration, gates, chosen = {})

choose(request, declaration, gates, chosen):
    if gates is empty: return chosen
    gate = first of gates
    for variant in declaration.gates[gate], in the order written:
        grant = fit(request.requirements[gate], variant)        # knobs and limits
        grant = narrow(grant, conflicts between variant, chosen and the request)
        if grant is not none:
            result = choose(request, declaration, rest of gates, chosen + {gate: grant})
            if result is not no: return result
    return no
```

- A matcher **MUST** apply these four checks to decide whether a <!-- rule: matching/four-checks -->
  declaration satisfies a request. They are the primary categories for the rules below, not
  an exhaustive list of independent constraints: provider-bound values such as a
  `provider_artifact` image, an `x-<provider>` extension or a volume mount pin the match to
  that provider, and `restores_need` must fit in addition to the request. The rules below
  state those constraints explicitly.
- `unknown`, or a value the declaration leaves out, **MUST NOT** satisfy a knob, fact or <!-- rule: matching/unknown-is-no -->
  limit the request compares, except as the `"any"`, unknown-limit and `reserved_ports` rules
  below say.
- A provider, or one class of it, **MUST** count as passing the baseline only when the <!-- rule: matching/baseline-passed -->
  newest of its committed run reports for this version and class that selected every
  baseline test of the matcher's version is clean, used exactly the SDK versions in the
  declaration's `verified.sdks`, and passed each of those tests. The report's own `baseline`
  summary is not read. A report that selected only some tests, such as a rerun of one test,
  proves what it ran and leaves the baseline to the full report. The reports read are the
  ones committed beside the declaration (`providers/<provider>/reports/` in this repository).
  The current baseline IDs are the union of `baseline.*` IDs in
  [suite.yaml](../conformance/suite.yaml) and [coverage.yaml](../conformance/coverage.yaml).
  Choose the complete report with the greatest `finished_at`, then check its cleanliness,
  results and SDK versions; do not filter by these before choosing or fall back to an older
  passing report. Filename and Git order do not decide which is newest. See
  [results and reports](conformance.md#results-and-reports) for report verification.
  If distinct complete reports share the greatest `finished_at` instant, the newest report
  is ambiguous and the baseline does not pass; do not fall back to an older report. Repeated
  copies of a report with identical JSON values count once; object key order is irrelevant,
  and booleans are distinct from numbers. Timestamp comparisons use instants,
  including when equivalent timestamps have different timezone offsets.

**Knobs.** A knob the request leaves out is not compared. A single declared value means the
same as a one-item list.

| Kind of knob | The request says | The variant fits when |
| --- | --- | --- |
| yes/no | `true` or `false` | it declares the same |
| pick one | one value, or a list of acceptable values | it offers one of them |
| all of | the list of values it needs | it offers every one of them |
| a number | how much it needs | it offers at least that much |

- A number knob, limit or fact declared `unlimited` **MUST** fit any number, and one declared <!-- rule: matching/numbers -->
  `{at_least: N}` fits up to `N` and is `unknown` above it.
- `"any"` **MUST** fit every declared value of its knob, `unknown` included. <!-- rule: matching/any -->
- An all-of knob or resource **MUST** fit only a variant or declaration that offers every value the request lists. <!-- rule: matching/all-of -->
- A `previews` `credential` in a request that accepts both `public` and `private` access **MUST** be <!-- rule: matching/credential-with-access-list -->
  compared only with variants whose access is private.

**Variants.**

- A matcher **MUST** use, for each gate, the first variant in the declaration that fits. <!-- rule: matching/first-variant -->
- An earlier gate **MUST** give way to its next fitting variant when its first would leave <!-- rule: matching/earlier-gate-gives-way -->
  a later gate with no fit, as `choose` above does by trying each variant in turn.
- Where a request lists several acceptable values, the match **MUST** grant those the chosen <!-- rule: matching/grant -->
  variant offers.

**Conflicts.** A variant may name what it cannot be combined with: a gate, one value of a
gate's knob, the `gpus` or `regions` resource, one of the facts `root`, `package_manager`,
`libc` or `kernel_features`, or an extension's key. A conflict works in
both directions. A conflict against a knob value applies only when the request names that
knob, including by saying `"any"`; an unnamed knob is not part of the grant.
A gate-name conflict fires only when another gate has a chosen variant for the request; a
gate the request leaves out has no chosen variant. A top-level `image` asks for
`custom_images` and counts for these conflicts even without `requirements.custom_images`.
An `x-<provider>.<key>` conflict fires
only when the request's matching `x-<provider>` object contains that key.

For a number knob, the token after `=` is a positive integer. A conflict such as
`previews.link_lifetime_seconds=3600` compares that number for equality with the
explicitly requested value: it fires for a request of `3600`, not `600` or `3601`, even
when the chosen variant offers a higher ceiling. It is not an inequality or a comparison
with the offered ceiling. If the request leaves the knob out, that conflict does not fire.

- A conflict that names a value the other variant offers in a list **MUST** remove that <!-- rule: matching/conflict-narrows -->
  value from the grant; the combination fails only when nothing the request accepts is
  left. A conflict with a value an all-of knob's request lists fails the combination, since
  the request needs every one. A conflict with a policy listed in a switchable request's
  `switches_to` **MUST** fail the combination, since every switch target is required.
- A conflict against a named knob that is `unknown` **MUST** fire. <!-- rule: matching/conflict-against-unknown -->
- A resource conflict **MUST** fire when the request asks for a GPU, pins a region, or names <!-- rule: matching/resource-conflict -->
  the fact it names.
- The conflicts of a `snapshots` variant **MUST** also bind the request's `restores_need`. <!-- rule: matching/snapshot-conflicts-bind-restores -->
- A conflict entry a matcher does not recognise **MUST** make its variant fail, never be <!-- rule: matching/unrecognised-conflict -->
  dropped.

**Limits.**

- A request that combines `kernel_features` with an `image` **MUST** be refused before matching. <!-- rule: matching/kernel-features-with-image -->

- A count limit left out or `unknown` **MUST** admit a single item, and no more. <!-- rule: matching/unknown-limit -->
  This single-item rule does not apply to `allow_wildcards` or `inject_wildcards`; wildcard
  entries require the corresponding limit to be `true` as stated below.
- An allowlist or denylist **MUST** fit only when every entry kind in its `allow` or `deny` <!-- rule: matching/allowlist-entry-kinds -->
  list is named in the variant's `entry_kinds`; a missing or `unknown` `entry_kinds` admits
  none. The request's entry kinds may be combined in one list, and its entry count still has
  to fit `max_allow` or `max_deny`, respectively.
- A request whose allowlist has a wildcard entry **MUST NOT** fit a variant without <!-- rule: matching/wildcards -->
  `allow_wildcards: true`; a request whose `inject_into` has a wildcard entry **MUST NOT**
  fit a variant without `inject_wildcards: true`.
- A request that lists a port a `previews` variant declares in `reserved_ports` **MUST NOT** <!-- rule: matching/reserved-ports -->
  fit that variant; a variant that lists none reserves none.

**Sizes.** A declaration lists sizes in the order the provider prefers them. A range such as
`{cpu: [0.25, 64], memory_mib: [128, 262144]}` fits asks within its bounds. Each range
field left out of the request uses the range's lower bound. For a requested minimum that is
compared, matching chooses that minimum when it lies in the range, or the lower bound when it
is below the range; a compared minimum above the upper bound makes that size not fit. The
memory-and-disk rule below determines the minimum compared for those two fields. If the
request names no size fields, no size is chosen. `resources.default_size` is descriptive only:
the matcher never reads or compares it, and it does not cause a size to be chosen.

- A matcher **MUST** choose the first declared size that fits. <!-- rule: matching/first-size -->
- For a request that names both `memory_min_mib` and `disk_min_mib`, a size **MUST** fit, <!-- rule: matching/disk-in-memory -->
  unless `disk_in_memory` is `false`, only when its memory covers them together; with
  `true`, `disk_mib` is not compared.

**Regions.** A request's `region` names one region, area or country. A region pins the
sandbox there. An area or a country is satisfied first through `located_in`, which pins
nothing; otherwise by the first declared region that lies wholly inside it, which is then
pinned.

- A region **MUST** fit only when every country the sandbox may run in lies inside what was <!-- rule: matching/regions -->
  asked for.
- `located_in` **MUST NOT** satisfy a request that names a provider's region. <!-- rule: matching/located-in-never-pins -->

**GPUs.**

- A request's `gpu_count` without `gpu_model` **MUST** fit any declared GPU model, as many as <!-- rule: matching/gpu-count-any-model -->
  asked, up to `max_gpus`.

**Lifetime.**

- A request's `at_end` **MUST** fit only a declaration whose provider ends the lifetime <!-- rule: matching/at-end -->
  itself (`enforced_by: provider`) and whose `at_end` offers the same state.

**Images.**

- A request's `image` **MUST** fit only a `custom_images` variant whose `source` offers the <!-- rule: matching/image -->
  corresponding kind: `oci` for a string, `private_oci` for an object with `private_oci`,
  `dockerfile` for an object with `dockerfile`, or `provider_artifact` for an object with
  `provider_artifact`.
- An `image` naming a `provider_artifact` **MUST** fit only the provider it names. <!-- rule: matching/provider-artifact-pins -->
- A request with an `image` and no `requirements.custom_images.prepared` **MUST** match only a <!-- rule: matching/image-prepared -->
  variant that offers `prepared: false`; a declaration that omits `prepared` offers `false`.
  An explicit `prepared: unknown` remains unknown. Requesting `prepared: true` opts into the
  prepared path.

**Restores.** How a tool restores a snapshot is its own. What it restores into is matched
like any request, against the declaration the snapshot was taken on.

- A declaration **MUST** satisfy a request's `restores_need` as well as the request itself. <!-- rule: matching/restores-need -->
  The `restores_need` request must also fit the declaration's sizes as usual. For each size
  minimum that the restore match actually compares under the size rules above, it must be no
  greater than the corresponding size chosen for the main request unless the chosen
  `snapshots` variant declares `resizes_on_restore: true`. If the main request chose no size,
  or the source size was not recorded, a compared restore size is `resource_unknown` unless
  that variant permits resizing. A smaller or equal minimum fits the recorded source size;
  a larger one does not.
- A tool that restores a snapshot **MUST** match the restored sandbox's request against the <!-- rule: tools/restore-matches-its-snapshot -->
  declaration and class the snapshot was taken on, as that declaration stands at the time
  of the restore, and within the saved sandbox's size unless the snapshot's variant
  declares `resizes_on_restore: true`.

**Account conditions.** The declaration describes the provider's best generally available
plan; this is the ceiling on what matching can offer, not proof that the caller's account has
that plan or meets an account condition. A value with a `needs` condition is offered only to
an account known to meet it. The reference matcher's `met_needs` argument supplies those
answers: `None`, an empty sequence or an empty mapping means no condition is answered as met;
a sequence applies to every declaration; a mapping supplies condition names by declaration
name (provider, or `provider/class`). Only conditions known to be met for that account should
be supplied.
`needs` names what some accounts do not get: under
`resources.needs`, a fact's name maps to its conditions; on a variant, a knob's name, or
`variant` for the variant as a whole, maps to its conditions. Condition names are the
provider's own, explained in its evidence. A tool that knows an account answers each
condition for it, and a gate, variant or value whose condition is not met is not offered to
that account.

- A tool **MUST** treat a `needs` condition it cannot answer as not met. <!-- rule: tools/unanswered-needs -->

A `resources.needs` fact whose condition is not met is not offered, unless the declaration's
`resources.unmet_limits` gives a finite ceiling for that fact and every unmet condition of
it. Then the request is still matched against the declared fact, and must also not ask for
more than the smallest of those ceilings (`lifetime_seconds` for `max_lifetime_seconds`,
`disk_min_mib` for `disk_mib`). A condition with no ceiling, or with `unknown`, leaves the
fact unanswered and the request is refused. A ceiling answers only its own fact: every
other unmet condition still applies.

**Extensions.**

- A requested volume mount **MUST** fit only the declaration for the provider named by <!-- rule: matching/volumes-pin -->
  that mount. The provider owns the volume, so a request naming it pins the match to that
  provider.
- A request that requires an `x-<provider>` extension **MUST** fit only that provider's <!-- rule: matching/extensions-pin -->
  declarations. Every key in the request's extension object must have an equal JSON value
  in the declaration's extension object: objects compare by keys and values, lists in order,
  numbers by numeric value, and booleans only with booleans. An empty extension object pins
  the provider but requires no extension key, even if the declaration has no extension block.
- An extension **MUST NOT** satisfy a gate this specification defines. <!-- rule: matching/extensions-never-satisfy-gates -->
