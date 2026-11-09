# Reference matcher vectors

`vectors/matching.json` is the frozen input and expected output set for the reference matcher.
The `cases` array contains cases with an `id`, a `request`, and either `provider` or `providers`.
Those names select the synthetic YAML declarations under `fixtures/providers/`; expectation
names are each selected declaration's name (`provider`, or `provider/class` if it has a class).
`rules` lists the specification rule ids the case covers. These declarations and reports are
synthetic and stay independent from the live provider declarations and reports.

The vector harness starts with the published regions and GPU-model registries, then applies a
fixture-only overlay. Each region-map entry below has a `countries` array and adds a
`regions` entry, replacing an existing entry only if its key is already present:

```text
{
  "alpha:us-east": {"countries": ["US"]},
  "beta:us-west": {"countries": ["US"]},
  "gamma:eu-west": {"countries": ["FR"]},
  "gamma:global": {"countries": ["FR", "US"]}
}
```

It also adds `amd:mi355x` to `gpu_models` only when the published registry does not already
contain it, using this model entry shape:

```text
{"vendor": "amd", "family": null, "compute_capability": null}
```

An independent implementation needs this same overlay to reproduce every vector; the fixture
identifiers are not additions to the published registries.

Each case may set `baseline` and `baseline_provider`. The default baseline mode is `passed`:
for every selected declaration, the harness creates a clean synthetic report that selects all
current baseline test ids and marks each passed. `"baseline": "missing"` supplies no reports.
`"baseline": "latest_failure"` adds an older full passing report and a newer full clean
report with its first baseline test marked `differs`, for the provider named by
`baseline_provider`; other selected providers get passing reports.
`"baseline": "tied_failure"` gives the passing and failing
reports the same newest instant; `"reverse_reports": true` reverses report enumeration.
The tie vectors require the same refusal in both orders. All reports use each
declaration's `verified.sdks`, class, the current spec version, and fixed timezone-aware
timestamps. They exist only in memory and cause no provider calls.

The vector harness accepts `met_needs` as a list of condition names shared by the selected
providers; when omitted, it passes an empty list. The public `match` function also accepts
`None`, a sequence shared by all declarations, or a mapping from declaration name to a
sequence of condition names. `None`, an empty sequence or mapping, and an absent mapping entry
mean no condition is answered as met. A declaration name is its provider name, or `provider/class`
when it names a class.

`expect` has required `eligible` and optional `chosen`, `rejected` and `results` fields.
`eligible` and `chosen` contain declaration names (`provider`, or `provider/class` if it has
a class); `rejected` is a request-level rejection reason. `results` maps declaration names
to assertions: `eligible` is a boolean,
`failure_reasons` is the ordered list of `failed[].reason`, `variants` maps a gate to its
zero-based chosen variant index, and `grants` maps `gate.knob` paths to the granted values
(or `null` when the matcher records an unknown grant). `resources` maps dot-separated paths
within the result's `resources` object to expected values. This JSON vector case illustrates
the shape:

```text
{
  "id": "first-fitting-variant-is-kept",
  "provider": "alpha",
  "request": {"requirements": {"previews": {"access": "public", "ports": [80]}}},
  "rules": ["matching/first-variant"],
  "met_needs": [],
  "expect": {
    "eligible": ["alpha"],
    "chosen": "alpha",
    "results": {
      "alpha": {
        "eligible": true,
        "variants": {"previews": 0},
        "grants": {"previews.access": ["public"]}
      }
    }
  }
}
```

`baseline` and `baseline_provider` may be omitted for this passing-baseline case. A vector
with `providers` instead of `provider` compares multiple declarations in one match. The
vector test builds these reports and the registry in memory, then asserts the expected
eligibility, choice, grants, resolved resources and failures. It makes no provider calls.

## Using the Python reference matcher

The `sandbox-provider-spec match` command does all of this for files on disk. When calling the
library directly, make sure the
request, every declaration and every report passes the package checker: `match` does not run
the declaration or report checker, and it does not load report files. Load declarations and
the committed JSON run reports as parsed mappings and pass the reports through `reports=`.
Passing no reports leaves providers without baseline proof.

`met_needs` is the caller's account knowledge, not a plan upgrade: omitted or `None`, an empty
sequence, and an empty mapping mean no account condition is known to be met. A sequence applies
to every declaration; a mapping is keyed by declaration name (`provider` or `provider/class`),
and an omitted name has no conditions met. Supply a condition only when it is known to hold for
that account. The declaration's best generally available plan is a ceiling on what may be
offered; it does not establish the current account's entitlement.

Always pass an explicit `Registry` built from the published registries. The default
`Registry()` is empty, so a place or GPU request cannot use the published identifiers.
From the repository root, this example checks and matches the E2B declaration using its
committed reports:

```python
from pathlib import Path

from sandbox_provider_spec.check import check_declaration, check_report, check_request, spec_dir
from sandbox_provider_spec.load import load
from sandbox_provider_spec.matcher import Registry, match
from sandbox_provider_spec.installed import installed_declaration_path

declaration_paths = [installed_declaration_path("e2b")]
declarations = [load(path) for path in declaration_paths]
request = {"resources": {"region": "US"}}

request_errors = check_request(request)
if request_errors:
    raise ValueError(request_errors)
for path, declaration in zip(declaration_paths, declarations, strict=True):
    result = check_declaration(declaration, source_path=path)
    if result.errors:
        raise ValueError(result.errors)

report_paths = sorted((declaration_paths[0].parent / "reports").glob("*.json"))
reports = [load(path) for path in report_paths]
for path, report in zip(report_paths, reports, strict=True):
    result = check_report(report, source_path=path)
    if result.errors:
        raise ValueError(result.errors)

spec = spec_dir()
registry = Registry.from_documents(
    load(spec / "registries/regions.json"),
    load(spec / "registries/gpu-models.json"),
)
result = match(request, declarations, reports=reports, registry=registry)

print("rejection:", result["rejected"])
print("eligible:", result["eligible"])
print("chosen:", result["chosen"])
for provider, outcome in result["results"].items():
    print(provider, "gates:", outcome["gates"])
    print(provider, "resources:", outcome["resources"])
    print(provider, "failures:", outcome["failed"])
```

The top-level result fields are `rejected`, `eligible`, `chosen` and `results`. Each usable
provider result has a non-null `class`, `provider`, `name`, `sdk_versions`, `eligible`, `gates`,
`resources`, `restores_need` and `failed`. When the declaration omits its class, the result's
`class` is `default`; its result key and `name` remain the bare provider name. Proof lookup
still compares the declaration's raw omitted class to a report's `null` class. An unusable
declaration remains ineligible and keeps its raw `class` result. A failure has a `reason` and
`detail`; gate results identify the chosen variant and grants, and resources contains the
resolved size and placement values.

`result["results"][name]["gates"]` maps each requested gate to a zero-based
`variant` index in that declaration's variant list and a `knobs` mapping. For
example, a request naming `pause_resume` with `keeps: files_and_memory` may receive
this JSON output fragment as its `gates["pause_resume"]` entry:

```text
{"variant": 0, "knobs": {"keeps": {"values": [{"value": "files_and_memory"}]}}}
```

Each knob's `values` is a list of value records, or `null` when that unconstrained
knob has no known grant. These are reference matcher result fields, distinct from
the flattened `gate.knob` paths used for vector assertions.

For an actual restore, `match_restore` is the public helper. Its snapshot mapping identifies
the owner with `provider` and `class` (`None` in older snapshots or `default` for the resolved
identity of an unnamed class), and records what the snapshot keeps. Either representation
matches only that unnamed route and provider; named classes require their exact class name.
`source_resources` may contain the chosen size mapping, such as
`{"cpu": 2, "memory_mib": 2048, "disk_mib": 4096}`; omit it or use `None` when the source
size was not recorded. The helper restricts matching to that provider and class. The current
snapshot variant that offers `keeps` binds the restore: its conflicts apply, and its
`resizes_on_restore` value controls whether a compared restore minimum may exceed the recorded
source size: without resizing, it may not; with resizing, it may, subject to the current
declaration's sizes. Without a recorded source size, a size-bearing request is unknown unless
that variant permits resizing. The helper call below uses the declarations and reports loaded in
the preceding example; the snapshot metadata must come from the caller's saved snapshot.

```python
from sandbox_provider_spec.matcher import match_restore

snapshot = {
    "provider": declarations[0]["provider"],
    "class": declarations[0].get("class"),
    "keeps": "files_and_memory",
    "source_resources": {"cpu": 2, "memory_mib": 2048},
}
restore = match_restore(
    {"resources": {"memory_min_mib": 2048}},
    snapshot,
    declarations,
    reports=reports,
    registry=registry,
)
print("restore eligible:", restore["eligible"])
```
