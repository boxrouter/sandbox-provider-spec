# Declarations

[Specification index](README.md) · [Documentation](../docs/README.md)

A declaration states what one provider offers, in the vocabulary of
[the specification](spec.md), and the evidence for each value. This page defines the
format and how a provider writes, verifies and owns its declaration. Read the
specification first: it defines the gates, knobs, settings and facts used here.

## Where it lives

Each declaration has a directory of its own, holding the files below. In this repository it is
`providers/<provider>/`; a provider or tool that keeps its declaration elsewhere uses the same
layout, because evidence cites reports by their path relative to the declaration:

- `declaration.yaml`, the declaration. A provider with several classes, whose sandboxes
  differ wholesale (containers and virtual machines, say), has one complete file per
  class, `declaration-<class>.yaml`; nothing is inherited between them.
- `reports/`, the cited run reports and every complete full-baseline run, including failed
  or unclean runs. Keep complete full-baseline reports even when no value cites them; the
  [baseline/report rules](conformance.md#results-and-reports) require them and use the newest
  such run to decide eligibility.
- optionally `evidence.md`, notes for human readers on how values were established. The
  evidence itself is in the declaration.

Supporting notes and diagnostic artifacts may live in additional files or directories.

A Python package can ship a declaration directory inside the package and register it under the
entry point group `sandbox_provider_spec.declarations`, named by the provider, with the
package's import name as the value. `sandbox-provider-spec installed-declaration <provider>
[--class <class>]` then prints the installed declaration's path without importing the package.

## An example

```yaml
spec: sandbox-provider-spec/0.1
provider: example
class: container                      # only where the provider has several classes
verified:
  date: 2026-09-29                    # the newest run the values rest on
  sdks: {example-sdk: "1.4.2"}        # the SDK packages the driver used
resources:
  kernel: filtered
  max_lifetime_seconds: 86400         # a number, {at_least: N} or unlimited
  sizes: [{cpu: 2, memory_mib: 4096}]
  located_in: ["US", "DE"]            # countries a sandbox may run in when nothing is pinned
  gpus: []                            # GPU model identifiers; [] means none
  needs: {max_lifetime_seconds: [pro_plan]}
gates:
  pause_resume: unsupported
  network_lockdown:
    - policy: allowlist
      entry_kinds: [names]
x-example: {directory_snapshots: true}
evidence:
  resources.kernel:
    source: https://docs.example.com/security
    read: 2026-09-29
    quote: Every sandbox runs under gVisor.
  resources.max_lifetime_seconds:
    source: https://docs.example.com/pricing
    read: 2026-09-29
    quote: Sandboxes on the Pro plan may run for up to 24 hours; on the Free plan, 1 hour.
  resources.sizes:
    source: https://docs.example.com/pricing
    read: 2026-09-29
    quote: The Pro plan sells sandboxes of 2 vCPUs and 4 GiB of memory.
  resources.located_in:
    source: https://docs.example.com/regions
    read: 2026-09-29
    quote: Sandboxes run in our data centres in the United States and Germany.
  resources.gpus:
    source: https://docs.example.com/hardware
    read: 2026-09-29
    quote: Sandboxes have no GPUs.
  resources.needs.max_lifetime_seconds:
    source: https://docs.example.com/pricing
    read: 2026-09-29
    quote: Sandboxes on the Pro plan may run for up to 24 hours; on the Free plan, 1 hour.
  gates.pause_resume:
    source: https://docs.example.com/lifecycle
    read: 2026-09-29
    quote: A sandbox cannot be paused; stop it and create a new one.
  gates.network_lockdown.0.policy:
    tests: [network_lockdown.allowlist.names]
    report: reports/<committed-run-report>.json
  gates.network_lockdown.0.entry_kinds:
    tests: [network_lockdown.allowlist.names]
    report: reports/<committed-run-report>.json
  x-example.directory_snapshots:
    source: https://docs.example.com/snapshots
    read: 2026-09-29
    quote: A directory snapshot saves one directory of a running sandbox.
```

## The fields

| Field | Required | Meaning |
| --- | --- | --- |
| `spec` | yes | The version of this specification the file is written against: `sandbox-provider-spec/0.1`. A tool refuses a version it does not know. |
| `provider` | yes | The provider's name: lowercase letters, digits and hyphens, chosen when its directory is added. It prefixes the provider's region identifiers and names its extension, `x-<provider>`. |
| `class` | where the provider has several | Which class the file describes. |
| `verified` | yes | `date`, the date of the newest run the values rest on, or the date the cited documentation was last reviewed when no run exists (a review date does not claim a test ran), and `sdks`, the SDK package versions of the newest report that selected every baseline test; matching requires that report to have used exactly these. SDK versions are strings: quote them in YAML, including two-part versions such as `"1.4"`. Every other report the evidence cites used the same versions of the packages it needed. Adding an SDK takes a new full run. For a provider with no Python SDK, name the client the driver uses (a REST client's package, or `flyctl`); `sdks` must not be empty, and a declaration whose values are only quotes names the SDK or client its documentation describes. |
| `resources` | yes | The provider's [facts](vocabulary.md#facts-and-resources) other than `lifetime_timer`, and `needs`. |
| `lifetime_timer` | where the provider ends a sandbox's lifetime itself | `enforced_by: provider`; `counts_paused_time`; and `at_end`, the state the timer leaves the sandbox in, or the list of states a caller chooses from at creation. Optional: `adjustable`, whether a new length can be set on a sandbox that exists; `step_seconds`, the timer's unit in seconds; and `counts_from`, `create`, `ready` or `unknown`, when the timer starts counting; `min_seconds`, the shortest lifetime the provider accepts; and `after_resume`, `same` (the default) or `pauses` where the timer pauses a sandbox that has been paused and resumed although it ends one that was not (`unknown` when untested). A provider without such a timer leaves the block out. |
| `gates` | yes | Each gate the provider offers, as a list of variants, or the word `unsupported`. |
| `x-<provider>` | no | What this specification does not define. |
| `evidence` | yes | The evidence for every value other than `unknown`: see [Evidence](#evidence). |

An omitted `class` remains omitted in the declaration and has the bare provider name as its
declaration identity. The reference matcher's route result resolves that usable declaration to
class `default`; it does not rewrite the declaration or its report identity. Reports for an
omitted class keep `class: null`, and proof lookup compares that raw value. An explicit
`class: default` is a named class and requires reports labelled `default`.

## Rules of the file

- **Fields.** A declaration **MUST** carry `spec`, `provider`, `verified`, `resources`, <!-- rule: declaration/required-fields -->
  `gates` and `evidence`, and `class` where the provider has several classes.
- **A gate** is a list of variants, or the word `unsupported`. A gate left out means nobody
  has looked, which matching reads as `unknown`. `[{}]` is one variant with nothing more to
  say.
- A gate's list **MUST** hold at least one variant. <!-- rule: declaration/gate-not-empty -->
- **The baseline is never written.** A declaration **MUST NOT** state the baseline: a <!-- rule: declaration/no-baseline -->
  provider passes the baseline tests or it does not.
- **A knob value** is one value, or a list of the values this variant offers. A single
  value means the same as a one-item list, and a value not listed does not match. A yes/no
  knob is `true`, `false` or `unknown`; left out, it is `unknown`. A number may be
  `{at_least: N}`, when asking for more is `unknown`, or `unlimited`.
- `unknown` **MUST NOT** appear inside a list. <!-- rule: declaration/unknown-not-in-a-list -->
- **A fact that takes a list** (`sizes`, `regions`, `located_in`, `gpus`, `root`, `arch`,
  `egress_ips`, `outbound_traffic`) may be `unknown` as a whole. An empty list means none,
  except that `arch` is never empty and `outbound_traffic`'s empty list means HTTPS only.
- **Unknown scalar facts.** Leave `default_cwd` and `max_lifetime_seconds` out when
  unknown. A written `default_cwd` is an absolute sandbox path; a written lifetime
  maximum follows the [fact table](vocabulary.md#facts-and-resources). Other scalar facts in that
  table may be written `unknown`.
- **`resources.default_size`** may be omitted, written `unknown`, or written as one concrete
  object with `cpu`, integer `memory_mib` and optional integer `disk_mib`. It describes the
  provider SDK's create path when no size is named; it is not the first preferred size in
  `resources.sizes`. If the result depends on an image or another path the field cannot name,
  leave it omitted or write `unknown`.
- **Write a second variant only when choosing one value forces another.** If the answers do
  not depend on each other, one variant holds lists.
- A knob that applies only under a condition **MUST** appear only in a variant where the <!-- rule: declaration/conditional-knob -->
  condition holds: `keeps` on `idle_shutdown` only where `on_idle` is exactly `paused`;
  `auto_wake` only where `on_idle` includes `paused` or `stopped`; `credential` on
  `previews` only where `access` includes `private`; and `changeable` on `network_lockdown`
  only where `policy` includes `allowlist` or `denylist`.
- **`conflicts`** on a variant names what it cannot be combined with.
  [Matching](matching.md) says how conflicts apply. An entry **MUST** name a gate <!-- rule: declaration/conflicts-name-real-things -->
  (`previews`), one value of a gate's knob (`previews.access=public`), `resources.gpus`,
  `resources.regions`, one of `resources.root`, `resources.package_manager`,
  `resources.libc` and `resources.kernel_features` (where the variant's environment differs from a
  sandbox created without an image), or a key of the declaration's own extension
  (`x-example.directory_snapshots`). For a number knob, write a positive integer after
  `=` (for example, `previews.link_lifetime_seconds=3600`); it compares for equality with
  that knob's explicitly requested value, not the variant's offered ceiling. A request
  that leaves the knob out does not trigger this conflict.
- **`needs`** names what depends on the account, such as a plan or a beta. Write the file
  for the provider's best generally available plan (see [Words](spec.md#3-words)) and name in
  `needs` every value that some accounts do not get: one a lower plan lacks, or one that needs
  a beta, a quota or a support request, or one that rests on an SDK call the provider marks
  experimental or private (a name that begins with `_`, or `experimental` in its name or
  documentation), under the condition name `experimental_sdk`. It has one shape wherever it
  appears: a map from a value's name to the list of conditions it depends on. Under
  `resources.needs` the name is a fact's (`max_lifetime_seconds: [pro_plan]`); on a
  variant it is one of the variant's knobs, or `variant` for the variant as a whole
  (`needs: {variant: [volumes_beta]}`).
  Condition names are the provider's own, and the evidence for the value explains each.
  A condition about how a feature behaves is not a `needs`: it belongs in a knob, a
  conflict or the documentation. `needs` has no key for a whole class: a class that only
  some accounts can use says so at the top of its `evidence.md`.
- **`resources.unmet_limits`** gives the ceiling that holds for a fact while one of its
  `resources.needs` conditions is not met: a map from a fact (`max_lifetime_seconds` or
  `disk_mib`) to a map from one of that fact's conditions to a positive integer in the
  fact's own unit, or `unknown`.
  `unmet_limits: {max_lifetime_seconds: {pro_plan: 3600}}` says a lower plan is documented
  to allow at most 3600 seconds. Cite the provider's documentation for each ceiling under
  `resources.unmet_limits.<fact>.<condition>`. Write a ceiling only where the provider
  documents it for every account that does not meet the condition; a ceiling is not the
  provider's physical maximum, allocates nothing, and does not make a request supported.
- **Limits** let a setting rule a variant out: `max_ports`, `max_allow` (allowlist
  entries), `max_deny` (denylist entries), `max_inject_into` (secret destinations),
  `max_mounts` and `max_tcp_ports` on their gates, and `max_gpus` under `resources`. Each is a positive number, `{at_least: N}` with
  positive `N`, `unlimited` or
  `unknown`. `allow_wildcards` and `inject_wildcards` are `true`, `false` or `unknown`;
  `true` says `*.` entries work for their network allowlist or hidden-secret setting.
  `entry_kinds` on a
  `network_lockdown` variant lists the entry kinds (`names`, `addresses`) it enforces
  together for an allowlist or denylist; left out or `unknown`, no kind is established.
  `reserved_ports` on a `previews`
  variant lists distinct integers from 1 to 65535 for the ports the provider keeps for
  itself; left out, it reserves none.
- A limit **MUST** state what was seen working, not what the provider accepted: a provider <!-- rule: declaration/limits-as-seen -->
  that accepts 30,000 allowlist entries but was seen enforcing 4,096 declares 4,096.
- **`resizes_on_restore: true`** on a `snapshots` variant says a restore may ask for a
  different size. Left out, a restore must fit the size the saved sandbox had.
- **`arch`** lists the architectures in the provider's order, default first. **`root`**
  lists the ways a command gets root, and `[]` means none.
- **Sizes are combinations**, since most providers tie CPU and memory together. `disk_mib`
  may sit inside a size, or under `resources` for every size. A size may leave out `cpu`
  where the provider sells memory alone; such a size does not fit a request that asks for
  CPU. List sizes in the order the provider prefers them:
  matching chooses the first that fits. A provider that sizes freely writes a range,
  `{cpu: [0.25, 64], memory_mib: [128, 262144]}`. `sizes` and `disk_mib` are the allocation
  the provider sells, not what a program inside measures.
- **Part of a list for better plans.** `needs` conditions a whole fact, so where only some
  sizes or regions need a better plan, declare the ones every self-serve account gets and
  name the rest in `evidence.md`.
- **`located_in`** lists the countries a sandbox may run in when no region is pinned. A
  declaration **MUST** leave it out unless the provider says where it places such a <!-- rule: declaration/located-in-only-where-stated -->
  sandbox; a provider that places it wherever it has capacity has none.
- **Registry identifiers.** `regions` takes identifiers from
  [registries/regions.json](registries/regions.json), `located_in` takes country codes, and
  `gpus` takes identifiers from [registries/gpu-models.json](registries/gpu-models.json). A
  new identifier is added to the registry in the change that first uses it, and ships in a
  patch release. A tool whose registry does not list an identifier reads that value as
  `unknown`; it does not refuse the file. Quote country codes in YAML: `"NO"` is Norway,
  while the YAML loader reads unquoted `NO` as the boolean `false`.
- **Unknown words.** A checker reports them. Tools check declarations before supplying
  them to a matcher; the reference matcher does not perform that check itself. Its
  defensive handling of unknown words cannot establish missing evidence or validate
  the rest of the file. A matcher that reads a declaration anyway
  treats a key this version does not define as making its variant, resource, size or gate
  "no", and at the top level the whole file; a value it does not define makes only that
  value "no". The declaration's own `x-<provider>` key is skipped; another provider's
  `x-` key makes the whole file "no".
- A checker **MUST** report every key and value a declaration uses that this version does <!-- rule: declaration/unknown-words-reported -->
  not define, apart from `x-` keys.
- A duplicate key **MUST** be an error, in YAML and in JSON. <!-- rule: declaration/duplicate-key -->
- **`x-<provider>`** holds what the specification does not define. It never satisfies a gate
  the specification defines.

## Evidence

Every value other than `unknown` rests on evidence, given in the declaration's `evidence`
map. A missing required citation makes the declaration fail checking; the matcher consumes
checked declarations and does not read evidence or rewrite an uncited value to `unknown`.
To leave an answer unestablished, write `unknown` or omit it where allowed. An evidence
entry for an `unknown` or omitted value is an error, except that an explicit
`resources.default_size: unknown` may carry a documentation quote explaining why its value
is unestablished. That quote is a reason for uncertainty, not evidence of a size. An omitted
`resources.default_size` has no evidence entry.

Each key is the path of one declared value from the top of the file, with a list item
written as its position, counting from 0: `resources.kernel`, `resources.regions` (a list
fact is one value), `lifetime_timer.at_end`, `gates.snapshots.0.keeps`,
`gates.previews.1.max_ports`, `gates.network_lockdown.0.conflicts`, `gates.<gate>.0` for a
variant written `{}`, `gates.<gate>` for a gate declared `unsupported`, and
`x-<provider>.<key>`. Each entry is one of two kinds:

- **Tests**: `{tests: [<test ids>], report: reports/<file>.json}` cites tests in one
  committed report. When a value rests on tests from several runs, use
  `{reports: [{tests: [<test ids>], report: reports/<file>.json}, ...]}` with at least two
  entries; use the single-report form for one run. Every report/test
  pair must establish part of that same value. The conformance tests run through the
  provider's driver; everything a program can observe is shown this way.
- **A quote**: `{source: <url>, read: <date>, quote: "<the words relied on>"}`. A dated quote
  of the provider's documentation, for what no test from inside a sandbox can reach: the
  kernel boundary, a plan's limits and a variant's `needs`, the sizes and disk a plan sells
  (a run creates one of them), where sandboxes run and where their outbound connections
  come from, a time limit longer than a run can wait (such as `max_run_seconds: unlimited`,
  or whether paused time counts towards the lifetime), a snapshot's `retention_seconds`, `max_gpus`, a gate
  declared `unsupported`, a variant's `conflicts`, and extension keys. The catalog's
  `evidence.quotable_paths` lists exactly which paths a quote may support.

A gate declared `unsupported` cites a test of that gate that came back `unsupported`, or a
permitted quote. An unrelated operation's result cannot establish that the gate is absent.
Evidence is written for an outsider: it says what the provider does and how that was
established, never how a particular tool uses the provider.

For `resources.outbound_traffic`, a quote supports only an empty list (`[]`), which declares
HTTPS-only outbound traffic. Each listed traffic kind is observable from inside the sandbox and
requires conformance test evidence.

- Each cited tests entry **MUST** name tests that passed, or for `unsupported` came back <!-- rule: declaration/evidence-holds -->
  `unsupported`, in a clean, committed run report for the same provider and class.
- A variant whose behavioral values are all absent or `unknown` **MUST** cite evidence for <!-- rule: declaration/unknown-variant-needs-evidence -->
  its gate's existence at `gates.<gate>.<i>`, as a knobless `{}` variant does. `needs` and
  `conflicts` are metadata: their citations establish those conditions or conflicts, not
  the gate's observable operations. This rule also applies to metadata-only variants and
  to unknown behavioral values accompanied by metadata.
- A gate **MUST NOT** be declared with variants when a clean report cited by that <!-- rule: declaration/no-gate-against-its-report -->
  declaration contains a newest completed `differs` or `error` observation of a current
  conformance test for an unconditional rule of that gate. Consider every valid cited
  report for the same provider, class and verified SDK versions, including reports cited
  only for other gates or facts. For each test, use the greatest `finished_at` among its
  selected observations (`passed`, `differs` or `error`). A newer passing observation
  supersedes older failures of that test. An omitted test, `not_run` or `unsupported`
  does not demonstrate recovery from a failure. At an equal newest timestamp, any
  `differs` or `error` still prohibits the gate, regardless of report order.
  A rule is unconditional when no test naming it proves a value
  and it is not stated for one knob value only, as `previews/private-credential-is-its-own`
  is for `access: private`. Declaring the gate `unsupported` is unaffected.

The newest observations chosen by these rules win over a declared value. When they
contradict the declaration, the declaration changes.

## Writing one

**Without a driver, you can declare only some values.** A quote supports exactly the
paths in the catalog's `evidence.quotable_paths`: these include facts such as the kernel,
sizes, regions, and resource limits; resource and variant `needs`; variant `conflicts`;
snapshot retention; extension keys; and unsupported gates. For `resources.outbound_traffic`,
a quote supports only `[]`. Other values that can be observed from inside a sandbox, including
gate variant knobs, need passing test evidence. A provider with no conformance report can declare quoted
facts and absent gates, leave other gates out, and matches no request until its baseline
report is committed. Adapter or HTTP conformance reports suffice; a separate native
SPS driver is optional.

1. **Start from the SDK.** Declare what the provider's own SDK can do, on its best generally
   available plan. Documentation says what to test; it is evidence only for facts no test
   can reach.
2. **Choose a conformance path**: use an installed adapter or HTTP consumer runner,
   or write an independent native driver. See [conformance.md](conformance.md#choosing-a-conformance-path).
   Each path uses native behavior and adds no missing capability. Keep its real
   implementation identity in the report; an adapter-identity report alone can support
   a declaration.
3. **Run the conformance tests** with `--suite core` and `--suite coverage`
   ([conformance.md](conformance.md)), and commit evidence reports under the
   [report-selection rules](conformance.md#results-and-reports). A report may prove values
   that do not depend on provider account conditions. For a value that does, cite a passing
   report that satisfies the declared condition, or a permitted dated documentation quote,
   and list that condition in `needs`. Only a report that selected every baseline test
   establishes the baseline.
4. **Fill in each value** from the report, with its entry in `evidence`:
   - a test that `passed` establishes the value it names;
   - a test that came back `unsupported` means the SDK cannot do it: declare the gate
     `unsupported`, or the value `false`, citing that test;
   - a test that `differs` shows the provider does something else: declare what the report
     shows, if a value names it, or leave the value `unknown` and remove its evidence entry;
   - anything no test has established yet, including gates whose tests are not written, stays
     `unknown`, or its gate is left out.
5. **Check the file** from the owning checkout or source package:
   `sandbox-provider-spec check providers/<provider>/declaration.yaml`. In a Git checkout,
   each cited report must be committed and unmodified. Its suite digest must match a
   [recognized suite](conformance.md#committing-and-checking-report-evidence); its source
   revision is retained for auditing even when the package has a different Git history.
   The checker does not decide the baseline: a declaration passes it only through a clean
   committed report that selected every baseline test
   ([matching](matching.md)), and until then it matches no request.

Any change to a declaration file changes its SHA-256, the digest an implementation pins.
A consumer that pins declarations serves them only from the released package it pins, never
from the source tree, so a merged change reaches it only when it repins that release together
with the declaration digests it verifies.

## Verifying it again

A declaration is verified by rerunning the conformance tests against it. The `verified`
block names the date of the newest run the values rest on and the SDK versions the driver
used. When a provider releases a new SDK version, or changes a feature, the tests are run
again, the new report is committed, and the declaration, its evidence and its `verified`
block follow the report.

The report's `sdk_versions` records the provider SDK versions used for the run. A
report made with another SDK version does not establish the same behavior; rerun the
conformance tests and update the declaration's `verified` block before claiming it.

## Ownership

A provider may own its directory under `providers/` and its driver. It asks for ownership
through the process in [GOVERNANCE.md](../GOVERNANCE.md); once it is granted, the provider
is asked to review every change to those paths. Anyone may
propose a correction to any declaration by opening a change with a run report or a dated
quote that shows the declared value is wrong. The evidence decides, whoever owns the file.
