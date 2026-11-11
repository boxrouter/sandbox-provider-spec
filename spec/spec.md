# Sandbox Provider Specification

[Specification index](README.md) · [Documentation](../docs/README.md)

This is version 0.1. Declarations, conformance tests and run reports written against it
carry `spec: sandbox-provider-spec/0.1`. The specification is 0.x: a minor version may
still change what a file means, and changes aim to stay additive.

## Contents

- [1. Scope](#1-scope)
- [2. Conventions](#2-conventions)
- [3. Words](#3-words)
- [4. Principles](#4-principles)
- [5. Baseline](#5-baseline)
- [6. Gates](#6-gates)
- [7. Facts and resources](#7-facts-and-resources)
- [8. Requests](#8-requests)
- [9. Matching](#9-matching)
- [10. Declarations](#10-declarations)
- [11. Conformance](#11-conformance)
- [12. Versioning](#12-versioning)
- [13. Where the specification stops](#13-where-the-specification-stops)

## 1. Scope

The Sandbox Provider Specification defines what a sandbox provider guarantees to the code
it runs, how a provider declares it, and how conformance proves it.

A **sandbox** is an isolated compute environment whose lifecycle, persistence, resources
and capabilities are controlled through a provider's API. Nothing here assumes a sandbox
is short-lived. How long one may run, whether it can pause, and what survives are
properties a provider declares, so the same words describe a sandbox that runs one command
and is gone and one an agent keeps for weeks.

The specification covers only differences that code relies on: the places where a program
written for one provider would break on another. It has four parts:

- **Vocabulary.** A [baseline](#5-baseline) every provider shares; [gates](#6-gates), the
  optional features, with knobs for the details where providers really differ; and
  [facts](#7-facts-and-resources) about the provider as a whole, such as isolation, sizes,
  lifetime, regions and GPUs.
- **Declarations.** A file per provider stating which gates and facts it offers, each value
  resting on evidence. [declarations.md](declarations.md) defines the format.
- **Requests and matching.** A [request](#8-requests) states what a program relies on;
  [matching](#9-matching) decides whether a declaration satisfies it.
- **Conformance.** Shared tests, written once and run on every provider through a thin
  driver over that provider's native API or SDK, directly or through a faithful adapter,
  produce the evidence.
  [conformance.md](conformance.md) describes them.

It serves developers choosing a provider, providers stating what they offer, and tools
that drive many providers, such as routers, agent frameworks and SDKs.

Price, speed and reliability are not declared. They change from day to day, and whoever
chooses between providers measures and ranks them. The specification defines no
programming interface either: each provider's own SDK remains the way to drive its
sandboxes.

## 2. Conventions

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT** and **MAY** are used as
described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) when, and only when, they appear in
capitals.

Each statement using one of the first four carries a comment naming its rule at the end of its
first line, in the form
`<!-- rule: <topic>/<name> -->`. Every rule is either named by a test or listed, with the
reason, in [untested.yaml](untested.yaml) as one no test can check;
[conformance.md](conformance.md) says how.

Rules about a provider are checked by the conformance tests, run against that provider.
Rules about a declaration or a request are checked by the checker in this repository, and
rules about matching by the test vectors of the reference matcher
([`sandbox_provider_spec.matcher`](../src/sandbox_provider_spec/matcher/); vectors in
[tests/matcher/vectors](../tests/matcher/vectors/)).

## 3. Words

| Word | Meaning |
| --- | --- |
| **Provider** | A service that creates sandboxes through its own API. |
| **Class** | A kind of sandbox a provider offers that differs wholesale from its others, such as containers and virtual machines. Each class has its own declaration. |
| **Plan** | What an account buys from a provider. A provider's **best generally available plan** is the highest plan anyone can buy without a sales conversation, a support request or beta access. |
| **Baseline** | What every provider does, natively and the same way. A request never asks for it. |
| **Gate** | An optional feature. A provider offers it or does not. |
| **Knob** | One detail of a gate where providers really differ and code relies on the answer. Matching compares knobs. |
| **Setting** | A value a request gives a gate for the sandbox being created, such as the ports to preview. A setting can rule a provider out through a limit or a provider pin. |
| **Variant** | One combination of knob values that a provider offers together. |
| **Limit** | How much, or what kind of, setting a variant accepts, such as the most ports it can preview at once, or whether allowlist entries may be wildcards. |
| **Fact** | A property of a provider or class as a whole, such as its isolation, its sizes or its regions. |
| **Resource** | What a request asks of the facts, such as a minimum memory size or a region. |
| **Declaration** | A provider's file of gates and facts, with the evidence for each value. |
| **Request** | What a program relies on, in the vocabulary of this specification. |
| **Pin** | To fix where a sandbox runs. A request pins a region when it names that region, or when an area or country cannot be satisfied through `located_in` and matching chooses a declared region inside it. It pins a provider when it names something only that provider holds: a volume, a `provider_artifact` image or an extension. |
| **Tool** | Software that creates sandboxes for requests, such as a router, an agent framework or an SDK. |
| **Conformance test** | A test, written once, that checks a rule on any provider through a driver. |
| **Driver** | A thin layer that performs a conformance test's operations with one provider's SDK. |
| **Run report** | The dated result of running the conformance tests against one provider. |
| **Evidence** | A conformance test in a committed run report proving a value or an absent operation, or a permitted dated quote of the provider's documentation. |
| **Extension** | The key `x-<provider>` and the keys under it, for something this specification does not define. |

A sandbox is in one of these states, whatever a provider calls them:

| State | Meaning |
| --- | --- |
| **running** | Its processes run and it can be used. |
| **paused** | Left by the provider's pause operation, or by an idle or lifetime pause. Its processes are stopped, and resuming it brings back what `keeps` declares: its files, or its files and its running processes. |
| **stopped** | Left by the provider's stop operation, or by a timer that stops it. Its files are kept and its processes are gone; it can be started again. |
| **destroyed** | It is gone. |

A sandbox is resumed or started again through the provider's own operation for it. The
specification names the state, not the call. A sandbox paused with `keeps: files_only` and a
stopped one look the same from inside; they differ in the operation that brings them back.

`unknown` is a value in its own right. It means nobody has established the answer.

## 4. Principles

1. **A request names what the program relies on.** A request **SHOULD** list every gate the <!-- rule: request/names-what-is-relied-on -->
   program calls or depends on, and nothing else. A program that calls pause requires
   `pause_resume` even where a snapshot would serve, because they are different operations.
2. **When in doubt, no.** `unknown`, or a value the declaration leaves out, never satisfies
   what a request compares, with three stated exceptions: `"any"` fits even an unknown or omitted knob,
   an unknown count limit admits one item, and a previews variant that lists no `reserved_ports`
   reserves none. A word the reader's version does not define is never guessed at: a
   request that uses one is refused, and in a declaration it counts as "no" for the value,
   variant, gate or file that holds it ([declarations.md](declarations.md#rules-of-the-file)).
   [Matching](#9-matching) and the [request rules](#8-requests) give the details.
3. **Every declared value rests on evidence.** A declaration **MUST** give every value other <!-- rule: declaration/evidence -->
   than `unknown` an entry in its `evidence` map: the conformance tests and committed run
   report that establish it or, for a fact no test can reach (the kernel boundary, a plan's
   limits and the sizes it sells, the list of regions), a dated quote of the provider's
   documentation. A missing required citation is a declaration-check error; it does not
   rewrite the value to `unknown`. To leave an answer unestablished, write `unknown` or
   omit it where allowed. An explicit `resources.default_size: unknown` may have a dated
   quote that explains the uncertainty; the quote does not establish a size. A tool supplies
   its matcher only declarations that pass the checker. The reference
   matcher expects its caller to check them first; it does not run the checker or read
   `evidence` itself. Defensive handling of unknown words does not replace this check.
4. **A declaration describes the provider.** It **MUST** state what the provider's native API or SDK <!-- rule: declaration/describes-the-provider -->
   exposes on the provider's best generally available plan, and name in `needs` every value
   that some accounts do not get: one a lower plan lacks, or one that needs a beta, a quota
   or a support request. A run on another plan establishes only what that plan cannot
   change; the conformance report records the tested outcomes. Conformance may exercise the
   native API or SDK directly, through an adapter, or through a conforming HTTP binding.
   A feature stays `unknown` until its selected path tests it or permitted documentation
   establishes it. A tool built on a provider may expose less or add more; that is the
   tool's to state, not the declaration's. A value that rests on an SDK call the provider
   marks experimental or private names `experimental_sdk` in `needs`.
5. **A request is met at creation.** A variant describes what the provider offers to a
   sandbox created to use it. Some providers must be told at creation: one previews only
   ports named when the sandbox was created, another pauses only sandboxes created as
   persistent. A tool that creates a sandbox for a request **MUST**, when it creates it, <!-- rule: tools/configure-gates-at-creation -->
   configure every gate the request names and provision what the request asks of the
   facts: the size, with a CPU and memory ceiling when `size_is_ceiling: true`, architecture and egress addresses chosen, the region pinned,
   `lifetime_seconds` with its `at_end`, and `long_running`; run commands as root the way the
   match granted, and with timeouts long enough for `run_seconds` and `process_seconds`; and
   set whatever the provider needs at creation to meet the baseline, such as opening
   outbound connections.
6. **A sandbox uses what its request named.** A tool that creates sandboxes for requests
   **SHOULD** refuse a program's use of a gate its request did not name. Otherwise a program <!-- rule: tools/refuse-unnamed-gates -->
   can come to depend on a feature one provider happens to have, and break the day it runs
   somewhere else.

## 5. Baseline

What every provider does, natively and the same way. A request never asks for it, and a
declaration never states it: a provider passes the baseline tests or it does not.

- A provider **MUST** create a sandbox with the environment variables it is given, and let a <!-- rule: baseline/lifecycle -->
  program get the sandbox, find it among the account's sandboxes and destroy it.
- A command run in a sandbox **MUST** return its output and its exit status, with standard <!-- rule: baseline/run -->
  output and standard error kept apart, and **MUST** run in the working directory and with
  the environment variables it is given.
- A program **MUST** be able to write a file with any bytes into an existing directory <!-- rule: baseline/files -->
  and read a file's bytes back through the provider's file interface.
- A program **MUST** be able to start a process in the background and read its output while <!-- rule: baseline/process-output -->
  it is still running.
- Closing a process's standard output and standard error **MUST NOT** mean that it has <!-- rule: baseline/process-eof-not-exit -->
  exited. Native execution state must remain running while execution continues, and its
  eventual exit status must be preserved. A transport need not expose stream EOF before
  native execution ends.
- A sandbox created without an image **MUST** have `bash` and `python3` on its path. <!-- rule: baseline/environment -->
- A sandbox **MUST** be able to open HTTPS connections to any public host unless its request names <!-- rule: baseline/outbound-network -->
  `network_lockdown`.
- Code in a sandbox **MUST NOT** obtain the instance metadata or credentials of the machine <!-- rule: baseline/no-metadata -->
  it runs on, from `169.254.169.254` or any other address the host's cloud serves them at.

A provider whose sandboxes start with outbound HTTPS connections closed meets the outbound rule
when its SDK opens them at creation; a tool creating a sandbox then opens them
([principle 5](#4-principles)).

Some things a program might expect are not in the baseline, because providers differ on them:

- **Output as exact bytes.** Most providers return a command's output as decoded text. A
  program that needs bytes writes them to a file and reads the file.
- **Other file operations.** Making, listing, testing and removing paths are commands a program
  runs, such as `mkdir -p`, `ls -A`, `test -e` and `rm -rf`. The file interface is promised only
  for writing and reading bytes.
- **A timeout on one command.** A program can run the command under `timeout`.
- **Where `HOME` points.** Most providers set it to the home directory of the user a command
  runs as; at least one sets it elsewhere. A program that relies on `~` sets `HOME` itself.
- **A shell.** Whether a command is a string a shell reads or a list of arguments is each
  SDK's own interface. In a sandbox created without an image `bash` is on the path, so a
  program that needs a shell runs `bash -c`.
- **How long a command may run.** Some providers stop a command a program waits for, or a
  background process, after a while: the facts `max_run_seconds` and `max_process_seconds`.
- **What the sandbox reports about itself.** `nproc` and `free` may report the host rather
  than the sandbox's allocation. A program sizes its work from the size the match chose.
- **Sending a process input, cancelling it and reattaching to it** are the
  [`processes`](vocabulary.md#processes) gate, and **an interactive terminal** is the
  [`terminal`](vocabulary.md#terminal) gate.
- **Who a command runs as, and where,** are the facts `default_user` and `default_cwd`;
  **how it gets root, and what the system is** (architecture, package manager and C library)
  are the facts `root`, `arch`, `package_manager` and `libc`; **how long
  a sandbox may run and how its lifetime ends** are the facts `max_lifetime_seconds` and
  `lifetime_timer` ([section 7](#7-facts-and-resources)).

## 6. Gates

| Gate | What it is | Knobs (compared) | Settings | Limits |
| --- | --- | --- | --- | --- |
| `idle_shutdown` | The sandbox stops by itself when idle. | `on_idle`, `custom_idle_time`, `auto_wake` | `idle_seconds` | |
| `pause_resume` | Pause a sandbox with a call and resume it later. | `keeps` | | |
| `previews` | A URL that reaches a port in the sandbox. | `access` (must be named), `credential`, `revocable`, `link_lifetime_seconds`, `websocket`, `loopback`, `any_port`, `survives_pause` | `ports` (required) | `max_ports`, `reserved_ports` |
| `network_lockdown` | Limits what the sandbox can connect to, enforced by the provider outside the sandbox. | `policy` (must be named; a request names exactly one; a request using `open` requires `switchable: true`), `changeable`, `switchable` | `allow` (host names or addresses; required for an allowlist), `deny` (host names or addresses; required for a denylist), `switches_to` (required with `switchable: true`) | `max_allow`, `max_deny`, `allow_wildcards`, `entry_kinds` |
| `hidden_secrets` | Credentials the provider adds to outgoing requests, which code in the sandbox cannot read. | `rotates`, `scrubs_responses`, `injection`, `header_templates`, `transparent`, `intercepts` | `inject_into` (required), `headers` (optional) | `max_inject_into`, `inject_wildcards` |
| `snapshots` | Save a sandbox and create new sandboxes from the save. | `keeps`, `original_after` (must be named), `deletable`, `retention_seconds` | | |
| `volumes` | Storage that outlives the sandboxes that mount it. | `sharing`, `read_only_mounts`, `kind` (must be named) | `mounts` (required) | `max_mounts` |
| `custom_images` | The sandbox starts from an environment the request brings. | `source`, `prepared`, `image_config`, `runs_entrypoint`, `build_context` | the request's `image` (see below) | |
| `user_selection` | Commands, new files and background processes can run as a named user. | `commands`, `files_write`, `process_start` | | |
| `processes` | Control of a background process beyond reading its output. | `input`, `cancel`, `reattach` | | |
| `terminal` | An interactive terminal in the sandbox. | `reattach` | | |
| `docker` | A Docker Engine runs in the sandbox. | `networking` | | |
| `tcp_ports` | A host and port on the internet that reach a TCP port in the sandbox. | `tls` (must be named) | `ports` (required) | `max_tcp_ports` |
| `desktop` | A graphical desktop a program sees and drives. | `live_view` | | |
| `file_links` | A link that reads or writes one file in the sandbox, safe to hand to a client without the provider account's credentials. | `operations`, `user_selection`, `link_lifetime_seconds`, `revocable` | | |

Matching tries gates in the order of this table.

A knob that **must be named** is one where a silent default would hurt: a program that
assumed a private preview must not be handed a public one. A request names it, or says
`"any"` to accept whatever the provider offers; `policy` takes exactly one value and never
`"any"`.

A request's top-level `image` asks for `custom_images`, and the kind of image it gives is
compared with `source`. A request names `custom_images` under `requirements` only for its
other knobs, and only together with an `image`.

Values are never ranked. `files_and_memory` is not a better `files_only`: it brings old
processes back, which a program may not want.

Each gate's knobs, their values, and the rules a provider follows when its declaration offers
them are in the [vocabulary](vocabulary.md#gates).

## 7. Facts and resources

A declaration's facts describe the provider or class as a whole. Most sit under `resources`
in the declaration; `lifetime_timer` is a block of its own. A request asks of the facts
through its `resources`, `lifetime_seconds` and `at_end`, and each is compared only when
the request names it.

| Group | Facts |
| --- | --- |
| Allocation | `sizes`, `size_is_ceiling`, `disk_mib`, `disk_in_memory` |
| Memory | `on_memory_exhausted` |
| Time | `max_lifetime_seconds`, `lifetime_timer`, `extendable_lifetime`, `long_running`, `max_run_seconds`, `max_process_seconds`, `paused_retention_seconds` |
| Place | `regions`, `located_in`, `egress_ips` |
| Network | `outbound_traffic` |
| Hardware and isolation | `kernel`, `kernel_features`, `arch`, `gpus`, `max_gpus` |
| Environment | `default_user`, `default_cwd`, `root`, `package_manager`, `libc`, `files_write_executable_effect` |
| Files | `file_stream_max_bytes` |

What each fact means, how a request asks for it, when it fits and its rules are in the
[vocabulary](vocabulary.md#facts-and-resources), with the region and GPU registries.

## 8. Requests

A request is a JSON or YAML object with these keys, all optional:

| Key | Meaning |
| --- | --- |
| `requirements` | The gates the program relies on, each with the knobs it relies on and the settings for the sandbox. An extension key is `x-` followed by a provider name: lowercase letters or digits in non-empty segments separated by single hyphens, such as `x-acme-cloud`. Other `x-` forms are refused. |
| `resources` | What the program asks of the facts: `cpu_min`, `memory_min_mib`, `on_memory_exhausted`, `disk_min_mib`, `size_is_ceiling`, `region`, `gpu_model`, `gpu_count`, `kernel`, `kernel_features`, `long_running`, `extendable_lifetime`, `paused_retention_seconds`, `root`, `arch`, `package_manager`, `libc`, `run_seconds`, `process_seconds`, `egress_ips`, `outbound_traffic` and `file_stream_bytes`. |
| `lifetime_seconds` | How long the sandbox must be able to run continuously. `null` asks for a sandbox with no lifetime: it runs until the caller destroys it, so `at_end` must be left out, and only a provider that never ends a sandbox fits it ([matching](matching.md)). |
| `at_end` | The state the sandbox ends in when its lifetime runs out: `destroyed` or `paused`. |
| `image` | The environment the program brings. Left out, the sandbox starts from the provider's own default environment. A string is a public OCI image reference; `{"private_oci": "<reference>"}` names an OCI image in a registry requiring a username and password or token. The tool supplies those credentials separately at creation; they never appear in the request. `{"dockerfile": ...}` holds the Dockerfile's text to build, such as `{"dockerfile": "FROM alpine"}`; `{"provider_artifact": ..., "provider": ...}` names an image, template or snapshot that one provider holds. The Dockerfile's build context is supplied by the tool when it creates the image and is not part of the request. `requirements.custom_images.prepared: true` asks the provider to prepare the source before creation and boot the prepared artifact. |
| `restores_need` | The request that sandboxes restored from this one's snapshots will make, with `requirements`, `resources` and `lifetime_seconds`. Restores stay on the provider that took the snapshot, so that provider must satisfy it too. It configures nothing. |

```json
{
  "lifetime_seconds": 1800,
  "at_end": "paused",
  "requirements": {
    "pause_resume": {},
    "previews": {"access": "public", "ports": [3000]},
    "snapshots": {"keeps": "files_only", "original_after": "any"}
  },
  "resources": {"memory_min_mib": 2048, "region": "EU"}
}
```

A knob left out is not compared. A list means any of those values is acceptable.
`"any"` means "not compared", said on purpose, and is valid only on a knob that must be named.

A request carries no version line. It is read under the version of the tool reading it, and
a word that version does not define is refused.

A checker **MUST** refuse, before any matching, a request that has any of these: <!-- rule: request/refused-before-matching -->

- a knob that must be named, left out
- an empty list
- `"any"` inside a list
- `"any"` on a knob that need not be named
- more than one `policy`, or `"any"` as the policy
- `allow` with anything but an allowlist, or `deny` with anything but a denylist
- an allowlist or a denylist with nothing in it
- an `allow` or `deny` entry that is neither a host name nor an IPv4 address or range, or has a port, path or IPv6 address
- a wildcard in `deny`
- a hostname outside the [network hostname syntax](vocabulary.md#network_lockdown), including an `inject_into` host
- `previews` or `tcp_ports` without `ports`
- `file_stream_bytes` naming neither `read` nor `write`
- a port outside 1 to 65535
- a value listed twice in a knob or resource list, or a repeated port, `allow` or `deny` entry, or `inject_into` host
- an empty `region`, `image`, `dockerfile`, `private_oci` or `provider_artifact` string, or an `image` outside the four exact shapes shown above
- `credential` on `previews` unless `access` is `private` or a list that includes `private` (`"any"` does not count)
- `idle_seconds` without `custom_idle_time: true`
- `changeable` with `deny_all` or `open`
- `open` without `switchable`
- `switchable` without `switches_to`, or `switches_to` without `switchable`
- `switches_to` naming the request's own policy
- `auto_wake` with `on_idle` naming only `destroyed`
- `survives_pause` in a request that names neither `pause_resume` nor `idle_shutdown`
- `source` under `requirements`, or `custom_images` under `requirements` without an `image`
- `read_only` on a mount unless `read_only_mounts` is true
- `root`, `package_manager`, `libc` or `kernel_features` together with an `image`
- `idle_shutdown` together with `long_running`
- `hidden_secrets` without `inject_into`
- `hidden_secrets.headers` without `header_templates: true` and `injection: sets_header`, or `header_templates: true` without `headers`
- `hidden_secrets.headers` that do not name distinct HTTP-token headers, contain fields beyond `name`, `prefix` and `suffix`, or use non-text affixes or affixes with C0 controls other than HTAB, DEL or C1 controls
- `hidden_secrets.headers` with wildcard, scheme, path, port or IP entries in `inject_into`
- an `inject_into` host an allowlist does not list or cover by name, a denylist lists or covers by name, or with `deny_all`; a wildcard host needs the same or a parent wildcard allowlist, and a denylist must not block any name under it
- `volumes` without `mounts`
- a mount outside the [mount shape](vocabulary.md#volumes): a missing or additional field, an invalid provider name, an empty volume name, a non-absolute path, or a repeated `(provider, volume, path)` tuple
- pins to more than one provider, through `mounts`, a `provider_artifact` image or extensions
- `at_end: paused` without `pause_resume`
- `restores_need` in a request that does not name `snapshots`
- an `image` or `at_end` in `restores_need`, or `custom_images` in its `requirements`
- a resource set to `false` or zero
- a non-finite number (`NaN`, positive infinity or negative infinity) in a defined request field
- a list of regions
- a value of the wrong type, such as a list on a yes/no or number knob
- `unknown` as a value
- a word this version does not define

## 9. Matching

A declaration satisfies a request when these four checks hold, together with the request's
provider pins, image constraints and `restores_need`:

1. The provider passes the baseline.
2. For every gate the request names, the declaration has a variant whose knobs all fit, and
   whose limits admit the request's settings.
3. The variants chosen conflict neither with each other nor with the resources requested.
4. Every resource the request names, and its `lifetime_seconds` and `at_end`, fit the
   declared facts.

[The matching guide](matching.md) defines how pins, images and `restores_need` are checked.
They are part of satisfying the request, not additional capabilities to assume.

Matching is deterministic: the same request and declaration give the same answer, eligible
or not, with the reasons, in any implementation. `unknown` never fits except as
[principle 2](#4-principles) states. Which of several eligible providers to use is not matching; each tool chooses in its own way
([section 13](#13-where-the-specification-stops)).

The full rules, the order in which variants are tried, and what a match grants are in
[matching.md](matching.md).

## 10. Declarations

A provider's declaration is `declaration.yaml`, or one `declaration-<class>.yaml` per class
where the provider has several. It sits in a directory of its own, beside the cited reports
and every complete full-baseline run, including failed or unclean runs. In this repository
that directory is `providers/<provider>/`. A declaration kept elsewhere uses the same layout. It names the date and the SDK versions it was verified with, and is
verified again by rerunning the conformance tests. [declarations.md](declarations.md)
defines the format and how a provider writes, verifies and owns its declaration.

## 11. Conformance

The conformance tests live in [conformance/](../conformance/). Each names the rules it
checks. Each baseline rule has tests, and each value's rules have a test or a waiver in
[untested.yaml](untested.yaml). A test is written once and runs on every provider
through a driver using the provider's native API or SDK, directly or through an adapter
or HTTP binding. A separate native driver is optional when adapter or HTTP conformance
produces the required reports. Every report retains its actual implementation identity
and versions. No path emulates a missing native capability: a known native absence is
`unsupported`, while an unfinished mapping is `not_run`. [conformance.md](conformance.md)
describes how to run the tests, how to write a driver and what a run report proves.

## 12. Versioning

Before the first public release, development tags are internal. They may change the
vocabulary while keeping the `sandbox-provider-spec/0.1` format identifier; a tool uses the
vocabulary shipped in its exact development tag or source revision. The format identifier
alone does not pin an internal vocabulary revision. The changelog records internal development
releases. The public version and compatibility policy start at publication. The rules below
describe published versions.

Every file this specification defines carries its version as major.minor:
`spec: sandbox-provider-spec/0.1`. That is declarations, conformance tests and run reports;
a request carries none ([section 8](#8-requests)). Anything a checker or a matcher must
learn raises the minor version: a new gate, knob, value or field, or a changed meaning.
Below 1.0 a minor version may change what a file means; from 1.0 a minor version only adds.
Patch releases change no file's meaning: they carry updated declarations and evidence, new
run reports, new tests for existing values, new registry identifiers, and documentation. A
new baseline test raises the minor version, because it leaves every earlier report short of
the full baseline.

Release candidates of a release (`v0.1.0rc1`) may still add words under its version; a tool
built on an earlier candidate reads them as words its version does not define.

- A tool **MUST** refuse a file whose version it does not know. <!-- rule: version/unknown-version-refused -->

## 13. Where the specification stops

- **Edge cases** are covered by the conformance tests and documentation, not by more
  vocabulary. A new word enters only when leaving it out would let a program be matched to
  a provider that breaks it.
- **Interfaces** are the providers' own. The specification says what a provider does, not
  how a program asks for it.
- **Price, speed and reliability** are measured and ranked by whoever chooses between
  providers.
- **A durable machine.** A long-lived agent computer is built from these capabilities (pause
  and resume, snapshots, volumes) and is not a primitive here.
- **Security.** The specification is not a security certification. It states a few
  isolation facts; each user owns their security model.
- **Linux.** A sandbox runs Linux: the baseline assumes a POSIX system with `bash` and
  `python3`. Providers that offer macOS or Windows machines declare only their Linux
  sandboxes. Runtimes that run only code compiled for them, such as WebAssembly components
  and JavaScript isolates, grant capabilities per interface instead, and so are a different
  kind of sandbox from the ones this specification describes; so are the controls an agent
  harness applies to processes on its own host. If classes for other operating systems are
  added, a declaration that names none describes a Linux sandbox, so existing declarations
  keep their meaning.
- **Account quotas.** How many sandboxes an account may run at once, and how fast it may
  create them, belong to the account and change on request. Whoever holds the account knows
  its own.
- **Waitlisted gates and knob values.** The definitions below preserve terms used in earlier
  vocabulary drafts and test data. They are not request or declaration vocabulary in this version;
  they return to the active vocabulary after a provider's own SDK or documentation establishes
  that it offers them.

  - `live_resize`: a running sandbox changes CPU and memory to another declared size and keeps
    its processes and files. `shrinks` says whether the size can also go down.
  - `idle_shutdown.keeps`: for `on_idle: paused`, says whether resuming restores only files
    (`files_only`) or files and running processes with their memory (`files_and_memory`).
  - `network_lockdown.deny_wins`: with an allowlist, a matching `deny` entry takes precedence
    over `allow`. `domain_traffic` says whether a host name applies to HTTPS on port 443
    (`https`), HTTP on port 80 and HTTPS on 443 (`http_and_https`), TLS on any port (`tls`),
    or all traffic to the name's resolved addresses (`all`). With `all`, other names served
    from the same addresses are also affected. `cuts_open_connections` says whether a policy
    change ends, within ten seconds, existing connections refused by the new entries.
  - `network_lockdown.http_rules`: an allowlist or denylist entry may be an object
    `{hosts, methods, paths}`. `hosts` is a nonempty list of host names, each once. `methods`
    is a nonempty list of upper-case HTTP method tokens, each once, or the single entry `ANY`
    for every method. `paths` is a nonempty list of globs beginning with `/`, each once, and
    requires `methods`. An allowlist rule with methods names hosts literally, without `*.`;
    a rule without methods covers hosts like an ordinary name entry. In paths, `*` matches
    any run except `/`, `**` matches any run including `/`, and other characters match
    themselves; matching covers the whole path without the query string. Each rule counts as
    one name entry and one entry toward its list limit. A matching allowlist request succeeds
    and other traffic to its hosts is refused; a matching denylist request is refused and
    other traffic to its hosts succeeds. Inspection of HTTPS means clients that pin
    certificates cannot use those hosts.
  - `egress_proxy`: outbound connections leave through a proxy run by the tool and chained
    outside the sandbox, so destinations see the proxy's address. The tool supplies its
    address and credentials at creation, and a `network_lockdown` policy applies before it.
    `protocol` is `socks5` or `http`; `traffic` is `http` or `any_tcp`; `transparent` says
    whether clients that ignore `HTTP_PROXY` and `HTTPS_PROXY` are also proxied; `fails_closed`
    says whether outbound connections fail rather than bypass the proxy while it is
    unreachable.
  - `hidden_secrets.injection: replaces_placeholder`: code sends a placeholder provided by
    the tool in a request header, and the provider replaces it there. `injection: adds_body_field`
    says the provider adds a named field holding the secret to JSON object bodies on POST,
    PUT or PATCH requests, leaving the other fields unchanged. `sets_header` promises to add
    the secret to a request header when code sends no credential. Only `header_templates: true`
    promises support for request-selected header names and affixes; replacing a conflicting
    header already sent by code remains waitlisted.
  - `workload_identity`: code proves its identity to an outside service with a short-lived
    OIDC token issued by the provider. The tool sets up the token's audience and, for injected
    delivery, the hosts and header that receive it; the request carries none of them.
    `delivery` is `environment` (a documented environment variable) or `injected` (a header
    added to requests and unreadable by code); `custom_audience` says whether the tool chooses
    the token's audience.
  - `snapshots.original_after: stopped`: after the snapshot, the saved sandbox remains stopped,
    keeping files while its processes are gone; it can be started again.
  - `docker.networking: bridge`: containers have their own networks, and a port published with
    `-p` reaches them from the sandbox. In the active `host` mode, containers share the
    sandbox's network.
  - `ssh`: a standard OpenSSH client, plus tools such as `scp`, `rsync`, `sftp` and remote
    editors, reaches the sandbox using the host, port, user and credential returned by the
    provider's SDK. `credential` is `key`, `token` (carried in the user name) or `password`;
    it must open only this sandbox and must not be an account API key.
  - `tcp_ports.tls: terminated`: the client connects with TLS, which the provider ends before
    passing decrypted bytes to the sandbox's TCP port. The active `none` value passes plain
    TCP bytes unchanged in both directions.
  - `private_network`: sandboxes on the same private network reach one another directly,
    without previews, TCP ports or the internet. The provider decides how a sandbox joins and
    what placement limits apply. `ip_version` is `ipv4` or `ipv6`; a server bound only to
    `0.0.0.0` is not reachable over IPv6.

- **Nested virtualization capability.** A sandbox with nested virtualization lets code inside it
  create virtual machines through the kernel's KVM interface, for example for an Android emulator,
  Firecracker or a virtual machine test. `nested_virtualization` is not currently part of the
  request vocabulary. Access may depend on account or plan features named in `needs`.

- **Known differences not yet in the vocabulary.** No provider with a declaration is known to offer these yet; some are offered by others.
  Each enters the vocabulary when a provider's own SDK or documentation shows it offers it
  ([GOVERNANCE](../GOVERNANCE.md)): volumes that several sandboxes mount while exactly one may write;
  a managed browser reached over the Chrome DevTools
  Protocol; private previews opened with HTTP basic authentication, or only by members of
  the provider account; TCP ports reachable only through a tunnel to the caller's machine,
  and TLS passed through to the sandbox; a signal, such as `SIGTERM` with time to act on it,
  before a sandbox's lifetime ends; a background process that keeps a sandbox from going idle
  when no program is connected; for network lockdown, DNS filtering of names the policy blocks;
  accelerators other than GPUs, such as TPUs, and accelerator topology; IPv6 addresses in allowlists and denylists;
  allowlist or denylist entries limited to ports or protocols; joining a sandbox to the account's
  own private network, such as a VPN or VPC; inbound TCP or UDP traffic that wakes a sandbox idle
  shutdown paused; credentials the provider adds to connections other than HTTP, such as database
  or SSH logins; placeholders for hidden secrets replaced outside request headers or in request bodies;
  snapshots of one directory,
  restored into another sandbox; volumes attached to or detached from a running sandbox,
  and snapshots of a volume; systemd running as the first process and starting services.

- **Considered and left out.** Providers offer these, but a program can get each from what the
  specification already promises, so none is a word: a code interpreter that keeps state between
  calls, and interpreter contexts that do not share state (a kernel the program installs and drives
  as a background process); shell sessions that keep state between commands (an interactive shell
  process); sidecar containers (a helper the program runs as a process, or with docker); allowlists
  of source addresses for exposed ports (`tcp_ports` does not promise that the sandbox
  receives the client's address, so the program cannot enforce a source-address allowlist);
  restoring a snapshot in place over the sandbox that produced it (the program starts a replacement sandbox from the snapshot);
  mounting only one directory of a volume (the `mounts` setting mounts the whole volume at a chosen
  path, so using a directory inside it only chooses where the program reads and writes); and a call that
  wakes a sandbox idle shutdown paused (the program resumes it);
  watching files for changes (a watcher process in the sandbox);
  commands the provider runs on a schedule (a scheduler the program runs);
  readiness checks before a sandbox is used (the program polls its own service);
  previews that rewrite headers or terminate HTTPS at the provider before forwarding plain HTTP to the service (the service sets its own headers and serves plain HTTP; HTTPS from the client to the preview URL is not promised);
  extended attributes and metadata on files (the program keeps its own index).
