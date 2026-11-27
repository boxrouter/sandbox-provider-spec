# Luxor declaration evidence

The declaration records only what a committed tester report or a dated quote of Luxor's documentation
proves. Every other value is `unknown` or absent. The reports are one package version
(`sps-provider-luxor` 0.1.2), run live on 2026-11-24 from the devbox with the spec tester 0.5.116:
`tester-default-baseline.json` (`--test baseline.`), `tester-default-core.json` and
`tester-default-coverage.json` (whole selections, with `file_stream_large=false`) and
`tester-default-select.json` (rows the long suites do not hold as selections).

## What the reports cover

- `default_user: tenki`, `default_cwd: /home/tenki`, `root: [sudo]`, `arch: [amd64]`, `libc: glibc`,
  `package_manager: apt`, `disk_in_memory: false`.
- `gates.pause_resume`: `keeps: files_and_memory` (`pause_resume.files_and_memory`, core).
- `gates.processes`: `input: true`, `cancel: true`, `reattach: true` (the adapter runs a guest supervisor, README.md;
  `processes.input.true`, core).
- `gates.snapshots`: `keeps: files_and_memory`, `original_after: briefly_paused`, `deletable: true`
  (`snapshots.*`, core). Luxor stores no labels and reports no size for a snapshot: discovery states
  `snapshot_labels_kept_by: router` and `snapshot_cost: unavailable`.
- `gates.previews`: `access: public`, `revocable: true`, `any_port: true` (`previews.access.public`,
  `previews.revocable.true.public`, core; `coverage.previews.any_port`). Not stated: `websocket`, `loopback`,
  `survives_pause`, `max_ports`, `link_lifetime_seconds`, `reserved_ports` (no passing row).
- `gates.network_lockdown`: three variants (names, addresses, both), each `deny_all` and `allowlist`, wildcards, at
  least 32 entries, `changeable: false` (`network_lockdown.*`, core; `coverage.network_lockdown.*`). The policy is
  fixed at create. `switchable` is not stated: `coverage.network_lockdown.switchable.false` reads `unsupported`.
  The rows need fixtures (an allowed and a denied URL, allowlists of names and addresses, wildcards and 32 entries), which the run supplied.
- Directory operations (`files.list`, `files.mkdir`, `files.remove`, `files.exists`): the `directories.*` rows pass
  in core. They are discovery `operations`, not a declaration gate.

## The lifetime timer is router-enforced

Luxor's timer pauses a session at `timeoutAt`, in a sweep that runs about once a minute; it never destroys
it (`sandbox-provider-pricing` `providers/luxor/evidence/2026-11-24-lifetime-timer.md`). So the declaration
says `enforced_by: router`, `at_end: destroyed`, `counts_paused_time: true`, each resting on the
specification's own definition, and Cloud's reaper ends the session. The tester rows
`lifetime_timer.at_end.destroyed` and `facts.extendable_lifetime` assume a provider-enforced timer and
read `differs` here; they prove nothing about a router-enforced one. `extendable_lifetime` is therefore
`unknown`, although the adapter extends `timeoutAt` with `ExtendSession`.

## Declared from documentation quotes (read 2026-11-24)

- `kernel: dedicated`: "A running full Linux VM" (/docs/sandbox/concepts).
- `sizes`: 1 to 16 vCPU and 512 to 65536 MiB, the Team plan's machine ("Machine size: 4 cores, 8 GB RAM | 16 cores,
  64 GB RAM", luxor.ai/pricing, read 2026-11-27). A 16-core, 65,536 MiB session was accepted on the Boxrouter workspace
  (Team) on 2026-11-27, and `nproc` printed 16, `MemTotal` 66895552 kB (`limits/sizes.json` of the luxor-adapter lane).
  `resources.needs.sizes: [team_plan]` and `unmet_limits.sizes.team_plan: {cpu: 4, memory_mib: 8192}` state that a
  workspace without the Team plan (Starter) is capped at 4 cores and 8 GB RAM, the same pricing row. An account's
  `discovery()` meets `team_plan` when `GetWorkspaceSandboxUsage` states `max_concurrent_jobs` of 100 or more
  (Starter 5, Team 100, the pricing page's "Concurrent sessions" row; the Boxrouter workspace reads 100). The disk range, 5 to 100 GiB,
  is the API's own (the template resources row of /docs/sandbox/templates says "disk (5-100 GB)"; the adapter's create
  asks for it and Luxor accepts it).
- `default_size`: "Unset options fall back to service defaults of 2 vCPU, 4096 MB, and a 5 GiB root disk." (/docs/sandbox/sessions).
- `idle_shutdown: unsupported`: "Sandboxes are not paused for inactivity" (/docs/sandbox/product).
- `hidden_secrets` is not declared: Luxor replaces a `secrets://NAME` placeholder that the code itself sends, which is
  not the standard's `sets_header` (a secret added to requests that carry no credential).

## Left `unknown` or unclaimed, and why

- `gpus`, `regions`, `long_running`: the documentation says nothing either way (`facts.long_running` needs a fixture).
  Luxor's create has no region field, but a missing field is not a quote that says "none".
- The 1 GiB file rows (`files.stream.v1.write.1gib`, `read.1gib`, `contract.files_1gib_roundtrip`): run
  from an AWS test server, see `sandbox-provider-pricing` `providers/luxor/evidence/`.
- `files.regular_write.usability.v1.authority` read `error` in the cited run: the tester then accepted
  only the codes `authorization` and `permission_denied`, and an SPS driver reports `forbidden`
  (coverage_regular_write.py). The tester has accepted `forbidden` since then; the
  adapter does answer `forbidden` for a protected path, so a new run can claim the row.
- Not offered by the adapter, and why:
  - `terminal`: `RunStart.pty` exists, but nothing documents it and a resize has no message. Planned as stage 1c.
  - `volumes`: SPS 1.0 has no volume operation, and no provider declares one.
  - `custom_images`: Luxor cannot back the four image operations (a template builds from a base image, a parent
    template or a snapshot, never from an OCI image or a Dockerfile). The tester's `custom_images.provider_artifact`
    row no longer needs them: it borrows the artifact without calling the provider, so the adapter can claim
    `source: provider_artifact` once a run proves it. A create from a registry image works.
  - `labels.update`: Luxor's session tags and metadata are fixed at create.
  - `hidden_secrets`: see above.
  - `user_selection`, `file_stream_max_bytes` (the 1 GiB rows need a rerun from the AWS test server on a clean tree).
- `contract.lifetime_ends` follows the router-enforced timer; coverage rows that did not pass
  (`differs`: arm64, root by default, other package managers, musl, disk in memory; `error`:
  `coverage.facts.max_run`) are in the committed coverage report and claim nothing.
- Two core rows (`snapshots.restore_options`, `snapshots.v1.outlives_source`) read `error` (`provider_error` at create)
  when the core and coverage suites ran in parallel, 15 sessions at once. Both pass alone and in the committed core
  run, which ran by itself.
- `tester-default-claims-20261124.json` holds two rows (`network_lockdown.deny_all`,
  `coverage.network_lockdown.allowlist.mixed`) that the third network variant's `policy` cites, because no one suite
  report selects both.
