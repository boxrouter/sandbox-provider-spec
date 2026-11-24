# Luxor declaration evidence

The declaration records only what a committed tester report or a dated quote of Luxor's documentation
proves. Every other value is `unknown` or absent. The reports are one package version
(`sps-provider-luxor` 0.1.0), run live on 2026-11-24 from the devbox with the spec tester 0.5.103:
`tester-default-baseline.json` (`--test baseline.`), `tester-default-core.json` and
`tester-default-coverage.json` (whole selections, with `file_stream_large=false`) and
`tester-default-select.json` (rows the long suites do not hold as selections).

## What the reports cover

- `default_user: tenki`, `default_cwd: /home/tenki`, `root: [sudo]`, `arch: [amd64]`, `libc: glibc`,
  `package_manager: apt`, `disk_in_memory: false`.
- `gates.pause_resume`: `keeps: files_and_memory` (`pause_resume.files_and_memory`, core).
- `gates.processes`: `cancel: true`, `reattach: true` (the adapter runs a guest supervisor, README.md).

## The lifetime timer is router-enforced

Luxor's timer pauses a session at `timeoutAt`, in a sweep that runs about once a minute; it never destroys
it (`sandbox-provider-pricing` `providers/luxor/evidence/2026-11-24-lifetime-timer.md`). So the declaration
says `enforced_by: router`, `at_end: destroyed`, `counts_paused_time: true`, each resting on the
specification's own definition, and Cloud's reaper ends the session. The tester rows
`lifetime_timer.at_end.destroyed` and `facts.extendable_lifetime` assume a provider-enforced timer and
read `differs` here; they prove nothing about a router-enforced one. `extendable_lifetime` is therefore
`unknown`, although the adapter extends `timeoutAt` with `ExtendSession`.

## Left `unknown` or unclaimed, and why

- `kernel`, `sizes`, `gpus`, `regions`, `long_running`: no tester row proves them here (`facts.sizes` and
  `facts.long_running` need fixtures). The adapter's discovery states the sizes it offers (1 to 4 vCPU,
  1 to 8 GiB, 5 to 100 GiB of disk, a Starter-plan ceiling); that is not evidence a declaration may cite.
- The 1 GiB file rows (`files.stream.v1.write.1gib`, `read.1gib`, `contract.files_1gib_roundtrip`): run
  from an AWS test server, see `sandbox-provider-pricing` `providers/luxor/evidence/`.
- `files.regular_write.usability.v1.authority` reads `error`: the tester accepts only the codes
  `authorization` and `permission_denied`, and an SPS driver reports `forbidden`
  (coverage_regular_write.py). The adapter does answer `forbidden` for a protected path.
- Not offered by the adapter: `custom_images`, `snapshots`, `network_lockdown`, `previews`, `terminal`,
  `user_selection`, `idle_shutdown`, process input, `labels.update` and directory operations (README.md
  lists them as gaps).
- `contract.lifetime_ends` follows the router-enforced timer; coverage rows that did not pass
  (`differs`: arm64, root by default, other package managers, musl, disk in memory; `error`:
  `coverage.facts.max_run`) are in the committed coverage report and claim nothing.
