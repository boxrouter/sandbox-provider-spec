# Superserve declaration evidence

The declaration records only what a committed report or a dated quote of the provider's documentation
proves. Values without supporting evidence remain `unknown`. The committed reports prove `size_is_ceiling`,
`default_user` and `default_cwd`; the timer and network claims wait for theirs.

## Resources

- `max_lifetime_seconds: 604800`: Superserve's `timeout_seconds` takes 1 to 604800 seconds (OpenAPI
  `CreateSandboxRequest`, read 2026-11-13), so 604800 is the longest window one create can ask for. The
  declaration states that bound as the admission cap. It is a cap on one window of active time, not on
  total lifetime: each resume starts a fresh window.
- `sizes`, `default_size`: two shapes, because a sandbox inherits its shape from its template. The default
  template `superserve/base` is 2 vCPU, 4096 MiB memory and 8192 MiB disk (the default size), from the
  templates page (read 2026-11-13). The adapter builds the standard-image template itself
  (`image_preparation.py`) at 2 vCPU, 2048 MiB and 8192 MiB, inside the documented template limits
  (build-spec page: minimum 256 MiB, Free plan maximum 2 vCPU and 4096 MiB) and within the team's legacy
  Free cap; that shape is the adapter's own choice, not a quoted figure. The adapter sets no shape on create. A live check on 2026-11-13 (run `ss-sizes-20261113T035827Z`, one sandbox
  of `superserve/base`, destroyed) agreed with the page: the template record (`GET /templates`) says
  `vcpu` 2, `memory_mib` 4096, `disk_mib` 8192; `GET /sandboxes/{id}` says `vcpu_count` 2, `memory_mib`
  4096; inside, `nproc` printed 2, `/proc/meminfo` `MemTotal` 4034076 kB (the guest kernel keeps part of
  the 4096 MiB) and `df -m /` a 7964 MiB root filesystem. Known discrepancy: a live run on this team on
  2026-10-23 saw 1 vCPU, 1024 MiB (`free -m` 984) and a 7.8 G root disk, before the 2026-11-11 rebuild
  of the system templates (`built_at` 2026-11-11T17:47:55Z); it no longer reproduces, and the declaration
  states the current measurement. The team's legacy Free plan is recorded at a cap of 2 vCPU, 2 GiB and 8 GiB disk per sandbox
  (research.md, 2026-11-13); the `superserve/base` sandbox above ran at 4096 MiB on this team regardless, so
  the cap did not bind the system template. The citation is
  the page's quote, not a report: no SPS conformance test proves `sizes`.
- `size_is_ceiling: true`: `coverage.facts.size_is_ceiling.true` passed in
  `reports/adapter-default-size-ceiling.json` (run `ev-cert-superserve-local80eeed14f0-1-1`) by measured
  use: a CPU burn measured 1.00 CPU against a 2-CPU request (the sandbox is a VM, so no cgroup quota is
  visible) and a memory hog aimed at twice the 4096 MiB request was killed. The adapter's
  `conformance-fixtures.json` names the test size (`test_size`: 2 vCPU, 4096 MiB).
- `default_user: root` and `default_cwd: /home/user`: `facts.default_user` and `facts.default_cwd` passed
  in `reports/adapter-defaults.json` (run `ev-cert-superserve-localfdf5bb43b5-1-1`) on a sandbox of the
  default template. The first run of that report (`ev-cert-superserve-local1167b7798f-1-2`) passed
  `facts.default_cwd` but ended `facts.default_user` in an `error` (`timeout` in `environment.observe`
  after 78 s) with the sandbox cleaned up; the one rerun passed both. A direct SDK check on 2026-11-13
  also read `uid=0(root)` and `/home/user`.
- `kernel`, `gpus`, `regions`, `located_in`, `paused_retention_seconds`, `max_run_seconds`,
  `max_process_seconds`, `long_running`, `extendable_lifetime`: `unknown` or absent; the documentation
  states none of them. `located_in` is absent because Superserve names no country for a default placement.

## Facts proved by a test, stated outside the declaration until their reports exist

The SPS checker refuses a citation of a report that is not committed, and refuses a documentation
quote for these paths, so the adapter's `support.yaml` states the timer under `adds`. These facts move
into this declaration, with their citations, once the live runs commit the reports.

- Lifetime timer `{enforced_by: provider, counts_paused_time: false, at_end: [destroyed]}`. The adapter
  creates with `timeout_seconds` set to the lifetime and `auto_delete_seconds` 0. Documentation
  (lifecycle page and OpenAPI, read 2026-11-13): `timeout_seconds` pauses the sandbox once its current
  active session has run that long, each resume starts a fresh window, and `auto_delete_seconds: 0`
  "deletes the sandbox as soon as it pauses". Proof to commit: `lifetime_timer.at_end.destroyed` in the
  default core report (`reports/default.json`); `counts_paused_time` is quotable from the same page.
- `network_lockdown`: not stated yet. Superserve documents an allow list (IPs, CIDRs, domains with `*.`
  wildcards) and a deny list (IPs and CIDRs only), set at create and replaced on an active sandbox
  (networking page and OpenAPI `NetworkConfig`, read 2026-11-13). The gate lands with the adapter's
  network implementation, because declaring it requires `network_update`; the variants and the tests
  that prove them are drafted with that implementation.

## Gates

No gate is declared here. Pause, resume, snapshots, extending a lifetime, previews and terminals are not
offered in this version, so their gates stay absent.
