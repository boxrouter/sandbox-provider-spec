# Superserve declaration evidence

The declaration records only what a committed report or a dated quote of the provider's documentation
proves. Values without supporting evidence remain `unknown`.

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

## Facts proved by adapter reports

These values cite the adapter's committed reports, copied beside this file as `reports/adapter-*.json`.

- Lifetime timer `{enforced_by: provider, counts_paused_time: unknown, at_end: [destroyed]}`. The adapter
  creates with `timeout_seconds` set to the lifetime and `auto_delete_seconds` 0. Documentation
  (lifecycle page and OpenAPI, read 2026-11-13): `timeout_seconds` pauses the sandbox once its current
  active session has run that long, each resume starts a fresh window, and `auto_delete_seconds: 0`
  "deletes the sandbox as soon as it pauses". Proof: `lifetime_timer.at_end.destroyed` in
  `reports/adapter-default.json`. `counts_paused_time` stays `unknown`: the adapter offers no pause, so
  `lifetime_timer.counts_paused_time.false` cannot run.
- `processes`: `commands.spawn`, a stdin write and its explicit EOF, and a signal that ends the process;
  no reattach, because the service stops a command whose connection is gone (`processes.input.true`,
  `processes.cancel.true`, `processes.reattach.false` in `reports/adapter-default.json`).
- `network_lockdown`: an allowlist of names and addresses with `*.` wildcards, and a switch between an
  allowlist and open (`reports/adapter-network-lockdown-default.json`,
  `reports/adapter-network-lockdown-coverage-default.json`). Not declared: `deny_all` (Superserve's refusal of
  an unlisted name over TLS reads as ambiguous, so its row is `not_run`), a denylist (its rows need a recording
  receiver at a blocked address) and `changeable` (Core refuses the empty allowlist that row sets).
- `custom_images`: a public OCI image is built as a team template and a sandbox boots from it, as
  `provider_artifact` when the caller names the template; an image's ENTRYPOINT and CMD do not run, and no
  template option takes registry credentials, so a private registry image is refused
  (`reports/adapter-custom-images-core-default.json`, `reports/adapter-custom-images-default.json`).

## Gates

Pause, resume, snapshots, extending a lifetime, previews and terminals are not offered in this version, so
their gates stay absent.
