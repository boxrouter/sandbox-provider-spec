# Superserve declaration evidence

The declaration records only what a committed report or a dated quote of the provider's documentation
proves. Values without supporting evidence remain `unknown`. No conformance report is committed yet.

## Resources

- `max_lifetime_seconds: 604800`: Superserve's `timeout_seconds` takes 1 to 604800 seconds (OpenAPI
  `CreateSandboxRequest`, read 2026-11-13), so 604800 is the longest window one create can ask for. The
  declaration states that bound as the admission cap. It is a cap on one window of active time, not on
  total lifetime: each resume starts a fresh window.
- `sizes`, `default_size`: `unknown`. The templates page (read 2026-11-13) lists `superserve/base` as 2
  vCPU, 4096 MiB memory and 8192 MiB disk, but a live run on this team on 2026-10-23 observed 1 vCPU,
  1024 MiB and a 7.8 G disk, and the team's plan caps a sandbox's shape. The live recon settles both.
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
- `size_is_ceiling: true`: not stated yet (the support file cannot carry it). Proof to commit:
  `coverage.facts.size_is_ceiling.true`.
- `network_lockdown`: not stated yet. Superserve documents an allow list (IPs, CIDRs, domains with `*.`
  wildcards) and a deny list (IPs and CIDRs only), set at create and replaced on an active sandbox
  (networking page and OpenAPI `NetworkConfig`, read 2026-11-13). The gate lands with the adapter's
  network implementation, because declaring it requires `network_update`; the drafted variants and the
  tests that prove them are in `scratchspace/superserve/ss-decl/network-variants.yaml`.

## Gates

No gate is declared here. Pause, resume, snapshots, extending a lifetime, previews and terminals are not
offered in this version, so their gates stay absent.
