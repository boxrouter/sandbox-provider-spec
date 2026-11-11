# Agent37 declaration evidence

The declaration records only what a committed report or a dated quote of the provider's documentation
proves. Values without supporting evidence remain `unknown`. No conformance report is committed yet.

## Resources

- `max_lifetime_seconds: unlimited`: the concepts page (read 2026-11-11) says an instance "Lives
  until you delete it". Agent37 has no timer that ends an instance (its only timer, auto-sleep,
  sleeps an idle instance and keeps its disk), so the declaration has no `lifetime_timer` block
  and serves only requests that ask for no lifetime (`lifetime_seconds: null`).
- `located_in: ["US"]`: the create page (read 2026-11-11) says `us` is the only region that runs
  the `default` instance type, which is the type the adapter creates; `eu` and `ap-south` run VM
  and Performance instances only.
- Sizes are documented (instance sizing page: 2 vCPU / 4 GB, 4 / 8, 4 / 16 and 4 / 32, default
  2 / 4) but stay `unknown` until recon observes them, because the page states memory in "GB"
  and the declaration needs MiB.

TODO(recon): cite the recon report rows for kernel, sizes, regions and the other limits.

## Gates

TODO(certify): one bullet per declared gate with the certified report and test that proves it.
