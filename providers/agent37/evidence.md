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
- `sizes` and `default_size`: the instance sizing page (read 2026-11-12) lists four shapes, 2 vCPU
  / 4 GB, 4 / 8, 4 / 16 and 4 / 32, with 2 / 4 the default, and says a template other than the two
  VM ones gets 4, 6, 12 or 24 GB of disk by shape when create sends no `disk`. Agent37's "GB" is a
  GiB: a live probe on 2026-11-12 (run `agent37-sizes-20261112T071858Z`, template `agent37-base`)
  read 4294967296 bytes of memory (`free -b`) and of billed disk (`df -B1` on the mount path) on a
  create with no `resources`, and 8589934592 bytes of memory and 6442450944 bytes of disk on
  `{cpu: 4, memory: 8}`, with `nproc` 2 and 4. Each declared size's `disk_mib` is that default
  disk, because the adapter sends `cpu` and `memory` only.
- `size_is_ceiling: true`: `coverage.facts.size_is_ceiling.true` passed in
  `reports/adapter-default-size-ceiling.json`. The instance's cgroup holds a 2-core CPU quota
  (`cpu.cfs_quota_us` 200000 over 100000) and a 4294967296-byte memory limit.

TODO(recon): cite the recon report rows for kernel, sizes, regions and the other limits.

## Gates

TODO(certify): one bullet per declared gate with the certified report and test that proves it.
