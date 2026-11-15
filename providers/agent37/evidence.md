# Agent37 declaration evidence

The declaration records only what a committed report or a dated quote of the provider's documentation
proves. Values without supporting evidence remain `unknown`. No conformance report is committed yet.

## Resources

- `max_lifetime_seconds: unlimited`: the concepts page (read 2026-11-11) says an instance "Lives
  until you delete it". Agent37 has no timer that ends an instance; auto-sleep only sleeps an idle
  instance and keeps its disk.
- `lifetime_timer: {enforced_by: router, counts_paused_time: true, at_end: destroyed}`: the
  declaration records the shared BoxRouter lease path for finite benchmark lifetimes. Its maximum
  is immutable, the running batch reaper destroys an expired bound instance, and the post-run
  label and batch sweeps confirm deletion by the provider's not-found response. Runner regressions
  cover expiration, an Agent37-labeled orphan, and an unconfirmed delete. No live paid run was
  used as evidence for the shared cleanup code.
- `located_in: ["US"]`: the create page (read 2026-11-11) says `us` is the only region that runs
  the `default` instance type, which is the type the adapter creates; `eu` and `ap-south` run VM
  and Performance instances only.
- `sizes` and `default_size`: the instance sizing page (read 2026-11-12) lists four shapes, 2 vCPU
  / 4 GB, 4 / 8, 4 / 16 and 4 / 32, with 2 / 4 the default. Standard instances accept 2-12,
  2-20, 2-40 and 2-80 GB disk by shape; VM instances accept 2-100 GB on every shape. The create
  API accepts an explicit `resources.disk` value in whole GB. A live probe on 2026-11-12
  (run `agent37-sizes-20261112T071858Z`, template `agent37-base`) confirmed the default 2 / 4
  shape and 4 GB default disk; the adapter now forwards an explicitly resolved disk size.
- `size_is_ceiling: true`: `coverage.facts.size_is_ceiling.true` passed in
  `reports/adapter-default-size-ceiling.json`. The instance's cgroup holds a 2-core CPU quota
  (`cpu.cfs_quota_us` 200000 over 100000) and a 4294967296-byte memory limit.

## VM class (`declaration-vm.yaml`)

Agent37's `vm` instance type: a full Linux virtual machine with its own kernel, on the same API
keys, endpoints and wallet as a default instance. Agent37 says it "needs a funded workspace"
(create page, read 2026-11-12): an account whose wallet cannot cover a day of VM compute cannot use
this class.

- `kernel: dedicated`: the VM instances page (read 2026-11-12) says a `vm` instance is "a full
  Linux virtual machine with its own kernel and KVM hardware virtualization". A live probe on
  2026-11-12 (run `agent37-vm-20261112T093014Z`) read kernel `7.0.0-38-generic`, `/dev/kvm` and
  `/dev/fuse`, and full capabilities for root.
- `sizes`, `default_size`: the instance sizing page says a VM takes the same four CPU/memory
  shapes, accepts 2-100 GB disk on each shape and defaults to 12 GB when the create omits disk.
  The create API accepts an explicit `resources.disk` value in whole GB.
- `size_is_ceiling: true`: `coverage.facts.size_is_ceiling.true` passed in
  `reports/adapter-vm-size-ceiling.json`.
- `default_user: root`, `default_cwd: /root`: the class's default image is `agent37-ubuntu`
  (Ubuntu with Docker running), which the adapter creates for a `provider_default` image on this
  class; `facts.default_user` and `facts.default_cwd` passed in `reports/adapter-vm-defaults.json`.
- `regions` and `located_in: ["US"]`: the VM instances page says VMs run in `us`, `eu` (France)
  and `ap-south` (India, Mumbai), and the create page says `us` is the default region.
- `max_lifetime_seconds: unlimited`: as for the default class (concepts page).

The `network_lockdown` variants are those of the default class, proven again on VMs:
`reports/network-lockdown-vm.json` (deny all, names, wildcards, 32 entries),
`reports/network-lockdown-addresses-vm.json` (addresses) and
`reports/network-lockdown-coverage-vm.json` (open, switchable).

TODO(recon): cite the recon report rows for kernel, sizes, regions and the other limits.

## Gates

TODO(certify): one bullet per declared gate with the certified report and test that proves it.
