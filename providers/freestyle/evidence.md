# Freestyle declaration evidence

The declaration records only what a committed tester report, a dated quote of Freestyle's
documentation or API, or a raw redacted answer in `packages/sps-provider-freestyle/evidence/`
proves. Values without evidence stay `unknown`.

## Resources

- `kernel: dedicated`: Freestyle's docs call every VM "a full Linux virtual machine"
  (https://www.freestyle.sh/docs/vms, read 2026-11-23).
- `sizes`, `default_size`: the default base snapshot `freestyle/ubuntu` is 4 vCPU, 8 GiB, 32 GB
  (https://www.freestyle.sh/docs/vms/base-snapshots); a live create returned `resources` cpu 4, memory
  8192 (MiB), storage 32768 (MiB). `freestyle/ubuntu-sm` (2 vCPU, 4 GiB, 16 GB) also boots on the Free
  plan (`evidence/probe-shapes-*`), but the adapter offers the default only. The 32 GB disk is the Free
  plan's maximum, so every plan can create it.
- `default_user: ubuntu`, `default_cwd: /home/ubuntu`: `facts.default_user` and `facts.default_cwd`
  (`reports/prober-default-core.json`); the docs say the same ("an `ubuntu` user with passwordless sudo.
  `vm.exec()` defaults to that user").
- `root: [sudo]`: `coverage.facts.root.sudo` (`reports/prober-default-coverage.json`).
- `max_lifetime_seconds: 315360000`: the API refuses a larger `ttlSeconds` ("ttlSeconds cannot exceed
  315360000 (10 years)", `evidence/probe-shapes-*`). It is a bound the API states, not a measured run.
- `file_stream_max_bytes` read and write at least 1 GiB: `files.stream.v1.read.1gib` and
  `files.stream.v1.write.1gib` (`reports/prober-default-coverage.json`). The adapter reads a large file as
  ranges (`reading.py`): one connection carried about 1.3 MB/s and six carried 5 to 6 MB/s from the
  devbox (`evidence/probe-read-throughput-*`); a single-stream 1 GiB read took 707 s, a single-request
  write 154 s (`evidence/probe-gib-*`).
- Left `unknown`: regions, `located_in`, GPUs, `paused_retention_seconds` (a paused VM is deleted after
  `autoDeleteSeconds`, which a plan caps at 30 days: seen as `autoDeleteSeconds: 2592000`,
  `autoDeleteFromPlan: true`, but not tested), `max_run_seconds`, `long_running`, `extendable_lifetime`.

## Lifetime timer

`lifetime_timer` is left out of the declaration (unknown). Freestyle's `ttlSeconds` deletes a VM that long
after creation, paused time included, but its sweep is not prompt: a VM with `ttlSeconds: 60` was gone
after 209 s and one with 30 s after 225 s (`evidence/probe-ttl-delrun-*`, `probe-lifetime-*`; a
`ttlSeconds: 1` VM was still running after 90 s), so `contract.lifetime_ends` does not pass.
`maxRunSeconds` 30 with `autoDeleteSeconds: 0` ended the VM within 12 s (paused at about 30 s, deleted at
once), but an ephemeral VM is deleted when it pauses, which would end every caller's pause. The adapter's
discovery still declares `enforced_by: provider`, `at_end: destroyed`, `counts_paused_time: true` because
Cloud keeps the real deadline of a class that lists `cost.capture` and arms the provider's timer as a
backstop past it. `lifetime.extend` moves `ttlSeconds` (`resources.extendable_lifetime: true` in discovery,
not in the declaration: `facts.extendable_lifetime` needs a control sandbox that ends on time).

## Pause and resume

`gates.pause_resume: files_and_memory`: `pause_resume.files_and_memory` passed
(`reports/prober-default-core.json`): a file and a running process written before the pause were intact
and finished after the resume. `POST /pause` banks the run into `totalRunSeconds` (`evidence/probe-bg-*`,
`probe-misc-*`).

## Cost

`cost.capture` is listed: the VM record, which holds `totalRunSeconds`, vanishes with the VM
(a deleted VM answers 404, as an id that never existed does; `evidence/probe-basic-*`), and a run is added
to `totalRunSeconds` only when it ends. The adapter's `cost` is `source: usage` (cpu, memory, disk
quantities, no amounts): `sandbox-provider-pricing` prices them (FA-12). `cost_final_within_seconds` is 0:
the figures are fixed by the capture, and the tester's `contract.cost_final` is exempt for a class that lists
`cost.capture`. Not measurable from the VM record, so not a line: egress ($0.02 per GB), which has no per-VM
counter.

## Gaps against the standard

Stated in the package README: a command on a paused VM wakes it instead of answering `conflict`, label
values are at most 63 bytes, and a deleted VM cannot be told from one that never existed.
