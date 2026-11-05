# Daytona declaration scope

Reviewed 2026-10-22 against current public documentation and committed native reports.

## Disk storage medium — 2026-10-26

The declaration now cites three clean, passing reruns of the same check from 2026-10-29
(`reports/native-container-disk1.json` to `disk3.json`, Daytona SDK 0.226.1). The 0.3.128 runs
below remain as the historical-suite fixtures that `tests/test_historical_daytona_0128_suite.py` reads.

The clean SPS 0.3.128 release-tag checkout ran
`coverage.facts.disk_in_memory.false` three times on the default Daytona container size.
All three reports are clean and pass: `reports/daytona-disk-memory-sps0128-run1.json`,
`reports/daytona-disk-memory-sps0128-run2.json`, and
`reports/daytona-disk-memory-sps0128-run3.json`. Each used SPS's native `DaytonaDriver`
with Daytona SDK 0.220.0, matching the SDK version in this declaration's existing native
reports. The isolated run environment used the published SPS 0.3.128 wheel metadata and
the 0.220.0 Daytona SDK while loading runner code from the clean 0.3.128 source checkout.
These runs do not load a provider adapter; its version is not part of these SPS
reports.
Each wrote 256 MiB to the default 3 GiB overlay. The recorded source was `cgroup_shmem`,
with `memory_before_bytes=0`, `memory_during_bytes=0`, and `memory_after_bytes=0`; each
reported `disk_in_memory=false`.

A separate live check confirmed the same fact at the 10 GiB size consumers request. Run
`sps-disk-memory-10g-20261026T201000Z` explicitly requested `disk_min_mib=10240`; Core
mapped this to Daytona `disk=10`, and `GET /sandbox` returned 10 GiB. The guest's raw
`df -h /` lines were `overlay 10G 24K 10G 1% /` before and `overlay 10G 56K 10G 1% /`
after. `findmnt -T /` returned target `/`, source `overlay`, filesystem `overlay` (not
tmpfs). The cgroup samples were `memory.max=1073741824`, `memory.current=38678528` before
and `40329216` after; `memory.stat` was `file=0`, `shmem=0` before and `file=1138688`,
`shmem=0` after. Five additional 256 MiB writes each reported false with cgroup shmem
samples `0/0/0` bytes. Cleanup left zero sandboxes with the run label.

The 10 GiB supplementary run used Core 0.13.190, adapter 0.5.156, and Daytona SDK
0.226.1. Core main now ships adapter 0.5.157, which requires `daytona==0.226.1`. The
canonical SPS runs above intentionally retain the declaration's existing SDK 0.220.0
identity so the other cited Daytona reports remain valid; they establish the native
Daytona storage-medium fact and do not claim current adapter behavior. A full Daytona
evidence refresh on SDK 0.226.1, including the current adapter version, remains a separate
follow-up; do not infer it from these three reports.

## GPU resources

The [GPU guide](https://www.daytona.io/docs/en/gpu-sandboxes/) says
“A GPU sandbox has up to 8 GPU units.” This supports `max_gpus: 8`.
The guide lists 16 vCPUs, 192 GiB memory and 512 GiB disk as per-sandbox defaults
that do not scale with GPU-unit count, rather than per-unit ceilings. Defaults do
not establish the full supported CPU/memory/disk range. The documented 1-vCPU,
1-GiB-memory, 1-GiB-disk allocation belongs to the default GPU snapshot, not the
whole product's supported size range. Leave `sizes` unknown rather than declare
that snapshot as the only size or imply arbitrary resource combinations. GPU
models also remain unknown in the machine-readable declaration until their
registry identifiers and allocation conditions are established.

## Lifetime and execution user

The [wall-clock TTL section](https://www.daytona.io/docs/en/sandboxes/#wall-clock-ttl)
says “if not set, the sandbox has no TTL deadline”. This supports the unlimited
maximum lifetime; disabling an inactivity timer alone would not establish it.

The [isolation table](https://www.daytona.io/docs/en/isolation/) says
“Code runs as root inside the sandbox without affecting the runner.” The native
`facts.default_user` report instead observed `daytona` through the driver's
command execution path. These observations cannot establish one image-independent
default for all container paths. Keep `default_user: unknown`. After live runs
resume, identify the SDK, default snapshot/image and user configuration; observe
`id -un` through ordinary process execution without a user override, and compare
the native sandbox user metadata before restoring a scoped claim. The existing
report remains unchanged as evidence of its original environment.

## State transport

The [Python SDK reference](https://www.daytona.io/docs/en/python-sdk/#polling-fallback)
says “the SDK falls back to polling automatically”. The driver leaves state
transport at the SDK default, using event streaming with its native fallback,
instead of explicitly selecting deprecated polling-only mode.
