# Blaxel declaration scope

Reviewed 2026-10-22 against current provider documentation and committed native reports.

The [sandbox overview](https://docs.blaxel.ai/Sandboxes/Overview) documents the
4-CPU/8-GB and 6-CPU/16-GB combinations. Blaxel's [quickstart SDK example](https://docs.blaxel.ai/Get-started)
includes `memory: 4096, // in MB`. A native SDK create on 2026-10-22 with
`memory=4096` reported `nproc=2` and
`/proc/meminfo` `MemTotal=4027324 kB` (about 3.84 GiB); the sandbox was deleted.
The declaration's `resources.sizes` documentation quote is copied from the
[quickstart SDK example](https://docs.blaxel.ai/Get-started):
`memory: 4096,   // in MB`.
The declaration therefore includes the 2-CPU/4096-MiB combination. Its unspecified
size remains the native default; this probe did not request a size-less create.
The included native report does not test a size-less create, so it is not cited for
the unspecified-size behavior.

The [process guide](https://docs.blaxel.ai/Sandboxes/Processes) says
“Use `keepAlive` to override this for the duration of a process.” The Python example
uses `keep_alive: True`; the flag suppresses standby only while that process runs.
It does not by itself establish the specification's sandbox-wide `long_running`
guarantee from creation, including intervals with no process. The declaration leaves
`long_running` unestablished because process-scoped keep-alive does not prove a
sandbox-wide guarantee.

The reports identify `blaxel==0.4.8`, whose generated process request contains
`keep_alive`. That flag suppresses standby only while the process runs; it does not
establish a sandbox-wide idle-disable guarantee. To establish `long_running`, evidence
must show a native sandbox-wide idle-disable setting and verify it across idle intervals
without a synthetic keep-alive workload. A process-only keep-alive test remains scoped
to that process.

The [proxy guide](https://docs.blaxel.ai/Sandboxes/Proxy) documents secret rotation
on a running sandbox. The declaration leaves rotation unknown because the available
evidence does not establish that behavior at the pinned SDK version. A native rotation
check at that SDK version is needed before offering either value.

Obtain the current match result locally, without provider calls:

```sh
sandbox-provider-spec match examples/requests/coding-agent.yaml providers/blaxel/declaration.yaml
```

Interpret that result with the current request, declaration and native reports;
do not append a `baseline_failed` reason that the matcher did not return.

## Disk

The [sandbox overview](https://docs.blaxel.ai/Sandboxes/Overview) and
[troubleshooting guide](https://docs.blaxel.ai/knowledge-base/troubleshooting/resolve-enospc-no-space-left-on-device-errors)
say the sandbox filesystem lives in memory: "Sandbox filesystem storage is in memory by
default for optimal speed, so storage needs count against the memory allocation" and "A
sandbox's memory allocation covers both runtime memory and filesystem storage." The
[storage guide](https://docs.blaxel.ai/Sandboxes/best-practices) sizes the filesystem at
about half the memory allocation by default. The declaration therefore claims
`disk_in_memory: true` and no separate `disk_mib`: a request naming memory and disk is
matched against memory covering both. The cited same-change report
`reports/prober-disk-in-memory-20261115.json` (blaxel 0.4.8) passes
`coverage.facts.disk_in_memory.true`: writing 256 MiB to the root filesystem raised cgroup
shared-memory use by the written amount and returned to baseline after cleanup.

## Custom images

The `custom_images` gate declares one variant, `source: provider_artifact`: a sandbox starts
from an image already in the provider's registry, named in the create request. The
[image documentation](https://docs.blaxel.ai/Sandboxes/Templates) says “You cannot directly use
“library” container images (such as those hosted on Docker Hub and other registries) as sandbox
images. Instead, you must create one or more custom images for your sandboxes using Dockerfiles
and ensure that each image includes Blaxel’s sandbox API binary.” The conformance report
`reports/adapter-provider-artifact.json` (blaxel 0.4.8) passes `custom_images.provider_artifact`.
Other registries' OCI references and Dockerfile builds in the request stay undeclared.

## Terminal

The `terminal` gate declares one knobless variant. The
[sandbox overview](https://docs.blaxel.ai/Sandboxes/Overview) says “You can explore the contents
of a sandbox with an interactive terminal.” The conformance report `reports/adapter-default-core.json`
(blaxel 0.4.8) passes `terminal.interactive`; reattaching a lost terminal is not established.

## Idle standby: `idle_shutdown` with `on_idle: paused` — 2026-11-20

Blaxel's [sandbox overview](https://docs.blaxel.ai/Sandboxes/Overview) says a sandbox without an
active connection "automatically transitions to a warm standby mode", "in approximately 15
seconds", keeping its memory, processes and filesystem, and that reconnecting wakes it. There is no
call to enter or leave standby ([standby control](https://docs.blaxel.ai/Sandboxes/Standby-control)).
That is the spec's `idle_shutdown` with `on_idle: paused`, with no caller-chosen idle time.

The claim was declared until 2026-10-21 and withdrawn then for lack of current evidence, not because
it failed. It is declared again on a fresh native run,
[`reports/native-idle-standby-20261120.json`](reports/native-idle-standby-20261120.json) (run
`blx-idle-standby-20261120`, Blaxel SDK 0.4.8, workspace `boxrouter-internal`): the sandbox read
`active` 3 s after create and `paused` (native state `STANDBY`) 75 s later; `clean=true`, the
sandbox was deleted. Separately, benchmark trials of 2026-11-18 showed the guest uptime stop about
15 s after the last request in every 60 s and 15 min wait (6 of 6).

`auto_wake` and `custom_idle_time` stay unclaimed. The adapter reports a sleeping sandbox as
`active` (it wakes on the next request), so the claim rests on the native report.
