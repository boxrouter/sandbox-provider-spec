# Blaxel declaration scope

Reviewed 2026-10-22 against current provider documentation and committed native reports.

The [sandbox overview](https://docs.blaxel.ai/Sandboxes/Overview) documents the
4-CPU/8-GB and 6-CPU/16-GB combinations. Blaxel's [quickstart SDK example](https://docs.blaxel.ai/Get-started)
includes `memory: 4096, // in MB`. A native SDK create on 2026-10-22 in the shared
INTERNAL account with `memory=4096` reported `nproc=2` and
`/proc/meminfo` `MemTotal=4027324 kB` (about 3.84 GiB); the sandbox was deleted.
The declaration's `resources.sizes` documentation quote is copied from the
[quickstart SDK example](https://docs.blaxel.ai/Get-started):
`memory: 4096,   // in MB`.
The declaration therefore includes the 2-CPU/4096-MiB combination. Its unspecified
size remains the native default; this probe did not request a size-less create.
The native core report's `facts.sizes` row remains `not_run` and is not cited for
this allocation result.

The [process guide](https://docs.blaxel.ai/Sandboxes/Processes) says
“Use `keepAlive` to override this for the duration of a process.” The Python example
uses `keep_alive: True`; the flag suppresses standby only while that process runs.
It does not by itself establish the specification's sandbox-wide `long_running`
guarantee from creation, including intervals with no process. The driver refusals
state this scope difference rather than claiming Blaxel has no keep-alive option.
The declaration leaves `long_running` unestablished.

The reports identify `blaxel==0.4.8`, whose generated process request already
contains `keep_alive`. The current public release is 0.4.19
([package metadata](https://pypi.org/project/blaxel/)). Neither a field's presence
nor a newer SDK establishes a sandbox-wide idle-disable guarantee. After live runs resume, review the current SDK and native
creation settings; run complete native core/coverage suites before changing the
SDK identity. To establish `long_running`, a run must observe a native sandbox-wide
idle-disable setting and verify activity across idle intervals without inserting
a synthetic keep-alive workload. A process-only keep-alive test must remain scoped
to that process.

The [proxy guide](https://docs.blaxel.ai/Sandboxes/Proxy) documents secret rotation
on a running sandbox. The pinned driver's rotation mapping is unimplemented, so it
returns `not_run`, rather than treating its own missing mapping as provider absence.
The historical `rotates: false` probe caught a driver refusal without making a
rotation call. The declaration now leaves rotation unknown and no longer cites
that result. A native rotation check at the declared SDK version is required before
offering either value; existing reports remain unchanged.

Obtain the current match result locally, without provider calls:

```sh
sandbox-provider-spec match examples/requests/coding-agent.yaml providers/blaxel/declaration.yaml
```

Interpret that result with the current request, declaration and native reports;
do not append a `baseline_failed` reason that the matcher did not return.

## Custom images

The `custom_images` gate declares one variant, `source: provider_artifact`: a sandbox starts
from an image already in the provider's registry, named in the create request. The
[image documentation](https://docs.blaxel.ai/Sandboxes/Templates) says “You cannot directly use
“library” container images (such as those hosted on Docker Hub and other registries) as sandbox
images. Instead, you must create one or more custom images for your sandboxes using Dockerfiles
and ensure that each image includes Blaxel’s sandbox API binary.” The adapter report
`reports/adapter-provider-artifact.json` (blaxel 0.4.8) passes `custom_images.provider_artifact`.
Other registries' OCI references and Dockerfile builds in the request stay undeclared.

## Terminal

The `terminal` gate declares one knobless variant. The
[sandbox overview](https://docs.blaxel.ai/Sandboxes/Overview) says “You can explore the contents
of a sandbox with an interactive terminal.” The adapter report `reports/adapter-default-core.json`
(blaxel 0.4.8) passes `terminal.interactive`; reattaching a lost terminal is not established.
