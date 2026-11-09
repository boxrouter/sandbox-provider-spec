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
