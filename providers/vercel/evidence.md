# Vercel declaration scope

Reviewed 2026-10-22 against current public documentation and the committed native reports.

## SDK identity

The [Python SDK reference](https://vercel.com/docs/sandbox/python-sdk-reference)
says “Install the Vercel Python package” and shows `uv add vercel` and
`from vercel.sandbox import sync as sandbox`. The committed reports instead identify
`vercel-sandbox==0.9.0`. Retaining that exact historical identity does not establish
conformance for the newer distribution or API. After live runs resume, migrate the
driver to the documented `vercel` API and produce complete native core and coverage
reports, including all baseline tests, before changing `verified.sdks` or its pin.

## Plan limits

The [pricing page](https://vercel.com/docs/sandbox/pricing) says
“Each vCPU includes 2 GB of memory.” Its plan table limits Hobby to 4 vCPUs,
Pro to 8 and Enterprise to 32. Valid counts are 1 and even counts from 2 to 32.
The declaration retains the 1/2/4-vCPU configurations available on every plan.
Pro additionally offers 6/8 vCPUs; Enterprise adds even counts from 10 through 32.
These larger combinations stay here because `needs` conditions a whole sizes list.

That table documents a maximum of 15 open ports on every plan. The native
`previews.listed_ports` result proves only `{at_least: 2}`. Preview variant knobs
require test evidence, so the declaration retains that proven lower bound.
A native run must expose and exercise fifteen distinct listed ports before raising it.

## Lifecycle and working directory

The [persistence guide](https://vercel.com/docs/sandbox/concepts/persistent-sandboxes)
says “Persistent sandboxes automatically save their filesystem state when stopped
and restore it when resumed.” The historical core report passes
`lifetime_timer.at_end.stopped`; the declaration records both proven outcomes,
`destroyed` and `stopped`, with that report cited for each. The declaration vocabulary
permits `stopped` even though creation requests currently select `destroyed` or
`paused`. The same report marks `lifetime_timer.at_end.paused` unsupported. A native
run using the current SDK must establish the `paused` contract before offering it.

The historical `facts.default_cwd` row proves `/vercel` for its tested environment.
The [image documentation](https://vercel.com/docs/sandbox/concepts/images) says
“If the Dockerfile defines `WORKDIR`, new commands start in that directory.”
The older overview's `/vercel/sandbox` statement does not establish a universal
default for the tested environment. Omit the unqualified fact rather than substitute
a documentation value for a native observation. The next native default-environment
run must identify its image and SDK and observe `pwd` without a caller workdir override.

## Custom images

The `custom_images` gate declares one variant, `source: provider_artifact`: a sandbox starts
from an image already pushed to the provider's registry, named in the create request. The
[image documentation](https://vercel.com/docs/vercel-sandbox/concepts/images) says “Sandbox
pulls images from Vercel Container Registry (VCR)” and “When you pass an image to
`Sandbox.create()`, Vercel resolves the reference against VCR and boots the sandbox from that
image's filesystem.” The adapter report `reports/adapter-provider-artifact.json`
(vercel-sandbox 0.9.0) passes `custom_images.provider_artifact`. OCI references from other
registries and Dockerfile builds stay undeclared: the native core report leaves OCI
preparation `not_run` and reports Dockerfile preparation as `unsupported`.

## Terminal

The `terminal` gate declares one knobless variant. The
[SDK reference](https://vercel.com/docs/vercel-sandbox/sdk-reference) says
“`sandbox.openInteractive()` opens interactive access, resuming the sandbox if needed. It returns a
WebSocket URL and token for connecting your WebSocket client to a controller-hosted PTY.” The
adapter report `reports/adapter-default-core.json` (vercel-sandbox 0.9.0) passes
`terminal.interactive`; reattaching a lost terminal is not established.
