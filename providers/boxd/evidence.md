# boxd declaration evidence

boxd is declared from its Python SDK 0.2.22 (the service's own documented API) and the
`boxrouter-boxd` Core adapter's fake-backed offline conformance run on 2026-11-02.

- `resources.kernel`: the SDK creates full machines (`machines.create`, wait_until_ready,
  exec) — boxd machines are VMs on a dedicated cluster.
- `resources.sizes` / `resources.default_size`: the SDK's own sizing table offers four
  machine sizes, all offered. Live 2026-11-02 (`run=boxd-slice2-20261102-090528`), one machine
  at a time: `nproc`/`free -m` read 1/3938, 2/7964, 4/16015 and 8/32119 MiB; boxd refuses any
  other pair (`2 vCPU with 4 GiB is not a supported machine size`).
- `resources.regions` / `resources.located_in`: SDK 0.3.0 supports explicit native `fra` and
  `nyc` region selection. On 2026-11-03, `regions.list()` returned Frankfurt and New York,
  both enabled; one labelled 1-vCPU/4-GiB VM per region passed create, readiness, get, command,
  region-scoped inventory and delete (`run=boxd-regions-20261103t215800z-1e476a`). Both
  exact-label inventories were empty after cleanup. The registry maps them to `boxd:eu-fra`
  in Germany and `boxd:us-nyc` in the United States. Account operations and billing stay at
  the home API. This is native regional feasibility evidence, not a fresh Core/hosted
  conformance report. `verified.sdks` still describes the retained gate reports' 0.2.22
  SDK; those immutable reports were not rewritten. An immediate New York usage lookup
  returned not-found; finalized post-delete attribution remains to be verified after the
  documented metering delay. The account's 100-machine limit per region is not a provider
  capability limit and is not added to this declaration.
- `resources.max_lifetime_seconds`: the SDK accepts `auto_destroy_timeout` on create; the
  adapter sends the requested lifetime on every create and its conformance fixture requests
  900 seconds. The exact server admission ceiling above the tested fixture value is not yet
  proven.
- Every field left `unknown` has no committed report or documentation read yet; the SPS
  rules keep them unknown rather than guessed.

Live contract evidence (a single INTERNAL smoke run) is reported in the boxd slice-1
adapter report in the Core workspace; committed run reports land with the launch slice.

- `x-boxd.isolated`: every BoxRouter create sends `isolated=True`. Proven live under
  `run=boxd-usage-20261102T1424Z`: an isolated machine keeps public HTTPS egress and DNS,
  runs commands and round-trips files, and its in-VM metadata token endpoint
  (`$boxd_gateway:9002/v1/auth/token`) is unreachable. The un-isolated alternative carries
  an in-VM credential that can create machines billed to the org.
- `x-boxd.usage_records`: `machines.usage(id)` answers after delete with boxd's own
  `cost_micro` and `complete` finality; the adapter's `read_cost`/`read_usage` carry the
  record verbatim under `boxd.machines.usage`, and `read_account_usage` reads the org's
  24-hour total. Proven live under `run=boxd-usage-20261102T1455Z`.
- `gates.network_lockdown`: boxd's egress allowlist is set from birth through the machine spec
  (`egress`), so nothing in the machine runs before it holds. The committed adapter-identity
  report `reports/adapter-default-network-lockdown.json` (boxrouter-boxd 0.1.3, boxd 0.2.22,
  SPS 0.3.155 suite, run `spec-run-20261102T093014Z-a212`) passes `allowlist.names`,
  `wildcards` and `max_allow` (32 entries; boxd itself accepts 256 and refuses 257).
  Not declared: `deny_all` (boxd's `none` blocks names, addresses and DNS live, but a refused
  HTTPS connection reads as a TLS failure, which the suite reports as ambiguous: `not_run`);
  `addresses` entries (an IPv4 literal was unreachable over HTTPS even with no policy);
  `after_resume` (pause is not offered); `changeable`/`switchable` (no report).
