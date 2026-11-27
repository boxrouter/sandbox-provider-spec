# Beam declaration evidence

The declaration records only what a committed tester report proves. Every other value is `unknown`
or absent. Every report was run live with the spec tester 0.5.147 (the version the declaration
verifies) from a clean committed tree. All but the five size reports named below are one package version
(`sps-provider-beam` 0.1.12, package digest `sha256:7df63703...`), run on 2026-11-25, run ids
`sps-sizes-row-20261125T...-<name>`:
`tester-default-baseline.json` (`--test baseline.`), `tester-default-coverage.json` (`--test coverage.`) and
`tester-default-select.json` (five tests the long suites do not hold as selections), `tester-default-custom-images.json`
(the image tests with `oci_image` a public Debian-based Python image pinned by digest, `image_marker=Debian` and
`provider_artifact_image` the id of an image prepared by the package in the same account, deleted afterwards),
`tester-default-size-1.json` to `-8.json` (`facts.sizes`, `coverage.facts.size_is_ceiling.true` and `coverage.facts.sizes.delivered` at 1,
2, 4 and 8 vCPUs with 1024, 2048, 4096 and 8192 MiB; run 2026-11-25 with spec tester 0.5.147, run ids `sps-sizes-row-<UTC>-size<N>`), the same three tests at five more sizes in
`tester-default-size-2cpu-4gib.json`, `-4cpu-8gib`, `-8cpu-16gib`, `-16cpu-32gib` and `-32cpu-64gib` (2, 4, 8, 16 and 32 vCPUs with 4096, 8192, 16384, 32768 and
65536 MiB; run 2026-11-27 under `provider-slot` from the devbox, with the tester at its own checkout `bc4622d71f` against the package source that adds these five sizes (still
version 0.1.12 until its change entry folds in), run ids `limits-b-<UTC>-<size>`; each run's sandboxes were destroyed and its apps deleted, and a read by label then found none) and `tester-default-core.json` (the whole core selection, run from an
AWS test server so that the 1 GiB file rows run: 50 passed, 2 unsupported, 2 not_run: the two `custom_images` rows, which the core run gave no image fixtures and which are cited from the image report). The baseline, coverage, select, image and size
runs are from the devbox, under `provider-slot`; the core run is from the test server, whose tree is a fresh git commit of
the same sources.

## What the reports cover

- `processes.reattach: true`: `processes.reattach.true` (core).
- `previews`: public, not revocable, any port, at least two ports (core, coverage). Private links are not
  offered (they need the account's own API token); `link_lifetime_seconds`, `websocket`, `loopback`
  and `survives_pause` are not claimed.
- `network_lockdown`: `deny_all`, `allowlist` and `open`, names, addresses and both, wildcards, `max_allow`
  at least 32, switchable and changeable. Run with the receiver fixtures of the earlier fixture
  deployment at `*.sps-fx.boxrouter.ai`; the address rows use two plain-HTTP literal addresses of
  `checkip.amazonaws.com` (`18.205.30.165`, `18.211.156.31`, range `18.192.0.0/10`), which are not ours and can change,
  so a rerun picks fresh ones that answer 2xx without a redirect from the runner and from a sandbox. No denylist.
- `custom_images`: `provider_artifact` and `oci` with `prepared: true` (`custom_images.provider_artifact`,
  `custom_images.oci`, `coverage.custom_images.prepare.registry`; the image tests `images.v1.prepare_oci`,
  `images.v1.idempotent_prepare`, `images.v1.get_and_list` and `coverage.custom_images.prepare.idempotent`
  and `.delete` pass too). `image_config`, `image_defaults` and Dockerfile sources are not declared, and
  `coverage.custom_images.prepare.size` and `prepared_size_without_request` did not run (no `larger_size`
  fixture).
- `extendable_lifetime: true`, `default_user: root`, `default_cwd: /workspace`, `lifetime_timer`
  (provider-enforced, ends `destroyed`), `root: [by_default]`, `arch: [amd64]`, `libc: glibc`,
  `package_manager: apt`, `disk_in_memory: false`, `on_memory_exhausted: process_killed`.

## Left `unknown` or unclaimed, and why

- `kernel`, `default_size`, `max_lifetime_seconds`, `regions`, `gpus`: Beam's documentation
  (read 2026-11-25) names no runtime, gives no sandbox size range (only the Python sandbox default of 1 CPU and
  128 MiB, which is not the size Cloud creates) and no lifetime maximum. The package's
  discovery states a 24 h lifetime from live probes; that is not evidence a declaration may cite.
- `sizes` are the nine that Cloud serves, cheapest first (1/1024, 2/2048, 2/4096, 4/4096, 4/8192, 8/8192, 8/16384, 16/32768 and 32/65536 MiB). `facts.sizes` creates a sandbox at each size and
  measures the guest: it passes only when the guest shows exactly the CPUs and MiB of memory asked (the guest's cgroup
  quota and memory limit equal the request), so each of the nine reports proves one entry of the list. The account's own limits read of 2026-11-27 (128 vCPU
  and 128 GiB for one sandbox) is not cited: it is not documentation. No size above 32 vCPU and 64 GiB, and no memory-to-CPU ratio other than the 1:1 and 1:2
  listed, was run, so none is declared. Beam's own
  record of a size is not used: the package writes it from the request.
- `size_is_ceiling: true` is claimed: `coverage.facts.size_is_ceiling.true` passes at each of the nine sizes (the
  guest's cgroup quota and memory limit equal the request exactly), and `coverage.facts.sizes.delivered` passes at 2/2048 and at each of the five sizes added on 2026-11-27.
- `contract.files_1gib_roundtrip` passes in the core report (run from an AWS test server, 2026-11-25). The
  `files.stream.v1.write.1gib` and `read.1gib` rows are not in the core selection and were not run; no
  `file_stream_max_bytes` is declared.
- `terminal`, `pause_resume`, `snapshots`, `idle_shutdown`, `user_selection`, `tcp_ports`: not offered; Beam has no PTY RPC
  in its client, no pause, and no snapshot delete. `processes.input` and `processes.cancel` are not claimed.
- Coverage rows that did not pass (`differs`: arm64, sudo, other package managers, musl, memory exhaustion that
  ends the sandbox, disk in memory; `error`: `coverage.facts.max_run`) are in the committed coverage report and
  claim nothing. `network_lockdown.after_resume` is `unsupported` (no pause), and the
  `cuts_open_connections` rows are `not_run` (the connection harness recorder is stale).
