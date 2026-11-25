# Beam declaration evidence

The declaration records only what a committed tester report proves. Every other value is `unknown`
or absent. All reports are one package version (`sps-provider-beam` 0.1.12, package digest
`sha256:7df63703...`), run live on 2026-11-25 with the spec tester 0.5.145 (the version the declaration
verifies), from a clean committed tree, run ids `beam-reverify-20261125T...-<name>`:
`tester-default-baseline.json` (`--test baseline.`), `tester-default-coverage.json` (`--test coverage.`) and
`tester-default-select.json` (five tests the long suites do not hold as selections), `tester-default-custom-images.json`
(the image tests with `oci_image` a public Debian-based Python image pinned by digest, `image_marker=Debian` and
`provider_artifact_image` the id of an image prepared by the package in the same account, deleted afterwards),
`tester-default-size-1.json` to `-8.json` (`coverage.facts.size_is_ceiling.true` and `coverage.facts.sizes.delivered` at 1,
2, 4 and 8 vCPUs with 1024, 2048, 4096 and 8192 MiB) and `tester-default-core.json` (the whole core selection, run from an
AWS test server so that the 1 GiB file rows run: 52 passed, 2 unsupported). The baseline, coverage, select, image and size
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

- `kernel`, `sizes`, `default_size`, `max_lifetime_seconds`, `regions`, `gpus`: Beam's documentation
  (read 2026-11-25) names no runtime, gives no sandbox size range (only the Python sandbox default of 1 CPU and
  128 MiB, which is not the size Cloud creates) and no lifetime maximum. `facts.sizes` is `not_run` with
  `driver_unimplemented` (the stated-facts driver has no allocation observation), so no row proves a size list. The package's
  discovery states four sizes (1/1024, 2/2048, 4/4096 and 8/8192 MiB) and a 24 h lifetime from live probes; that is
  not evidence a declaration may cite.
- `size_is_ceiling: true` is claimed: `coverage.facts.size_is_ceiling.true` passes at each of the four sizes (the
  guest's cgroup quota and memory limit equal the request exactly), and `coverage.facts.sizes.delivered` passes at 2/2048.
- `contract.files_1gib_roundtrip` passes in the core report (run from an AWS test server, 2026-11-25). The
  `files.stream.v1.write.1gib` and `read.1gib` rows are not in the core selection and were not run; no
  `file_stream_max_bytes` is declared.
- `terminal`, `pause_resume`, `snapshots`, `idle_shutdown`, `user_selection`, `tcp_ports`: not offered; Beam has no PTY RPC
  in its client, no pause, and no snapshot delete. `processes.input` and `processes.cancel` are not claimed.
- Coverage rows that did not pass (`differs`: arm64, sudo, other package managers, musl, memory exhaustion that
  ends the sandbox, disk in memory; `error`: `coverage.facts.max_run`) are in the committed coverage report and
  claim nothing. `network_lockdown.after_resume` is `unsupported` (no pause), and the
  `cuts_open_connections` rows are `not_run` (the connection harness recorder is stale).
