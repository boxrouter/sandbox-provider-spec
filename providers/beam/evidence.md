# Beam declaration evidence

The declaration records only what a committed tester report proves. Every other value is `unknown`
or absent. All reports are one package version (`sps-provider-beam` 0.1.4, discovery digest
`sha256:db100eaf...`), run live on 2026-11-23 from the devbox through `provider-slot` with the
spec tester 0.5.84: `tester-default-baseline.json` (`--test baseline.`, clean, 18 passed),
`tester-default-core.json` and `tester-default-coverage.json` (whole selections), and
`tester-select-20261123.json` (five tests the long suites do not hold as selections).

`tester-default-custom-images.json` is a later run (2026-11-25, package 0.1.8, discovery digest
`sha256:5d0d8796...`, spec tester 0.5.84, the version the declaration verifies, from an AWS test server, run id
`t20-beam-img-20261125T0011Z`):
`--test images.v1. --test custom_images. --test coverage.custom_images.` with `oci_image` a public
Debian-based Python image pinned by digest, `image_marker=Debian` and `provider_artifact_image` the id of
an image prepared by the package in the same account (deleted afterwards).

## What the reports cover

- `processes.reattach: true`: `processes.reattach.true` (core).
- `previews`: public, not revocable, any port, at least two ports (core, coverage). Private links are not
  offered (they need the account's own API token); `link_lifetime_seconds`, `websocket`, `loopback`
  and `survives_pause` are not claimed.
- `network_lockdown`: `deny_all`, `allowlist` and `open`, names, addresses and both, wildcards, `max_allow`
  at least 32, switchable and changeable. Run with the receiver fixtures of the earlier fixture
  deployment (`allowed_ip_url` replaced by a literal-IP connectivity check); those fixtures are not
  durable, so a rerun needs them again. No denylist.
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
  (read 2026-11-23) names no runtime, gives no sandbox size range and no lifetime maximum, and no tester
  row proves them here (`facts.sizes` needs a size fixture). The package's discovery states sizes and a
  24 h lifetime from live probes; that is not evidence a declaration may cite.
- The 1 GiB file rows (`files.stream.v1.write.1gib`, `read.1gib`, and `contract.files_1gib_roundtrip`,
  `not_run` in the core report): they need an AWS test server this devbox lacks; the reports were run with
  `file_stream_large=false`. No `file_stream_max_bytes` is declared.
- `terminal`, `pause_resume`, `snapshots`, `idle_shutdown`, `user_selection`, `tcp_ports`: not offered; Beam has no PTY RPC
  in its client, no pause, and no snapshot delete. `processes.input` and `processes.cancel` are not claimed.
- Coverage rows that did not pass (`differs`: arm64, sudo, other package managers, musl, memory exhaustion that
  ends the sandbox, disk in memory; `error`: `coverage.facts.max_run`) are in the committed coverage report and
  claim nothing. `network_lockdown.after_resume` is `unsupported` (no pause), and the
  `cuts_open_connections` rows are `not_run` (the connection harness recorder is stale).
