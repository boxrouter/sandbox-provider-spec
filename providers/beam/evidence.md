# Beam declaration evidence

The declaration records only what a committed tester report proves. Every other value is `unknown`
or absent. All reports are one package version (`sps-provider-beam` 0.1.4, discovery digest
`sha256:db100eaf...`), run live on 2026-11-23 from the devbox through `provider-slot` with the
spec tester 0.5.84: `tester-default-baseline.json` (`--test baseline.`, clean, 18 passed),
`tester-default-core.json` and `tester-default-coverage.json` (whole selections), and
`tester-select-20261123.json` (five tests the long suites do not hold as selections).

## What the reports cover

- `processes.reattach: true`: `processes.reattach.true` (core).
- `previews`: public, not revocable, any port, at least two ports (core, coverage). Private links are not
  offered (they need the account's own API token); `link_lifetime_seconds`, `websocket`, `loopback`
  and `survives_pause` are not claimed.
- `network_lockdown`: `deny_all`, `allowlist` and `open`, names, addresses and both, wildcards, `max_allow`
  at least 32, switchable and changeable. Run with the receiver fixtures of the earlier fixture
  deployment (`allowed_ip_url` replaced by a literal-IP connectivity check); those fixtures are not
  durable, so a rerun needs them again. No denylist.
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
- `custom_images`: not offered (Beam runs every sandbox as root in `/workspace`, so BoxRouter's standard image
  cannot run).
- `terminal`, `pause_resume`, `snapshots`, `idle_shutdown`, `user_selection`, `tcp_ports`: not offered; Beam has no PTY RPC
  in its client, no pause, and no snapshot delete. `processes.input` and `processes.cancel` are not claimed.
- Coverage rows that did not pass (`differs`: arm64, sudo, other package managers, musl, memory exhaustion that
  ends the sandbox, disk in memory; `error`: `coverage.facts.max_run`) are in the committed coverage report and
  claim nothing. `network_lockdown.after_resume` is `unsupported` (no pause), and the
  `cuts_open_connections` rows are `not_run` (the connection harness recorder is stale).
