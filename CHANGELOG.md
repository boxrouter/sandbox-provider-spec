# Changelog

Notable changes to the specification and its tools. [GOVERNANCE.md](GOVERNANCE.md#versioning)
says what each kind of release may change.

## Unreleased

- 0.5.8: Boxd's SPS reports (prober core, coverage, user-selection, disk-in-memory, snapshot, default and the size-ceiling copy) rerun live on adapter-boxd 0.1.123. No claim, vocabulary or conformance-suite change.
- 0.5.7: Modal's two declarations (default and vm) are re-dated to 2026-11-18 for the rerun of its reports on adapter-modal 0.4.280, which claims `custom_images` `image_defaults` in its own adds. No claim, vocabulary or conformance-suite change in the declarations.
- 0.5.6: E2B's declaration claims `custom_images` `image_defaults` on its Dockerfile variant and on its provider-artifact variant (a prepared image reaches create as an artifact), proved by `coverage.custom_images.defaults.dockerfile` in a clean live run on adapter-e2b 0.4.312, and is re-dated to 2026-11-18. No vocabulary or conformance-suite change.
- 0.5.4: Vercel's declaration is re-dated to 2026-11-18 for the rerun of its prober reports on adapter-vercel 0.5.269. No claim, vocabulary or conformance-suite change.
- 0.5.2: Daytona's container class declares `custom_images` `image_defaults` on its Dockerfile variant and on its provider-artifact variant (a prepared image reaches create as an artifact) and its prepared OCI variant, proved by `coverage.custom_images.defaults.dockerfile` and `coverage.custom_images.defaults.registry` in a clean live run on adapter-daytona 0.5.331. No vocabulary or conformance-suite change.
- 0.5.1: Rename the three image-defaults coverage rows to `coverage.custom_images.defaults.dockerfile`, `coverage.custom_images.defaults.distro_dockerfile` and `coverage.custom_images.defaults.registry`, so that no row id is a prefix of another (a `--test` names a prefix, and `prepare.registry` also ran `prepare.registry_defaults`). The coverage suite changes; the 0.5.0 suite is recorded in `conformance/historical-suite-rules.json` so its reports remain recognized. No vocabulary or rule changed.
- 0.5.0: Add the `custom_images` knob `image_defaults` (yes/no) and the rule `custom_images/image-defaults`: an ordinary image, whatever its source, runs commands and processes that name no directory or user with its own environment variables, in its working directory and as its user, with no `image_config` in the request; a provider that cannot apply one of them for an image refuses it before creating anything. Add three additive coverage rows that check it without the explicit knob: `coverage.custom_images.prepare.dockerfile_defaults` (a prepared Dockerfile on `python:3.12-slim` with `ENV`, `WORKDIR` and `USER 1001`), `coverage.custom_images.prepare.dockerfile_distro_defaults` (the same on `ubuntu:24.04`, for routes that only take the system they run) and `coverage.custom_images.prepare.registry_defaults` (the grafana image: `GF_PATHS_HOME`, `/usr/share/grafana`, uid 472). No existing check digest changes; the previous coverage suite (`sha256:4eca18f6...`) is recorded in `conformance/historical-suite-rules.json` so its reports stay recognized. No declaration changes: a provider claims `image_defaults` in its own `adds` when a clean run of these rows passes. Motivation: `image_config` is explicit-only and the hosted request cannot name it, so E2B Dockerfile ENV, Boat WORKDIR and USER, Modal USER and Boxd numeric USER were silently dropped until the 2026-11-18 image audit; no row would have caught it.
- 0.4.77: Daytona's container class declares `custom_images` `image_config` (env, workdir, user) on its prepared OCI image variant, proved by `coverage.custom_images.prepare.image_config.{env,workdir,user}` in a clean live run on adapter-daytona 0.5.325. No vocabulary or conformance-suite change.
- 0.4.64: Enforce only explicit `date` and `date-time` formats through the same stable checker in
  declaration and HTTP binding validation. Optional URI validators no longer affect SPS results.
  No vocabulary or conformance-suite change.
- 0.4.63: Agent37's VM declares `disk_in_memory: false` from its existing passing
  `coverage.facts.disk_in_memory.false` row. No vocabulary or conformance-suite change.
- 0.4.60: Boxd publication back to hidden until tonight's full run ends (founder 2026-11-16, approvals founder-2026-11-16-boxd-hide-until-run and founder-2026-11-16-boxd-default-hide-until-run); it is republished with graduation receipts from that run. No vocabulary or conformance-suite change.
- 0.4.59: Daytona's `adapter-container-user-selection.json` rerun live on adapter-daytona 0.5.317. No vocabulary or conformance-suite change.
- 0.4.57: Refresh Blaxel's size-ceiling, default coverage, disk-in-memory, and user-selection reports from the clean spec runs in certification run 43820005571. The default-core report was not adopted because its terminal cleanup failed. No vocabulary or conformance-suite change.
- 0.4.56: Boxd declares `resources.disk_in_memory: false` and named runner-user capabilities with cited evidence. No vocabulary or conformance-suite change.
- 0.4.55: Superserve's SPS reports (adapter copies of the packaged runs, adapter-defaults, size ceiling, prober core and coverage) rerun live on adapter-superserve 0.1.17; the prober core report now passes `idle_shutdown.on_idle.destroyed`. No vocabulary or conformance-suite change.
- 0.4.53: Boxd's default benchmark class is published under the 2026-11-16 founder approval. No vocabulary or conformance-suite change.
- 0.4.51: Boxd's SPS reports (default, size ceiling, prober core and coverage, snapshot) rerun live on adapter-boxd 0.1.107. No vocabulary or conformance-suite change.
- 0.4.48: Boat's five SPS reports (processes, size ceiling, user selection, prober core and coverage) rerun live on adapter-boat 0.3.87. No vocabulary or conformance-suite change.
- 0.4.40: Agent37 declares `processes` (input, cancel, reattach) from same-change core reports; its VM class declares `user_selection` (commands, files_write, process_start) from `coverage.guest_user.selectable`. No vocabulary or conformance-suite change.
- 0.4.37: Boat declares `processes` (input false, cancel, reattach) and `user_selection` (commands, files_write, process_start) with same-PR reports that certify the adapter behavior; the adapter no longer adds `processes` on its own. No vocabulary or conformance-suite change.
- 0.4.52: Modal declares certified process reattachment for its default and VM classes, and the VM class declares named-user command, file-write, and process-start support using `coverage.guest_user.selectable`. No vocabulary or conformance-suite change.
- 0.4.33: Blaxel declares `user_selection` for commands, file writes and process starts, with a clean same-PR report. No vocabulary or conformance-suite change.
- 0.4.32: Vercel declares `user_selection` (commands, files_write, process_start) with a same-PR report that certifies the adapter behavior. No vocabulary or conformance-suite change.
- 0.4.31: E2B declares `user_selection` (commands, files_write, process_start) with a same-PR report that certifies the adapter behavior. No vocabulary or conformance-suite change.
- 0.4.30: Blaxel declares `disk_in_memory: true`, proved by a clean same-change
  `coverage.facts.disk_in_memory.true` report (writing 256 MiB to the root filesystem
  raised cgroup shmem by the written amount). Blaxel's documentation states sandbox
  filesystem storage is in memory by default, sized at about half the memory
  allocation. A request naming memory and disk is matched against memory covering
  both: an Actions runner ask for 8,192 MiB of memory and 8,192 MiB of disk now
  fits the declared 6-CPU/16,384-MiB size instead of refusing `resource_mismatch`.
  No vocabulary or conformance-suite change.
- 0.4.29: Preserve a requested `size_is_ceiling` fact in the matcher output so adapter planners can honor the validated size ceiling. No vocabulary or conformance-suite change.
- 0.4.28: Preserve a requested `size_is_ceiling` fact in the matcher output so adapter planners can honor the validated size ceiling. No vocabulary or conformance-suite change.
- 0.4.26: Daytona's container class declares `user_selection` (commands, files_write, process_start), proved by `coverage.guest_user.selectable` in a same-change report. No vocabulary or conformance-suite change.
- 0.4.21: `coverage.guest_user.selectable` reads the two files it made back by running `cat` as the named user, where it read them through the file API as the default user. The file is private to the named user (mode 0600) and a provider whose file API runs as a non-root default user cannot read it; the check proves the bytes written, not that the file API is root. The knobs and rules are unchanged. The check's digest changes, so earlier reports of it need a rerun; the coverage suite this replaces is recorded in `conformance/historical-suite-rules.json`.
- 0.4.20: Prefix `guest_user.selectable` as `coverage.guest_user.selectable` so adapter evidence
  planning selects the coverage suite. Record the previous suite digest in
  `conformance/historical-suite-rules.json` so its existing reports remain recognized. No rule
  or catalog changed.
- 0.4.18: the specification is distributed from its GitHub repository only. The unused package-index
  publishing workflow, its test and the README build hook for it are removed; every install command in
  the README, the guides and the `serve` and `test` hints is `uvx --from git+https://github.com/boxrouter/sandbox-provider-spec`
  (or `pip install` of the same address), and a test refuses any other install form. No rule, declaration,
  catalog or suite change.
- 0.4.13: the network checks' runner-side requests to the receivers (the control request and the
  recorder read in `coverage_network_probe.py`) are tried up to three times, pausing 1 s and then
  3 s, after a timeout, a TLS handshake failure, a connection reset or a 5xx. A 4xx, a certificate
  that does not verify and any other failure end at once. Each control try sends its own token. The
  sandbox's own reach probes are never retried, because there a timeout is the result. After the
  last try the row is still `not_run` with the same reason (`network_control_unavailable` or
  `network_receiver_observer_unavailable`), and its detail names the call, the number of tries and
  the cause, for example `runner observer request (3 tries): TimeoutError: ...`. No declaration,
  catalog or suite change.
- 0.4.12: `guest_user.selectable` starts from the provider's default image and creates its user there (`useradd`, under `sudo -n` when the guest user is not root), instead of building a `python:3.12-slim` Dockerfile. A provider that takes no Dockerfile, or only its own base image, can now reach the user-selection checks; the three knobs and their rules are unchanged. The check's digest changes, so earlier reports of it no longer count for it; the coverage suite that this replaces is recorded in `conformance/historical-suite-rules.json` so reports of every other coverage test stay recognized.
- 0.4.11: a gate the declaration does not list is refused with 'previews: this route does not list it, so it is not offered' instead of 'not declared; nobody has looked'. Wording only; no rule, declaration, schema or catalog change.
- 0.4.10: test-only. The locked-create store test no longer depends on a 50 ms scheduling window: a worker thread that a starved host schedules after its request's deadline frees its slot without touching the store, so `pending` fell below 8 (seen as 7, 5 and 4 on a one-core starvation repro, and in the SPS mirror export's standalone check). It uses a 1 s deadline and keeps its blocked store calls blocked for the nine seconds that takes (a 300 s sqlite busy timeout for that endpoint instead of 10 s). No rule, declaration, schema or catalog change.
- 0.4.9: every refusal fix the matcher's request check gives is now an instruction with a verb ('Set requirements.tcp_ports.tls to "any".'), where it was a JSON fragment (a quoted key and value) or a bare 'leave it out'. Wording only; no rule, declaration, schema or catalog change.
- 0.4.8: a request with no lifetime (lifetime_seconds: null) that a route cannot honor says what the route does instead ('this route ends every sandbox after at most 86,400 s') in place of the 'lifetime_timer declared, max_lifetime_seconds unlimited' sentence. Wording only; no rule, declaration, schema or catalog change.
- 0.4.7: a size refusal reads 'The request needs 1,000 CPU; the largest size offers 8.', and a lifetime refusal states the most (or least) a route allows in seconds instead of 'declared max_lifetime_seconds' and 'lifetime_timer min_seconds'. Wording only; no rule, declaration, schema or catalog change.
- 0.4.6: a refused account limit says what the account allows ('this account allows at most 3,600 s') and no longer names the declaration's condition. Wording only; no rule, declaration, schema or catalog change.
- 0.4.5: the matcher's size refusal names the ask no size can hold and the most a size offers ("needs 1,000 CPU; the largest size offers 8."), or says that no single size holds all asks, instead of printing the asks as a Python dict. Wording only; no rule, declaration, schema or catalog change.
- 0.4.4: Boat’s verification date advances to 2026-11-15 for the committed local prober reports; declared capability values are unchanged.

- 0.4.3: Boxd declares native deny-all egress (`none`) after a Cloud API probe through the
  adapter blocked direct-IP HTTPS and an unlisted host and confirmed deletion. No catalog or
  suite change.
- 0.4.1: the `lifetime_timer` row of `spec/declarations.md` and the matcher's no-lifetime message
  say "the router" instead of the product name, which the public-neutrality test refuses in
  distributed prose. Wording only; no rule, declaration, schema or catalog change.
- 0.3.234: the report tests' `document` helper takes a `Sequence` of results, which is what
  `report` accepts, so the package's mypy passes again. Test typing only; no rule, test,
  declaration or catalog change.
- 0.3.233: Boxd declares native snapshots and queries the adapter-declared regions for account
  inventory. Snapshots retain files and memory, can be deleted, and leave the source's post-capture
  state unknown. No catalog or conformance change.
- 0.3.226: adds `docs/implement.md`, "Implement SPS 1.0", the one page that takes a provider from nothing to a passing tester: the two ways to conform (an adapter or a native API), the eleven required operations, discovery and prices, cost, errors, the template adapter, the manifest, the tester, the optional sections and versioning. The README is rewritten to lead with it and is 150 lines. No rule, test, declaration or catalog change.
- 0.3.210: deletes what the 1.0 provider API supersedes: the HTTP binding 0.1 to 0.3 text (`spec/binding-http.md`), its OpenAPI file, the installed Docker backends and starter of `http_reference`, the binding's type module, generator and example files, and the guides `docs/http-binding-reference.md` and `docs/how-to/run-http-conformance.md`, with the tests that covered only those. `http_binding_validation`, `spec/http-binding.schema.json` and the in-memory `http_reference.Endpoint` stay until Cloud's own HTTP tests move to 1.0. No declaration or catalog change.
- 0.3.208: adds the ten `contract.` tests of the 1.0 provider API to `conformance/suite.yaml` (discovery, idempotent create with the same and another body, the label filter, `not_found` codes, `unsupported` requests, the command timeout, a 1 GiB round trip, repeated destroy, final cost), and the driver steps they use. The tester selects every one of them for every provider; `--quick` leaves out the 1 GiB round trip and the final-cost wait. `baseline.process_eof_is_not_exit` and `lifetime_timer.at_end.destroyed` also name `provider-api/process-eof-not-exit` and `provider-api/lifetime-enforced`, and the reference server's tests name the four rules about credentials and unknown fields, so the 18 waivers of the `provider-api` rules in `untested.yaml` are removed. The outgoing suite digests are recorded in `historical-suite-rules.json`. No declaration or catalog change.
- 0.4.0 adds `router` as a `lifetime_timer.enforced_by` value. Router timers must count paused
  time and destroy at expiry; the matcher only accepts finite create requests whose requested end
  is destruction.
- Blaxel's brand files record where they came from (`providers/blaxel/brand/sources.yaml`: the live site's X symbol, the archived brand-page terms). Provenance only; no mark, declaration or catalog change.
- 0.3.209: the `file_links.v1.*` and `files.stream.v1.*` checks (file links and streamed transfer, including the 64 MiB, 1 GiB and 5 GiB rows) are opt-in. A run executes them only with `--opt-in streamed_transfer`; `--suite coverage` and `--test` leave them out, and naming one in `--test` without the option is refused. `file_links` and `file_stream_max_bytes` stay optional declarations. No check, rule, declaration or catalog change, so no digest moves.
- 0.3.201 carries the prober's first live report `prober-default-core` under `providers/e2b/reports/`. No declaration or catalog change.
- 0.3.200: `spec/provider-api.md` holds the normative rules of the provider API 1.0 (18 rules under the `provider-api` topic), and `check-rules` reads it. `spec.md` now says that prices and per-sandbox cost belong to the provider API; speed and reliability stay undeclared. The 18 rules are waived in `untested.yaml` until the 1.0 contract tests name them. No declaration or catalog change.
- 0.3.199: adds `spec/provider-api-1.0.openapi.yaml`, the OpenAPI 3.1 file for the 1.0 provider API (20 operations, the twelve error codes with their fault), with one example per schema under `spec/provider-api-1.0-examples/`. No declaration or catalog change.
- 0.3.198: `brand.yaml` takes an optional `attribution` (a statement of at most 1000 characters that a brand's rules require wherever its mark is shown), carried in `brand.json`. Vercel declares its statement. Additive; no declaration or catalog change.
- 0.3.197: Daytona's and Vercel's brand marks are the providers' official SVG symbols (`brand/mark.svg`; `mark.png` is removed), so every provider's mark is a vector file that web can flatten to its one-colour benchmark mark. Both stay one-colour (no `mark_colours`) and draw at the sizes their PNGs did. No declaration or catalog change.
- 0.3.196 carries adapter-modal 0.4.247's recertified reports `adapter-default-core`, `adapter-default-size-ceiling` and
  `adapter-vm-size-ceiling` under `providers/modal/reports/`. No declaration or catalog change.
- 0.3.195 republishes 0.3.194's contents with adapter-superserve 0.1.7's recertified reports under
  `providers/superserve/reports/`. Those reports changed under 0.3.194 after it was published (cloud#6090), so one
  version had two contents. No declaration or catalog change.
- Superserve declares what its adapter's committed reports prove: `processes` (`input: true`, `cancel: true`,
  `reattach: false`), `network_lockdown` (an allowlist of names and addresses with wildcards, and a switch between
  an allowlist and open), `custom_images` (`oci` prepared, `provider_artifact`, neither running an image's
  entrypoint) and a provider-enforced `lifetime_timer` that destroys at its end. Each value cites the adapter's
  report, committed beside the declaration. No catalog change.

- Add one coverage row, `coverage.custom_images.prepare.dockerfile_standard_base_context`: a prepared Dockerfile whose base is the provider's own standard image (the runner fixture `standard_base_dockerfile` holds its `FROM` and four `COPY`/`ADD` lines) copies a text file and a byte-exact binary, adds a plain file and unpacks a compressed local tar carried under a non-tar name, and every marker is read back byte-exact. It proves `source: dockerfile`, `prepared: true` and `build_context: true` only. A provider that accepts a Dockerfile only on its standard image (Boxd) has no other way to prove build context; `coverage.custom_images.prepare.dockerfile_distro_context` is unchanged and still runs on providers that accept a named distribution base. The row is additive: no existing check digest changes. The coverage suite it replaces (`sha256:3756d977…`, 154 ids) is recorded in `conformance/historical-suite-rules.json`, so reports of it stay recognized. No declaration or catalog change.

- Boat declares its disk: `disk_mib: 48637` on each size and provider-wide, and `disk_in_memory: false`. The
  documentation's machine table gives every offered size 51 GB of disk in its own column, read as decimal
  gigabytes (the lower reading); a live stock machine (2026-11-11) showed a 78 GiB root with 54 GiB free. A
  request that names memory and disk is now matched against each separately, so a 4 vCPU, 8192 MiB machine
  with an 8192 MiB disk floor fits Boat's `default` size. `disk_in_memory: false` cites a certifying
  `coverage.facts.disk_in_memory.false` report from the Boat adapter.

- Agent37 gains `declaration-vm.yaml`, its `vm` class (a dedicated kernel; the same four shapes; regions
  `agent37:us`, `agent37:eu` and `agent37:ap-south`; the default class's `network_lockdown`),
  with five reports on that class. The region registry lists the three Agent37 regions with their countries.
- Brand files: Agent37 has `providers/agent37/brand.yaml` and `brand/` (the symbol from agent37.com, `order: 7`, no `launched`
  until it is offered in the legal roster), so `brand.json` carries its logo and mark. `brand.yaml` accepts an optional
  `mark_colours: own`, shipped in `brand.json`, which says the mark file is drawn in the brand's own colours; without it a
  mark is one colour. Boat (blue `#5B74E0`), E2B (Fire Orange `#FF3001`, now `brand/mark.svg`; `mark.png` is removed) and
  Modal (its green 3D logo, now both `logo` and `mark`; `brand/mark.svg` is removed) set it. Each provider's
  `brand/sizes.yaml` records its mark's drawn size in a 16 px box. `tests/test_provider_brand.py` fails when a provider
  Cloud serves has no mark, when a coloured mark holds an `<image>`, a rect over the viewBox, a white fill or a filter, or
  when a mark draws more than 1 px from its recorded size. No declaration or catalog change.

- `coverage.network_lockdown.switchable.true` and `coverage.network_lockdown.policy_transition.denylist` no longer
  fail at random. Each `fixture.coverage_policy_change` call starts its own idle-activity heartbeat, and the first call's
  heartbeat kept running and rewrote the shared `/tmp/sps-idle-activity.json` under its own pid, so the second call
  compared two pids about half the time. Each call's heartbeat now writes its own file (`idle_activity.py` takes the
  path as its argument). The check digests of every check that runs `coverage_network.py` change.

- E2B and Agent37 declarations: `verified.date` 2026-11-12 (E2B) and 2026-11-13 (Agent37), so their SHA-256 changes. The
  cited network-lockdown reports were re-run live because the heartbeat change above changes their check digests: E2B
  `native-default-core` (17 passed) and Agent37 `network-lockdown`, `network-lockdown-addresses` and
  `network-lockdown-coverage` (7 passed, including `coverage.network_lockdown.switchable.true`).

- Modal and Blaxel declarations: `verified.date` 2026-11-12 (modal `declaration.yaml` and
  `declaration-vm.yaml`, blaxel `declaration.yaml`), so their SHA-256 changes. The #5148 evidence
  lane refreshed the cited live reports on that date: `native-default-core` (ModalDriver 0.3.189
  for modal, BlaxelDriver 0.3.189 for blaxel) and the adapter-side certify reports
  (`adapter-default-core`, size-ceiling, provider-artifact) under `providers/modal/reports/` and
  `providers/blaxel/reports/`.
- Daytona container declaration: `verified.date` 2026-11-12. Kit #5312 refreshed the Daytona reports on that date; the date moves with them so the reports are not newer than the declaration they cite. No behaviour change.
- Agent37's declaration states its four shapes in `resources.sizes` (2 vCPU / 4096 MiB, 4 / 8192,
  4 / 16384 and 4 / 32768, each with the disk a create that names none gets), `default_size`
  2 / 4096 / 4096 and `size_is_ceiling: true`, so its SHA-256 changes. A live probe showed Agent37's
  "GB" is a GiB; `size_is_ceiling` rests on the new report `adapter-default-size-ceiling.json`.

- A run on a provider with no lifetime timer may set `file_transfer_lifetime_seconds` to null: the
  file-link and 1 GiB/5 GiB stream checks that request that lifetime then send creates that name no
  lifetime, so they run instead of ending `not_run`. coverage.yaml is unchanged, and a run that sets
  a number (or leaves the default 600) sends the same creates as before. The check digests of the
  file-link and stream checks change, because `coverage_file_transfer.py` changed.

- Agent37's declaration moves `verified.date` to 2026-11-12, so its SHA-256 changes. Its cited report
  `adapter-defaults.json` is re-certified live against boxrouter-agent37 0.1.3, whose `provider.py` changed
  (`facts.default_cwd`, `facts.default_user`). It is re-certified again against 0.1.4, whose `guest.py`
  changed for streamed transfers, and against 0.1.5, whose `provider.py` prepares the standard image.

- A report run before 0.3.182 stopped naming `lifetime_seconds` in 76 coverage creates still stands
  for those checks where a run now sends the same create. New `src/sandbox_provider_spec/lifetime.py`
  owns `DEFAULT_LIFETIME_SECONDS` (300): the lifetime a create that names none asks for on a provider
  with a lifetime timer. Every native driver now sends it (E2B, Modal, Vercel and Daytona sent 120 s, so
  0.3.182 had shortened their runs of these tests from 300 s), and an adapter's own default can read it.
  `conformance/historical-create-lifetimes.json` records the number each of those creates named, and
  `check_digests.historical_check_digest` (formerly `historical_rule_digest`, which restored only rule
  labels) restores it when it equals the `create_lifetime` the caller's driver sends for a create that
  names none. The 64 checks that named 300 s qualify on providers with a timer; the 12 network-lockdown
  checks that named 600 s never do. Check digests are unchanged.

- `providers/boxd/publication.yaml` holds Boxd hidden again (founder reversal 2026-11-12, "not put boxd for now"): it
  withdraws the 0.3.184 decision to publish Boxd's default route, so `publication.json` keeps Boxd out of every benchmark
  page build. Adopt 0.3.185, not 0.3.184.

- `conformance/historical-suite-rules.json` records the coverage suite that 0.3.182 replaced
  (`sha256:f79f539d…`), as the conformance rules require for any suite change. Without it, reports of
  that suite read "report suite digest is not recognized", including Boat, Daytona, E2B and Vercel
  baseline reports whose checks did not change. A new test refuses an active hosted report whose suite
  this package does not recognize.

- Coverage tests no longer name an incidental `lifetime_seconds` in their create steps: 76 tests
  (the facts, previews, desktop, terminal, network-lockdown, hidden-secrets, custom-image and
  regular-write tests, and the 64 MiB streams) create with the lifetime the run gives its fixtures.
  A provider with no lifetime timer can now run them; before, its create was refused. A coverage create
  names a lifetime only when its test proves a lifetime fact, or when its own work outlasts the default
  (the two 5 GiB streams); `tests/test_create_lifetime.py` enforces this. The changed tests have new
  check digests. The cited reports that ran them are re-certified live: Boxd `adapter-terminal-coverage` and
  `adapter-default-size-ceiling`, Daytona `adapter-container-custom-images-oci` and
  `adapter-container-size-ceiling`, and Modal `adapter-default-size-ceiling` and `adapter-vm-size-ceiling`, all
  passing. Modal's two declarations move `verified.date` to 2026-11-11, so their SHA-256 changes.

- Agent37 declares its default class (`providers/agent37`): no lifetime timer and
  `max_lifetime_seconds: unlimited` (it serves only `lifetime_seconds: null`), `located_in: [US]`, and its
  default image's user `node` and directory `/home/node`, each cited from Agent37's documentation or a
  committed adapter report. Everything else is `unknown`.

- A request may set `lifetime_seconds: null`: a sandbox with no lifetime, which runs until the caller
  destroys it. New rule `matching/no-lifetime`: such a request fits only a declaration with no
  `lifetime_timer` block and `resources.max_lifetime_seconds: unlimited`, and is refused before
  matching (`setting`) when it also names `at_end`; `sandbox-provider-spec check` reports that as
  `at_end with a null lifetime_seconds`. A request with a number is matched as before.

- The catalog, check-digest and evidence readers share one strict parse per file content, using libyaml
  when it is installed. `sandbox-provider-spec check` on one declaration parses `suite.yaml` and
  `coverage.yaml` once instead of about ten times. Evidence now reads the packaged suites with the strict
  loader too, so a duplicate key there is reported as an invalid suite. Check digests are unchanged.

- Boat declares `located_in: [DE, FI, FR]`, cited from its compliance page (read 2026-11-10): sandboxes run on
  machines in Germany, Finland and France. Snapshot copies the page says can be stored outside the EU are
  storage, not where a sandbox runs.

- Boxd declares `gates.terminal` with `reattach: true`, with certifying `terminal.interactive` and `coverage.terminal.reattach` reports from the Boxd adapter against release 0.3.177 (`verified.date` 2026-11-09). This is the terminal declaration deferred from 0.3.177.

- Rebuilt 0.3.177 without the Boxd terminal declaration and supersede 0.3.176. Cloud #4630 (`47d6d712d`) declared `gates.terminal` before its certifying reports existed, so the standalone check failed. The declaration, its evidence and the reports are deferred to 0.3.178.

- Boat's `lifetime-at-end.json` report is rerun on the current adapter (0.3.48) and spec suite (0.3.174); `lifetime_timer.at_end.destroyed` passed again. The declaration is unchanged.

- `brand.yaml` accepts `launched: true`, shipped in `brand.json`, for a provider BoxRouter offers in production. A provider without it is not launched, so a consumer that names only launched providers (a legal roster) leaves it out. Every provider except Boat declares it.

- Remove a stray `# in-tree edit` comment that a test run had left at the end of every provider declaration (it changed each declaration's digest). Declarations are otherwise unchanged from 0.3.174. The 0.3.175 release carried the stray comments and is superseded by this one.

- Add `matcher.coverage(catalog, declarations, reports, *, require_baseline=True)`: the `gate`, `gate.knob` and `resources.<ask>` entries at least one provider declares and, by default, proves with the matcher's baseline rule (`require_baseline=False` reads declarations only, as `declared_fit` does). `setting_backers(catalog)` maps each request setting to the entry it follows through its `only_with` rule. A consumer that exposes part of the vocabulary uses them to check that what it exposes is backed.

- Boat's `max_lifetime_seconds` moves from the free-trial ceiling (7200) to the
  documented paid-plan maximum (2592000, 30 days). The trial limit is now an
  unmet account condition: `resources.needs.max_lifetime_seconds` names
  `paid_plan`, and `resources.unmet_limits.max_lifetime_seconds.paid_plan`
  keeps 7200 as the ceiling a trial account publishes. Both values cite Boat's
  auto-stop documentation.

- E2B declares `lifetime_timer.after_resume: pauses` again, restoring the
  2026-10-28 live-check observation through the provider's own `evidence.md`
  inside this package; the earlier citation pointed into a private repository
  and was scrubbed.

- Boat and boxd declare `extendable_lifetime: true` and a `lifetime_timer` (`enforced_by: provider`, `at_end: [destroyed]`, `counts_paused_time: unknown`), cited to fresh adapter-identity runs of `facts.extendable_lifetime` and `lifetime_timer.at_end.destroyed`. boxd's other evidence was rerun on the current adapter and Boxd SDK 0.3.0 (`verified.sdks` moves from 0.2.22), and its `processes` variant now declares `reattach: true` (`processes.reattach.true` passed; the previous false-reattach evidence no longer holds on the current adapter).

- State the lifetime-extension contract. After a successful extension (`resources.extendable_lifetime: true`) the provider ends the sandbox no later than the new end, and with `lifetime_timer.adjustable: true` a set of any length is refused or does the same; the vocabulary says a client that only renews a lifetime needs `extendable_lifetime` alone, and one that sets an exact or shorter lifetime needs `adjustable` as well. Add the optional, never-compared `lifetime_timer.clearable` (`true`, `false` or `unknown`: a timer that was set can be removed from a sandbox that exists), with its rule `facts/lifetime-timer-clearable`. Vercel's `adjustable` becomes `false`: its SDK only lengthens a running sandbox's deadline (the same dated quote), so it declares `extendable_lifetime: true` alone; the new digest needs the paired adapter-pin adoption before Cloud serves it. Blaxel, Daytona (`default`) and E2B already declare `extendable_lifetime: true` and `adjustable: true` from passing reports and dated quotes; every other provider and class leaves them unknown until a report or quote shows them, and none declares `clearable`.

- Modal's `default` and `vm` classes declare `sizes` as ranges, so a fitting request is provisioned at the size it asked for rather than the next listed point, and declare `size_is_ceiling: true`, cited to fresh adapter runs. The upper bounds are unchanged: Modal documents no number, so each stays the largest size a run has created.

- The file-link cases that previously requested a 600-second sandbox lifetime (all `file_links.v1.*` except the two `link_lifetime` cases) and the two 1 GiB stream checks now request it through the optional `file_transfer_lifetime_seconds` fixture, which defaults to 600 and is forwarded unchanged to `create`; a value that is not a positive integer refuses the run before any provider call. The 17 tests whose create operand changed get new check digests, as do the other six transfer checks because a check digest also binds its check module's source; the previous coverage suite digest is preserved in the historical rule registry so committed reports stay evidence. Assertions, waits, proofs and every other requested bound are unchanged.

- Refresh Boat's `size_is_ceiling` report and its sources from the accepted native run; declared values and shapes are unchanged.

- Blaxel's `adapter-default-core` sources file records the shipped report's digest; the export had rewritten the report bytes after the sources were generated, so the pair failed Adapter Kit's trace binding. A regression test now checks every shipped report/sources pair.

- Boat's `default` class declares `small` (2 vCPU / 4 GiB) beside `default` (4 vCPU / 8 GiB) from the current public machine table; `large` and `xlarge` stay out. Disk remains unknown.

- Native gates proven by committed adapter runs and the providers' documentation: Blaxel and Vercel declare `terminal`; Modal declares `network_lockdown` (domain-name allowlist with wildcards and at least 32 entries, and an address allowlist); E2B declares `file_links` (read and write).

- Blaxel's and Vercel's `custom_images.provider_artifact` evidence is a fresh adapter run on the current adapters (boxrouter-blaxel 0.5.246, boxrouter-vercel 0.5.229; Core 0.13.366, Adapter Kit 0.24.306), so Adapter Kit's support check binds it to the released code.

- Add one coverage row, `coverage.custom_images.prepare.dockerfile_distro_context`: a Dockerfile built on the named distribution base `ubuntu:24.04` copies a text file and a byte-exact binary through `COPY`, adds a plain context file through `ADD`, and unpacks a compressed local tar carried under a non-tar name, the image is prepared and started, and every copied, added and unpacked marker is read back byte-exact. It proves `source: dockerfile`, `prepared: true` and `build_context: true` only — no `image_config` or environment claim — exercising `ADD` and archive unpacking where the existing prepared context row uses `COPY` alone. The row is additive: no existing check digest changes, and the previous coverage suite digest is preserved in the historical rule registry so committed reports stay evidence. No declaration or catalog change.

- Add one coverage row, `coverage.custom_images.prepare.dockerfile_distro`: a Dockerfile built on the named distribution base `ubuntu:24.04` writes a fixed marker through `RUN`, the image is prepared and started, and the marker is read back byte-exact. It proves `source: dockerfile` and `prepared: true` only — no `build_context`, `image_config` or context claim — giving providers that prepare distribution-base Dockerfiles a canonical `prepared` row where the existing `prepared` rows require OCI or the Python base. The row is additive: no existing check digest changes, and the previous coverage suite digest is preserved in the historical rule registry so committed reports stay evidence. No declaration or catalog change.

- Blaxel and Vercel declare `custom_images` with `source: provider_artifact` (a sandbox starts from an image already in the provider's registry), cited by passing adapter reports of `custom_images.provider_artifact`. Other sources stay undeclared.

- boxd declares Frankfurt and New York placements from SDK 0.3.0 regional discovery and labelled native create/run/delete checks. Existing gate reports remain historical; no snapshot or prepared-image capability is added.

- boxd's `default` class cites gate evidence from boxrouter-boxd 0.1.18 (native file listing); its declaration is unchanged.

- The evidence check leaves a report's own implementation stack (its adapter and the shared Core and Kit distributions) out of the `verified.sdks` comparison; provider SDKs still match exactly. boxd's declaration lists only the boxd SDK, so its digest no longer depends on BoxRouter's builds.

- boxd's `default` class cites gate evidence from boxrouter-boxd 0.1.16 (pause_resume, processes, network_lockdown, size_is_ceiling), and its declaration records the verified SDK versions.

- `resources.size_is_ceiling` can be proven on a dedicated-VM guest by a measured use test (a CPU burn at least twice the request and a
  memory hog above the allocation) when cgroup bounds are unproven. A gate's presence can be cited by a passing enum-knob row. The published
  0.3.155 coverage suite stays recognizable, so reports that cite it keep their identity. boxd's `default` class adds processes (input, cancel; no
  reattach), `pause_resume`, its allocation ceiling and its disk size, and no longer offers snapshots.

- boxd's `default` class declares all four machine sizes and `network_lockdown` (allowlist of names and
  wildcards, at least 32 entries) from a committed adapter run; `deny_all` and address entries stay out.

- Reword the in-development notes (`in_development.*`) as ranking-reason fragments: no provider name,
  no final period, and the test's ranking unit instead of "run". The meaning is unchanged; the one
  upstream source link moves from the sentence to a comment above it.

- Add a declaration for a new provider's `default` class: kernel, one machine size, lifetime ceiling and
  no gates. Its lifetime timer is left out until a Kit-bound report proves its ending; the evidence
  note says what a live smoke showed.

- Declare one provider's `network_lockdown` policy `deny_all`, cited from a clean native run of
  `network_lockdown.deny_all` (passed 2026-11-01) whose literal-IP control was a plain-HTTP endpoint.
  The existing address allowlist variant is unchanged.

- Let the environment write handover fact (`fuse_mount.provider_terminal_handover_env_132`) describe why each holder was revoked. A delegation may carry `revoke_basis`: `orphaned` (literally `is_orphaned: true`) or `owner_client` (`is_orphaned: false`, the holder belongs to the terminated owner's recorded client, and it was revoked). A non-orphaned holder that was revoked without the `owner_client` basis, and a basis that contradicts the flag, are refused. Facts without `revoke_basis` keep the previous shape. The check digests of the four `*_env_132` rows change with the module; reports that cite the old digests are stale and need a fresh run. No declaration, catalog or suite change.

- Correct one provider's terminal-bench FreeCAD note: the template builder's working-directory probe
  treats the image's micromamba login-hook stderr as fatal; cite the upstream `saveWorkdirMeta`
  source.

- Bound the fixture lifetime of the streamed-transfer and link-lifetime coverage rows to what each needs, not an hour. `files.stream.v1.*.64mib` ask for 300 seconds, `*.1gib` for 600 and `*.5gib` for 900; `file_links.v1.link_lifetime.read` and `.write` ask for 900 (they observe a link for the runner's `link_lifetime_wait_seconds`, normally 300). Committed reports show the longest complete row (create, 1 GiB or 5 GiB fixture and transfer) at 199 s for 1 GiB and 491 s for 5 GiB on the slowest of five providers, so each bound leaves at least a 1.8x margin; a provider slower than that fails the row instead of leaving a paid box running for an hour. Only these eight check digests change; the previous coverage suite digest stays recognized through the historical rule registry. No declaration, rule or catalog change, and no declaration cites these rows.

- Add the optional `resources.unmet_limits` declaration member: a ceiling (a positive integer, or `unknown`) for `max_lifetime_seconds` or `disk_mib` while one of that fact's `resources.needs` conditions is not met. The reference matcher offers the fact to an account that has not met the condition only up to the smallest such ceiling, and still refuses it when any unmet condition has no finite ceiling. The checker requires each ceiling to name a condition of the same fact and cite documentation. Three bundled declarations state their lower-plan ceilings.

- Remove `stopped` from the HTTP binding's sandbox state (`get`, `list` and allocation results, the schema, the TypedDicts and the binding reference). A sandbox that can resume is `paused`; one that cannot is `destroyed`. The reference Docker backend now reports an exited container as `destroyed`. This narrows what an endpoint may return: an endpoint that answered `stopped` must answer `paused` or `destroyed`. The `http.*` check digests change with the modules; no declaration or cited report uses them.

- Re-point seven declarations' evidence at native reports run 2026-10-29 on current SDKs, on this suite or on the previous suite digests the historical registry recognizes, and delete the superseded reports nothing cites. The declarations' digests change, so each adapter support file that pins one moves to this release.
- Build three coverage Dockerfiles (`guest_user.selectable`, `coverage.custom_images.build_context`, `coverage.custom_images.prepare.dockerfile_context`) from an Amazon ECR Public mirror of `python:3.12-slim` with the same image digest, so a builder that cannot pull anonymously from the default registry still proves Dockerfile support. `custom_images.dockerfile` keeps its default-registry `FROM`, so a provider with that limit still shows it. Give `idle_shutdown.custom_idle_time.true` a 600-second lifetime, well past its two-minute observation, so a lifetime timer cannot end the sandbox before the idle timer is observed. Only those four check digests change; the previous core and coverage suite digests stay recognized through the historical rule registry.

- Fail a live run that leaves one of its own snapshots behind. After the suite the driver of the provider with an organization-wide snapshot limit reads the snapshot inventory for names carrying this run's token, deletes each by exact id, and reports every one as `run_snapshot_left_behind` (or `run_snapshot_not_removed` when the provider has not removed it within two minutes; `run_snapshots_unverified` when the inventory cannot be read), so the report is not `clean` even though the account is. An interrupted run (Ctrl-C, or SIGTERM, which now unwinds like an interrupt) releases everything it still owns and runs the same check before it exits. Other runs' snapshots are never read as ours. No declaration, catalog or suite change.
- Compare the `http.buffered` timing limits on whole microseconds, not binary floats. `judge_kill_gap(4.88)` returned `early` because `4.88 + 0.02 + 0.1` is `4.999999999999999` in floating point, so a gap that is ambiguous on paper (the whole interval reaches the five-second grace) could be reported as a defect, and the same pattern sat in the TERM host-interval and handler-margin comparisons, the bracket width and the foreground result-time limits. No limit, margin or resolution changes; a value exactly on a boundary is judged as on the boundary. The `http.buffered` check digests change with the module; no declaration, report or suite digest cites them.
- Add optional `providers/<id>/brand.yaml` (chart colour, logo, one-colour mark) and `providers/<id>/publication.yaml` (state `hidden`, `candidate` or `published` per provider and class; no file means hidden). Stable releases ship them as `brand.json` (assets embedded) and `publication.json`, plus optional `providers/<id>/notes.yaml` (the provider's published sentences, shipped as `notes.json`), so a consumer reads a new provider's presentation and publication state from its own folder. `make check` validates both; no declaration or catalog change.

- Package every provider directory under `providers/` into the wheel with one `force-include` entry, and list provider files in the distribution manifest by pattern (`data/providers/*/declaration*.yaml`, `evidence.md`, `README.md`, `drivers/*.py`), so a new provider adds no packaging line. The wheel's contents are unchanged. The catalog description check now reads provider names from `providers/`.

- Add the optional `lifetime_timer.after_resume` fact (`same`, `pauses` or `unknown`; default `same`) and
  rule `facts/lifetime-timer-after-resume`: where a provider's timer pauses a sandbox that has been
  paused and resumed although it ends one that was not, a tool knows the resumed sandbox outlives its
  lifetime until something destroys it. No request compares it. E2B declares `pauses`.
- Remove `gates.processes[0].input` and its evidence from the Daytona container declaration. Daytona's native API cannot send end-of-input to a process, so the declaration no longer offers process input; an omitted gate knob never satisfies a request for it. Process cancel and reattach are unchanged.

- Change the HTTP binding's `buffered_commands_v1` output limit from an error to a marked prefix, matching BoxRouter's operation contract (`commands.output_limit`). A command whose stream exceeds `output_limit_bytes` (`L`) now returns a success with its exit status and, for that stream, exactly its first `L` bytes with `stdout_truncated` / `stderr_truncated` set; a stream of `L` bytes or fewer is whole and unflagged. Both booleans are required in every buffered result (and rejected in baseline results), and a truncated stream must be exactly `L` bytes. The endpoint still must not replace the result with `limit_exceeded`, terminate the command at `L`, replay it, or report completion before it ends. The reference runner's frame (now `SPSB2`) carries the flags and no longer has an `overflow` state; `BufferedRunnerResult` gains `stdout_truncated` and `stderr_truncated`, and the `http.buffered_run` hook returns both flags. The diagnostic `http.buffered.overflow` is replaced by `http.buffered.output_limit` (exit status, exact prefixes, flags, no replay, no early completion). This changes what a buffered result means and requires the new fields: a consumer must read the flags. The previous coverage suite digest stays recognized through the historical rule registry.

- Add the `file_links` gate: a link the provider issues for one file path, which a client holding only the link uses to read or write that file over HTTPS. Knobs `operations` (`read`, `write`), `user_selection`, `link_lifetime_seconds` and `revocable`; twelve `file-links/*` rules (one path, one operation, expiry, requested lifetime, own credential, exact bytes both ways, missing parents, default-user usability, named user, revocation, interrupted write). Add the declaration fact `resources.file_stream_max_bytes` (`{read, write}`, each a byte count or `{at_least: N}`, never unlimited) and the request resource `file_stream_bytes`, which the matcher compares per direction; evidence cites each direction separately (`resources.file_stream_max_bytes.read`). Add the `file_links.v1.*` and `files.stream.v1.*` coverage tests (64 MiB always; 1 GiB and 5 GiB with `file_stream_large: true`) through the new driver operations `files.link`, `files.revoke_links`, `files.write_stream` and `files.read_stream`, which no shipped driver implements yet, so those tests report `not_run`. The HTTP binding notes that HTTP-5's whole-body rule covers only `files.write` and `files.read_bytes`. No declaration changes; existing check identities are unchanged, and the previous coverage suite digest stays recognized through the historical rule registry.

- Add isolated `files.regular_write.usability.v1` coverage checks (`exact_bytes`, `create_parents`, `create_access`, `overwrite_access`, `authority`, `executable_effect`, `byte_bound`, `outcome`, `staging_cleanup`) and the optional declaration fact `resources.files_write_executable_effect` (`preserved`, `may_clear`, `unverified`). Existing check identities are unchanged. Writing a file does not guarantee it remains executable.

- Add three tagged Daytona 0.3.128 native reports for `resources.disk_in_memory: false`, with cgroup shmem observations and supplementary 10 GiB overlay evidence.

- Fix the HTTP conformance runbook release-tag jq escaping and setup guidance; document the installed buffered helpers, backend request conventions, and common not-run reasons. Give the 0.3 admission starter a direct error when its required backend methods are missing.

- Measure `disk_in_memory` with cgroup v2 `shmem` (or guest `/proc/meminfo` `Shmem`) so ordinary disk page cache and host-wide `MemAvailable` noise do not flip the fact. Keep `MemAvailable` only as a recorded fallback, and include the source and raw samples in coverage reports.

- Make a correct buffered helper provable. `buffered_runner_argv` started `E` before the child existed, so `http.buffered.execution_term`, `group_kill` and `observation_versus_execution` could not prove an exact-`E` TERM. The timer now starts once the child is spawned and TERM follows `E` by `BUFFERED_RUNNER_TERM_ALLOWANCE_S` (0.25 s). The check's judgments are unchanged, and the Docker reference backend uses the same helper.

- Bound the host-metadata probe. Its requests ran one after another, each waiting out a two-second timeout, so unroutable link-local addresses outlasted a five-second observation window and the row showed only a failed exchange. The same paths are now asked concurrently in at most three short waves within a 3.5-second budget; detection is unchanged.

- Refuse a report with the null source revision (`DEVELOPMENT_REVISION`) as evidence. A consumer records it for a local development run whose SPS source it could not verify, so such a report is never cited or promoted.

- Add the guide "Run the HTTP conformance suites" (`docs/how-to/run-http-conformance.md`, since removed): where to get `boxrouter-http`, the in-process `boxrouter-http-suite` command, certifying and development provenance, the guest, network and cap expectations, and result reading. Document the starter variables, the `run_buffered` result mapping and the file and state failure codes in the HTTP reference.
- The catalog describes each capability gate, displayed setting and the region resource.

- Publish the reusable inline HTTP buffered command runner (TERM, five-second grace, original process-group KILL) and have the Docker reference backend use the same helper.

- Correct the `http.buffered.*` TERM-time proof: the host's send time only bounds native dispatch from below, so it can show a TERM early but never on time. A TERM is now proven not early only against the workload's own start stamp plus the handler margin; everything between is unproven. SPS 0.3.119 could pass a TERM up to the start-to-send delay early.

- Add six focused `http.buffered.*` diagnostics to the coverage suite for the HTTP binding's `buffered_commands_v1` semantics: exact bytes and ordinary exit codes, execution-limit TERM, the original group's KILL after the leader exits, observation expiry versus the execution limit, background survival with final foreground output, and overflow without replay or early termination. They use the existing client through one new `http.buffered_run` driver hook, public command witnesses and bracketed guest timing; a driver without the hook reports `not_run`. They add no baseline requirement, capability or report format. The previous coverage suite digest stays recognized through the historical rule registry.

- Clarify that Vercel custom image support remains unproven and undeclared until a matching conformance report establishes it.

- Resolve known unsupported operations and fast conformance checks before elapsed-time waits. Independent lifetime control and extension observations share a wait when the configured sandbox capacity allows it; the default capacity keeps waits serial. Historical reports remain stale evidence when check digests change.

- Include the authoring guides in wheels under `spec_dir() / "docs"`, so an installed provider kit does not require a source checkout to read its instructions.
- Do not require a native per-command execution limit for the host-metadata baseline; keep its probe, isolation assertion and bounded HTTP requests unchanged.
- Ship the HTTP reference starter factory in the installed package as `sandbox_provider_spec.http_reference.starter:create_application`; importing it reads no configuration. `examples/http-binding/starter.py` stays as a thin wrapper that builds `application` from the same factory.
- Set the generated HTTP 0.3 reference starter's observation limit to 60 seconds so its discovery matches the documented Core envelope; 0.1 and 0.2 starters keep five seconds.
- Resolve omitted declaration classes to `default` in route results while preserving raw
  report identity and restore ownership.
- Define HTTP binding 0.3 admission and recovery shapes, add a pure declared-fit API without claiming conformance proof, and validate retained recovery boundaries.
- Implement the explicit HTTP 0.3 reference control plane with requestful backend admission, durable replay/recovery, and bounded fake-native WSGI coverage; native fulfillment remains separate.
- Align HTTP 0.3 public labels with 32-entry and UTF-8 byte bounds, reject NUL, and keep backend-internal metadata outside public label observations.
- Add the HTTP 0.3 Docker source backend with an engine-owned finite lifetime, retained `StartedAt` recovery, explicit cached image/network configuration, and full-size bounded default-principal `cat`/`tee` transfers; only SDK-fake coverage is included.
- Remove test-account plan metadata from run reports and committed evidence. Reports now
  reject the obsolete field instead of accepting it as legacy metadata.

The first public draft, format version 0.1 (`spec: sandbox-provider-spec/0.1`):

- The specification: a baseline every provider passes, 14 gates with 43 knobs, and facts
  about compute, time, place, network, hardware and environment.
- The declaration, request and run report formats, with JSON Schemas, the vocabulary as a
  catalog, and registries of region and GPU model identifiers.
- Deterministic matching rules, a reference matcher, and test vectors for independent
  implementations.
- A conformance suite of 181 tests, a runner with drivers for six providers, and the
  Docker Engine reference declaration with its run reports.
- The `sandbox-provider-spec` command: `check` validates requests, declarations and reports;
  `match` says which declarations satisfy a request and why the others do not; `run` produces
  evidence against a provider.
- Example requests for common workloads.

Public release notes will start with the first published tag. This unreleased entry describes
the working draft.
