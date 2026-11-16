# Superserve declaration evidence

The declaration records only what a committed report or a dated quote of the provider's documentation
proves. Values without supporting evidence remain `unknown`.

## Resources

- `max_lifetime_seconds: 604800`: Superserve's `timeout_seconds` takes 1 to 604800 seconds (OpenAPI
  `CreateSandboxRequest`, read 2026-11-13), so 604800 is the longest window one create can ask for. The
  declaration states that bound as the admission cap. It is a cap on one window of active time, not on
  total lifetime: each resume starts a fresh window.
- `sizes`, `default_size`: two shapes, because a sandbox inherits its shape from its template. The default
  template `superserve/base` is 2 vCPU, 4096 MiB memory and 8192 MiB disk (the default size), from the
  templates page (read 2026-11-13). The adapter builds the standard-image template itself
  (`image_preparation.py`) at 2 vCPU, 2048 MiB and 8192 MiB, inside the documented template limits
  (build-spec page: minimum 256 MiB, Free plan maximum 2 vCPU and 4096 MiB) and within the team's legacy
  Free cap; that shape is the adapter's own choice, not a quoted figure. The adapter sets no shape on create. A live check on 2026-11-13 (run `ss-sizes-20261113T035827Z`, one sandbox
  of `superserve/base`, destroyed) agreed with the page: the template record (`GET /templates`) says
  `vcpu` 2, `memory_mib` 4096, `disk_mib` 8192; `GET /sandboxes/{id}` says `vcpu_count` 2, `memory_mib`
  4096; inside, `nproc` printed 2, `/proc/meminfo` `MemTotal` 4034076 kB (the guest kernel keeps part of
  the 4096 MiB) and `df -m /` a 7964 MiB root filesystem. Known discrepancy: a live run on this team on
  2026-10-23 saw 1 vCPU, 1024 MiB (`free -m` 984) and a 7.8 G root disk, before the 2026-11-11 rebuild
  of the system templates (`built_at` 2026-11-11T17:47:55Z); it no longer reproduces, and the declaration
  states the current measurement. The team's legacy Free plan is recorded at a cap of 2 vCPU, 2 GiB and 8 GiB disk per sandbox
  (research.md, 2026-11-13); the `superserve/base` sandbox above ran at 4096 MiB on this team regardless, so
  the cap did not bind the system template. The citation is
  the page's quote, not a report: no SPS conformance test proves `sizes`.
- `size_is_ceiling: true`: `coverage.facts.size_is_ceiling.true` passed in
  `reports/adapter-default-size-ceiling.json` (run `ev-cert-superserve-local80eeed14f0-1-1`) by measured
  use: a CPU burn measured 1.00 CPU against a 2-CPU request (the sandbox is a VM, so no cgroup quota is
  visible) and a memory hog aimed at twice the 4096 MiB request was killed. The adapter's
  `conformance-fixtures.json` names the test size (`test_size`: 2 vCPU, 4096 MiB).
- `default_user: root` and `default_cwd: /home/user`: `facts.default_user` and `facts.default_cwd` passed
  in `reports/adapter-defaults.json` (run `ev-cert-superserve-localfdf5bb43b5-1-1`) on a sandbox of the
  default template. The first run of that report (`ev-cert-superserve-local1167b7798f-1-2`) passed
  `facts.default_cwd` but ended `facts.default_user` in an `error` (`timeout` in `environment.observe`
  after 78 s) with the sandbox cleaned up; the one rerun passed both. A direct SDK check on 2026-11-13
  also read `uid=0(root)` and `/home/user`.
- `paused_retention_seconds: 2592000`: Superserve's `auto_delete_seconds` (the garbage-collection window of a paused
  sandbox) takes 0 to 2592000 seconds, 30 days (OpenAPI `CreateSandboxRequest` and `PatchSandboxRequest`, read
  2026-11-14); with it set, a paused sandbox shows `auto_delete_at` exactly 30 days on (ss-v018 live look, 2026-11-14).
  The adapter holds that retention for the length of a caller's pause. It is the longest a paused sandbox is kept
  here, not a retention Superserve promises by default (unset, a paused sandbox is kept until deleted).
- `extendable_lifetime`: `unknown`, not claimed in 0.1.9. `facts.extendable_lifetime` passed in an earlier round (a 300 s
  lifetime extended to 420 s was still running 305 s on, and the control with no extension had ended), but Core's live row
  `extend.ends_at_extended_end` fails (see "Core contract rows that fail"), so the extension is not claimed. The handle still
  implements `ensure_lifetime` and `lifetime.set`, because a hosted resume calls it.
- `kernel: dedicated`: Superserve's create page calls a sandbox "an isolated Firecracker MicroVM" (read 2026-11-16), and a live
  check the same day agreed: the guest ran its own Linux 6.1.158 as root with every capability, `CONFIG_FUSE_FS=y` and `/dev/fuse`.
- `gpus`, `regions`, `located_in`, `max_run_seconds`, `max_process_seconds`, `long_running`: `unknown` or
  absent; the documentation states none of them (`long_running` is also not offered: `facts.long_running` ended
  `capability_unavailable` at the create, run `ss-cert018-C-021732`, so it is not claimed). `located_in` is absent
  because Superserve names no country for a default placement.

## Facts proved by adapter reports

These values cite the adapter's committed reports, copied beside this file as `reports/adapter-*.json`.

- Lifetime timer `{enforced_by: provider, counts_paused_time: false, at_end: [destroyed]}`. The adapter
  creates with `timeout_seconds` set to the lifetime and `auto_delete_seconds` 0. Documentation
  (lifecycle page and OpenAPI, read 2026-11-13): `timeout_seconds` pauses the sandbox once its current
  active session has run that long, each resume starts a fresh window, and `auto_delete_seconds: 0`
  "deletes the sandbox as soon as it pauses". Proof: `lifetime_timer.at_end.destroyed` in
  `reports/adapter-default.json`. `counts_paused_time: false` rests on the OpenAPI quote in the declaration's
  evidence and on the live looks below; its SPS row, `lifetime_timer.counts_paused_time.false`, cannot run
  against this adapter: it creates a 60 s sandbox and pauses it at once, and the adapter refuses a pause with
  under 60 s of lifetime left (`invalid_state`) because Superserve's timer never fires before 60 s of active time,
  so a stored total below 60 s would lengthen the lifetime. The row errored on that refusal; it did not observe
  a countdown during the pause.

  Timer measurements (ss-v018, live, 2026-11-14, labels `ss-v018-20261114T00*`, cleanup by label 0 each run):
  - **Floor and tick.** `timeout_seconds` of 25, 30, 40 and 55 all paused the sandbox 60.4 to 70.9 s after its
    `started` or `resumed` audit row, never earlier. Pauses land on a shared tick about every 11.5 s (three
    sandboxes paused at 00:16:49.11, .12 and .13; the next one 11.5 s later). The rule seen: the timer pauses at
    the first tick after max(`timeout_seconds`, 60 s) of active time. It never fires early. The end is a deletion
    where `auto_delete_seconds` is 0, seen 12 to 16 s after the total (a 142 s total ended 157.6 s after the create
    returned). SPS `step_seconds` only forbids ending early, so the declared step of 1 stays true; how late a timer
    may end has no SPS fact (adapter-planner, 2026-11-14).
  - **`PATCH timeout_seconds` is the session's total.** It counts from the session's start (a create or a
    resume), not from the PATCH: asking for a 142 s total at age 20.3 s ended the sandbox after at least 140 s. The
    audit row for `started` and `resumed` is written about 0.2 s after the create or resume answered, so an age
    counted from the answer is never short.
  - **Pause** (`POST /pause` waited): `204` in 0.4 to 1.5 s. While paused `GET` shows `auto_delete_seconds` as set
    and `auto_delete_at` exactly 30 days on; `PATCH timeout_seconds` on a paused sandbox is `204` and is what the
    next session starts with. A background shell loop kept counting through pause and resume (processes and memory
    survive; `cold_restart` false). `auto_delete_seconds: 0` deletes at the pause, and set on an already paused
    sandbox deletes at once, so the adapter holds the retention for the length of the pause and sets 0 only on a
    running sandbox.
  - **Resume** keeps the `auto_delete_seconds` setting and cancels its countdown, so the adapter sends 0 again.
    An exec or file call through the SDK on a paused sandbox resumes it silently, so a handle that knows the
    sandbox is paused refuses before the SDK is asked.
  - **Not observed:** that a resumed session runs for exactly the stored total (the 60 s floor hides totals
    below it), a pause of days, the tick's period on other accounts or hosts.
- `processes`: `commands.spawn`, a stdin write and its explicit EOF, and a signal that ends the process;
  no reattach, because the service stops a command whose connection is gone (`processes.input.true`,
  `processes.cancel.true`, `processes.reattach.false` in `reports/adapter-default.json`).
- `network_lockdown`: an allowlist of names and addresses with `*.` wildcards, and a switch between an
  allowlist and open (`reports/adapter-network-lockdown-default.json`,
  `reports/adapter-network-lockdown-coverage-default.json`). Not declared: `deny_all` (Superserve's refusal of
  an unlisted name over TLS reads as ambiguous, so its row is `not_run`), a denylist (its rows need a recording
  receiver at a blocked address) and `changeable` (Core refuses the empty allowlist that row sets).
- `custom_images`: a public OCI image is built as a team template whose `start_cmd` is the image's ENTRYPOINT and
  CMD, and a sandbox boots from it, as `provider_artifact` when the caller names the template; the template
  carries the image's env, working directory and user, and no template option takes registry credentials, so a
  private registry image is refused. The entrypoint is started once while the template is built and kept alive in
  its snapshot, so every sandbox from the template shares that process's state: an entrypoint that sets up state
  of its own per sandbox, or that exits, is wrong for this route. `runs_entrypoint: true` and `image_config`
  (`env`, `workdir`, `user`) passed in `reports/adapter-custom-images-default.json` (run
  `ss-cert018-C-050014`); `custom_images.oci` and `.provider_artifact` in
  `reports/adapter-custom-images-core-default.json` (run `ss-cert018-B-050212`). The declaration's
  earlier `runs_entrypoint: false` is gone: its row now differs, as it should. A `provider_artifact` request
  naming `runs_entrypoint: true` for a template BoxRouter did not build is refused before dispatch.
- `docker`: Docker Engine in a second team template built on the standard image (the default user is in the
  `docker` group; `dockerd` is the template's `start_cmd`), so a create that names `docker` starts from it, never from a caller's image, and the
  variant conflicts with `custom_images`. `coverage.docker.host` passed in `reports/adapter-docker-default.json`
  (run `ss-cert018-E-031812`).

## Gates

- `pause_resume: keeps files_and_memory`: `pause_resume.files_and_memory` passed in `reports/adapter-pause-default.json`
  (run `ss-cert018-C-031046`): a file and a running process's memory survive a pause and resume, on the same sandbox.
  A caller's pause stores the lifetime left as the next session's total and holds `auto_delete_seconds` at 30 days
  for the length of the pause (see the timer measurements above).
- `idle_shutdown: custom_idle_time true, on_idle destroyed`: both rows passed in `reports/adapter-idle-default.json`
  (run `ss-cert018-I-032610`). An `idle_shutdown` request becomes `idle_timeout_seconds` (60 s to 7 days); the idle
  pause deletes the sandbox because the adapter's `auto_delete_seconds` is 0 (a 60 s idle sandbox was gone at 61.0 s,
  ss-v018). `auto_wake` is not claimed and a preview or wake rule was not tested.
- `previews`, public variant: `access public`, `revocable true`, `max_ports at_least 2`, `any_port`,
  `link_lifetime_seconds at_least 120`, `reserved_ports [49983]`, `websocket true` and `survives_pause true`, from
  `reports/adapter-previews-core-default.json` (run `ss-cert018-D-031046`) and
  `reports/adapter-previews-default.json` (run `ss-cert018-D-031529`). Ports 1 to 1023 are refused by the
  adapter too, but the runner proves at most 64 reserved ports, so only 49983 is declared. The link lifetime is 120 s
  because the run's sandboxes are capped at 300 s; a 300 s observation would need a longer lifetime. A revoke
  unpublishes the port, which ends that preview (one preview per port; its id is the port).
  Not declared (rows run, 2026-11-14, AWS): the **private variant**. `previews.access.private`,
  `previews.credential.link`, `previews.revocable.false` and `previews.link_lifetime_seconds` `differs`: the link
  form answers with a cookie-bootstrap redirect and the SPS probe deliberately does not follow redirects, and
  `previews.access.private` is the only row that proves `access: private` and it opens the link form. The header
  form works (`previews.credential.header` and `previews.credential_scope` passed in the report above; ss-previews'
  live look: 401 without the header, 200 with it, tokens are port-scoped) but cannot be declared without the access
  row. `coverage.previews.loopback` `differs` (a server bound to `127.0.0.1` only is 502), so `loopback` is not
  declared. In the first run `coverage.previews.reserved_ports` was `not_run` (`adapter_planning_refused`: the adapter
  refused a create that lists 49983); 0.1.9 accepts that create and refuses the open of it.
- `terminal: reattach true`: `coverage.terminal.reattach` passed in `reports/adapter-terminal-default.json` (run
  `ss-cert018-D-050014`). A terminal is a pty under the guest supervisor, so closing an observer never ends the
  shell and a later connection reattaches to it; Superserve's own `/terminal` socket is not in its SDK and a closed
  socket ends the shell.
- `snapshots: keeps files_and_memory, deletable true`: both rows passed in `reports/adapter-snapshots-default.json`
  (run `ss-cert018-D-032225`). Not declared: `original_after` (the row `snapshots.original_after.briefly_paused`
  ended `not_run`, `snapshot_ticker_gap_ambiguous`: the runner's ticker could not tell the capture's pause from a
  gap), `retention_seconds` (a snapshot is kept until deleted, which no row proves) and `resizes_on_restore`.

## Core contract rows that fail (two refused lines)

`reports/contract-default.json` and `reports/contract-default-standard.json` (Core's live conformance; runs
`ss-cert018-ctdflt-033108` and `ss-cert018-ctstd-033108`, AWS, 2026-11-14) both end `FAIL` on one row,
`extend.ends_at_extended_end` (check `lifetime_extends`). `release_matrix --ready` refuses Superserve for exactly these two
lines ("rows fail live: extend.ends_at_extended_end", one per report) and for nothing else. Reason: the check extends a
lifetime and expects the sandbox to end by the extended end plus 10 s of grace and 5 s of polling. Superserve's timer ends a
sandbox late: it pauses at the first shared tick (about every 11.5 s) after max(`timeout_seconds`, 60 s) of active time and
then deletes the sandbox 12 to 16 s later (`auto_delete_seconds` 0), so the check reported "the sandbox still ran 15 s past
the 80 s its lifetime was extended to". The shorten half of the row (a `lifetime.set` of 30 s on a sandbox created with
100 s) cannot be honoured either, because Superserve never ends a sandbox before 60 s of active time. The declared step
stays 1, and neither the row nor the declaration was changed to make it pass (adapter-planner and the coordinator,
2026-11-14). `extend.total_budget` is not applicable: the class declares no extendable lifetime. The handle's
`provider_times` reports the deadline (the newest started or resumed audit row plus the stored `timeout_seconds`; the real
end can fall up to one tick later).

## Snapshots

- Source: docs.superserve.ai/sandbox/snapshots and OpenAPI `createSandboxSnapshot` (read 2026-11-13): a
  snapshot saves memory and disk (`mem+fs`), "a running sandbox is paused briefly while the snapshot is
  taken, usually for under a second, and then continues", it "stays until you delete it, even after the
  original sandbox is gone", and a fork "starts exactly where the snapshot left off".
- Live look (ss-gaps look 3, 2026-11-14, one measurement): the capture took 0.35 s. The source stayed `active`
  at every 3 s poll for 42 s afterwards and its background process kept running; a poll cannot see a pause
  under a second, so `briefly_paused` rests on the documentation and `continues` is not claimed. A fork was
  created in 0.4 s with the source's files, its running process, the snapshot's vCPU, memory and disk, and the
  metadata the fork's request set. A delete was followed by `404` on `GET /snapshots/{id}`; the forks and the
  source were unaffected. Superserve's internal pause did not trigger `auto_delete_seconds: 0`, which a
  caller's pause does (about 7.6 s later, ss-cost).
- Limits: 100 snapshots per team, 20 per sandbox, 4 being taken at once per team (docs, Limits). Past one,
  the capture answers `429` with `too_many_snapshots` or `too_many_snapshots_in_flight`. The adapter maps the
  first to Core's `quota_exceeded` and the second to `rate_limited`; Core's contract has no snapshot limit
  field. The team is one pool, so these are not per-customer limits. The adapter's snapshots are offered by
  Core used directly with the caller's own key; the hosted API has no snapshot endpoint (`not_hosted`).
- What a fork inherits (docs, OpenAPI `from_snapshot`, and look 3): the snapshot's machine, so a restore cannot
  resize (`resizes_on_restore` is not claimed); the source's `timeout_seconds` but not its
  `auto_delete_seconds` (a fork given neither had `timeout_seconds` 240 and `auto_delete_seconds` null), so
  the adapter passes both, as a create does; the source's network rules unless the request passes `network`,
  so the adapter passes the open rules when the request names none; the source's secrets, bound again with
  fresh proxy tokens (the adapter binds none). Processes running at capture keep the environment they started
  with, including the source's secret proxy credentials, which do not work in the fork.
- Live look through the adapter (ss-snap, 2026-11-14, run `ss-snap-20261114T003713Z`, sandboxes destroyed and
  the snapshot deleted by id, a by-label list empty afterwards, $0.0006): the capture of a sandbox with an
  allowlist of `1.2.3.4` took 0.5 s and the source read `active` with its timer and rules unchanged. A fork
  whose request named no network read `network: null` and reached `https://example.com` (`200`) while the
  source could not (`000`), so the open rules the adapter sends replace the source's allowlist; a fork with
  an allowlist of `example.com` reached it and not `example.org`. Forks had `timeout_seconds` 120 and 90 and
  `auto_delete_seconds` 0, the file the source wrote before the capture (`before`, not the later write), and
  the run's label. A snapshot read by id was `ready`, a second delete answered as the first, and the read
  after the delete was `404`.
- Not declared: `original_after`, `retention_seconds`, `resizes_on_restore` (above).
- No team-wide read: Superserve lists snapshots only under their source sandbox
  (`GET /sandboxes/{id}/snapshots`), which also works for a deleted sandbox, so the adapter's
  `list_artifacts("snapshot")` is unavailable and `get_artifact` reads one snapshot by id. Superserve has no
  team-wide snapshot listing, so a caller must keep its snapshot ids.
- Cost: Superserve has no published snapshot storage price, and the pricing data marks disk `not_billed`; the
  retained storage of a snapshot is not metered by BoxRouter.

## Hidden secrets: a model difference (not claimed)

The adapter does not claim `hidden_secrets`. Superserve's secret proxy substitutes a stand-in that the code in
the sandbox sends; the SPS `injection: sets_header` promises the header even when the code sends no credential.
Observed live (ss-gaps look 4, 2026-11-14; fake secret values; public echo hosts `httpbin.org` and
`postman-echo.com`), with a `custom` secret (two header templates) and a `bearer` secret bound as `TESTKEY` and
`TESTBEARER`:

| Request from the sandbox | What the receiving host saw |
| --- | --- |
| no stand-in, to a host in the secret's hosts (custom and bearer secrets) | no header |
| the stand-in bare in the custom header, or in another header, or sent to a host not in the secret's hosts | the stand-in, unchanged |
| the stand-in in the template's form (`pre-$TESTKEY-suf`) | `X-Test-Secret: pre-<value>-suf`, and `X-Second: two-<value>`: every header of the secret is set, including one the request did not send |
| bearer stand-in as `Authorization: Bearer $TESTBEARER` | `Authorization: Bearer <value>` |
| the same with `curl --noproxy '*'` or Node `fetch` (clients that ignore the proxy variable) | the stand-in, unchanged |
| the secret rotated, same shell | the new value; a loop already running used the new value from its next request (within about 2 s) |

The model: the sandbox gets `HTTPS_PROXY=https://sb:<token>@192.0.2.1:9443` and a trusted `Superserve Sandbox
Proxy CA`; a client that honours the variable goes through the proxy, which swaps a stand-in the code sends for
the real value. The environment token is a signed sandbox token whose payload lists each binding's env key,
hosts and auth template (not values), and code in the sandbox can read it. Values this supports:
`rotates: true`, `header_templates: true` (custom headers, up to 8, `{{ value }}` prefix and suffix),
`transparent: false`, `intercepts: all_https` (every host's certificate is issued by the Superserve CA through
the proxy), `scrubs_responses: false` (an echoing host returned the real value in the response body). Only
`injection: sets_header` is not met, so the gate is not claimed; a stand-in-replacement `injection` value in the
SPS vocabulary, or Core mapping `HiddenSecret.placeholder` to Superserve's generated stand-in, would be the
SPS owner's decision. A secret is stored in the team by name; 2 were created and no cap was hit.
