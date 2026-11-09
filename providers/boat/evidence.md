# Boat declaration scope (slice 1)

Reviewed 2026-11-01 against the provider's public documentation and one live smoke
(`run=boat-slice1-20261101T091550Z`, boat-sdk 1.13.0).

The declaration offers Boat's `small` (2 vCPU, 4 GB) and `default` (4 vCPU, 8 GB) sizes from the
[size table](https://docs.boat.dev/machines) (read 2026-11-05). `large` and `xlarge` are real sizes
left out until they are requested; `xlarge` also needs the $100 plan. Docs quotes are not live
qualification. The lifetime ceiling is the free-trial limit (2 hours); paid plans allow 30 days
([auto-stop](https://docs.boat.dev/long-running-tasks/auto-stop)).

## Lifetime timer and extension

Boat's auto-stop (`ttlSeconds`) counts from creation and is not moved by commands, only by a
running agent prompt, which the adapter never starts. `facts.extendable_lifetime` and
`lifetime_timer.at_end.destroyed` passed in the committed `lifetime-extend.json` and
`lifetime-at-end.json` reports: a sandbox whose lifetime was extended from 300 to 420 seconds
was still running after the original end, and an unextended control was gone after its end.
`lifetime-at-end.json` was rerun on 2026-11-09 with adapter 0.3.48 and spec 0.3.174 on an account
without zero data retention: the sandbox was again gone (not found) after its end. The adapter
creates every sandbox with background snapshots off (`snapshots: false`), so the end erases the
machine instead of keeping a resumable disk; the declaration records only the observed
`destroyed`. One earlier run of the extension test timed out reading the
control sandbox after its end and was rerun once; the committed report is the clean rerun. `adjustable`, `step_seconds`, `counts_from` and
`min_seconds` stay unknown until a dated quote or report establishes them, and
`counts_paused_time` is `unknown` because Boat has no pause.

## Left unknown

Regions, placement country, disk size in MiB (the docs give "51 GB" without a unit base), paused
retention (Boat has no pause), GPUs (the docs say none), long-running and run limits. Default user
and working directory (`user`, `/home/user`) are observed but are claimed only through a report.

## Gates

None. Boat's stop ends processes and keeps the disk; it is not offered as `pause_resume`.
