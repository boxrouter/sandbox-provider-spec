# Boat declaration scope (slice 1)

Reviewed 2026-11-01 against the provider's public documentation and one live smoke
(`run=boat-slice1-20261101T091550Z`, boat-sdk 1.13.0).

The declaration offers Boat's `small` (2 vCPU, 4 GB) and `default` (4 vCPU, 8 GB) sizes from the
[size table](https://docs.boat.dev/machines) (read 2026-11-05). `large` and `xlarge` are real sizes
left out until they are requested; `xlarge` also needs the $100 plan. Docs quotes are not live
qualification. The lifetime ceiling is the free-trial limit (2 hours); paid plans allow 30 days
([auto-stop](https://docs.boat.dev/long-running-tasks/auto-stop)).

## Lifetime timer: not yet declared

Boat's auto-stop (`ttlSeconds`) counts from creation and is not moved by commands, only by a
running agent prompt, which the adapter never starts. In the smoke the record's `archiveAfter`
equalled created + 90 s and the sandbox was gone (404, absent from the exact-label inventory) right
after. That account has zero data retention, where a stop is a delete; on an account without it a
stop keeps the disk for 14 days and is resumable, so the ending is `stopped`, not `destroyed`.
Creating with `snapshots: false` is documented to erase the disk at stop; the smoke cannot separate
that from the account setting. `lifetime_timer` therefore stays out of this declaration until a
Kit-bound report proves its `at_end`.

## Left unknown

Regions, placement country, disk size in MiB (the docs give "51 GB" without a unit base), paused
retention (Boat has no pause), GPUs (the docs say none), long-running and run limits. Default user
and working directory (`user`, `/home/user`) are observed but are claimed only through a report.

## Gates

None. Boat's stop ends processes and keeps the disk; it is not offered as `pause_resume`.
