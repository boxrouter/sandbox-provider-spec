# Boxd declaration evidence

The declaration combines Boxd SDK documentation with the committed conformance reports in this directory. Values without supporting evidence remain `unknown`.

## Gates

- `gates.terminal` is a pty under the guest supervisor that also keeps processes (Boxd adapter 0.1.68): closing an observer never ends the shell and a reconnect from the identity finds it, so `reattach` is true. `reports/adapter-terminal.json` (`terminal.interactive`) and `reports/adapter-terminal-coverage.json` (`coverage.terminal.reattach`) are certifying runs of the adapter against the released 0.3.177 wheel; both passed.

## Resources

- `resources.kernel` and `resources.sizes` follow the Boxd Python SDK documentation. It describes full machines and four CPU/memory sizes.
- `resources.disk_mib` and the `disk_mib` of every size are the fixed 100 GiB disk allocation: the SDK documents it as the platform constant, identical on every machine, so a request that names no disk resolves to it.
- `resources.default_size` follows the SDK's machine and disk-allocation documentation. The disk allocation is fixed at 100 GiB; the SDK does not expose a disk-used value.
- `resources.max_lifetime_seconds` is Boxd's bound on the platform delete timer a create carries (`delete_after`), ten years: a live create with 315360000 seconds succeeded and 315360001 was refused with `delete-after of 315360001s is too long (max 315360000s, ten years)` (2026-11-08). The earlier value of 900 was only the conformance fixture's request, not a limit.
- `resources.regions` and `resources.located_in` follow the SDK's explicit region selection and region listing for Frankfurt and New York. The declaration uses the corresponding `boxd:eu-fra` and `boxd:us-nyc` identifiers.

## Lifetime and extension

`facts.extendable_lifetime` and `lifetime_timer.at_end.destroyed` passed in `reports/lifetime-extend.json`
(a sandbox extended from 300 to 420 seconds ran past its original end; an unextended control was gone
after it). `lifetime_timer.counts_paused_time` is `unknown`. The process, pause and network-lockdown values
and the size ceiling were rerun on the current adapter and Boxd SDK 0.3.0 so that every cited report
shares one SDK set; with the current adapter a process can be reattached after its stream closes
(`processes.reattach.true` passed), so the declaration now says `reattach: true`.

## Declared extensions

- `x-boxd.isolated` follows the SDK documentation for isolated machines. The declaration records the SDK's documented authentication behavior for that mode.
- `x-boxd.usage_records` follows the `machines.usage()` SDK documentation. Usage remains queryable by machine id or name after deletion and includes cost and completion status.

## Conformance

The conformance fields cite `reports/default.json` and `reports/adapter-default-size-ceiling.json`. Ambiguous or untested behaviors stay `unknown` or `not_run` in the declaration and reports.
