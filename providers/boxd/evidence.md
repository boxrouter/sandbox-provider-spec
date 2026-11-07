# Boxd declaration evidence

The declaration combines Boxd SDK documentation with the committed conformance reports in this directory. Values without supporting evidence remain `unknown`.

## Resources

- `resources.kernel` and `resources.sizes` follow the Boxd Python SDK documentation. It describes full machines and four CPU/memory sizes.
- `resources.default_size` follows the SDK's machine and disk-allocation documentation. The disk allocation is fixed at 100 GiB; the SDK does not expose a disk-used value.
- `resources.max_lifetime_seconds` follows the conformance fixture, which requests a 900-second lifetime and checks the create-time `auto_destroy_timeout` value.
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
