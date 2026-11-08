# E2B resource scope

Reviewed 2026-10-22 against the provider's public documentation.

The [region table](https://docs.e2b.dev/faq/egress-ip-ranges) identifies the
default US deployment as Google Cloud `us-west1`. US West on AWS `us-west-2`
requires support activation. The declaration offers only the default `e2b:us`;
`located_in: [US]` describes placement without a region override.
EU (`europe-west1`) and APAC (`asia-southeast1`) require Pro or above and support
activation. They are documented here rather than in `resources.regions`, because
the declaration format conditions a whole list, not individual regions.

## Entrypoint and network scope

The [start-command guide](https://docs.e2b.dev/template/start-ready-command)
explains that the command runs during template preparation and is captured in a
snapshot; it does not run again for each sandbox. A marker inherited from that
snapshot cannot prove startup execution. The declaration leaves `runs_entrypoint`
unknown while preserving Dockerfile preparation and build-context support. A future
probe must supply a distinct value only at sandbox creation and observe an
entrypoint effect containing that value in each of two sandboxes from one artifact.
The historical static-marker report is unchanged and no longer cited for this knob.

The [internet-access guide](https://docs.e2b.dev/network/internet-access#catch-all-wildcard)
documents HTTP Host inspection on port 80 and TLS SNI inspection on port 443, with a
shared-endpoint limitation: an allowed hostname can also permit other destinations
on the same endpoint. The declaration therefore retains only the independently
proven address allowlist. Name and wildcard variants are withheld until a native
probe distinguishes the allowed name from an unlisted HTTP authority on the same
endpoint, including a Host/SNI mismatch. The prior name probes do not test that case.

The native `network_lockdown.deny_all` test passed on 2026-11-01
([report](reports/e2b-native-network-deny-all-sps0155-20261101.json)). The provider's
[internet-access guide](https://docs.e2b.dev/network/internet-access) describes the same behavior:
`allow_internet_access=false` is equivalent to `network.deny_out=['0.0.0.0/0']`. The run's
literal-IP control `allowed_ip_url` was a plain-HTTP endpoint, because a blocked HTTPS connection
to an unrecorded address fails in the TLS handshake and the test treats that as ambiguous. The
earlier `not_run` rows came from that fixture shape.

The [plan table](https://docs.e2b.dev/billing) establishes the self-serve 8-vCPU
and 8-GiB memory ceilings. Higher Pro and custom Enterprise limits do not establish
an unrestricted range. Pro disk is documented as 20+ GiB, so `disk_mib` declares
a lower bound of 20480 MiB with the existing `pro_plan` condition.

Timer granularity remains `unknown`. The native core report marks
`edge.lifetime.granularity` passed, but that row has no `proves` value for
`lifetime_timer.step_seconds`; the checker rejects it as evidence of one second.
The lifecycle guide's timeout example establishes units only. After live runs
resume, a native run must measure timer resolution and emit a proof of the
observed step before the declaration can claim it.

A live check on 2026-10-28 observed the timer after a resume: a sandbox created
with `lifecycle: {on_timeout: kill}`, paused, then resumed with
`connect(timeout)` was paused, not killed, when that timeout ran out; the
sandbox's reported lifecycle still read `kill`, and the older `/resume` call
with `autoPause: false` behaved the same. A create that was never paused ends
in a kill as declared, and the remaining running-time budget carried across the
resume was honoured to within the 5 s poll. The declaration therefore claims
`lifetime_timer.after_resume: pauses`.

## File links

The `file_links` gate declares one variant that reads and writes. The
[upload guide](https://e2b.dev/docs/filesystem/upload) says “you can use pre-signed URLs to let
users upload files securely”, and the [download guide](https://e2b.dev/docs/filesystem/download)
says “you can use pre-signed URLs to let users download files securely.” The adapter report
`reports/adapter-file-links.json` (e2b 2.59.0) passes `file_links.v1.read_exact` and
`file_links.v1.write_exact`. User selection, link lifetime and revocation are not declared: the
same report's `file_links.v1.user_selection` row is an error.
