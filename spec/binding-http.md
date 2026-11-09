# Provider HTTP binding 0.1, 0.2 and 0.3

Private PP1/PP2 definition. This document defines a wire contract; it does not supply
an HTTP client, endpoint, admission integration or an onboarding service. Release
and adoption remain held for a separately sequenced feature cohort. Existing SPS
conformance reports do not prove this new binding.

## Authority and artifacts

The [SPS baseline](spec.md#5-baseline), [vocabulary](vocabulary.md),
[request schema](request-schema.json) and [declaration schema](declaration-schema.json)
remain authoritative. This binding adds transport and allocation-key obligations;
it does not change those sources or any consumer's existing guarantees. MUST, MUST
NOT and SHOULD are normative. Each section's `HTTP-*` identifier is a binding
requirement, not an addition to the existing SPS rule catalog.

[http-binding.schema.json](http-binding.schema.json) is the canonical wire shape
source. [http-binding.openapi.json](http-binding.openapi.json), Python wire types
and message fixtures are generated from it, including its examples. The OpenAPI
uses the existing request/declaration schema resources, bundled unchanged; their
URN identifiers retain their own reference scopes. Types describe shapes, not
validation, capabilities or an HTTP client.

From a checkout containing this package, using its configured development environment:

```sh
.venv/bin/python tooling/http_binding/generate.py
.venv/bin/python tooling/http_binding/generate.py --check
.venv/bin/python tooling/http_binding/validate.py
.venv/bin/python -m pytest -q -n 0 tests/test_http_binding_schema.py tests/test_http_binding_semantics.py
```

Generation uses the existing pinned Ruff formatter for Python types; it does not
regenerate any catalog, declaration, conformance artifact or package manifest.
Semantic fixtures are generated from `tooling/http_binding/semantic_cases.py` into
`examples/http-binding/semantics.json` and
checked by the binding-only validator. They are examples of required outcomes,
not a substitute for testing a running implementation.

## HTTP-1: Transport, discovery and authority

All endpoints MUST use HTTPS at an operator-admitted origin. Every request,
including discovery, uses an account-scoped bearer credential. A credential is
bound to the configured origin and account; an endpoint MUST NOT trust an
`account_id` in a body as authorization. Cross-account requests MUST be rejected
before any native lookup or mutation. Authentication precedes resource disclosure.
A caller MUST verify every returned account and resource identity.

The client MUST disable redirects, send no credentials to another origin, and
bound connection time, total observation time and response bytes. Discovery's
`endpoint_origin` MUST equal the configured origin, not redirect it. Origins have
scheme `https`, a DNS name or IP literal and optional port, with no userinfo, path,
query or fragment. Hosted admission MUST reject private, loopback, link-local and
metadata destinations and protect every connection against DNS rebinding. Local
development exceptions require explicit local configuration and are not hosted
admission. JSON validation alone does not establish origin safety.

Authenticated `GET /.well-known/sandbox-provider-spec.json` returns `Discovery`.
Its binding version is `sandbox-provider-http/0.1`, `sandbox-provider-http/0.2` or `sandbox-provider-http/0.3`;
its ordered `operations` value names exactly the nine operations below. Version
0.1 retains its original UTF-8 `run` behavior, empty `core_modes`, and 32 MiB
request and response caps. Version 0.2 may opt out of additional modes with an
empty `core_modes`, or advertise `buffered_commands_v1`; version 0.3 requires that
mode. That capability applies
to every offering in discovery; an endpoint MUST NOT advertise it if any offering
does not provide its semantics. Offerings have unique `offering_id`
values and immutable `declaration_id` values. In 0.1, `declaration_id` identifies
native declaration content. In 0.2 and 0.3, it is a selection token binding native
declaration content, effective binding version, advertised modes and admitted
capacities. A producer MUST change the token when any bound promise changes. An
identifier MUST NOT be rebound to different selection content. Declarations use existing SPS facts, gates,
conditions and evidence, including account/image/region conditions. A server MUST
refresh the declaration identity when those facts change. The client uses the
existing SPS checker and matcher; schema validity alone is not a passing baseline
or evidence report. A `provider_id` is stable for the admitted endpoint's provider;
account IDs are opaque within that provider and contain no credentials.

A new create MUST name a currently offered selection token. Stale selection is
`conflict`, before dispatch. An existing create key is replayed under HTTP-3
before reevaluating the current selection; replay retains the originally selected
modes and capacities for that allocation's lifetime, even if discovery changes.
`server_revision` identifies
implementation changes; it does not invalidate live allocation keys.

For binding 0.3, an empty current offering list is valid discovery: it prevents
new allocations while allowing `get` to recover a retained allocation after its
original offering disappears. A genuinely new create against an empty list, or
with a stale offering selection token, returns `409 conflict`. Bindings 0.1 and
0.2 continue to require at least one current offering.

## HTTP-2: Messages, bounds and identity

The nine operations are JSON POSTs with `Content-Type: application/json`; requests
and replies MUST be strict UTF-8 JSON with unique object keys, finite numbers and
Unicode scalar strings. Compression is not bound: clients MUST NOT request it and
servers MUST NOT use it. Unknown object fields and unsupported semantics MUST be
refused before dispatch, never ignored. The path and body's `operation` MUST agree.
A request ID is correlation only: it grants no retry or deduplication semantics.
A well-formed reply echoes the operation, request ID and account ID. Authorization
errors may return null IDs rather than disclose an account; malformed requests
may have no usable request ID.

| Operation | POST path | Owning SPS rule |
| --- | --- | --- |
| `create` | `/sps/v1/create` | `baseline/lifecycle` |
| `get` | `/sps/v1/get` | `baseline/lifecycle` |
| `list` | `/sps/v1/list` | `baseline/lifecycle` |
| `destroy` | `/sps/v1/destroy` | `baseline/lifecycle` |
| `run` | `/sps/v1/run` | `baseline/run` |
| `files.read_bytes` | `/sps/v1/files.read_bytes` | `baseline/files` |
| `files.write` | `/sps/v1/files.write` | `baseline/files` |
| `process.start` | `/sps/v1/process.start` | `baseline/process-output` |
| `process.output` | `/sps/v1/process.output` | `baseline/process-output` |

Discovery is not a tenth workload operation. Closing a client handle (`release`)
has no endpoint and MUST NOT destroy or otherwise mutate remote work.

Sandbox identity is the full tuple `(provider_id, account_id, offering_id,
sandbox_id, incarnation)`. Every sandbox operation MUST address that exact
incarnation. Native IDs may be reused only with a new incarnation. Process identity
adds `(process_id, incarnation)` to the full sandbox identity. A PID alone is not
an acceptable identity. Results MUST preserve these identities; list items MUST
belong to the authenticated account and selected offering, if any. The server
MUST fence stale handles so they cannot affect a replacement resource.

Discovery advertises per-request bounds no larger than the schema ceilings:
32 MiB serialized request and response bodies, 16 MiB decoded file or UTF-8 text
output, 1,000 list items or output frames, and 60,000 ms observation time. Lower
advertised limits are permitted and MUST be enforced. Text output limits count
UTF-8 bytes across both streams, not characters or original undecoded bytes.
File limits count decoded bytes; base64 and JSON overhead also count toward the
body limit. Clients check size while reading, before parsing a complete body.
Servers MUST reject known excessive inputs before dispatch. An unexpectedly large
result is a `limit_exceeded` error, never a truncated success. The one exception is
`buffered_commands_v1` command output over its requested per-stream limit, which is
a marked prefix, not an error (see HTTP-4). Discovery itself is
bounded by the 32 MiB ceiling and the client's lower configured response cap.

Configured bounds MUST permit the mandatory result and error envelopes for
identities the endpoint issues and request IDs it accepts. At the maximum
admitted output cap, a server MUST be able to retain and return at least one
four-byte Unicode scalar with its complete frame/envelope. A one-byte overall
output cap or buffer cannot satisfy this requirement. A caller may still choose
a smaller per-read `limit_bytes`, which can fail with 413 under HTTP-6. Admission
and endpoint tests must establish this coherence; schema-valid positive integers
alone do not prove it.

Fields whose sizes interact MUST fit all bounds, including JSON escaping. The
maximum file/text payload need not fit the serialized response cap; such a result
can return an explicit size error. Process servers MUST split new frames to fit
a response before assigning stable sequences, and apply bounded buffering; they
MUST report loss using HTTP-6. After shape validation, a caller requesting more than an advertised limit gets
`limit_exceeded/not_dispatched`, not silently reduced execution semantics. Invalid
wire shapes, including values outside schema ceilings, are `invalid_request`.

## HTTP-3: Create and allocation keys (new wire obligation)

`create` selects an offering/declaration, supplies the existing SPS request and
initial environment, and returns `pending`, `ready`, `unavailable` or `unknown`. `ready` requires
a sandbox identity. `pending` means accepted but not ready; `unknown` means the
allocation outcome cannot yet be established. Either may have a known identity.
`unavailable` requires a known identity and means the allocated sandbox is now
known unusable (for example destroyed or stopped); replay MUST preserve it rather
than allocate again. A definitive initial allocation failure is retained as the
same error under that key, with no new native attempt. Only `ready` authorizes
treating creation as ready for work. Identical-key replay
can obtain a later observation. `get` observes a known identity without creating,
resuming or repairing it. Environment setup and requested resource/image/lifetime
semantics MUST be complete before `ready`. Unsupported requirements MUST fail
before allocation using the existing request checker, declaration and matcher.
No requested gate or condition may be silently discarded.

This wire adds a requirement absent from the SPS baseline: an account-scoped
allocation key MUST bind atomically to one allocation attempt. The key is a
10-digit Unix issuance timestamp, a colon, and a cryptographically random 128-bit
nonce in lowercase hexadecimal. The key window is exactly 86,400 seconds from
issuance. The server accepts a new key only when `issued_at <= now + 60` and
`now < issued_at + 86400`; later future timestamps are invalid. At the expiry
instant and forever afterward it MUST return `expired_key` without dispatch.
The server's UTC clock determines expiry; clients allow for clock uncertainty and
MUST NOT extend the window locally. Authentication and authorization still apply
to a replay. The same key in another account is a different namespace.

The required `SPS-Request-Digest` header is `sha256:` plus the lowercase SHA-256 of
the **exact UTF-8 request body bytes**, including whitespace and request ID. The
server MUST recompute it before dispatch. This avoids requiring a second JSON
canonicalization protocol. A retry MUST reuse the saved body bytes and digest;
reserializing a semantically equivalent object is not an identical retry.

Before native allocation, the server MUST durably and atomically reserve
`(account_id, allocation_key, request_digest)`. Concurrent identical attempts and
replays return the same allocation identity or its pending/unknown observation;
they MUST NOT allocate again. A different digest under an existing key is a
`conflict`, even if current offering selection would otherwise accept it. The
binding MUST survive handler cancellation, lost replies and server restart for
the full key window. Existing keys MUST be looked up before current declaration
admission, so changed offerings cannot strand a valid replay. A crash between
native submission and recording its identity yields `unknown` until reconciled;
it MUST NOT cause another allocation. A native atomic key facility or durable
submit-once handling can satisfy this requirement. It is not a promise of eventual
successful allocation or recovery of an identity after every crash.

The result echoes the key, digest and `key_expires_at = issued_at + 86400`.
The server retains the binding through expiry. Before returning the first
`expired_key` for an account/key, it MUST durably latch that expiry, including
when the key has never been seen before. It can retain permanent per-key
rejection state or durably advance a monotone UTC expiry floor to at least that
key's expiry. Admission and replay MUST consult the latch, including after
restart or UTC rollback. A retained allocation reservation alone is insufficient:
without an expiry latch, rollback could make it replayable again.

With a floor, subsequent key windows use `max(current_UTC, durable_expiry_floor)`;
the floor MUST be persisted before deleting an expired reservation as well.
No durable clock update is required for an ordinary unexpired request. If the
expiry latch cannot be committed, the endpoint MUST fail closed without a new
allocation or an `expired_key` claim. Losing both rejection records and the floor
is not conforming recovery. Expiry does not destroy an allocation or prove that
the original attempt never happened.
A client MUST NOT automatically replace an uncertain key with a new key. Resource
reconciliation and cleanup remain necessary after key expiry.

## HTTP-4: Lifecycle observation and commands

`get` reports the exact incarnation's observed state. `absent` requires an
authoritative native absence result. Provider errors, expired credentials and
transport failures MUST NOT become `absent` or `destroyed`. A failed lookup can be
an error or `unknown`; neither is success evidence. `destroy` distinguishes
`accepted` from observed `destroyed` or authoritative `absent`. Accepted deletion
is not confirmed termination. Destroying an absent exact incarnation may succeed,
but a lost destroy reply is still unknown and MUST NOT be blindly redispatched.

`list` uses opaque cursors bound to account, optional offering filter and server
pagination state. A cursor used with another scope is invalid. `next_cursor=null`
ends enumeration. Pagination is a moving inventory, not a consistent global
snapshot; changes can cause omissions or duplicates across pages. Each page MUST
have unique exact identities; clients deduplicate across pages. A failed page is
an error, not an empty page or proof of absence. Cursors MUST NOT encode credentials
or be accepted as authorization.

`run` executes `argv` directly with the supplied environment overlay and cwd.
`cwd=null` uses the declared default; empty environment leaves inherited variables
unchanged. The initial create environment remains effective unless overridden.
There is no implicit shell; use `bash -c` explicitly. A provider with a shell-only
native interface MUST preserve each argument exactly through verified quoting.
A successful run returns both complete text streams and an observed native integer
exit status; nonzero exit is a successful observation. No exit code is inferred
from EOF, HTTP status, disconnection or an empty stream. Native negative statuses
are preserved if exposed as integers; a signal without an integer status is an
error with unknown exit, not an invented zero.

Text is JSON Unicode, transported as UTF-8. Native text MUST be preserved without
stripping, newline normalization or Unicode normalization. If native output is
bytes, decode each stream with UTF-8 replacement of invalid sequences, maintaining
incremental decoding state across native chunks. Native text is not evidence of
original byte fidelity. `run` succeeds only with `output_complete=true`; missing
output, or text output over the aggregate limit, is an error, even when a native exit status is
known. (`buffered_commands_v1` instead returns a marked prefix; see HTTP-4.)

`observation_timeout_ms` bounds the server's wait, not the workload's execution.
When the wait expires without a complete result, return `timeout` with the known
outcome; never success with a guessed exit. Transport deadlines are separate and
may expire without any reply. This binding neither guarantees termination nor
requires continuation when observation ends. Native termination under a weaker
no-termination-guarantee promise is not a contradiction. A stronger must-continue
or execution-limit mode needs its own support and proof under HTTP-8.

### Version 0.2 buffered command mode

An endpoint MAY advertise `buffered_commands_v1` in `core_modes`. It is an
optional mode on the existing `run` operation, selected with
`mode="buffered_commands_v1"`; it adds no operation or capability catalog.
Requests without `mode` retain the 0.1 text behavior. An unknown mode, a mode
request on 0.1, or a mode absent from the admitted discovery for that sandbox
MUST be refused before dispatch
with the existing `Error` envelope and `unsupported_mode`. Discovery applies the
capability to every listed offering. The producer binds each new allocation to
the selection token returned by discovery. Existing sandbox operations continue
to use their exact incarnation and originally selected modes and capacities;
removing an offering from the current list does not invalidate that allocation.

The request otherwise uses the existing argv, cwd, environment overlay and
account/sandbox incarnation. It runs under the offering's declared default
execution principal. It does not select a user, provide stdin or a PTY, promise
process-byte fidelity, or claim any optional operation. It has
`encoding="base64"`, a positive `execution_limit_ms` (`E`) independent of
`observation_timeout_ms` (`O`), and `output_limit_bytes` (`L`) per stream.
`E` starts at native command dispatch. `O`, connection expiry, disconnect, or
closing a local client handle MUST NOT terminate a dispatched command or stop
its execution timer. The endpoint MUST NOT blindly replay it, and this mode adds
no run lookup endpoint.

If still running at `E`, the native command MUST receive TERM. If its initial
process group remains running, send KILL after five seconds. Retain that
escalation obligation after the leader exits on TERM; do not send KILL early.
Escaped groups are outside this guarantee. Ordinary foreground completion
cancels escalation; ordinary background work survives, and output completion
does not wait for descendant pipe EOF. If termination or observation cannot
establish the outcome, report `unknown`. Exit codes 124, 137, or 143 alone do
not prove a timeout. On execution expiry, do not claim completion until the
termination obligation settles.

Output is byte-exact per stream, including NUL, invalid UTF-8 and empty bytes.
Preserve ordinary nonzero exit status. Finalize both streams after foreground
completion and before the completion receipt. Concurrent writes during
finalization may be included; there is no atomic shared-stream snapshot or
promise of an earlier physical-shell-exit boundary. Later writes through
inherited descriptors MUST NOT alter a completed result. Native implementations
need not use files, copies or any particular guest utility.

A successful mode response echoes mode and encoding and contains
`stdout_base64`, `stderr_base64`, `stdout_bytes`, `stderr_bytes`, `exit_code`,
and `output_complete=true`, with the existing correlation and sandbox identity.
It MUST NOT include UTF-8 `stdout` or `stderr` fields.
Base64 MUST be canonical, counts MUST equal decoded lengths, and each stream
MUST fit `L`. Success MUST NOT downgrade to UTF-8. The result also carries the
booleans `stdout_truncated` and `stderr_truncated`, both required, and no other
partial-output signal.
Retain the existing `Error` envelope and statuses. Observation expiry is
`timeout/unknown`; execution expiry cannot claim `completed` until termination
settles. Exit code alone never determines the outcome.

Output over `L` is not an error. When a command ends with more than `L` bytes
on a stream, the response is still a success: it carries the command's real exit
status and, for that stream, exactly its first `L` bytes with that stream's
`*_truncated` flag `true`. A stream of `L` bytes or fewer is returned whole and its flag is
`false`; in particular a stream of exactly `L` bytes is not truncated. A truncated stream's count is
therefore exactly `L`, and the two flags are independent. The endpoint MUST NOT
replace the result with `limit_exceeded`, MUST NOT terminate the command because
its output reached `L`, MUST NOT replay it, and MUST NOT report completion before
the command has finished: output limits never change when a command ends. A provider that
cannot retain the first `L` bytes of a stream through a command's end MUST NOT
advertise this mode. `output_complete` stays `true`: it says the result is final, not that
no bytes were dropped; `*_truncated` says that. A response without both flags is invalid.

When version 0.2 advertises this mode, it adds only
`buffered_command_output_bytes` (per-stream capacity) and `execution_ms`
(maximum `E`) to `limits`. The first may be below 16 MiB and
remains shape-valid; requests above it are rejected before dispatch. The common
consumer path needs up to 16 MiB per stream. A maximum result with two 16 MiB streams
uses 44,739,248 bytes in base64 before its JSON envelope, so 0.2 permits a
64 MiB serialized response cap. Request bodies remain capped at 32 MiB. The
0.1 32 MiB request/response caps and 16 MiB aggregate UTF-8 command output bound
retain their existing meanings. Providers need not advertise 64 MiB when they
do not offer the mode, nor lower the consumer's supported maximum. The declared
wire cap and schema do not prove bounded native storage.

The offline validator checks advertised capacities against response envelopes,
request and response caps, canonical base64 and both decoded stream bounds. It
does not establish implementation behavior or provider eligibility. Mode and
capability, credential, offering, image/default-principal and capacity admission
must be completed before workload allocation when those requirements are known;
the existing declaration and matcher remain the source of native facts.

## HTTP-5: Exact native files

`files.read_bytes` reads a whole file through the provider's native file interface;
`files.write` writes decoded bytes to a file in an existing directory through that
interface. Standard padded base64 is canonical: decoding and reencoding MUST give
exactly the transmitted string. `byte_count` MUST equal the decoded length.
Empty files are valid. Read limits apply to the whole file: oversized or incomplete
reads fail and MUST NOT return a successful prefix. A successful write reports the
entire requested byte count, never a partial success.

Paths are absolute, NUL-free native guest paths. The endpoint MUST confine file
operations to the identified sandbox; it MUST NOT interpret them as host paths.
Native symlink/permission behavior remains subject to sandbox isolation. Native
file authority MUST be stated as an existing provider/account/image condition and
admission evidence: it may be a control-plane/root principal even when commands
use an unprivileged default user. This binding does not claim the native file
principal equals the declared command default user. A consuming client MUST refuse
any default- or selected-user file guarantee not established for that authority. No
selected-user mode, automatic parent creation, atomic replace, fsync, stable
snapshot of a concurrently changing file, or privileged access is implied. A
partial or uncertain write returns an error whose outcome remains unknown unless
native evidence establishes failure or completion. Files MUST NOT be implemented
by a command capture/upload protocol as a substitute for native byte IO.

### File links and streamed transfer

HTTP-5's whole-body, base64 rule applies only to `files.write` and `files.read_bytes`.
It does not apply to file links ([`file_links`](vocabulary.md#file_links)) or to streamed
transfer ([`file_stream_max_bytes`](vocabulary.md#facts-and-resources)), which move bytes
without base64 and without holding the whole file in one message. Binding versions 0.1 to
0.3 define no operation for either; a binding version that adds them follows these rules:

- `files.link` takes the sandbox, an absolute `path`, an `operation` (`read` or `write`), a
  `lifetime_seconds` and an optional `user`, and returns the link as `url`, `method`,
  `headers` and an optional `form_field`. The client sends exactly that request, to the
  link's own host, with no binding credential; the URL and header values are secrets and
  never appear in logs or reports.
- A streamed write sends the file's raw bytes as the request body, with `Content-Length` or
  chunked transfer encoding, and names the exact `size` beforehand. Fewer or more bytes than
  `size` fail the write, whose outcome is unknown once any byte was sent.
- A streamed read returns the file's raw bytes as the response body, with
  `Content-Length` when the size is known. A body that ends early is a failed read, never a
  complete file.
- Bodies are not capped by HTTP-2's message limits; a provider's size limit is its declared
  `file_stream_max_bytes`.

## HTTP-6: Native background output, retention and exit

`process.start` uses the provider's native background-process facility and returns
an identity after observing native acceptance. It does not wait for completion.
Neither an uploaded supervisor nor `nohup`, PID files or streamed foreground
`run` can create a missing facility. Cwd, arguments and environment follow HTTP-4.
The process remains addressable for observation while this endpoint instance
retains the handle; `process_addressability=endpoint_lifetime` does not promise
reattachment after restart or durable history. A lost start reply is an unknown
mutation and MUST NOT be repeated automatically.

`process.output` is bounded polling, not a PTY or writable process attachment.
The first cursor is zero. Each nonempty frame has a monotonically increasing
integer sequence and exactly one of stdout/stderr. Text follows HTTP-4's decoding
rule. A sequence orders observations; it makes no claim about simultaneous writes
across streams. Native chunks may be combined or split at Unicode scalar
boundaries. Once assigned, a retained sequence's stream and text MUST be stable. It MUST NOT be
split differently on subsequent polls. `limit_bytes` bounds the returned UTF-8
text across both streams. If the next retained frame cannot fit that request
bound or the serialized response cap, return `limit_exceeded` without advancing
the cursor; do not return an empty success that can never progress. A four-byte
Unicode scalar cannot fit a one-byte bound and MUST fail this way. Clients may
retry this read with a larger admitted bound; no process is restarted.

The response begins at `max(request.cursor, first_available_cursor)`, with
contiguous sequences and `next_cursor` immediately after the returned frames.
`gap` MUST equal `first_available_cursor > request.cursor`. On an empty page, `next_cursor = max(request.cursor, first_available_cursor)`: it
advances over a reported lost prefix even without frames. The first-available
cursor and issued high-water mark MUST be monotone and the former MUST NOT exceed
the latter, including across empty reads. A request beyond the highest cursor ever issued
is invalid, not an empty page that invents history. Sequence exhaustion MUST be
reported as `output_unavailable`, never wrapped or silently reused.

`process_retention_seconds` is the maximum age of retained frames, measured from
endpoint observation, not a durable-history guarantee. The advertised
`process_buffer_bytes` bounds retained UTF-8 text per process across both streams.
Frames may be evicted sooner under that capacity bound, oldest first; every lost
prefix MUST advance `first_available_cursor` and produce `gap` for an affected
reader. A disconnected reader does not apply backpressure to the remote process
or get an unlimited spool. Servers MUST make output observable while running;
an implementation that always drops it before any read fails the SPS baseline.
Loss of the cursor/identity state itself is `output_unavailable`, never a reset
to cursor zero pretending that no output was lost.

`stdout_eof` and `stderr_eof` mean native stream closure has been observed and all
retained frames of that stream through closure have been returned by this cursor.
They do not imply process exit: a program may close both descriptors and keep
running. `execution_state=exited` requires a native integer `exit_code`; running or
unknown state requires null. Observed exit does not mean all output was drained.
A consumer drains remaining frames until both EOF flags are true; any gap remains
visible and prevents a claim of complete history.

`observation_end` explains why this read ended: `page` (bounded page),
`wait_timeout` (no further observation before deadline), `stream_end` (native EOF),
`process_exit` (native exit), or `unavailable` (observation lost). It does not replace
execution state. `stream_end` requires at least one EOF flag; `process_exit`
requires exited state; `unavailable` requires unknown state and MUST NOT invent
EOF. Deadline expiry or client disconnect MUST NOT create an exit observation.
Process cancellation, stdin and reconnecting native attachments are unbound modes.

## HTTP-7: Errors and uncertain mutations

An HTTP 200 carries the operation's validated result. An error carries `Error`;
clients MUST validate both shape and correlation before trusting any field.
A malformed or missing response after a mutation has unknown outcome. Client
libraries MUST disable automatic POST retries for run, start, write and destroy,
including after 5xx, timeout or disconnection. Create is replayable only as HTTP-3
allows. Read-only operations may be retried within observation/credential bounds;
a retry observes the current state, not a prior snapshot.

| HTTP status | Error code |
| --- | --- |
| 401 | `unauthenticated` |
| 403 | `forbidden` |
| 409 | `conflict` |
| 410 | `expired_key` |
| 413 | `limit_exceeded` |
| 422 | `invalid_request`, `unsupported_mode` |
| 502 | `provider_error`, `output_unavailable` |
| 504 | `timeout` |

Discovery authentication errors use empty 401/403 bodies, disclosing no identity.
For errors on a recognized operation route, `Error.operation` MUST come from the
route, including when the JSON body cannot be decoded or supplies another
operation. Unavailable or invalid request/account IDs are null. Unknown routes
return an empty 404; they MUST NOT invent an operation identity.

The offline validator's `BindingValidationError` remains a `ValueError` and adds
`code`: `invalid_request` for malformed shapes/values, `limit_exceeded` for decoded
or serialized input above an advertised bound. Endpoints can map a pre-dispatch
rejection through the shared status table without duplicating the bounds. The
exception does not determine native outcome; after dispatch, an invalid reply is
a provider contract violation and cannot establish `not_dispatched`.

For operation errors, `outcome` is one of:

- `not_dispatched`: this attempt made no native workload call. It says nothing
  about an earlier uncertain attempt under the same key or identity.
- `failed`: a native operation returned a definitive failure. This is not a
  rollback guarantee; a failed mutation may have partial effects.
- `unknown`: the effect or completion cannot be established.
- `completed`: native completion is known, but the requested result could not be
  delivered, for example because output exceeded a bound.

An error's exit code is non-null only for `run` with `outcome=completed` and an
observed native exit. Input, authorization, conflict and expired-key errors MUST
be `not_dispatched`. Diagnostics MUST be sanitized and bounded; never include
credentials, command contents, environment values, file contents or native stack
traces. Unknown native outcomes MUST NOT become definite failures merely because
they are represented by an exception. Neither `failed` nor `completed` authorizes
a blind mutation retry.

## HTTP-8: Guarantee mapping and refusal

| Requirement | Binding status and authority |
| --- | --- |
| Lifecycle, cwd/env, separate text streams and truthful exit | Required; `baseline/lifecycle`, `baseline/run`; HTTP-2/3/4 |
| Exact file IO in existing directories | Required native interface; `baseline/files`; HTTP-5 |
| Background output observable before exit | Required native facility; `baseline/process-output`; HTTP-6 |
| bash/python3, public HTTPS unless restricted, no host metadata | Unchanged required baseline: `baseline/environment`, `baseline/outbound-network`, `baseline/no-metadata`; provider/runtime proof still required |
| Account identity, HTTPS/discovery, bounds, correlation, unknown outcomes | Explicit new wire requirements; HTTP-1/2/7 |
| Atomic account-scoped create keys and expiry | Explicit new wire requirement, not existing SPS or native-API proof; HTTP-3 |
| Byte-exact command output | Bound by `buffered_commands_v1` in 0.2 when selected and mandatory in 0.3, per stream; otherwise text output is UTF-8 replacement-decoded |
| Process output byte fidelity and binary pipelines | Not bound. Process frames remain text and do not establish process-byte fidelity or pipeline semantics; consumers requiring either MUST refuse |
| Per-command execution limit or guaranteed continuation after timeout | Bound by version 0.2 `buffered_commands_v1` when selected and mandatory in 0.3, with its execution and observation rules; otherwise consumers requiring either MUST refuse |
| Selected-user execution or arbitrary reads as a selected user | Not bound. Default-user native files do not prove this mode; refuse |
| Files mkdir/list/exists/remove | May use ordinary native commands under the SPS baseline. No equivalent portable composition is proven here |
| Process stdin/cancel/reattach, PTY, pause, snapshots, previews, image build, secrets or other optional operation families | Existing declaration vocabulary remains authoritative; no optional operation bindings are supplied by this version |

`core_modes` is exactly empty in version 0.1. A native gate declaration does not
invent a wire operation or authorize a client to infer its support. Create-time
requirements can be fulfilled only where the existing declaration/matcher and
native creation actually support them; any requirement needing an unbound runtime
operation MUST be refused for that workload. No second capability matrix is added.
Optional bindings require an explicitly specified version and mode, not ignored fields.

Where a consumer's existing unconditional guarantee cannot be satisfied by this
binding, the endpoint MUST NOT be selected for that workload. Refusal MUST happen
before allocation, not after creating a sandbox and discovering a missing mode. Exact file-based output
capture, guest `timeout`, or text-marker protected-file checks are possible shared
compositions to evaluate separately; none is certified equivalent by these
fixtures. Existing consumer guarantees and provider-native behavior remain in
force. This binding does not permit omitting required binary output or relaxing those
guarantees.

## Proof boundary

The schema/drift tests cover every operation's valid request/result and rejection
shapes. Offline semantic fixtures cover correlation, identity, bounds, exact file
encoding, create-key replay/conflict/expiry/lost response, failed lookup, process
cursor gaps, EOF without exit, deadlines and disconnect. Synthetic declarations
are shape examples, not conformance evidence. Offline create traces constrain
outcomes; they do not implement or prove atomic storage, races or crash recovery.

PP2 must prove the actual client's strict parser, origin admission, credential
binding, redirects, bounded IO, configured-bound coherence, retry prevention and
consumer-path refusal/composition behavior. The offline discovery validator checks shapes and
local consistency; it does not prove that the configured caps can serve required
envelopes or arbitrary Unicode output.
PP3 must prove all nine native handlers, including allocation races/restarts,
expired keys, sandbox identity reuse, output while running and native cleanup.
PP4 must prove a second implementer can use these artifacts and obtain an honest
report. Existing conformance suite/report adoption, release distribution and
hosted routing remain separately owned. No provider call or passing onboarding
claim follows from this PP1 definition.

## HTTP-9: Binding version 0.3 admission and recovery

Version `sandbox-provider-http/0.3` uses the same nine workload operations and
all identity, correlation, error and key rules above. It adds no negotiation,
headers, RPCs or native declaration vocabulary. Discovery for 0.3 MUST advertise
`buffered_commands_v1`; its execution and observation semantics in HTTP-3 remain
mandatory. Native file reads and writes MUST use the same default principal and
authority as ordinary commands. Access through an archive or privileged control
plane is not equivalent. A provider unable to establish that authority MUST
refuse the create before allocation. Process frames remain text; 0.3 does not
bind original-native byte fidelity, stdin, cancellation, reattachment, PTY or
other unlisted operations.

A 0.3 create request adds `labels`, a map of at most 32 string entries. UTF-8
keys are at most 63 bytes and values at most 255 bytes; NUL is forbidden in both.
The ASCII-escaped serialized JSON map is at most 64 KiB. Labels are caller-supplied
observations only. A reserved or grant-looking label MUST NOT create or broaden
any capability. Lifetime policy continues to use `lifetime_seconds` and `at_end`
inside the existing SPS request; no second lifetime input is defined.

Create and get results carry separate `admission`, `labels` and `lifetime`
members. `admission` is immutable for that allocation and contains:

- `selection`: the original binding, core modes, advertised limits, process
  retention and addressability, and exactly the selected offering with its
  selection token and declaration;
- `requirements`: the normalized requirements accepted from the create request,
  never additional gates or grants copied from the declaration;
- `resources`: the exact resource facts selected by declaration fitting, using
  selected-value names such as `size` (`cpu`, `memory_mib`, `disk_mib`), `region`,
  `gpu` (`model`, `count`), `root`, `arch`, `egress_ips`, `kernel_features` and
  `outbound_traffic`; and
- the originally accepted `lifetime_seconds` and `at_end`, nullable when the
  request omitted them.

Selected resource facts are not request asks. A fitted size may contain only the
fields the matcher established, including a disk-only `size`; `region` may be
null when declared `located_in` establishes the requested place without pinning a
provider region. Resource objects reject request-only keys and unknown fields.

The descriptor MUST NOT contain the original full request, create environment,
credentials or secrets. A present allocation MUST have retained admission.
A pending or unknown create with no native identity, and a truly absent get, may
return null admission/observations. A producer MUST NOT invent metadata for an
allocation that has none. `labels` and `lifetime` are observed mutable state, not
part of the grant. `lifetime.ready_at` and `lifetime.ends_at` are UTC timestamps
or null when not established. A response claiming `ready` while a lifetime was
requested MUST establish the actual timer policy and clock before it is ready;
stopped does not mean destroyed, and no reaper fallback is implied. List items
include actual labels and lifetime observations, but do not repeat full
admission.

Admission is retained for the resource's lifetime, independently of the
86,400-second allocation-key replay window. Exact account/key/body replay is
resolved from the retained reservation before consulting mutable current
discovery; a replay MUST NOT be rejected because its original offering or caps
have since disappeared or shrunk. The original selection is never replaced by
new discovery. After recovery, workload exchanges use that retained selection.

A bootstrap get that recovers admission uses a fixed 4 MiB control-response
ceiling, independent of current workload response limits and further limited by
the client's configured local control-response cap. This fixed protocol ceiling
is not a discovery knob. Its identity request uses the existing 32 MiB protocol
request ceiling rather than the workload request cap. A create whose complete
retained admission descriptor cannot fit within that envelope MUST be rejected
as `limit_exceeded` before key reservation or native dispatch. The client
authenticates the response, checks
correlation and the full provider/account/offering/sandbox/incarnation identity,
and only then accepts admission. It MUST NOT use present-day discovery as a
substitute when retained selection is unavailable.

For a genuinely new 0.3 create, the producer validates bounded wire shape and
body first, checks the account-scoped key and exact body, and handles an existing
replay or conflict before mutable declaration fitting. For an unreserved key it
selects the current offering, invokes the pure declaration-fit check, constructs
and bounds admission, and only then reserves the key and dispatches. Malformed
shape is `422 invalid_request`; a valid value exceeding a configured or protocol
bound is `413 limit_exceeded`; an incompatible declaration is `422
invalid_request` with bounded diagnostics. Strict conformance matching continues
to require current baseline proof. Declaration fit answers compatibility only;
it does not establish runtime availability, account/funding admission or
`proven_only` eligibility.
