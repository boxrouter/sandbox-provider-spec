# Provider API 1.0: the normative rules

This page holds the rules of the provider API that span several operations. The shapes and the
meaning of every field are in the [OpenAPI file](provider-api-1.0.openapi.yaml);
this page does not repeat them. A provider conforms in one of two ways: it serves the HTTP API at an HTTPS base URL
that it chooses, or it ships a Python package that implements the `Provider` class. Both forms
carry the same rules.

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT** and **MAY** are used as in
[spec.md](spec.md#2-conventions). Each rule sentence ends with a rule comment in the form that
spec.md describes, under the topic `provider-api`; tests cite the rules by those ids. Paths such as `/v1/sandboxes` are relative
to the provider's base URL. An operation has a dotted name (`files.read`); its Python method and
its OpenAPI `operationId` replace each dot with an underscore (`files_read`).

## 1. Credentials

Every request, discovery included, carries `Authorization: Bearer <token>`. The token is the
provider account's own API token, as the provider issues it, and it decides the account. A request
has no other credential and no field that names an account.

- A provider **MUST** accept the bearer token as the only credential and **MUST** answer a request <!-- rule: provider-api/bearer-only -->
  with a missing, wrong or expired token with `unauthenticated`.
- A provider **MUST NOT** put a token in a result, an error message or a log line, and **MUST NOT** <!-- rule: provider-api/no-credential-echo -->
  send it to another host.

A Python adapter receives the same authority as a mapping from its declared credential fields to
their values. A provider whose API needs several values (a key id and a secret, or a key and a
team id) declares several fields.

## 2. Requests and unknown fields

Control requests and results are JSON (`application/json`, UTF-8). A request body is at most 1 MiB.

- A provider **MUST** refuse a request that has a field this contract does not define, with <!-- rule: provider-api/unknown-fields-refused -->
  `invalid_request`, so that a requirement is never dropped silently.

A consumer ignores result fields that it does not know. A provider may add result fields only with
the prefix `x-<provider_id>-`. A newer consumer therefore learns when an older provider cannot
honor a field, and an older provider never drops it.

## 3. Identifiers

`sandbox_id` and `process_id` are chosen by the provider: 1 to 128 characters from
`A-Z a-z 0-9 . _ : -`, so that they fit in a URL path unescaped.

- A provider **MUST NOT** reuse an id for a different sandbox, or for a different process in the <!-- rule: provider-api/ids-not-reused -->
  same sandbox, for as long as it keeps any record of the id.

A `destroy` sent with an old id can therefore never end a newer sandbox.

## 4. Creating a sandbox

`create` takes an `Idempotency-Key` header of 8 to 63 characters from `a-z 0-9 -`, starting with a
letter or a digit (a UUID fits).

- Within 24 hours, a repeated `create` with the same key **MUST NOT** make a second sandbox: with <!-- rule: provider-api/idempotent-create -->
  the same body it returns the sandbox that the first create made, with status 201; with a
  different body it is refused with `conflict`; while the first create is still in progress it is
  refused with `conflict` and `retry_after_seconds`.

A consumer sends a repeat only after an earlier create's outcome was unknown, and never sends two
creates with one key at the same time.

- A provider **MUST** return from `create` only when the sandbox can serve `run`, `files.*` and <!-- rule: provider-api/create-returns-running -->
  `process.*`, and the result's state **MUST** then be `running`.
- A provider **MUST** end the sandbox in the `at_end` state no later than `lifetime_seconds` after <!-- rule: provider-api/lifetime-enforced -->
  `create` returns, even if the consumer has gone away.

A provider refuses a lifetime above the class's `max_lifetime_seconds` with `unsupported`. A
provider that cannot run a sandbox without a lifetime refuses `lifetime_seconds: null` with
`unsupported`. A request that no size, region, image, class or section can meet is refused with
`unsupported`, and nothing is created.

## 5. Labels and `list`

Labels are a map of at most 32 entries. A key is 1 to 63 bytes from `A-Z a-z 0-9 _ . / -`; a value
is 0 to 255 bytes of UTF-8. They carry no meaning for the provider and never change what a
sandbox may do.

- A provider **MUST** return a sandbox's labels exactly as given at create from `get` and `list`, <!-- rule: provider-api/list-labels-exact -->
  and `list` **MUST** return a sandbox when it has every `label` filter with exactly that value,
  and not otherwise.

`list` returns sandboxes that have not ended (`running`, `paused` or `stopped`). The order is
unspecified and the cursor is opaque. A sandbox created or ended during paging may appear twice or
not at all. The first `=` in each `label` value separates the key from the value.

## 6. Destroying a sandbox

- A provider **MUST** return from `destroy` as soon as it has accepted the request, with the <!-- rule: provider-api/destroy-on-acceptance -->
  sandbox ending without any further call from the consumer.
- A repeated `destroy` of an ending or ended sandbox **MUST** succeed with state `destroyed`, and <!-- rule: provider-api/destroy-repeat -->
  a `destroy` of an id that the provider has no record of **MUST** return `not_found`.

After `destroy` returns, `get` may report the last state for a short time and then `destroyed` or
`not_found`; `list` stops returning the sandbox once it has ended. While the provider keeps a
record of an ended sandbox, `get` returns it with state `destroyed`. A consumer treats both
`destroyed` and `not_found` as ended. `get` only observes: it never resumes, wakes or extends a
sandbox.

An operation on a destroyed sandbox returns `not_found`; on a paused or stopped one it returns
`conflict` unless the operation exists for that state.

## 7. Commands

`run` holds the call open until the command ends; longer work uses `process.start`. Running a
command and getting a nonzero exit code is a result, not an error. The exit code is 128 + N when
signal N ended the command.

- When `timeout_ms` passes, a provider **MUST** end the command and every process that the command <!-- rule: provider-api/run-timeout-ends-command -->
  started, and **MUST** return the output so far with `timed_out: true`.

A timeout is a result, not an error. A missing `cwd` is refused with `not_found`.

`run` and `process.start` take an optional `user`, and `files.write` an optional `user` query
parameter. They name the operating-system user who runs the command, starts the process or
creates the file. Null or omitted means the class's default user, and the rules of
`user_selection` (`vocabulary.md`) say what a class that claims a knob **MUST** do. A class that
does not claim the knob answers `unsupported` to a request that names a user. A user that the
sandbox does not have is `not_found`.

`run` takes an optional `output`, `text` (the default) or `base64`. With `base64`, the result holds
the exact bytes of each stream as `stdout_base64` and `stderr_base64`, and its `stdout` and
`stderr` are empty.

- A class that lists `run.base64` in `classes[].operations` **MUST** answer `output: base64` <!-- rule: provider-api/run-base64 -->
  with the exact bytes that the command wrote to each stream, up to `output_limit_bytes`, in
  `stdout_base64` and `stderr_base64`, and **MUST** leave `stdout` and `stderr` empty. A class that
  does not list it answers `unsupported`.

## 8. Files

Both file operations stream raw bytes (`application/octet-stream`), so that one operation serves a
10-byte file and a 5 GiB file. Paths are absolute, at most 4096 bytes, with no NUL byte and no
component over 255 bytes, and they name paths in the filesystem that commands see.

- A file operation **MUST** move the whole file or fail: a provider **MUST** end `files.read` with <!-- rule: provider-api/files-whole-or-fail -->
  the last byte (or the terminating chunk) and report `files.write` as done only after every byte
  is in the file, so that a connection that ends early is a failed read, never a short file, and a
  body shorter or longer than `Content-Length` fails with `invalid_request` and outcome `unknown`.
- A provider **MUST** accept files of at least 1 GiB in both directions, and discovery's <!-- rule: provider-api/files-limit-floor -->
  `limits.file_bytes` **MUST NOT** state less than 1073741824.

A missing file is `not_found`; a directory is `invalid_request`; a file over `limits.file_bytes`
is `too_large`. `files.write` creates the file or replaces its whole content, so repeating it with
the same bytes gives the same result. A consumer that needs only a prefix may close a read early.

- When the parent directory of a `files.write` path is missing, a provider **MUST** do one of two <!-- rule: provider-api/files-write-parents -->
  things: create every missing directory on the path, as `mkdir -p` would, and write the file; or
  refuse with `not_found` and create nothing. A consumer relies on neither: to have parents
  created, it makes them itself and writes again. Providers differ here natively, so the contract
  allows both instead of making an adapter check the parent before every write.

## 9. Background processes

A process keeps running after `process.start` returns and while nobody reads its output. The
provider keeps at least `limits.process_output_bytes` of the newest output per stream, and the
record for at least `limits.process_retention_seconds` after the process exits; afterwards
`process.output` returns `not_found`. Output between a cursor and the first returned chunk that
was discarded is reported with `gap: true`.

- A provider **MUST** report that a process has exited only with `state: exited` and an <!-- rule: provider-api/process-eof-not-exit -->
  `exit_code`, and **MUST NOT** treat the end of standard output or standard error as an exit.

Closing both streams does not mean that the process exited: a process can close its streams and
keep running, or exit while a child holds a stream open. This is the rule of the baseline test
`baseline/process-eof-not-exit`.

## 10. Cost

`cost` is offered, not required. A provider offers it by stating `limits.cost_final_within_seconds` <!-- rule: provider-api/cost-offered -->
in discovery. Without that value `cost` answers `unsupported`, and a consumer treats the provider
as one that does not state a cost.

`cost` returns what a sandbox cost: a `status` of `accruing` or `final`, a `source` of `reported`
or `calculated`, the `lines` and their `total_usd`, and `as_of`. `reported` means that the
provider's own records state the amounts. `calculated` means that each quantity comes from the
provider's own usage records and is multiplied by the provider's published price. It works in
every state of the sandbox. The sandbox ends when `get` reports it `destroyed` or it is gone;
every timing rule here counts from then.

A line has an `item` and an `amount_usd`. `quantity` and `unit` are required when `source` is
`calculated`, as what the amount was priced from, and optional when `source` is `reported`. `start`
and `end` give the period that the line covers, which may be a billing period (such as an hour)
that contains the usage. Both null means that the line covers no period, as
a fee does. `start` set with `end` null is an open period, which runs up to `as_of` and is allowed
only while the status is `accruing`. `total_usd` is the sum of the line amounts. While the status is
`accruing` and nothing is metered yet, `total_usd` may be null and `lines` empty. A sandbox for which
the provider bills nothing returns one line with the amount `"0"`. An amount of `"0"` always means a
true zero, never "not counted yet".

- A provider **MUST** take the quantities of a cost from its own records of the sandbox, never <!-- rule: provider-api/cost-provider-records -->
  from a clock in the consumer or in an adapter.
- Amounts **MUST** be the provider's published list price when the usage happened, in US dollars <!-- rule: provider-api/cost-list-price -->
  as decimal strings, before any plan, free tier, trial, credit or discount. The prices in discovery
  are list prices too: a plan or discount on an account never changes them. A `reported` cost
  states those list amounts in the provider's records. A source that states amounts net of a
  discount is turned into list amounts from its quantities, and the cost is then `calculated`.
- `as_of` **MUST** be the time up to which the figures count usage. It may be earlier than the <!-- rule: provider-api/cost-stated-at -->
  time of the read, for records that lag.
- A `calculated` line's `amount_usd` **MUST** equal its `quantity` times the price that discovery <!-- rule: provider-api/cost-priced-from-discovery -->
  states for its `item` and `unit`, rounded to the decimal places that the amount states (a
  difference of at most half a unit in the last of them is rounding). Where discovery states several
  prices for them (by size, region or variant), one of them applies. The tester does not check a line
  whose `item` and `unit` discovery does not price.
- Every line **MUST** have an `item` and an `amount_usd`, and a `calculated` line **MUST** also <!-- rule: provider-api/cost-lines -->
  have a `quantity` and a `unit`. `total_usd` **MUST** be the sum of the line amounts, or null
  where the paragraph above allows it.
- A provider **MUST** make the cost `final` within `limits.cost_final_within_seconds` after the <!-- rule: provider-api/cost-final-within -->
  sandbox ends, or, when the cost includes storage that outlives the sandbox, after that storage
  ends. `final` means that the figures **MUST NOT** change afterwards. A `final` cost has a
  `total_usd` and no open line. The provider chooses the number and states it as it is.
- A provider **MUST** keep the cost readable after the sandbox ends at least until it is `final`. <!-- rule: provider-api/cost-retained -->

While the sandbox exists, `cost` returns the cost so far with status `accruing`. SPS defines no
correction after `final`: a consumer that finds a later difference reconciles it itself.

## 11. Errors

An error has an HTTP status and a body with `code`, `message`, `outcome` and
`retry_after_seconds`. `message` is for people: at most 1024 characters, with no credentials and
no response bodies from other systems. `outcome` is `failed` when the operation had no effect and
`unknown` when it may have taken effect. Caller-fault codes have outcome `failed`, except
`invalid_request` when a streamed file upload is shorter or longer than its declared size; that
outcome is `unknown` because some or all bytes may have been written.
`retry_after_seconds` is set when retrying later can work, and the same value goes in a
`Retry-After` header. The `code` is authoritative; the HTTP status only mirrors it.

| Code | HTTP | Fault |
| --- | --- | --- |
| `invalid_request` | 400 | caller |
| `unauthenticated` | 401 | caller |
| `forbidden` | 403 | caller |
| `not_found` | 404 | caller |
| `conflict` | 409 | caller |
| `too_large` | 413 | caller |
| `unsupported` | 422 | caller |
| `quota_exceeded` | 402 | caller |
| `rate_limited` | 429 | caller |
| `unavailable` | 503 | provider |
| `timeout` | 504 | provider |
| `provider_error` | 500 | provider |

- A provider **MUST** use each code with the HTTP status and the fault of this table, and a <!-- rule: provider-api/error-fault-fixed -->
  consumer **MUST** treat the fault as fixed by the code, whatever the message says.

A response without a valid error body (a dropped connection, or an HTML page from a proxy) counts
as `provider_error` with outcome `unknown`. In a Python adapter, any exception other than
`SpsError` counts as `provider_error` with outcome `unknown`.

## 12. Retries

`discovery`, `get`, `list`, `files.read`, `process.output` and `cost` change nothing and are safe
to retry. `create` is safe to retry with the same `Idempotency-Key`, and `destroy` and
`files.write` are safe to repeat. `run`, `process.start` and `process.write_stdin` are never
retried after an `unknown` outcome, because they could run a command twice.

## 13. Versioning

The standard follows semantic versioning. The URL path carries the major version (`/v1`).
Discovery's `spec_version` and an adapter's `spec_version` carry `major.minor`.

A 1.x minor release only adds. It may add optional operations, optional request fields, result
fields and vocabulary, and it never adds or changes an error code: the twelve codes stay fixed for
all of 1.x. Nothing that a 1.0 provider does becomes wrong in a later 1.x. A consumer reads
`spec_version` and sends only the fields of that minor or older; because a provider refuses
unknown request fields (section 2), a requirement is never dropped without notice. A 2.0 would be
a new path (`/v2`), served beside `/v1` for a transition period.

## 14. The adapter manifest and author rules

Each adapter's Python package holds `sps-provider.yaml`, with `provider_id` (`a-z 0-9 -`, 2 to 32
characters, the entry point's name), `name`, `spec_version`, `credential_fields` (each with
`name`, `secret` and `description`) and `api_domains`. Each `api_domains` entry is an exact host
name or a suffix written with a leading dot (`.example.com`), which matches every host under it.
The package validates the manifest against a schema when a `Provider` subclass is defined. Release
tools, the tester and hosts read the file without importing the adapter.

Rules for adapter authors:

- The adapter calls only the hosts in `api_domains`, and only with the credentials that it was
  given. It does not read environment variables, files outside its package, or global state.
- Its dependencies are the provider's own SDK and `httpx`.
- It never logs or returns a credential, and never puts a provider's raw response body in an
  error message (rule `provider-api/no-credential-echo`).
- It may hold HTTP clients and caches of provider data, but nothing that a later call needs for
  correctness: a consumer may create a fresh instance for every call.

## 15. The served token

The reference server (`sandbox-provider-spec serve`) serves any adapter over the HTTP API. It
builds the adapter's credentials from each request's bearer token.

- A server **MUST** read the bearer token of an adapter with one declared credential field as that <!-- rule: provider-api/served-token-encoding -->
  field's value; of an adapter with several, as `sps1.` followed by the unpadded base64url
  encoding of a JSON object that maps every declared field name to its value; and **MUST** answer a
  token that does not decode to exactly the declared fields with `unauthenticated`.

The server keeps at most one adapter instance per distinct token, for a bounded time, and calls
`aclose()` when it drops one. `--socket` serves plain HTTP on a Unix socket for a host that
isolates each adapter; `--port` binds to 127.0.0.1 unless `--host` says otherwise. TLS is the job
of whatever fronts the server.

## 16. Terminals

A terminal is a program, by default a login shell, on a pseudo-terminal in the sandbox, driven
over one WebSocket that carries input, output, resizes and the exit status. It belongs to the SPS
gate `terminal`. Version 1.0 covers the variant with `reattach: false`; a provider that claims
`reattach: true` gets no reattach operation in 1.0. `terminal.open` is described in the
[OpenAPI file](provider-api-1.0.openapi.yaml); this section holds the link rules and the messages
that travel on the WebSocket.

**The link.** `terminal.open` returns a `url`, the `headers` to send with it and `expires_at`.

- A provider **MUST** sign the link so that a client that sends only the URL and `headers` is <!-- rule: provider-api/terminal-link -->
  served, with no credential of the consumer; **MUST** serve it once only; and **MUST** refuse a
  second connection, and one after `expires_at`, with an HTTP status from 400 to 499 before the
  upgrade. The link is a `wss://` URL (`ws://` only where plain HTTP is allowed), and `expires_at` is
  30 to 600 seconds after the call.

A link without the account's token lets a consumer hand it to a browser, which cannot set an
`Authorization` header on a WebSocket. Treat the URL as sensitive and never log it.

**Start.** `terminal.open` checks the sandbox (`not_found`; `conflict` when it is not running) and
the fields, and starts nothing.

- A provider **MUST** start the program when the link is connected: on a new pseudo-terminal of the <!-- rule: provider-api/terminal-start -->
  given size, as the class's default user, as the leader of a new session and process group, with
  `TERM` set to `term`, `env` added to the sandbox's environment, and `cwd` as the working
  directory, and **MUST** report a missing `cwd` as a `not_found` error message.

**Messages.** Binary frames are bytes; text frames are JSON control messages. A frame carries at
most 65536 bytes.

- A provider **MUST** carry the messages of this list, and **MUST** refuse a text frame that is not <!-- rule: provider-api/terminal-messages -->
  valid JSON, has an unknown `type` or has an unknown field with an `error` message
  `invalid_request`, then close the connection.
  - A binary frame from the client is input: its bytes reach the terminal in the order sent.
  - A binary frame from the provider is output: the bytes that the terminal produced.
    Standard output and standard error are one stream on a terminal, and the provider converts no
    encoding.
  - `{"type": "resize", "columns": c, "rows": r}` from the client sets the terminal's size, and the
    program receives `SIGWINCH`.
  - `{"type": "exit", "exit_code": n}` from the provider says that the program exited, with
    128 + N when signal N ended it.
  - `{"type": "error", "error": {...}}` from the provider carries an error body (the
    [error table](provider-api-1.0.openapi.yaml)), for example `not_found` for a missing `cwd`,
    or `quota_exceeded` for a connection beyond the capacity limit. The provider then closes with
    code 1011.
- A provider **MUST** deliver output in order, and **MUST NOT** reorder, drop or repeat output while <!-- rule: provider-api/terminal-ordered-output -->
  the connection lives.
- A provider **MUST** apply a `resize` message to the pseudo-terminal, so that the program sees the <!-- rule: provider-api/terminal-resize -->
  new size and receives `SIGWINCH`.
- A provider **MUST** send the `exit` message after the last output frame and then close the <!-- rule: provider-api/terminal-exit -->
  connection with code 1000.

**End.** 1.0 has no operation to reconnect.

- When the connection closes for any reason other than the program's exit, a provider **MUST** end <!-- rule: provider-api/terminal-close-ends -->
  the terminal: it sends `SIGHUP` to the terminal's process group, then `SIGKILL` to what remains
  of the group 5 seconds later. A process that left the group (`setsid`) is not part of the terminal.

**Liveness.** A pause, stop or end of the sandbox ends its terminals: the provider closes each
connection with code 1001.

- A provider **MUST** answer WebSocket pings, **MUST** send a ping at least every 30 seconds, and <!-- rule: provider-api/terminal-liveness -->
  **MUST NOT** end a terminal for being idle while the connection lives and the sandbox runs.

**Capacity.** A provider serves at least 4 open terminals per sandbox at once. A connection beyond
its limit gets an `error` message `quota_exceeded`.

## 17. Snapshots

A provider that claims the `snapshots` section (`vocabulary.md`) implements `snapshot.create`,
`snapshot.get`, `snapshot.list`, `snapshot.delete` and `snapshot.cost` (when it offers `cost`), and a
`create` that takes `snapshot`. A snapshot saves a sandbox, and a restore is a `create` that starts a new sandbox from
it. The gate's knobs `keeps`, `original_after`, `deletable` and `retention_seconds`, and its fact
`resizes_on_restore`, keep the meaning that the vocabulary gives them.

`snapshot.create` takes `keeps` (`files_only`, `files_and_memory` or null, meaning the `keeps` of
the variant that the sandbox was created with) and `labels` (section 5), and an `Idempotency-Key`
as `create` does. It returns a snapshot in state `saving` or `ready`; a consumer reads
`snapshot.get` until the state is `ready`. A snapshot holds the whole filesystem that commands can
write, including `/tmp` and the default user's home directory, except `/proc`, `/sys`, `/dev` and
mounted volumes. It does not hold the create request's `env`, `labels` or lifetime: a restore
names its own.

- A snapshot **MUST** hold everything that an operation reported as done before `snapshot.create` <!-- rule: provider-api/snapshot-consistency -->
  started (a `files.write`, a `run` that returned, a `files.mkdir`), as of one moment between the
  start and the return of the call. A write that a running process makes during the call may or
  may not be in it, and with `files_and_memory` the captured processes and memory belong to the
  same moment as the files.
- Within 24 hours, a repeated `snapshot.create` with the same key and body **MUST NOT** make a <!-- rule: provider-api/snapshot-idempotent -->
  second snapshot: it returns the first one with status 201. The same key with a different body is
  `conflict`, and a repeat while the first call is in progress is `conflict` with
  `retry_after_seconds`.
- A snapshot **MUST** outlive its sandbox: pausing, destroying or ending the saved sandbox never <!-- rule: provider-api/snapshot-outlives-sandbox -->
  deletes or changes its snapshots. A snapshot stays restorable until it is deleted or until its
  `expires_at`, which is at least `retention_seconds` after `created_at` for a variant that states
  `retention_seconds`.
- A restore **MUST** start a new sandbox with the snapshot's size and class, with the `labels`, <!-- rule: provider-api/snapshot-restore -->
  `env` and lifetime of the restoring request and not of the saved sandbox, and **MUST** refuse a
  request that names an `image` with `invalid_request`, another class or another size (unless the
  variant has `resizes_on_restore: true`) with `unsupported`, a snapshot in state `saving` or
  `failed` with `conflict`, and a deleted or expired snapshot with `not_found`. One snapshot can
  be restored many times, and each restore is a separate sandbox.
- `snapshot.list` **MUST** return the account's snapshots that are neither deleted nor expired, <!-- rule: provider-api/snapshot-list -->
  in any state, and only those that have every `label` filter with exactly that value and, when
  `sandbox_id` is given, were taken from that sandbox. `snapshot.get` **MUST** return the labels
  exactly as given to `snapshot.create`.
- `snapshot.delete` **MUST** return once the provider has accepted it, and a restore after it <!-- rule: provider-api/snapshot-delete -->
  **MUST** answer `not_found`. A repeated delete **MUST** succeed with state `deleted`, and an id
  that the provider has no record of **MUST** be `not_found`. A variant with `deletable: false`
  refuses the delete with `unsupported`. Deleting a snapshot never affects a sandbox that was
  restored from it.
- `snapshot.cost` **MUST** return a cost (section 10) whose `sandbox_id` is the saved sandbox and <!-- rule: provider-api/snapshot-cost -->
  whose `snapshot_id` is the snapshot, with lines of the item `snapshot` only: its storage, and a
  charge for each capture where the provider bills one. The status is `accruing` while the
  snapshot is stored, and **MUST** become `final` within `limits.cost_final_within_seconds` after
  the snapshot is deleted or expires. It stays readable at least until it is `final`. A provider
  whose snapshots are free lists the `snapshot` price with `"price_usd": "0"` and
  `"included": true`, and returns one `snapshot` line with the amount `"0"`. A provider that does
  not offer `cost` (section 10) answers `unsupported` to `snapshot.cost`.

After `snapshot.create` returns, the saved sandbox is in the state that the variant's
`original_after` names. A snapshot of a paused sandbox is either taken or refused with `conflict`.
A restore keeps the environment of restored processes and applies its `env` to what starts after
the restore; terminals and network connections are not restored. A snapshot stays on its
provider: a portable copy (for example a tar file through `files.read` and `files.write`) is the
consumer's choice. `snapshot.list` returns snapshots in an unspecified order with an opaque
cursor, with `limit` from 1 to `limits.list_limit` and 100 by default.

## 18. Directory operations

Four operations make, list, test and remove paths: `files.list`, `files.mkdir`, `files.remove`
and `files.exists`. They are a provider-side fast path for what every program can already do with
commands such as `mkdir -p`, `ls -A`, `test -e` and `rm -rf`, which the SPS baseline leaves to
commands (`spec.md` section 5, "Other file operations").

They are not an SPS gate. SPS admits a new word only when leaving it out would let a program be
matched to a provider that breaks it (`spec.md` section 13), and no provider breaks these:
commands give the same result on every provider. A request cannot ask for them, and matching
never compares them. A provider claims them in discovery, and they turn on when the tester
passes them. Where they are off, a consumer runs the commands instead.

- A provider that offers the directory operations **MUST** list all four, and no other directory <!-- rule: provider-api/directory-operations-claimed -->
  operation, in `classes[].operations` of each class that has them, and **MUST NOT** list some but
  not all of them. Each operation acts with the permissions of the class's default user, and a path that the
  user may not read or change is `forbidden`. Each result **MUST** be the result that the
  equivalent commands, run as that user at the same moment, would give.
- `files.list` **MUST** return the immediate entries of the directory at `path`, without `.` and <!-- rule: provider-api/files-list -->
  `..` and without recursing, sorted by the bytes of their names. Each entry has `name`, `type`
  (`file`, `directory`, `symlink`, or `other` for a FIFO, socket or device) and `size` (the
  entry's own size in bytes, as `lstat` reports it). It **MUST NOT** follow a symbolic link that
  is an entry: its type is `symlink`. A missing `path` is `not_found`; a `path` that is not a
  directory is `invalid_request`.
- A listing **MUST** come in pages that follow name order: `limit` is 1 to `limits.list_limit`, <!-- rule: provider-api/files-list-paging -->
  default 100, each page starts after the last name of the page before it, and a null
  `next_cursor` ends the listing. The cursor is opaque. An entry present during the whole listing
  appears exactly once; one added or removed during it may appear or not.
- `files.mkdir` **MUST** create a directory, and with `parents: true` every missing ancestor, as <!-- rule: provider-api/files-mkdir -->
  `mkdir -p` would. An existing directory at `path` is success with or without `parents`. A
  missing parent without `parents` is `not_found`. An entry that is not a directory, at `path` or
  at an ancestor that `parents` would create, is `conflict`.
- `files.remove` **MUST** remove a file, a symbolic link (the link, never its target), an entry <!-- rule: provider-api/files-remove -->
  of type `other`, or an empty directory. A non-empty directory needs `recursive: true`; without
  it the call is `conflict` and removes nothing. A recursive removal never follows a symbolic
  link, and if it fails part way its outcome is `unknown`. A missing `path` is `not_found`, and
  `path` `/` is `invalid_request`.
- `files.exists` **MUST** return `{"exists": true, "type": <type>}` when an entry exists at <!-- rule: provider-api/files-exists -->
  `path`, with the type as `files.list` gives it, and `{"exists": false, "type": null}` when none
  does, including when its parent is missing. It **MUST NOT** follow a final symbolic link: a
  dangling link exists, with type `symlink`.
