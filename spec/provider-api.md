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
  `create` returns, even if the consumer has gone away. This applies to a class whose discovery
  states `lifetime_enforced_by: provider` or states nothing about it.
- A provider **MUST** still honour `destroy` at any time for a class whose discovery states <!-- rule: provider-api/lifetime-router-enforced -->
  `lifetime_enforced_by: router`: such a class has no timer of its own, and the caller (the
  router) ends each of its sandboxes no later than `lifetime_seconds` after `create` returns. The
  tester does not run `contract.lifetime_ends` for it and reports it as `not_claimed` (in the
  JSON report a `not_run` whose reason begins `not_claimed:`), never as `passed`.

A class whose discovery states `ordered_sessions: true` tells the caller that a command (`run`,
`process.start`) and a session transition (`pause`, `resume`, `stop`) on one sandbox must not
overlap: the caller records each one's outcome before it sends the next. A class that states nothing
serves them concurrently. The provider is not asked to refuse an overlap, and the tester does not
check the property, so a provider that states it cites its evidence in its README.

A class whose discovery states `memory_totals_untrusted: true` tells the caller that the memory
total a sandbox reports about itself is not the memory it can use, so the caller takes no total
from the sandbox. A class that states nothing has a total that is its own. The tester does not
check it, so a provider that states it cites its evidence in its README.

A provider refuses a lifetime above the class's `max_lifetime_seconds` with `unsupported`. A
provider that cannot run a sandbox without a lifetime refuses `lifetime_seconds: null` with
`unsupported`. A request that no size, region, image, class or section can meet is refused with
`unsupported`, and nothing is created.

`create` takes `secrets` when its request names the `hidden_secrets` section (without that
requirement the request is `invalid_request`). Each secret is a `placeholder` that code in the sandbox sees, the
`value` that the provider adds to requests for its `hosts`, and optionally the `headers` that carry
it. The value is write-only: the provider returns it from no operation, and neither a log line nor an
error body of the server or the client holds it, so the reference server and client cut it out of
every validation message. Code in the sandbox never reads it.

`get` returns a sandbox's `times` when the provider keeps any: each is a `kind` (`created`,
`started`, `ready`, `paused`, `resumed`, `stopped`, `ended`, `deadline`, `billed_start`,
`billed_end`, `requested`, `stop_requested`, `updated` or `checkpointed`), the time `at`, and the
provider's own field name as `source`. `list` may leave them out. They are the provider's own
statements, never a clock of the consumer or the adapter; a cost read places the provider's bill
against them.

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
`user_selection` (`vocabulary.md`) say what a class that claims a knob does. A class that
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

A provider offers `cost` by stating `limits.cost_final_within_seconds` in discovery. Without <!-- rule: provider-api/cost-offered -->
that value `cost` answers `unsupported`, and a consumer treats the provider as one that does not
state a cost.

- A provider whose discovery states `spec_version` 1.1 or later **MUST** offer `cost`. A <!-- rule: provider-api/cost-required -->
  consumer that bills from these figures cannot bill a sandbox that has no cost, so from 1.1 the
  operation is required. A 1.0 provider may still leave it out (section 13). The least a
  provider needs is its own record of what each sandbox used: a `usage` cost states those
  quantities and no prices. A provider whose records go with the sandbox lists `cost.capture`
  (below).

`cost` returns what a sandbox cost: a `status` of `accruing` or `final`, a `source` of `reported`,
`calculated` or `usage`, the `lines` and their `total_usd`, and `as_of`. `reported` means that the
provider's own records state the amounts. `usage` means that each line states a quantity and a unit
from the provider's own usage records and no amount: the consumer prices the quantities, so the
provider keeps no copy of its prices in its adapter. `calculated` means that each quantity comes
from the provider's own usage records and is multiplied by the provider's published price; it stays
valid. It works in
every state of the sandbox. The sandbox ends when `get` reports it `destroyed` or it is gone;
every timing rule here counts from then.

A line has an `item` and an `amount_usd`. `quantity` and `unit` are required when `source` is
`calculated`, as what the amount was priced from, and when it is `usage`, as what the line reports;
they are optional when `source` is `reported`. When `source` is `usage`, `amount_usd` is null on
every line and `total_usd` is null. `start`
and `end` give the period that the line covers, which may be a billing period (such as an hour)
that contains the usage. Both null means that the line covers no period, as
a fee does. `start` set with `end` null is an open period, which runs up to `as_of` and is allowed
only while the status is `accruing`. `total_usd` is the sum of the line amounts, except for `usage`.
While the status is
`accruing` and nothing is metered yet, `total_usd` may be null and `lines` empty. A sandbox for which
the provider bills nothing returns one line with the amount `"0"`. An amount of `"0"` always means a
true zero, never "not counted yet".

- A provider **MUST** take the quantities of a cost from its own records of the sandbox, never <!-- rule: provider-api/cost-provider-records -->
  from a clock in the consumer or in an adapter.
- Amounts **MUST** be the provider's published list price when the usage happened, in US dollars <!-- rule: provider-api/cost-list-price -->
  as decimal strings, before any plan, free tier, trial, credit or discount. The prices in discovery
  are list prices too: a plan or discount on an account never changes them. A provider may state
  none: an empty `prices` list states no prices, and a consumer that prices a `usage` cost takes the
  price from elsewhere. A `reported` cost
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
  where the paragraph above allows it. A `usage` line **MUST** have an `item`, a `quantity` and a
  `unit`, and **MUST** have a null `amount_usd`; the `total_usd` of a `usage` cost **MUST** be null.
- A provider **MUST** make the cost `final` within `limits.cost_final_within_seconds` after the <!-- rule: provider-api/cost-final-within -->
  sandbox ends, or, when the cost includes storage that outlives the sandbox, after that storage
  ends. `final` means that the figures **MUST NOT** change afterwards. A `final` cost has no open
  line, and a `total_usd` unless its source is `usage`. The provider chooses the number and states it as it is.
- A provider **MUST** keep the cost readable after the sandbox ends at least until it is `final`. <!-- rule: provider-api/cost-retained -->
  A class that lists `cost.capture` (below) is exempt from this rule.

While the sandbox exists, `cost` returns the cost so far with status `accruing`. SPS defines no
correction after `final`: a consumer that finds a later difference reconciles it itself.

`cost` takes the optional query parameter `created_at`, the time that `create` or `get` returned
for the sandbox. It is a lookup hint only. A provider whose usage records are kept by time may use
it to bound where it looks, does not report a cost from before it, and ignores it when it knows the
time itself. A provider that needs the time and gets none answers with an error of its own.

A provider that states `limits.account_cost_window_seconds` offers `account.cost`
(`GET /v1/cost?start=&end=`), which returns what the whole account was charged between `start`
(inclusive) and `end` (exclusive): `status`, `total_usd`, `source`, `lines` and `as_of`, with the
amounts and the sources of a sandbox cost (`reported`, `calculated` or `usage`, whose lines state
quantities, no amounts and a null `total_usd`, as for a sandbox cost). It needs no sandbox, so it
counts charges for sandboxes that are gone, and a billing true-up compares it with the sum of the
sandbox costs (the consumer prices a `usage` account cost as it prices a `usage` sandbox cost). A window that is empty, reversed or longer than the stated limit is `invalid_request`.
Without the limit `account.cost` answers `unsupported`.

A provider that states `limits.cost_batch_max`, and `limits.cost_final_within_seconds`, offers
`cost.batch` (`GET /v1/costs?sandbox_id=&sandbox_id=`), which returns the `Cost` of each of up to
`cost_batch_max` sandboxes in one call, for a provider whose cost source is one report of the
account that a read of one sandbox filters. It has no `created_at` hint: a provider that needs one
does not offer it. No id, a repeated id or more ids than the limit is `invalid_request`; without the
limit it answers `unsupported`.

- A provider that offers `cost.batch` **MUST**, for each sandbox it finds, return the `Cost` that <!-- rule: provider-api/cost-batch-same -->
  `cost` returns for that sandbox when read at the same time: the same `status`, `total_usd`,
  `source` and `lines` (`as_of` may differ).
- A provider that offers `cost.batch` **MUST** return every sandbox of the call that it finds, <!-- rule: provider-api/cost-batch-complete -->
  following its own paging, **MUST NOT** return one that was not asked for, and **MUST** leave out
  one it does not find: a sandbox that is not in the answer is read with `cost`, so a missing
  sandbox is never stated as a zero cost.
**Capturing the cost before the end.** Some providers delete their usage records with the sandbox,
so `cost` cannot be read after the end. Such a provider lists `cost.capture` in `classes[].operations`
of each class that has it. `POST /v1/sandboxes/{sandbox_id}/cost/capture`, with an `Idempotency-Key`
header, fixes the figure while the records still exist and returns it as a `Cost`.

- A provider that lists `cost.capture` **MUST**, on a capture, return the cost that it will state <!-- rule: provider-api/cost-capture -->
  for that sandbox. After a capture the sandbox allows only `get`, a repeated capture and
  `destroy`; every other operation on it is `conflict`. A repeated capture, with the same key or
  another, **MUST** return the same figures. A consumer captures once, immediately before it
  destroys, and keeps the figure. The provider need not keep `cost` readable after the sandbox ends.

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
all of 1.x. Nothing that a 1.0 provider does becomes wrong in a later 1.x. A minor may require an
operation that an earlier minor left optional, but only of a provider whose discovery states that
minor or a later one; a consumer still handles providers of the earlier minor, which may leave it
out. 1.1 requires `cost` (section 10). A consumer reads
`spec_version` and sends only the fields of that minor or older; because a provider refuses
unknown request fields (section 2), a requirement is never dropped without notice. A 2.0 would be
a new path (`/v2`), served beside `/v1` for a transition period.

Every class in 1.0 is a Linux sandbox, and a class that names no operating system is one. A later
1.x may let a class be another operating system without breaking a consumer written before it: that
class is never `default`, a request that names no class gets `default`, and `create` reaches any
other class only by naming its id. A consumer that does not know the field naming the operating
system therefore never meets such a class unless it asks for it.

## 14. The adapter manifest and author rules

Each adapter's Python package holds `sps-provider.yaml`, with `provider_id` (`a-z 0-9 -`, 2 to 32
characters, the entry point's name), `name`, `spec_version`, `credential_fields` (each with
`name`, `secret`, `description`, an optional `required_for_managed` (a field that a consumer with
its own account may leave out but that a deployment running the provider on its own account must
supply), an optional `account_identity: false` (a field that only tunes how the provider is served,
not which account it is, so a host that fingerprints an account by its credential fields leaves it
out) and, for a secret, an optional `public_prefix` such as `dtn_` that its values start
with) and `api_domains`. Each `api_domains` entry is an exact host
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
gate `terminal`. A provider that claims `reattach: true` implements `terminal.reattach` and
`terminal.end` as well (the end of this section). `terminal.open` is described in the
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

**End.** A terminal opened without an `id` cannot be reached again.

- When the connection closes for any reason other than the program's exit, a provider **MUST** end <!-- rule: provider-api/terminal-close-ends -->
  the terminal that was opened without an `id`: it sends `SIGHUP` to the terminal's process group,
  then `SIGKILL` to what remains of the group 5 seconds later. A process that left the group
  (`setsid`) is not part of the terminal.

**Liveness.** A pause, stop or end of the sandbox ends its terminals: the provider closes each
connection with code 1001.

- A provider **MUST** answer WebSocket pings, **MUST** send a ping at least every 30 seconds, and <!-- rule: provider-api/terminal-liveness -->
  **MUST NOT** end a terminal for being idle while the connection lives and the sandbox runs.

**Capacity.** A provider serves at least 4 open terminals per sandbox at once. A connection beyond
its limit gets an `error` message `quota_exceeded`.

**Reattach.** A class whose `terminal` variant states `reattach: true` accepts an `id` in
`terminal.open` (8 to 63 characters of `a-z 0-9 -`, chosen by the caller, as for an idempotency
key) and serves two more operations. A class without the claim refuses an `id` with `unsupported`.

- A terminal opened with an `id` **MUST** keep running after its connection closes, and a provider <!-- rule: provider-api/terminal-reattach -->
  **MUST** serve `terminal.reattach` for it until the program exits, `terminal.end` is called, or
  the sandbox is paused, stopped or ended. `terminal.reattach` (`POST .../terminals/{id}/link`)
  returns a link as `terminal.open` does, under the same link rules; connecting it attaches to the
  same program, with what was set in its shell, and carries its output from then on (a provider
  may replay recent output first). A terminal that is not running is a `not_found` error, reported in an `error` message when the
  link is connected, as a missing `cwd` is. A connection
  that is already attached is closed (code 1000), so one connection serves a terminal at a time.
  The `exit` message reaches the connection that is attached when the program exits.
- A provider **MUST** end a terminal on `terminal.end` (`DELETE .../terminals/{id}`) as a closed <!-- rule: provider-api/terminal-end -->
  connection ends one without an `id` (`provider-api/terminal-close-ends`). An id that is already
  gone succeeds.

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
- A provider whose discovery states `snapshot_labels_kept_by: router` (default `provider`) **MUST** <!-- rule: provider-api/snapshot-labels-router-kept -->
  still accept `labels` on `snapshot.create` and treat them as part of the request for
  `provider-api/snapshot-idempotent`, although it has nowhere to store them and the caller, the
  router, keeps them itself. It **MAY** return `{}` as the `labels` of `snapshot.get` and
  `snapshot.list`, **MAY** ignore the `label` filter of `snapshot.list`, and **MAY** answer
  `snapshot.list` only when `sandbox_id` is given, otherwise with `invalid_request` and `field`
  `sandbox_id`, because the router keeps the account-wide record. Every other rule of this
  section still applies. As for images, the statement is the same on every class that claims
  `snapshots`, and a caller treats a provider as router-keeping when any class states it. The
  tester leaves out the assertions about labels read back and filtered, lists snapshots by
  `sandbox_id`, and checks all the rest.
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
- A provider whose discovery states `snapshot_cost: unavailable` (default `offered`) **MUST** <!-- rule: provider-api/snapshot-cost-unavailable -->
  answer `unsupported` to `snapshot.cost`, because it has no record from which to state what a
  snapshot costs (for example a snapshot that is gone, with its storage period, after the
  delete). It **MUST** still offer `cost` for sandboxes when it states
  `limits.cost_final_within_seconds`. The statement is the same on every class that claims
  `snapshots`, and a caller treats a provider as unable to report a snapshot's cost when any
  class states it. The tester leaves out `snapshots.v1.cost` and checks all the rest.

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

## 19. Prepared images

A provider that lists `image.prepare`, `image.get`, `image.list` and `image.delete` in
`classes[].operations` (all four or none, as section 18 says of the directory operations) offers
prepared images, and claims `custom_images` knob `prepared: true` on the same class. A prepared
image is made ahead of creation, from an OCI image, a private OCI image or a Dockerfile, and a
`create` with `image: {"provider_artifact": "<id>"}` starts a sandbox from it. They turn on when the
tester passes them. A provider that states them also states `limits.image_context_bytes`, at least
512 MiB.

`image.prepare` is one `multipart/form-data` request with an `Idempotency-Key`, as `create` has.
The part `request` comes first and is JSON: the `source`, the `resources` that a sandbox from the
image must start with (or null for any size) and `labels` (section 5). A Dockerfile source may be
followed by the part `context`, a tar archive of the build context. In the Python form the adapter
receives the context as a stream of bytes, and the size when the caller gave one. A source
carries `digest` and `config` (`env`, `workdir`, `user`, `entrypoint`, `cmd`) that the caller
resolved: the provider reaches no registry for them, because the egress proxy allows only the
provider's own domains.

- `image.prepare` **MUST** return a prepared image in state `preparing`, `ready` or `failed`, and <!-- rule: provider-api/image-prepare -->
  a consumer reads `image.get` until the state is `ready`. A `failed` image carries `error`, a body
  as an error response has. The provider **MUST** apply the `config` of an OCI source as the
  defaults of every sandbox made from the image, and **MUST NOT** read a registry to find them.
  A `private_oci` source's `credentials` **MUST NOT** be returned, logged or stored beyond the
  preparation. The provider **MUST** make any OCI image or Dockerfile runnable and **MUST NOT**
  treat one image differently by its name or reference; what the provider needs to run an
  arbitrary image (an entrypoint, an init wrapper) is part of its own build.
- A build context **MUST** travel only in the part `context` and **MUST NOT** be held whole in <!-- rule: provider-api/image-context -->
  memory: a server reads it as a stream. A context over `limits.image_context_bytes` is
  `too_large`, a context with a source that is not a Dockerfile is `invalid_request` (unless the
  provider lists `image.prepare.oci_layout`, section 22), and a part
  that follows `context` or a part named otherwise is `invalid_request`. A body cut short is
  `invalid_request` with outcome `unknown`.
- Within 24 hours, a repeated `image.prepare` with the same key and the same request **MUST NOT** <!-- rule: provider-api/image-idempotent -->
  make a second image: it returns the first one with status 201. The same key with a different
  request is `conflict`.
- `image.list` **MUST** return the account's images that are not deleted, in any state, and only <!-- rule: provider-api/image-list -->
  those that have every `label` filter with exactly that value. `image.get` **MUST** return the
  labels exactly as given to `image.prepare`, and an id that the provider has no record of is
  `not_found`. The order is unspecified, the cursor is opaque, and `limit` is 1 to
  `limits.list_limit`, 100 by default.
- A provider whose discovery states `image_labels_kept_by: router` (default `provider`) **MUST** <!-- rule: provider-api/image-labels-router-kept -->
  still accept `labels` on `image.prepare` and treat them as part of the request for
  `provider-api/image-idempotent` (the same key with other labels is `conflict`), although it
  has nowhere to store them and the caller, the router, keeps them itself. It **MAY** return `{}`
  as the `labels` of `image.get` and `image.list` and **MAY** ignore the `label` filter of
  `image.list`. Every other rule of this section still applies. The statement is about the
  provider's images, not one class's: it is the same on every class that lists `image.prepare`,
  and a caller treats a provider as router-keeping when any class states it. The tester leaves
  out the assertions about labels read back and filtered, and checks all the rest.
- A provider whose discovery states `image_delete_in_use: conflict` (default `accepted`) **MUST** <!-- rule: provider-api/image-delete-in-use -->
  change nothing when it answers `image.delete` with `conflict` (the image stays `ready` and
  every sandbox is untouched), and **MUST** accept the delete once no sandbox made from the
  image is running or paused. It **MAY** answer `conflict` while one is, because it cannot
  remove an image that a sandbox still runs from. The statement is the same on every class that
  lists `image.prepare`, and a caller treats a provider as blocking when any class states it and
  retries the delete later. The tester destroys the sandbox before it deletes the image and
  checks all the rest.
- A `create` from `provider_artifact` **MUST** start a sandbox only from a `ready` image: a <!-- rule: provider-api/image-create -->
  `preparing` or `failed` image is `conflict`, and a deleted image or an id that the provider has
  no record of is `not_found`. A sandbox of a different size than the image is bound to is
  `unsupported`.
- `image.delete` **MUST** return once the provider has accepted it, and afterwards `image.get` and <!-- rule: provider-api/image-delete -->
  a `create` from the image **MUST** answer `not_found`. A repeated delete **MUST** succeed with
  state `deleted`, and an id that the provider has no record of is `not_found`. Deleting an image
  never affects a sandbox that was made from it.

## 20. Preview access, lifetime and revocation

`preview.link` makes an HTTPS URL that reaches one port of a sandbox. It is the section `previews`;
this part adds two optional request fields, three optional result fields and one operation. A
provider that does not claim them is still a valid 1.0 provider.

- `preview.link` **MAY** carry `access` (`public` or `private`, default `public`) and <!-- rule: provider-api/preview-access -->
  `lifetime_seconds`. A class **MUST** answer `unsupported` for an `access` that its `previews`
  claim does not list. A `public` link serves any client that has the URL. A `private` link serves
  only a request that carries the credential in the result, and **MUST NOT** serve one without it.
- The result **MAY** carry `access` (what the link is; absent means `public`) and `credential`: <!-- rule: provider-api/preview-credential -->
  `link` when a private link's credential is inside the URL, `header` when it is among `headers`,
  and null for a public link. The URL and the headers are sensitive and never logged.
- A link **MUST** stop working no later than `expires_at`, and a link made with <!-- rule: provider-api/preview-lifetime -->
  `lifetime_seconds` **MUST** have an `expires_at` no later than that many seconds after the call
  returns, plus the provider's own clock skew. Without `lifetime_seconds` the provider chooses the
  lifetime, and `expires_at` is null when the link does not expire.
- A class whose `previews` claim has `revocable: true` **MUST** return an `id` for each link and <!-- rule: provider-api/preview-revoke -->
  answer `preview.revoke` (`DELETE /v1/sandboxes/{sandbox_id}/previews/{preview_id}`). It returns
  once the provider has accepted the revoke; afterwards that link **MUST NOT** serve, and no other
  link of the sandbox is affected. An id that is already revoked, expired or gone is success. A
  sandbox that does not exist is `not_found`. A class that is not `revocable` **MAY** return a null
  `id` and answers `unsupported`.

## 21. Updating labels

`labels.update` (`PATCH /v1/sandboxes/{sandbox_id}/labels`) changes a sandbox's labels after it was
created, so that a reaper or a caller can mark it. It is not an SPS gate: a provider lists
`labels.update` in `classes[].operations` of each class that has it, apart from the four directory
operations, and it turns on when the tester passes it.

- The body is `{"labels": {...}}`. The provider **MUST** set each key given to its value, remove <!-- rule: provider-api/labels-update -->
  each key given with the value `""`, and leave every other label as it was. The result is the
  sandbox with its labels, and `get` and `list` **MUST** show the new labels from then on, within
  the time that a `list` after a `create` may take. A result that would have more than 32 labels is
  `invalid_request`, and then no label changes. A sandbox that does not exist is `not_found`.
- A provider **MAY** refuse to change a label that is part of the sandbox's identity, with <!-- rule: provider-api/labels-update-identity -->
  `conflict`, and then **MUST** change none of the labels of that call.

## 22. What a prepared image needs from the caller, and what it costs

These additions to section 19 are optional. A provider that lists none of them behaves as section 19
says.

**Image facts.** The caller resolves, from the image itself, what a provider would otherwise read
from a registry. An OCI source's `config` may also carry `init` (true when the image's CMD starts a
machine init as process 1), `user_name` and `home` (the name and home directory of a numeric
`user`, read from the image's `/etc/passwd`). A Dockerfile source may carry `base`, an
`{oci, digest, config}` for its single `FROM`, in the form of an OCI source. Each is absent when the
caller could not resolve it.

- A provider **MUST** use these facts where it needs them and **MUST NOT** read a registry or the <!-- rule: provider-api/image-facts -->
  image to find them.

**OCI layout.** A provider that lists `image.prepare.oci_layout` in `classes[].operations`, next to the
four image operations, cannot reach the registry that holds the image. The caller reads the image,
at the digest it states, and sends it as an OCI image layout (a tar archive with `oci-layout`,
`index.json` and `blobs/sha256/`) in the part `context`. `image.prepare` is not addressed to a
class, so the claim holds for the provider's image preparation as a whole. The provider states
`limits.image_layout_bytes`.

- With the claim, every OCI source **MUST** arrive with the part `context`, and a request without it <!-- rule: provider-api/image-oci-layout -->
  is `invalid_request` with `field` `context`. The layout is bounded by `limits.image_layout_bytes`
  (`too_large` above it), a Dockerfile's context stays bounded by `limits.image_context_bytes`, and
  the provider **MUST NOT** need registry credentials for an image that arrives this way.

**Image bindings.** A class that lists `image.prepare` may state `image_binds`, the list of what a
prepared image of the class is tied to: `cpu_min`, `memory_min_mib`, `disk_min_mib`, `region` and
`kernel`. A class that does not list `image.prepare` states none, and an absent or empty list means
that the image fits any size. A prepared image's `resources` holds exactly the fields the list
names (`cpu`, `memory_mib`, `disk_mib`, `region` and `kernel` for the five), so that a caller can
set the size of a request before it prepares and tell two preparations apart.

**Image cost.** A provider that lists `image.cost` next to `image.prepare`, and that offers `cost`
(states `limits.cost_final_within_seconds`), answers `GET /v1/images/{id}/cost` with a cost of
what preparing the image cost the provider, for a `ready` image and for a `failed` one.

- The cost of an image **MUST** carry `image_id` and no `sandbox_id`, and **MUST** reach `final` <!-- rule: provider-api/image-cost -->
  within `limits.cost_final_within_seconds` after the preparation has ended. It stays readable at
  least until it is `final`, as a sandbox's cost does (section 10). `created_at`, the time at which
  the caller started the preparation, is a lookup hint only: a provider whose records are kept by
  time may use it to bound where it looks, **MUST NOT** report a cost from before it, and ignores it
  when it knows the time itself.

**Error fields.** An error body may carry `failed_step` and `field`, and in `PreparedImage.error` it
tells a caller which side failed.

- `failed_step` **MUST** be the 1-based number of the Dockerfile instruction whose own command <!-- rule: provider-api/error-failed-step -->
  failed, and a provider **MUST NOT** set it for a failure that the build's own command did not
  cause (a full disk, a lost connection): a caller routes on it, and does not try another provider
  for a customer's broken build.
- `field` **MUST** name a field of the request that is at fault <!-- rule: provider-api/error-field -->
  (`context`, `source`, `image`). On a `create` that answers `provider_error`, `image` means that the
  prepared image it named never booted, and a caller retires that image.

## 23. Account capacity

`account.capacity` tells a consumer what the account that owns the credential may still start, run
and spend, so that it can admit work without trying a start that the provider will refuse. A
provider that has such limits lists `account.capacity` in `classes[].operations` of each class that
it applies to; like the directory operations, it is no SPS gate, and it turns on when the tester
passes it.

`GET /v1/account/capacity` takes no parameters and returns one object:

| Field | Meaning |
| --- | --- |
| `as_of` | The time that the figures describe. |
| `starts` | A list of `{window_seconds, used, limit, remaining}`: how many starts each limited window allows. Empty when no starts are limited. |
| `can_start` | Whether the account may start a sandbox now, or null. |
| `paid_overage_enabled` | Whether starts beyond a window's limit are allowed and charged, or null. |
| `concurrency` | `{active, limit}`, the running sandboxes against the cap, or null. |
| `prepaid` | `{balance_usd, past_due}`, the prepaid balance in US dollars as a decimal string, or null. |
| `stored_artifacts` | Optional. `{used, limit}`: the prepared images and snapshots, counted together, that the account holds and may hold; each is null when not reported. Absent when the provider reports neither. |

- A provider that lists `account.capacity` **MUST** return every field, and a field whose value it <!-- rule: provider-api/account-capacity -->
  does not know **MUST** be null, never a zero or a guess; only `stored_artifacts` may be left out.
  `remaining` is the number of starts left in the window.
- A provider **MUST** state `stored_artifacts` only from its own API's answer for that account, <!-- rule: provider-api/stored-artifacts -->
  `used` **MUST NOT** be less than the number of prepared images and snapshots that `image.list` and
  `snapshot.list` return for the account, and `used` **MUST NOT** exceed `limit` when both are
  stated. `limits.stored_artifacts_documented` in discovery is the figure that the provider documents
  for its default plan: a consumer **MUST NOT** enforce it, evict on it or treat it as a ceiling.

## 24. Static discovery

A provider that ships a Python package may also state what the package says about every account,
before any call: `Provider.static_discovery()`, an optional classmethod that returns the same
`Discovery` document as `discovery()`, with no I/O and no credentials. A consumer that runs the
package reads the provider's facts from it alone, with nothing recorded that can go stale. A
provider that does not state it leaves the method unimplemented, and the rule below does not apply.
The sandbox-provider-spec package's `within(discovery, ceiling)` is the one comparison: it returns
the path of every value of `discovery` that steps outside `ceiling`, one per line, and nothing when
`discovery` is within it.

- When a class states `static_discovery()`, every account's `discovery()` **MUST** return the same <!-- rule: provider-api/discovery-within-static -->
  classes or fewer, each with equal or narrower values: fewer regions, sizes, images, variants or
  operations, smaller limits, `ready` false where the static one is true, and the same price where
  both state one. A value that only the live document states is outside it.

`sandbox_provider_spec.v1.installed()` returns the installed packages' `Provider` classes by
provider id, from the `sandbox_provider_spec.providers` entry-point group; an id named twice is
refused.

## 25. Updating the network policy

A class whose `network_lockdown` variant states `switchable: true` or `changeable: true` implements
`network.update` (`PUT /v1/sandboxes/{id}/network`). It is no separate claim: the knob is the claim,
and the tester proves it with `network_lockdown.switchable.true` and
`network_lockdown.changeable.true`. The body is `{policy, allow, deny}`, the settings of the
`network_lockdown` requirement of `create`: `policy` is `deny_all`, `allowlist`, `denylist` or
`open`, `allow` lists an allowlist's entries and `deny` a denylist's.

- A provider **MUST** apply the policy before it returns, so that connections opened afterwards <!-- rule: provider-api/network-update -->
  follow it, and the sandbox keeps its processes and files; the rules of `network_lockdown`
  (`vocabulary.md`) hold for the new policy. It **MUST** refuse with `unsupported` a policy that
  its variant does not offer (a `switchable` variant offers its `switches_to` and the starting
  policy) and entries it may not change (`changeable`), and a sandbox that was created without
  `network_lockdown`; it changes nothing then.

An `allow` list of an update may be empty: an allowlist with no entries lets nothing through
(unlike `create`, where an allowlist needs a nonempty `allow`), and the tester's
`coverage.network_lockdown.changeable.true` sends one. An update is the same call to a provider
whether it switches the policy or only changes its entries. The consumer decides which one it asks
for from what discovery claims.

## 26. Pausing, resuming and extending: the record is `get`'s

`pause` and `resume` (section `pause_resume`) change the sandbox's state, and `lifetime.extend`
its deadline. In process, each returns the sandbox or nothing (`None`). A provider returns nothing
when it would read its record only to fill the result: the operation is then the provider's own
call and nothing more. `lifetime.extend` still never shortens a lifetime, so a provider whose call
would shorten one reads the deadline before the call, never after it. `get` is where a
consumer reads the record (its state, size, lifetime and times), so a consumer never relies on a
result being present. Over HTTP the answer stays the sandbox: the reference server answers a
provider's `None` with one `get` of its own, so the wire answer of 1.0 is unchanged.

`resume` takes an optional `lifetime_seconds` (in process, the keyword argument of that name; over
HTTP, the body field), the lifetime the sandbox has left. It is an input of the operation, as
`create`'s `lifetime_seconds` is: a consumer that keeps a sandbox's lifetime budget sends what is
left, so a paused sandbox runs on that budget again without a second call. A class offers it by
listing `resume.lifetime` in `classes[].operations`; left out, `resume` does what it did without it.

- A class that lists `resume.lifetime` **MUST**, for a `resume` with `lifetime_seconds` N, arm its <!-- rule: provider-api/resume-lifetime -->
  lifetime timer in the same call so that it ends the sandbox N seconds after the resume (rounded
  up to the timer's `step_seconds`), as `lifetime_timer.at_end` says, whatever the timer held
  before the pause. A class that does not list it **MUST** answer `unsupported` to a request that
  sets `lifetime_seconds`, and changes nothing; its consumer resumes without it and then extends
  the lifetime (`lifetime.extend`).

The answer follows the paragraph above: a sandbox or `None`. A consumer that reads `ends_at` from
a returned sandbox can see the armed timer; a `None` says nothing more than the claim does.
