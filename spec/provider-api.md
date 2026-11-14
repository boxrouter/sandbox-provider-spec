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
the same bytes gives the same result. The parent directory must exist, or the write is
`not_found`. A consumer that needs only a prefix may close a read early.

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

`cost` returns a sandbox's cost with a status of `accruing` or `final`, and a source of `reported`
or `calculated`. `reported` means that the provider's billing system states the amounts.
`calculated` means that each quantity comes from the provider's own usage records and is
multiplied by the price in discovery. An item that discovery does not price has an unknown price,
never a zero price.

- A provider **MUST** take the quantities of a cost from its own records of the sandbox, never <!-- rule: provider-api/cost-provider-records -->
  from a clock in the consumer or in an adapter, and **MUST** be able to state a cost for every
  sandbox that it creates.
- A provider **MUST** make the cost `final` within 7 days after the sandbox ends and keep it <!-- rule: provider-api/cost-final-retained -->
  readable for at least 7 days after that.

While the sandbox exists, `cost` returns the cost so far with status `accruing`. A provider whose
usage records disappear with the sandbox cannot meet the retention rule on its own. Such a
provider reads the usage as part of `destroy` and returns the final cost in the destroy result. A
consumer uses the destroy result's cost when it is present, and otherwise reads `cost` until it is
`final`.

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
