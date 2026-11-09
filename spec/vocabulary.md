# Vocabulary

[Specification index](README.md) · [Documentation](../docs/README.md)

Every gate and fact the [Sandbox Provider Specification](spec.md) defines: its knobs and values,
what each means, and the rules a provider follows when its declaration offers it. The
[overview of the gates](spec.md#6-gates) says how requests use them; the words
**MUST**, **SHOULD** and **MAY** are used as [section 2](spec.md#2-conventions) of the
specification says.

## Gates

The rules in each section say what a provider does when its declaration offers a value. A
provider whose declaration does not offer a value owes nothing for it.

Count limits compare with the number of entries in a request setting. The `entry_kinds` limit
compares with which kinds an allowlist or denylist contains:

| Gate | Limit | Compared with |
| --- | --- | --- |
| `previews` | `max_ports` | `ports` |
| `network_lockdown` | `max_allow` | `allow` |
| `network_lockdown` | `max_deny` | `deny`, for `denylist` |
| `network_lockdown` | `entry_kinds` | kinds of entries in `allow` for `allowlist` or `deny` for `denylist` |
| `hidden_secrets` | `max_inject_into` | `inject_into` |
| `volumes` | `max_mounts` | `mounts` |
| `tcp_ports` | `max_tcp_ports` | `ports` |

[Declaration rules](declarations.md#rules-of-the-file) define the limit values;
[matching](matching.md) defines how numbers, lower bounds and unknown limits fit a count.

### fuse_mount

A remote userspace filesystem can be mounted through the class's native command and file
operations. This gate has no knobs. Request it with `fuse_mount: {}`. Existing FUSE, root
and outbound-traffic facts describe prerequisites; none alone establishes this gate.

- An offered variant **MUST** pass the combined mount, default-user create/edit/fsync, <!-- rule: fuse_mount/lifecycle -->
  checkpoint, active-writer fence, credential release and fresh-mount resume scenario.
  The resumed mount must recover the checkpoint, allow default-user edits and retain those
  edits after the old writer attempts write/fsync through its previously writable descriptor.
  A local directory or a failed command unrelated to fencing does not satisfy the scenario.

- A default-placement variant **MUST** bind the actual native default plan, exact route, <!-- rule: fuse_mount/default-placement -->
  account, credentials, execution class and image copy, and pass the same lifecycle on two
  distinct actual guests. It records physical placement as unknown and measures guest
  write/fsync plus acknowledged backend checkpoint latency on the writer and successor.
  Such evidence applies only to omitted-location requests; it never proves explicit geography.
  A changed plan, source, credentials or expired measurement requires refreshed evidence.

- A provider-terminal handover **MUST** observe the exact old provider incarnation terminated, <!-- rule: fuse_mount/provider-terminal-handover -->
  resolve its current issuance, and revoke only each exact delegation whose provider-reported
  orphan state is the literal boolean `true`. A connected writer's competing Cloud admission is
  refused without dispatching a successor; this does not claim that native mounts exclude one
  another. The test must observe that the still-connected writer can write after Cloud refuses
  admission, without revoking its delegation. The later handover successor
  uses the normal no-force path in the same explicitly requested access mode, and the test
  records default-user write, acknowledged save/checkpoint, matching readback and owned cleanup.
  The report binds requested and observed access mode to the execution binding and its
  `access_mode:<mode>` prerequisite; it establishes no untested mode or cross-mode interaction.
  A `branch` mode is a separate view, not a security boundary.

- A read-mode provider-terminal handover **MUST** refuse a competing Cloud admission while the <!-- rule: fuse_mount/provider-terminal-handover-read -->
  same connected read-only client remains able to read. It records no revocation or successor
  dispatch from that refusal. The client must receive `EROFS` for a write attempt, then read back
  the expected bytes with the same digest. The normal no-force successor uses `read` mode. It
  retains the exact terminal, current issuance, orphan-only delegation, fresh clearance, source,
  prerequisite and cleanup requirements of a provider-terminal handover.

- A shared-mode provider-terminal handover **MUST** refuse a competing Cloud admission while <!-- rule: fuse_mount/provider-terminal-handover-shared -->
  the same connected writer remains able to write after refusal. The shared successor uses the
  normal no-force path in `shared` mode. Evidence records a default-user write, acknowledged
  `fsync` and `sync`, the exact acknowledged checkpoint identity, matching successor readback and
  owned cleanup. It retains the exact terminal, current issuance, orphan-only delegation, fresh
  clearance, source and prerequisite requirements of a provider-terminal handover. Public
  `shared` maps to native `--conditional`; the CLI's separate `--shared` flag is not required.

- The SPS 0.3.130 provider-terminal handover check **MUST** bind the exact public Core <!-- rule: fuse_mount/provider-terminal-handover-130 -->
  fields `native_id`, `incarnation`, `created_at_ms` and `session_id`, including explicit nulls
  for uncaptured optional fields. Its closed `binding_basis` lists the non-null fields in that
  canonical order. An ID-only binding remains ID-only, and normal public Core binding
  verification remains required.
- The SPS 0.3.130 read handover check **MUST** preserve the connected-reader refusal and <!-- rule: fuse_mount/provider-terminal-handover-read-130 -->
  exact public Core binding requirements of the SPS 0.3.130 provider-terminal handover check.
- The SPS 0.3.130 shared handover check **MUST** preserve the connected-writer refusal and <!-- rule: fuse_mount/provider-terminal-handover-shared-130 -->
  exact public Core binding requirements of the SPS 0.3.130 provider-terminal handover check.

- The SPS 0.3.131 branch-fork handover check **MUST** preserve the exact terminal, public <!-- rule: fuse_mount/provider-terminal-branch-fork -->
  Core binding, current issuance, orphan-only revocation, fresh clearance, busy connected-writer,
  normal no-force successor, and owned cleanup requirements. Both branch requests explicitly name
  the same acknowledged checkpoint N. Normal seed release may advance the source head to autosave
  checkpoint N+1; capture the source-head baseline after release, and never substitute that head for
  the explicitly selected checkpoint N. Evidence records distinct branch identities, default-user
  write/fsync/sync,
  matching branch readback, matching source readbacks from the fork and parent, private-marker absence
  from both, and an unchanged source head. It claims no branch Save, reusable branch, publication of
  the source head, persistence guarantee, or security boundary.

- The SPS 0.3.132 environment-profile handover check **MUST** bind the actual provider route and <!-- rule: fuse_mount/provider-terminal-handover-env-132 -->
  account, execution class, access mode and exact prepared Core image handle, including its
  provider, ID, key and resources. It records the environment credential kind without inventing a
  credential version, and keeps the captured route and account as provenance. Normal public Core
  binding verification remains required.
- The SPS 0.3.132 read handover check **MUST** preserve the environment-profile binding and the <!-- rule: fuse_mount/provider-terminal-handover-read-env-132 -->
  connected-reader refusal, `EROFS` write refusal, and exact readback required by the SPS 0.3.130
  read handover check.
- The SPS 0.3.132 shared handover check **MUST** preserve the environment-profile binding and the <!-- rule: fuse_mount/provider-terminal-handover-shared-env-132 -->
  connected-writer refusal, acknowledged checkpoint, and exact readback required by the SPS
  0.3.130 shared handover check.
- The SPS 0.3.132 branch-fork handover check **MUST** preserve the environment-profile binding and <!-- rule: fuse_mount/provider-terminal-branch-fork-env-132 -->
  the fresh-fork, selected-checkpoint, source-head and private-marker requirements of the SPS
  0.3.131 branch-fork handover check. It claims no branch Save or reusable branch.

Scope an observed-region variant with `needs.variant`: `image:sha256:<digest>` names the immutable tested
image; `region:<region>` names the concrete execution region; `fuse_mount_account` requires
positive account permission; `fuse_mount_egress:sha256:<digest>` requires positive reachability
under the effective egress policy. Hash that policy's JSON with sorted keys, no whitespace,
and SHA-256; an absent policy is `{"policy":"open"}`. The fixture adds `controller:sha256:<digest>` for the pinned complete host implementation.
Default-placement variants instead carry `placement:default` and
`native_plan:sha256:<digest>` without a `region:` condition. Their separate
`default-placement/v1` profile records the actual execution and calibration identities;
observed-region reports cannot be reinterpreted as default-placement evidence.
The `default-placement/v1` profile is diagnostic-only: it establishes no capability or
volume admission and cannot replace the retained-writer fencing guarantee.
Other prerequisites remain explicit `needs` entries. Unknown or unconfirmed prerequisites do not satisfy the gate. A report for
one image, class or region does not attest another. Declaration proof remains required even
when the prerequisites have been confirmed.

The opt-in `sandbox_provider_spec.fuse_mount.FuseMountRunner` runs `fuse_mount.lifecycle`.
Supply `fuse_mount_create`, `fuse_mount_prerequisites`, a host-side `fuse_mount_controller`, and its pinned
`fuse_mount_controller_digest`. The controller's complete ordered source-file manifest is
hashed before mutations and checked afterwards; the report records only that digest, never
paths or credentials. The controller owns remote cleanup and keeps control credentials on
the host. Missing controller/source inputs produce `not_run` before allocation. Ordinary
conformance dispatch is unchanged; an ordinary runner cannot attest this new fixture.

The separate `fuse_mount.provider_terminal_handover` check uses
`sandbox_provider_spec.fuse_mount_handover.ProviderTerminalHandoverRunner` and a
`fuse_mount_handover_controller`. It records a closed, mode-bound object under the structured
`fuse_mount_handover` observation. Its controller source manifest is checked before the
callback can allocate resources; the callback and cleanup own all resources they create.
The distinct read and shared checks use `ProviderTerminalHandoverReadRunner` and
`ProviderTerminalHandoverSharedRunner` with the same source-bound controller fixture key and
callback. Each selected ID, rule and fixture operation is fixed to its matching access mode;
their observations remain under the same structured `fuse_mount_handover` key. The legacy
lifecycle, default-placement and original write/branch handover checks remain separate identities.

### idle_shutdown

The sandbox stops by itself after a period without activity. What counts as activity
differs between providers. What counts as activity is not compared.

| Knob | Values | Meaning |
| --- | --- | --- |
| `on_idle` | `paused`, `stopped`, `destroyed` | The state the idle sandbox ends up in. |
| `custom_idle_time` | yes/no | The request may choose how long the sandbox waits, in `idle_seconds`. |
| `auto_wake` | yes/no | Traffic to a preview wakes the sandbox by itself. Only in a variant whose `on_idle` includes `paused` or `stopped`. |

- With `on_idle: paused`, an idle sandbox **MUST** end up paused. <!-- rule: idle_shutdown/paused -->
- With `on_idle: stopped`, an idle sandbox **MUST** end up stopped. <!-- rule: idle_shutdown/stopped -->
- With `on_idle: destroyed`, an idle sandbox **MUST** be destroyed. <!-- rule: idle_shutdown/destroyed -->
- With `custom_idle_time: true`, the provider **MUST** wait the `idle_seconds` a request <!-- rule: idle_shutdown/custom-idle-time -->
  chose before acting on an idle sandbox.
- With `auto_wake: true`, an HTTP request to one of the sandbox's previews **MUST** wake it, <!-- rule: idle_shutdown/auto-wake -->
  with no other call.

### pause_resume

A call pauses the sandbox; a later call resumes it.

| Knob | Values | Meaning |
| --- | --- | --- |
| `keeps` | `files_only`, `files_and_memory` | What survives a pause. |

- With `keeps: files_only`, the whole root filesystem **MUST** survive a pause and resume. <!-- rule: pause_resume/files-only -->
- With `keeps: files_and_memory`, running processes and their memory **MUST** also survive, <!-- rule: pause_resume/files-and-memory -->
  so a process started before the pause carries on after the resume.

### previews

A URL that reaches a port in the sandbox. The request's `ports` setting lists the ports the
program will serve on; each is an integer from 1 to 65535, listed once.

| Knob | Values | Meaning |
| --- | --- | --- |
| `access` | `public`, `private` | Who can open the URL. Must be named: some providers offer only public links. |
| `credential` | `link`, `header` | How a private preview carries its credential. Only in a variant whose `access` includes `private`. |
| `revocable` | yes/no | One link can be revoked while the sandbox keeps running. |
| `link_lifetime_seconds` | a number | How long a link keeps working, at least, while the sandbox runs. |
| `websocket` | yes/no | A WebSocket connection to the URL reaches the port. |
| `loopback` | yes/no | A server that listens only on `127.0.0.1` is served. Many development servers listen there by default; one that listens only on `::1` is not promised. |
| `any_port` | yes/no | The provider gives a URL for a port not listed when the sandbox was created. Such a port counts towards `max_ports`, and `reserved_ports` still applies. |
| `survives_pause` | yes/no | A URL given before the sandbox was paused, by `pause_resume` or `idle_shutdown`, reaches it after it resumes, so a URL handed to someone else keeps working. |

A variant may also list, as a limit, `reserved_ports`: distinct integers from 1 to 65535
for ports the provider keeps for itself,
which no preview serves. A request that lists one of them does not fit that variant. A
variant that lists none reserves none.

- The provider **MUST** give a URL for each port listed in `ports`, up to `max_ports`, and <!-- rule: previews/serves-listed-ports -->
  the URL reaches a server listening on that port on all the sandbox's interfaces (`0.0.0.0`).
- A `public` preview **MUST** serve a client that presents no credential. <!-- rule: previews/public-serves-anyone -->
- A `private` preview **MUST** refuse a client that does not present its credential. <!-- rule: previews/private-needs-credential -->
- A `private` preview's credential **MUST NOT** be an API key for the provider account, and <!-- rule: previews/private-credential-is-its-own -->
  it opens only its own preview, so it is safe to hand to a third party.
- With `credential: link`, the URL **MUST** carry the credential, so a client that follows <!-- rule: previews/credential-link -->
  the link and sends nothing else is served. A person can click it.
- With `credential: header`, the preview **MUST** serve a client that sends the credential <!-- rule: previews/credential-header -->
  in a request header. This suits programs and does not work in a browser.
- With `revocable: true`, revoking one link **MUST** stop it working while the sandbox and <!-- rule: previews/revocable -->
  its other links keep running.
- A link **MUST** keep working for at least `link_lifetime_seconds` while the sandbox runs. <!-- rule: previews/link-lifetime -->
- With `websocket: true`, a WebSocket connection to the URL **MUST** reach a WebSocket <!-- rule: previews/websocket -->
  server on the port, with messages passing both ways.
- With `loopback: true`, the URL **MUST** reach a server that listens only on `127.0.0.1`. <!-- rule: previews/loopback -->
- With `any_port: true`, the provider **MUST** give a URL for a port that was not listed <!-- rule: previews/any-port -->
  when the sandbox was created.
- With `survives_pause: true`, a URL given before the sandbox was paused **MUST** reach it <!-- rule: previews/survives-pause -->
  after it resumes.
- A port a variant lists in `reserved_ports` **MUST** be one the provider does not preview <!-- rule: previews/reserved-ports -->
  for a program.

### network_lockdown

Limits what the sandbox can connect to.

| Knob | Values | Meaning |
| --- | --- | --- |
| `policy` | `deny_all`, `allowlist`, `denylist`, `open` | No outbound connections; only to the listed host names and IPv4 addresses or ranges; everywhere except the listed host names or IPv4 addresses or ranges; or no restriction, as the baseline promises. Must be named, with exactly one value: an allowlist is not what a program that assumes deny-all wants. `open` is only allowed for a request with `switchable: true`. |
| `changeable` | yes/no | The entries of a running sandbox's policy can be changed, and the sandbox keeps its processes and files. Only in a variant whose `policy` includes `allowlist` or `denylist`. |
| `switchable` | yes/no | A running sandbox can change to another policy the same variant offers, and it keeps its processes and files. |

`allowlist` and `denylist` accept host names, IPv4 addresses and ranges, or a mix of them in
one `allow` or `deny` list. Each entry is classified by its syntax: four dotted decimal
octets with an optional prefix length are an address; anything else must be a host name,
optionally with the `*.` wildcard prefix. The `allow` setting lists what an allowlist lets
through, and `deny` what a denylist shuts out. An allowlist policy requires a nonempty
`allow` list; a denylist policy requires a nonempty `deny` list. A name entry is a host name:
one label such as `localhost`, or labels separated by dots. Each label has 1–63 ASCII
letters, digits or hyphens, with no leading or trailing hyphen; the name has at most 253
characters and no trailing dot. A name cannot consist only of digits and dots; IPv4
addresses are address entries. In an allowlist a name may have the wildcard prefix `*.`,
such as `*.example.com`. An address entry has four decimal octets, each
0–255 with no leading zeros except `0` itself, optionally followed by `/` and a prefix
length. The prefix uses ASCII digits and has a value from 0 to 32; leading zeros in the
prefix are accepted. Host bits may be set: `10.0.0.1/24` covers `10.0.0.0/24`, and `/0`
covers all IPv4 addresses. Dotted netmasks and IPv6 addresses are not covered. Whether a
denylist name entry also shuts out the names under it is not promised; a request lists each
name it needs shut out. An allowlist name entry lets through at least HTTPS to port 443 of that
name, and a denylist name entry blocks at least that connection.
Host-name coverage ignores ASCII letter case: `A.com` is covered by `a.com`.
Duplicate detection compares whole entries: strings are compared exactly as written. So
`A.com` and `a.com` are distinct entries; likewise `10.0.0.1` and `10.0.0.1/32` are two
address entries. It does not combine or rewrite entries.

A refused connection returns no data from its destination. The request may still reach the
destination and change its state.
The provider may refuse it, let it time out, or accept it and then close it, so a program cannot rely
on `connect()` failing. Lookups of names, and DNS traffic to a resolver on port 53, are outside these rules.

`switches_to` is a nonempty list of other policy values, each listed once; it may be named only
with `switchable`, and is required when `switchable: true`. The same variant must offer the
starting policy and every listed policy. The `allow` or `deny` entries for a later policy are
supplied when the switch happens; limits apply to the starting policy's entries.

- The provider **MUST** enforce the policy outside the sandbox. <!-- rule: network_lockdown/enforced-outside -->
- Code in the sandbox, even running as root, **MUST NOT** be able to lift the policy. <!-- rule: network_lockdown/root-cannot-lift -->
- With `policy: deny_all`, every outbound connection **MUST** be refused. <!-- rule: network_lockdown/deny-all -->
- With `policy: allowlist`, HTTPS connections to listed host names and connections to listed addresses **MUST** <!-- rule: network_lockdown/allowlist -->
  succeed, and connections to anything the policy does not cover be refused.
- A variant **MUST** enforce an allowlist or denylist that holds entries of every kind its <!-- rule: network_lockdown/entry-kinds -->
  `entry_kinds` lists, together in one list.
- With `policy: denylist`, HTTPS connections to the listed host names and connections to the <!-- rule: network_lockdown/denylist -->
  listed addresses **MUST** be refused, and connections to anything else succeed.
- With `changeable: true`, a program **MUST** be able to change the entries of a running <!-- rule: network_lockdown/changeable -->
  sandbox's policy; the new entries hold when the call returns, and the sandbox keeps its
  processes and files.
- With `switchable: true`, a program **MUST** be able to replace a running sandbox's policy. <!-- rule: network_lockdown/switchable -->
  It can switch to any other policy the same variant offers; connections opened after the call
  returns follow the new policy, and the sandbox keeps its processes and files.
- With `policy: open`, outbound connections **MUST** succeed as the [baseline](spec.md#5-baseline) promises until a program switches the policy. <!-- rule: network_lockdown/open -->
- The policy **MUST** hold for the sandbox's whole life, including after a pause and resume. <!-- rule: network_lockdown/holds-after-resume -->
- A variant **MUST** enforce an allowlist of `max_allow` entries, shutting out everything <!-- rule: network_lockdown/max-allow -->
  else.
- A variant **MUST** enforce a denylist of `max_deny` entries. <!-- rule: network_lockdown/max-deny -->
- With `allow_wildcards: true`, an entry `*.example.com` **MUST** let through every name <!-- rule: network_lockdown/wildcards -->
  under `example.com`. A wildcard is not promised to cover the bare domain; a request that
  needs both lists both.

An egress control that code in the sandbox can bypass, such as a proxy a program may choose
not to use, does not qualify as this gate.

### hidden_secrets

Credentials a program uses without being able to read them: the provider adds them to
outgoing requests on the program's behalf. Credentials a program reads for itself are
ordinary environment variables. Its required setting, `inject_into`, is a nonempty list of
host names whose requests receive the secrets. It uses the host-name syntax described
under [network_lockdown](#network_lockdown), including single labels such as `localhost` and
the leading `*.` wildcard prefix; the name after that prefix may not consist only of digits
and dots. Repeated identical entries are refused. When the request also names
`network_lockdown`, its starting policy must let every named host through by name: `open` has
no restriction, an allowlist must list an exact host or cover it with a wildcard, and a
denylist must not list or cover an exact host.
For an `inject_into` wildcard, an allowlist
needs the same wildcard or one for a parent domain, and a denylist must not block any name under
it. A wildcard does not promise to cover its bare domain; a request that needs both lists
both. `deny_all` and an allowlist with no name entries let no host through by name. This check
considers only the starting policy, even if the sandbox can switch later. A service a program
must call at an address of the provider's instead of the real host is not this gate.

| Knob | Values | Meaning |
| --- | --- | --- |
| `rotates` | yes/no | A secret's value can change while the sandbox runs, and later requests carry the new value. |
| `scrubs_responses` | yes/no | The provider removes a secret's value from responses before code in the sandbox reads them. |
| `injection` | `sets_header` | How the secret reaches a request: the provider sets a request header to carry the supplied secret. |
| `header_templates` | yes/no | Whether the provider can use each request's named header templates for this secret. A request must name `true` to select headers. |
| `transparent` | yes/no | The secret reaches requests from any client, including one that ignores the sandbox's proxy variables (`HTTP_PROXY`, `HTTPS_PROXY`), such as Node's built-in `fetch`. Without it, only clients that honour those variables get the secret. |
| `intercepts` | `injected_hosts`, `all_https` | Which HTTPS connections the provider terminates to do it. A client that pins certificates or uses its own certificate authorities rather than the system's, or runs in a container inside the sandbox, rejects the provider's certificate on those. |

The secrets never appear in a request ([requests](spec.md#8-requests)). The tool that
creates the sandbox supplies them to
the provider.

`headers` is an optional `hidden_secrets` setting. It is a nonempty list of objects with a
required HTTP-token `name` and optional text `prefix` and `suffix`, which default to empty.
Header names are compared case-insensitively and may not repeat. Prefixes and suffixes may
not contain C0 controls other than HTAB, DEL or C1 controls. No other fields are accepted. When a request includes `headers`,
it must also name `header_templates: true` and `injection: sets_header`; it must list one or
more distinct exact DNS hostnames in `inject_into` (no wildcard, scheme, path, port or IP).
For every HTTPS request to each listed host, the provider sets each selected header to its
prefix, followed by the supplied secret value, followed by its suffix. All selected headers
use that same secret value.

- The provider **MUST** add each secret to the outgoing requests bound for the hosts in <!-- rule: hidden_secrets/injected -->
  `inject_into`, sent the way an ordinary HTTP client sends them, honouring the sandbox's
  proxy variables, and satisfying the declared `injection` mode.
- Code in the sandbox **MUST NOT** be able to read a secret's value. <!-- rule: hidden_secrets/unreadable -->
- With `rotates: true`, a secret's new value **MUST** reach requests made after the call that <!-- rule: hidden_secrets/rotates -->
  changes it returns, from processes already running, with no new sandbox.
- With `scrubs_responses: true`, a response from a host in `inject_into` whose headers or <!-- rule: hidden_secrets/scrubs-responses -->
  uncompressed body contain a secret's value verbatim **MUST** reach code in the sandbox with
  the value removed or replaced by the secret's placeholder.
- With `injection: sets_header`, a request to a host in `inject_into` **MUST** carry the secret <!-- rule: hidden_secrets/injection -->
  in a request header, though code sent no credential. `header_templates: true` establishes
  support for the selected names and affixes described above; `sets_header` alone does not.
- With `transparent: true`, a request to a host in `inject_into` from a client that ignores <!-- rule: hidden_secrets/transparent -->
  the sandbox's proxy variables **MUST** carry the secret too.
- With `intercepts: injected_hosts`, an HTTPS connection to a host not in `inject_into` <!-- rule: hidden_secrets/intercepts -->
  **MUST** present that host's own certificate.
- A variant **MUST** add each secret to requests for every host in an `inject_into` setting <!-- rule: hidden_secrets/max-inject-into -->
  that fits its declared `max_inject_into` limit.
- With `inject_wildcards: true`, an `inject_into` entry `*.example.com` **MUST** add each secret to requests for every name under `example.com`. <!-- rule: hidden_secrets/wildcards -->
  A wildcard is not promised to cover the bare domain; a request that needs both lists both.

### snapshots

A snapshot saves a sandbox. Restoring one creates a new sandbox on the same provider.
Restoring one snapshot several times forks the sandbox.

| Knob | Values | Meaning |
| --- | --- | --- |
| `keeps` | `files_only`, `files_and_memory` | What the snapshot captures. |
| `original_after` | `continues`, `briefly_paused`, `terminated` (the saved sandbox ends up destroyed) | What becomes of the sandbox that was saved. Must be named: some providers end the sandbox they snapshot. |
| `deletable` | yes/no | A snapshot can be deleted through the provider's API. |
| `retention_seconds` | a number | How long a snapshot stays restorable after it is taken, unless it is deleted. A request says how long it needs. |

A declaration may also state `resizes_on_restore`: whether a restore may ask for a different
size than the saved sandbox had. It is not a knob: a request cannot ask for it, and matching
uses it only for restores ([matching](matching.md)).

- With `keeps: files_only`, a restored sandbox **MUST** have the saved root filesystem. <!-- rule: snapshots/files-only -->
- With `keeps: files_and_memory`, a restored sandbox **MUST** also have the saved processes <!-- rule: snapshots/files-and-memory -->
  running, with their memory.
- After a snapshot, the saved sandbox **MUST** be in the state `original_after` declares: <!-- rule: snapshots/original-after -->
  still running (`continues`); running again after a short freeze (`briefly_paused`); or
  destroyed (`terminated`).
- A snapshot **MUST** be restorable more than once, each restore a separate sandbox. <!-- rule: snapshots/restores-many-times -->
- A restore **MUST** accept the same creation options as a new sandbox, apart from its <!-- rule: snapshots/restore-takes-its-own-options -->
  image and its size, so that a restored sandbox can be given gates the saved one did not
  have. Whether it may ask for a different size is `resizes_on_restore`.
- With `deletable: true`, a snapshot **MUST** be deletable through the provider's API. <!-- rule: snapshots/deletable -->
- With `resizes_on_restore: true`, a restore **MUST** be able to ask for a different size. <!-- rule: snapshots/resizes-on-restore -->
- A snapshot that is not deleted **MUST** stay restorable for at least `retention_seconds` <!-- rule: snapshots/retention -->
  after it is taken.

A short freeze may drop connections open to the sandbox, such as a command's streamed
output; a program that needs them kept asks for `continues`.

### volumes

Storage that outlives the sandboxes that mount it. The `mounts` setting lists the volumes
to mount, each with `provider`, `volume`, and `path`: the provider the volume belongs to, the
volume's name there, and where to mount it in the sandbox. A volume belongs to one provider,
so naming one pins the request to that provider. Each mount may also have `read_only`, a
boolean that defaults to `false`; `provider` is a lower-case ASCII letter/digit name with
hyphens between nonempty groups, `volume` is nonempty text, and `path` is an absolute sandbox
path such as `/data`. The same `(provider, volume, path)` tuple cannot occur twice. The
complete shape is in [request-schema.json](request-schema.json).

| Knob | Values | Meaning |
| --- | --- | --- |
| `sharing` | `one_sandbox`, `many_writers` | One sandbox mounts the volume at a time; many mount it and all write. |
| `read_only_mounts` | yes/no | A mount can be read-only: every write through it fails. |
| `kind` | `filesystem`, `object_store` | Whether file locks hold as on a local disk. Must be named: file locks and SQLite misbehave on object storage. |

A program that needs one sandbox to write while others read asks for `many_writers`.

- What a sandbox writes to a volume **MUST** remain after every sandbox that mounted it is <!-- rule: volumes/persists -->
  destroyed.
- With `sharing: many_writers`, several sandboxes **MUST** be able to mount and write to the <!-- rule: volumes/many-writers -->
  volume at once, each seeing what the others wrote.
- With `sharing: one_sandbox`, a provider **MUST** prevent a second sandbox from mounting a <!-- rule: volumes/one-sandbox -->
  volume while another sandbox has it mounted.
- With `kind: filesystem`, file locks **MUST** hold as they do on a local disk. <!-- rule: volumes/filesystem-locks -->
- With `read_only_mounts: true`, every write through a mount the request marks `read_only`, from any user including root, **MUST** fail, and reads **MUST** succeed. <!-- rule: volumes/read-only -->
- A variant **MUST** mount `max_mounts` volumes in one sandbox. <!-- rule: volumes/max-mounts -->

### custom_images

The sandbox starts from an environment the request brings in its top-level `image`.

| Knob | Values | Meaning |
| --- | --- | --- |
| `source` | `oci`, `private_oci`, `dockerfile`, `provider_artifact` | An OCI image reference in a public or credentialed registry; a Dockerfile the provider builds; an image, template or snapshot the provider already holds. |
| `prepared` | yes/no | Whether the provider prepares the source before sandbox creation and boots the resulting artifact (`true`), or creates directly from the source (`false`). A declaration that omits this knob means `false`; an explicit `unknown` remains unknown. |
| `image_config` | `env`, `workdir`, `user` | Commands that name no directory or user run with the image's environment variables (`env`), in its working directory (`workdir`), as its user (`user`). A request lists every property it relies on and fits only a variant that offers them all. |
| `runs_entrypoint` | yes/no | The image's entrypoint runs when the sandbox starts, as a program whose image starts a service expects. |
| `build_context` | yes/no | With `source: dockerfile`, `COPY` and `ADD` can read files the tool supplies while preparing the image. The context is supplied outside the matching request. |

What else an image must contain for a provider to start it (a language runtime, an
`/etc/os-release` file, a program the provider supplies) differs between providers, and
each provider's evidence says.

- With `source: oci`, a sandbox **MUST** be able to start from an OCI image reference in a <!-- rule: custom_images/oci -->
  public registry.
- With `source: private_oci`, a sandbox **MUST** be able to start from an OCI image in a <!-- rule: custom_images/private-oci -->
  registry that refuses anonymous pulls, using only the registry username and password the
  tool supplies outside the request.
- With `source: dockerfile`, a sandbox **MUST** be able to start from a Dockerfile, built by <!-- rule: custom_images/dockerfile -->
  the provider.
- With `source: provider_artifact`, a sandbox **MUST** be able to start from an image, <!-- rule: custom_images/provider-artifact -->
  template or snapshot the provider holds.
- With `prepared: true`, the provider **MUST** prepare the requested image source before sandbox <!-- rule: custom_images/prepared -->
  creation, and create **MUST** boot the prepared artifact.
- With `runs_entrypoint: true`, the image's entrypoint **MUST** run when the sandbox starts. <!-- rule: custom_images/runs-entrypoint -->

- With `source: dockerfile` and `build_context: true`, the provider **MUST** build the image <!-- rule: custom_images/build-context -->
  with the supplied files available to Dockerfile `COPY` and `ADD`; the resulting sandbox
  must contain the copied bytes. A request may name `build_context` only with a Dockerfile image.

### processes

Control of a process started in the background, beyond reading its output, which every
provider offers ([baseline](spec.md#5-baseline)).

| Knob | Values | Meaning |
| --- | --- | --- |
| `input` | yes/no | A program can write to a running process's standard input. |
| `cancel` | yes/no | A program can stop a running process and keep the sandbox. |
| `reattach` | yes/no | A program that lost its connection to a running process can connect to it again. |

- With `input: true`, what a program writes to a running process **MUST** reach the <!-- rule: processes/input -->
  process's standard input.
- With `cancel: true`, a program **MUST** be able to stop a running process while the <!-- rule: processes/cancel -->
  sandbox keeps running.
- With `reattach: true`, a program that lost its connection to a running process **MUST** be able <!-- rule: processes/reattach -->
  to connect to it again and read the output it produces from then on.

### user_selection

Select a named operating-system user for commands, new files and background processes.

| Knob | Values | Meaning |
| --- | --- | --- |
| `commands` | yes/no | A command runs as the requested named user. |
| `files_write` | yes/no | A new file written by the file API is created by the requested named user. |
| `process_start` | yes/no | A background process starts as the requested named user. |

- With `commands: true`, selecting a named user **MUST** run the command with that user's <!-- rule: user-selection/commands -->
  identity; a missing user or unavailable switch **MUST** fail without running the command.
- With `files_write: true`, selecting a named user **MUST** create a new file owned by that <!-- rule: user-selection/files-write -->
  user; changing ownership after creation does not establish support.
- With `process_start: true`, selecting a named user **MUST** start the process with that <!-- rule: user-selection/process-start -->
  identity; a missing user or unavailable switch **MUST** fail without starting the payload.

### terminal

An interactive terminal in the sandbox: a shell on a pseudo-terminal, the way a person at a
keyboard uses one.

| Knob | Values | Meaning |
| --- | --- | --- |
| `reattach` | yes/no | A program that lost its connection to the terminal can connect to it again. |

- The provider **MUST** give a program a shell on a pseudo-terminal in the sandbox: what the <!-- rule: terminal/interactive -->
  program types reaches the shell, the shell's output comes back, and programs run in it
  see a terminal.
- With `reattach: true`, a program that lost its connection to a terminal **MUST** be able to <!-- rule: terminal/reattach -->
  connect to it again and find the same shell, with what was set in it.

### docker

A Docker Engine runs in the sandbox: a program uses `docker` to pull images and run
containers, as a test suite that starts its database in a container does.

| Knob | Values | Meaning |
| --- | --- | --- |
| `networking` | `host` | Containers share the sandbox's network. |

- A program **MUST** be able to pull a public image and run a container from it, as the <!-- rule: docker/runs-containers -->
  default user or, where that fails, as root by a way `root` lists, and the container can
  open outbound connections unless the request names `network_lockdown`.
- With `networking: host`, a server a container listens on **MUST** be reached from the <!-- rule: docker/host -->
  sandbox at `127.0.0.1`.

Where Docker needs an image the provider supplies or an option at creation, a tool sets it
when it creates the sandbox ([principle 5](spec.md#4-principles)); where that rules out another gate
or a fact, the variant's `conflicts` names it, such as `custom_images`
([matching](matching.md)).

The provider supplies Docker Engine: in its default environment, in an image it publishes, or
through an option at creation. A third-party image the tool names at creation counts as that
option when the provider runs it and Docker Engine works in the sandbox. Where a program has
to install Docker Engine itself, as root through the package manager, the provider does not
offer this gate; whether such an installation runs is not promised.

### tcp_ports

A host and port on the internet that reach a TCP port in the sandbox, for clients that do
not speak HTTP: a database, an SSH server, a game server. The `ports` setting lists the
ports, as for previews. Anyone who has the host and port can connect; a program that needs
more adds its own authentication.

| Knob | Values | Meaning |
| --- | --- | --- |
| `tls` | `none` | The client connects with plain TCP and every byte passes unchanged. Must be named: a client written for TLS breaks on plain TCP. |

- The provider **MUST** give a host and port for each port listed in `ports`, up to <!-- rule: tcp_ports/reachable -->
  `max_tcp_ports`, and a TCP connection to it reaches what the sandbox serves on that port.
- With `tls: none`, a client **MUST** connect with plain TCP, and every byte passes unchanged <!-- rule: tcp_ports/tls-none -->
  in both directions.

### desktop

A graphical desktop in the sandbox that a program sees and drives, as a computer-use agent
does.

| Knob | Values | Meaning |
| --- | --- | --- |
| `live_view` | yes/no | The SDK gives a URL, carrying its own credential, that shows the desktop live in a browser. |

- The provider's SDK **MUST** take a screenshot of the desktop and send it pointer and <!-- rule: desktop/control -->
  keyboard input that reaches the applications on it.
- With `live_view: true`, the SDK **MUST** return a URL that shows the desktop, live, in a <!-- rule: desktop/live-view -->
  browser; its credential **MUST NOT** be an API key for the provider account.

### file_links

A link the provider issues for one file path in a running sandbox, so that a client holding
only the link can read that file or write it over HTTPS, without the provider account's
credentials and without the bytes passing through the program that asked for the link. A
link is a URL plus, where the provider needs them, an HTTP method, request headers and the
name of a multipart form field; the client sends exactly what the link describes.

| Knob | Values | Meaning |
| --- | --- | --- |
| `operations` | `read`, `write` | The operations a link can be issued for: `read` returns the file's bytes, `write` replaces the file with the request body. A request lists every operation it uses, and a variant fits only when it offers all of them. |
| `user_selection` | yes/no | A link can name a user in the sandbox: a `write` link leaves a file that user owns, and a `read` link reads with that user's permissions. |
| `link_lifetime_seconds` | a number | The longest lifetime a caller can request for a link. |
| `revocable` | yes/no | Every outstanding link of one sandbox can be invalidated while the sandbox keeps running. |

Here a link is *refused* when the provider answers with a client error status (400–499)
and neither returns the file's bytes nor changes the file.

- A link **MUST** reach only the path it was issued for: the same request with any other <!-- rule: file-links/one-path -->
  path in place of that path is refused.
- A link **MUST** permit only the operation it was issued for: a `write` request sent with <!-- rule: file-links/one-operation -->
  a `read` link, and a `read` request sent with a `write` link, are refused.
- A link **MUST** be refused once the lifetime requested for it has passed. <!-- rule: file-links/expiry -->
- A link requested with a lifetime up to `link_lifetime_seconds` **MUST** keep working for <!-- rule: file-links/link-lifetime -->
  that long while the sandbox runs.
- A link's credential **MUST NOT** be an API key for the provider account, and a client <!-- rule: file-links/own-credential -->
  that sends only what the link describes **MUST** be served, so a link is safe to hand to a
  third party.
- A `read` link **MUST** return exactly the file's bytes. <!-- rule: file-links/read-exact-bytes -->
- A successful `write` **MUST** leave exactly the sent bytes at the path, including an <!-- rule: file-links/write-exact-bytes -->
  empty body and a shorter body over a longer file.
- A successful `write` **MUST** create missing parent directories. <!-- rule: file-links/write-parents -->
- A file left by a successful `write` **MUST** be readable and writable by the user a <!-- rule: file-links/write-usable -->
  command runs as when it names none.
- With `user_selection: true`, a `write` link issued for a named user **MUST** leave a file <!-- rule: file-links/user-selection -->
  that user owns, reads and writes, and a `read` link issued for that user **MUST** be refused
  for a file that user cannot read.
- With `revocable: true`, revoking a sandbox's links **MUST** make every link issued before <!-- rule: file-links/revocable -->
  then refused, while the sandbox keeps running and a link issued afterwards works.
- A `write` whose request body ends before the length it announced **MAY** leave part of <!-- rule: file-links/interrupted-write -->
  the body at the path; that is not a failure. The path **MUST** then hold its previous
  content, no file, or a prefix of the sent body (possibly empty), and a later complete `write`
  through a new link **MUST** leave exactly its bytes.

## Facts and resources

In a request, `lifetime_seconds`, `idle_shutdown.idle_seconds`, `memory_min_mib`,
`disk_min_mib`, `gpu_count`, `run_seconds`, `process_seconds` and each value of
`file_stream_bytes` are positive integers.
For these fields, an integer is a finite number with no fractional part, so `2.0` has
the same meaning as `2`. `cpu_min` and `paused_retention_seconds` are positive finite
numbers and may be fractional, for example `0.5`; `paused_retention_seconds` is measured
in seconds. Non-finite values such as `NaN` or infinity are not valid in defined request
fields. A resource minimum belongs under `resources`; `lifetime_seconds` is top-level and `idle_seconds`
is a setting of `requirements.idle_shutdown`. [request-schema.json](request-schema.json)
defines the structural types and bounds of request fields. Schema validation is necessary
but not sufficient: the [section 8 refusal rules](spec.md#8-requests) also apply, including
semantic combinations and address syntax checked by the checker and reference matcher.

A declaration's facts describe the provider or class as a whole. Most sit under `resources`
in the declaration; `lifetime_timer` is a block of its own. A request asks of the facts
through its `resources`, `lifetime_seconds` and `at_end`, and each is compared only when
the request names it; `disk_in_memory` is compared when the request names both
`memory_min_mib` and `disk_min_mib`.

A provider whose plan restricts outbound traffic records the condition in
`resources.needs.outbound_traffic`.

Resource meanings in the table below are generated from the canonical `resource_descriptions`
map in [catalog.yaml](catalog.yaml).

| Fact | Meaning | A request asks | It fits when |
| --- | --- | --- | --- |
| `sizes`, `disk_mib` | The CPU, memory and disk the provider allocates. Most providers tie CPU and memory together, so sizes are combinations. | `cpu_min`, `memory_min_mib`, `disk_min_mib` | a declared size has at least that much of each |
| `size_is_ceiling` | A sandbox created with a declared size cannot use more CPU time or memory than that size, however many processes it runs. | `size_is_ceiling: true` | it is `true` |
| `max_lifetime_seconds` | The longest a sandbox may run continuously: at least 300, as a number, {at_least: N} or unlimited. Never written unknown; left out, it is unknown. | `lifetime_seconds` | the maximum is at least that |
| `extendable_lifetime` | The lifetime of a running sandbox can be lengthened. | `extendable_lifetime: true` | it is `true` |
| `long_running` | A sandbox is not stopped for being idle or unattended; this is separate from how long it may live (max_lifetime_seconds). | `long_running: true` | it is `true` |
| `regions`, `located_in` | The regions a request can pin, and the countries a sandbox may run in when none is pinned. | `region`: a region, an area or a country | every country the sandbox may run in lies inside it |
| `gpus`, `max_gpus` | The GPU models offered, and how many one sandbox may have. | `gpu_model` (one or a list), `gpu_count` | one of those models is offered, that many; `gpu_count` alone accepts any model |
| `kernel` | What sits between the code and the host's kernel: shared (an ordinary container), filtered (a layer such as gVisor intercepts system calls) or dedicated (a virtual machine or microVM with its own kernel). | `kernel` (one or a list) | it is one of them |
| `kernel_features` | Kernel facilities code in the sandbox can use, as root: mount a FUSE file system (fuse), load an eBPF program (ebpf), create a child cgroup and limit its memory (nested_cgroups), or add netfilter rules that act on the sandbox's own traffic (netfilter). An empty list means none. | `kernel_features`, every one it uses | it offers all of them |
| `default_user`, `default_cwd` | The user a command runs as, and the directory it runs in, when the sandbox was created without an image and the command names neither. A written default_cwd is an absolute sandbox path; leave it out when unknown, rather than writing unknown. |  | not compared |
| `default_size` | The allocation a create receives when the caller names no size and the driver omits a native size setting. It is a concrete {cpu, memory_mib} shape, with optional disk_mib, or unknown. Leave it out or use unknown when that path has not been established. |  | not compared |
| `root` | How a command in a sandbox created without an image gets root: by_default (commands run as root), sudo (the default user has passwordless sudo), per_command (the SDK runs a command as root when asked). An empty list means no way. | `root`: the ways the program can use (one or a list) | it lists one of them |
| `arch` | The processor architectures a sandbox can run on, as OCI names them: amd64, arm64. The first is the default. | `arch` (one or a list) | it offers one of them |
| `package_manager`, `libc` | In a sandbox created without an image: the system package manager (apt, apk, dnf, pacman or none); and the C library (glibc or musl), which decides which prebuilt binaries run. | `package_manager`, `libc` (one or a list) | it is one of them |
| `max_run_seconds` | The longest a command a program runs and waits for may take: a number, {at_least: N} or unlimited. | `run_seconds` | the maximum is at least that |
| `max_process_seconds` | The longest a background process may run before the provider stops it, in the same forms. | `process_seconds` | the maximum is at least that |
| `egress_ips` | Where a sandbox's outbound connections can come from, for a destination that allows addresses: published_ranges (within ranges the sandbox provider itself publishes for this) or dedicated (addresses reserved to the account). A list of what the provider offers; [] means neither. | `egress_ips` (one or a list) | it offers one of them |
| `outbound_traffic` | Outbound traffic beyond HTTPS that a sandbox created without network_lockdown can send: plain HTTP to port 80 (http); TCP to any public address and port (any_tcp); UDP to any public address and port (udp). A declaration lists what it offers; [] means HTTPS only. | `outbound_traffic`, every kind it needs | it offers all of them |
| `outbound_ip_families` | Address families from which a sandbox can open a socket and complete a TCP handshake to a public literal address of the same family: ipv4 or ipv6. An omitted declaration is unknown. | `outbound_ip_families`, every family it needs | it offers all of them |
| `ipv4_destination_reach` | How an IPv4 literal destination is reached: native after an IPv4 handshake, or nat64 after an IPv6 translated-literal handshake and definite native IPv4 absence. none is reserved; this fact is informative and a failed probe remains unknown. |  | not compared |
| `needs` | Restrictions a provider plan applies to outbound traffic. |  | not compared |
| `disk_in_memory` | Files written to the sandbox's own filesystem take its memory rather than disk. | (with `memory_min_mib` and `disk_min_mib`) | unless it is `false`, the size chosen has memory for both together |
| `on_memory_exhausted` | What the provider ends when a process allocates more memory than the sandbox has: the process (process_killed) or the sandbox (sandbox_ended). | `on_memory_exhausted` (one or a list) | it is one of them |
| `paused_retention_seconds` | How long the provider keeps a paused or stopped sandbox before deleting it: a number, {at_least: N} or unlimited. | `paused_retention_seconds` | the declared value is at least that |
| `lifetime_timer` | Whether the provider ends a sandbox when its lifetime runs out (`enforced_by: provider`; a provider without such a timer leaves the block out), whether paused time counts (`counts_paused_time`), and the state the sandbox ends in (`at_end`): `destroyed`, `stopped` or `paused`, or a list of those a caller chooses from at creation. Optional and compared: `min_seconds`, the shortest lifetime the provider accepts. Optional and never compared: `adjustable` (the timer of a sandbox that exists can be set to a new length), `clearable` (a timer that was set can be removed from a sandbox that exists, so it has no end of its own; `true`, `false` or `unknown`), `step_seconds` (the timer's unit; a lifetime that is not a whole number of steps is rounded up to one) `counts_from` (`create`: the provider accepts the create; `ready`: the sandbox can run commands; or `unknown`) and `after_resume` (`same`, the default: a resumed sandbox ends as `at_end` says; `pauses`: the timer pauses a sandbox that has been paused and resumed, although it ends one that was not; or `unknown`). | `at_end`: `destroyed` or `paused`; `lifetime_seconds` | the provider ends the lifetime itself and its `at_end` offers that state; `lifetime_seconds` is at least `min_seconds` |
| `guest_reserved_tcp_ports` | A non-empty subset of TCP ports whose provider-owned listener was observed and blocked the exact tested guest bind tuple. Omitted ports, other families, scopes and times are not established; an empty table does not mean no ports are reserved. Omitted resource means unknown. |  | not compared |
| `files_write_executable_effect` | What a regular-file write may do to executable bits: preserved keeps execute access on a 0755 overwrite, may_clear may drop it, unverified has no packaged claim. Writing a file does not guarantee it remains executable. Check or explicitly set executable permission before running it as a program. Omitted resource means unverified. The field is informative and never compared. |  | not compared |
| `file_stream_max_bytes` | The largest file one streamed transfer through the provider's own API moves intact, for read (out of the sandbox) and write (into it): a number of bytes or {at_least: N}, each proven by a transfer of that size. Never unlimited; a direction left out is unknown. | `file_stream_bytes`: `{read: N, write: N}`, naming either or both | the declared value for each named direction is at least N |
| `unmet_limits` | The ceiling that holds while a condition named under needs is not met: for a limited fact (max_lifetime_seconds or disk_mib) and one of its conditions, a positive integer in the fact's own unit, or unknown. It narrows what an account can be offered and never proves a request is supported. |  | not compared |

For `outbound_ip_families`, a probe uses literal addresses and forces `AF_INET` or `AF_INET6`;
it does not resolve a name. A successful TCP handshake proves the corresponding family. A negative
result requires both `ENETUNREACH` or `EADDRNOTAVAIL` and complete local address and route evidence;
timeouts and other errors leave the result unknown. An omitted declaration stays unknown, so a
request that asks for a family does not match it.

`file_stream_max_bytes` describes streamed transfer: one call of the provider's own API or
SDK that moves a file into the sandbox (`write`) or out of it (`read`) as a sequence of chunks,
so neither side needs the whole file in one message. It is how a program moves a file too
large for one regular-file write or read. Each direction is a number of bytes or
`{at_least: N}`, and is proven only by a transfer of that many bytes; a direction left out, or
written `unknown`, is unknown. Nothing is declared unlimited. A request names the size it will
move in `file_stream_bytes`, for example `{write: 1073741824}`, and a direction it leaves out
is not compared.

`ipv4_destination_reach` is informative and never affects matching. `native` requires a successful
IPv4 handshake. `nat64` requires a successful IPv6 handshake to the IPv4 literal translated under
an explicitly supplied, provenance-bearing NAT64 prefix, plus definite native IPv4 absence. There
is no automatic prefix or DNS discovery. `none` is never inferred by this probe; missing prefixes,
timeouts and failed candidate connections remain unknown.

A request's resources and lifetime are requirements: matching compares them, and a tool that
creates the sandbox then provisions them ([principle 5](spec.md#4-principles)). `sizes` and
`disk_mib` are the allocation the provider sells and reports; a program inside always sees
a little less. `kernel` says one narrow thing, and nothing about who else runs on the host.

`kernel` says what isolates the code. `kernel_features` says what it may do, and a dedicated
kernel does not imply any of them.

`root`, `package_manager` and `libc` describe a sandbox created without an image;
a request that brings an image decides them itself and does not ask for them. Where a gate's
variant needs an environment the provider supplies, such as a Docker or desktop image, the
variant's `conflicts` names each of those facts that differs there ([matching](matching.md)).

- A sandbox created with a declared size **MUST** receive that allocation. <!-- rule: facts/sizes -->
- With `size_is_ceiling: true`, a sandbox created with a declared size **MUST NOT** use more CPU time per second than the size's `cpu`, or more memory than its `memory_mib`. <!-- rule: facts/size-is-ceiling -->
- A sandbox **MUST** be able to run continuously for `max_lifetime_seconds`. <!-- rule: facts/max-lifetime -->
- With `extendable_lifetime: true`, the lifetime of a running sandbox **MUST** be able to <!-- rule: facts/extendable-lifetime -->
  be lengthened, and after a successful extension the provider **MUST** end the sandbox no later
  than the new end (never at the old one). A client that renews a lifetime in steps, only ever moving
  the end later, needs only this fact. A client that must also set an exact or shorter lifetime
  needs `lifetime_timer.adjustable: true` as well. Where `extendable_lifetime` is not
  `true`, the lifetime given at creation is fixed.
- With `long_running: true`, a sandbox created to stay on **MUST** keep running while idle. <!-- rule: facts/long-running -->
- A sandbox created in a declared region **MUST** run in that region. <!-- rule: facts/regions -->
- A sandbox created without a region **MUST** run in one of the countries `located_in` lists. <!-- rule: facts/located-in -->
- A sandbox created with a declared GPU model **MUST** have that GPU, as many as asked up to <!-- rule: facts/gpus -->
  `max_gpus`.
- The kernel boundary **MUST** be what `kernel` declares. <!-- rule: facts/kernel -->
- In a sandbox created without an image, a command that names no user or directory **MUST** <!-- rule: facts/default-environment -->
  run as `default_user`, in `default_cwd`.
- In a sandbox created without an image, each way `root` lists **MUST** run a command as <!-- rule: facts/root -->
  root, and `root` lists `by_default` exactly when the default user is root.
- A sandbox created for a declared architecture **MUST** run on it. <!-- rule: facts/arch -->
- In a sandbox created without an image, the package manager `package_manager` names, unless <!-- rule: facts/package-manager -->
  it is `none`, **MUST** be on the path and, run as root by a way `root` lists, install a
  package from the distribution's default repositories.
- In a sandbox created without an image, the C library **MUST** be the one `libc` names. <!-- rule: facts/libc -->
- A command a program runs and waits for, with the SDK's own timeout for it set as long as <!-- rule: facts/max-run -->
  the SDK allows, **MUST** be allowed to run for `max_run_seconds` and return its output and
  exit status.
- A background process, started with the longest timeout the SDK allows, **MUST** be allowed <!-- rule: facts/max-process -->
  to run for `max_process_seconds`.
- With `disk_in_memory: true`, files written to the sandbox's own filesystem **MUST** count <!-- rule: facts/disk-in-memory -->
  against its memory; with `false`, they **MUST NOT**.
- When a process in a sandbox allocates more memory than the sandbox has, the provider **MUST** do what `on_memory_exhausted` declares: end that process and keep the sandbox running (`process_killed`), or end the sandbox (`sandbox_ended`). <!-- rule: facts/on-memory-exhausted -->
- A sandbox created for a declared `egress_ips` value **MUST** connect out from such <!-- rule: facts/egress-ips -->
  addresses.
- With `outbound_traffic` including `http`, a sandbox created without `network_lockdown` **MUST** reach a public plain-HTTP endpoint on port 80. <!-- rule: facts/outbound-http -->
- With `outbound_traffic` including `any_tcp`, a sandbox created without `network_lockdown` **MUST** reach a public TCP endpoint on any address and port. <!-- rule: facts/outbound-tcp -->
- With `outbound_traffic` including `udp`, a sandbox created without `network_lockdown` **MUST** reach a public UDP endpoint on any address and port. <!-- rule: facts/outbound-udp -->
- A sandbox declared with an `outbound_ip_families` value **MUST** complete a TCP <!-- rule: facts/outbound-ip-families -->
  handshake from a socket forced to that family to a public literal address of that family.
- `ipv4_destination_reach: native` **MUST** have a successful native IPv4 handshake; <!-- rule: facts/outbound-ip-families -->
  `nat64` **MUST** have a successful IPv6 handshake to an explicitly translated IPv4 literal and
  definite native IPv4 absence. This fact never asserts `none` from a failed probe.
- Each `guest_reserved_tcp_ports` member **MUST** be blocked by an established provider-owned <!-- rule: facts/guest-reserved-tcp-ports -->
  listener for the exact tested guest bind tuple and the bound class/image/runtime scope; omitted
  ports remain unknown.
- A successful regular-file write **MUST** leave exactly the supplied bytes, including empty and <!-- rule: files/regular-write-exact-bytes -->
  binary input and a shorter overwrite, and return that byte count.
- A successful regular-file write **MUST** create missing parent directories and leave them <!-- rule: files/regular-write-parents -->
  traversable by the configured execution user.
- The configured execution user **MUST** be able to open a newly created regular file for read <!-- rule: files/regular-write-create-access -->
  and write.
- After overwriting an ordinary `0600`, `0640` or `0755` regular file, that user **MUST** still <!-- rule: files/regular-write-overwrite-access -->
  be able to open it for read and write. Mode, owner and inode need not be preserved.
- A write that the configured execution user cannot authorize **MUST** fail as an authorization <!-- rule: files/regular-write-authority -->
  error, without chmod or chown widening.
- `files_write_executable_effect` **MUST** be `preserved`, `may_clear` or `unverified`. <!-- rule: facts/files-write-executable-effect -->
  `preserved` keeps execution-user execute access on a `0755` overwrite. `may_clear` accepts
  either result. Omitted means `unverified`. Writing a file does not guarantee it remains
  executable.
- Inclusive 16 MiB writes **MUST** succeed; a caller's smaller `limit_bytes` and 16 MiB plus one <!-- rule: files/regular-write-byte-bound -->
  **MUST** be refused before provider dispatch and without creating the target or parents.
- File-write outcomes **MUST** distinguish not-dispatched, confirmed and unknown, and **MUST NOT** <!-- rule: files/regular-write-outcome -->
  replay an uncertain write.
- Where staging is used, confirmed work **MUST** remove only owned staging; uncertain work **MUST** <!-- rule: files/regular-write-staging-cleanup -->
  retain its identity and report uncertainty without claiming rollback.
- A single streamed write of a file of up to `file_stream_max_bytes.write` bytes **MUST** <!-- rule: facts/file-stream-write -->
  leave exactly those bytes at the path, and return that byte count.
- A single streamed read of a file of up to `file_stream_max_bytes.read` bytes **MUST** <!-- rule: facts/file-stream-read -->
  return exactly the file's bytes, all of them.
- A paused or stopped sandbox **MUST** remain resumable for at least <!-- rule: facts/paused-retention -->
  `paused_retention_seconds`.
- With `lifetime_timer` `enforced_by: provider`, the provider **MUST** end a sandbox when its <!-- rule: facts/lifetime-timer -->
  lifetime runs out, leaving it in the state `at_end` declares, and count paused time only
  where `counts_paused_time` is `true`. `at_end` describes the sandbox as a program sees it
  afterwards, never a session inside the provider.
- With `lifetime_timer` `adjustable: true`, a new length set on a running sandbox, longer or shorter, <!-- rule: facts/lifetime-timer-adjustable -->
  **MUST** either be refused or end the sandbox no later than the new end: the moment of the set
  plus the new length, or creation plus the new length where the provider counts from creation. A
  shorter length that is accepted ends the sandbox early; a longer one lets it run until the new end
  and never beyond `max_lifetime_seconds`. A provider that can only lengthen declares
  `extendable_lifetime` without `adjustable`.
- With `lifetime_timer` `clearable: true`, a sandbox whose timer is removed **MUST** no longer be ended <!-- rule: facts/lifetime-timer-clearable -->
  by it. With `clearable` `false` or `unknown`, a client that needs a sandbox without an end must create it
  without a lifetime, never rely on removing one.
- With `lifetime_timer` `step_seconds`, the timer **MUST NOT** end a sandbox before its lifetime <!-- rule: facts/lifetime-timer-step -->
  rounded up to a whole number of steps.
- With `lifetime_timer` `counts_from`, the timer **MUST NOT** end a sandbox before its lifetime <!-- rule: facts/lifetime-timer-counts-from -->
  has passed since that moment.
- With `lifetime_timer` `min_seconds`, the provider **MUST** accept a lifetime of that many seconds. <!-- rule: facts/lifetime-timer-min -->
- With `lifetime_timer` `after_resume: pauses`, a sandbox paused and then resumed **MUST** be paused, not <!-- rule: facts/lifetime-timer-after-resume -->
  destroyed, when its timer runs out; with `same` it ends as `at_end` says.
- In a sandbox created without an image, with `kernel_features` including `fuse`, a command run as root by a way `root` lists **MUST** open <!-- rule: facts/kernel-fuse -->
  `/dev/fuse` and mount a FUSE file system with it.
- In a sandbox created without an image, with `kernel_features` including `ebpf`, a command run as root by a way `root` lists **MUST** load <!-- rule: facts/kernel-ebpf -->
  a socket-filter eBPF program with the `bpf` system call.
- In a sandbox created without an image, with `kernel_features` including `nested_cgroups`, a command run as root by a way `root` lists **MUST** <!-- rule: facts/kernel-nested-cgroups -->
  create a child cgroup, move a process into it, and set the child's memory limit.
- In a sandbox created without an image, with `kernel_features` including `netfilter`, a command run as root by a way `root` lists **MUST** <!-- rule: facts/kernel-netfilter -->
  add a netfilter rule that refuses its own outbound connection to an address, and remove it again.
  This never lifts a `network_lockdown` policy, which the provider enforces outside the sandbox.

### Registries

Region, area and country identifiers come from [registries/regions.json](registries/regions.json):
a provider's region is written as a provider-qualified identifier (`example:eu-west`), an area is a
group of countries (`EU`, `EEA`), and a country is its ISO 3166-1 alpha-2 code (`US`); the
registry lists every such code. Quote country codes in YAML requests and declarations:
`"NO"` is Norway, but the YAML loader reads unquoted `NO` as the boolean `false`.
GPU models come from
[registries/gpu-models.json](registries/gpu-models.json) (`nvidia:a100-80gb`).

A registry entry says where an identifier places compute, or what a model is; it does not
say anyone offers it. The registries are data, versioned with the specification: a new
identifier is added in a patch release. An entry never changes meaning once published,
except that `countries: null`, meaning the countries are not yet known, may be filled in
once.

- A tool **MUST** treat an identifier its registries do not list as matching nothing: in a <!-- rule: registries/unknown-identifier-matches-nothing -->
  request it fits no declaration, and in a declaration it reads as `unknown`.
