# Conformance

[Specification index](README.md) · [Documentation](../docs/README.md)

The shared tests turn a provider's declaration into evidence. They exercise its native
API or SDK directly, through a faithful adapter, or through an HTTP binding, independently
of the declaration. Rules live in [spec.md](spec.md),
[vocabulary.md](vocabulary.md), [matching.md](matching.md) and
[declarations.md](declarations.md); this page explains the test format and tools.

The baseline's `baseline.process_eof_is_not_exit` workload closes both guest output
file descriptors, writes a readiness marker, and waits for a release file. The runner
checks native process state while that workload is still blocked, releases it, and
requires exit 7. This checks execution state and the eventual exit code without requiring
an SDK or transport to expose EOF early. A fault-injection result must distinguish a
premature completion response emitted during native execution from a wrong exit code
emitted after native completion; retain the independent injection witness with its report.

## The tests

[conformance/suite.yaml](../conformance/suite.yaml) carries the specification version and
one `tests` list. Each test has a stable `id`, a descriptive `title`, `rules`, `proves`, and
`steps`. Baseline tests name the [baseline](spec.md#5-baseline) rules they check and prove
no declared value, since a declaration never states the baseline. Timer behavior is tested
separately under `lifetime_timer.*`, because providers can end lifetimes differently.

Every test either names one or more normative rule IDs in `rules`, or has a nonempty
`non_normative` explanation. A non-normative test records diagnostic behavior outside the
draft's guarantees. Its result remains visible in a report but does not establish or disprove
conformance and is not part of baseline eligibility. A test cannot declare both fields.
`check-rules` requires every rule ID to point to normative text and every normative rule to
have a test or a documented waiver in `spec/untested.yaml`.

`rules` lists the rule identifiers checked. `proves` lists the declared values checked:
`{gate: pause_resume, knob: keeps, value: files_only}` or
`{fact: lifetime_timer.at_end, value: destroyed}`. A gate without knobs uses a presence
target, such as `{gate: terminal, value: true}`. Reports retain both lists even when a
test does not pass. These lists identify coverage targets; the result determines what
the test establishes. A proof value may name a fixture, such as
`$runner.link_lifetime_wait_seconds`; the report records the number used. A missing or
invalid proof fixture makes the test `not_run` before anything is created, with an empty
proof list. Endpoints, credentials and native identifiers are never proof values.

`facts.default_user` and `facts.default_cwd` observe a sandbox created without an image.
The runner executes `id -un` or `pwd` without selecting a user or directory. Only after a
successful command does it resolve `$observed.default_user` or `$observed.default_cwd`
to a validated single line and record that concrete fact. No expected fixture value is
compared. Input, cancellation, reattachment and interactive terminals are gate tests;
their creation requirements name the gate they exercise.

## Every rule is checked or explained

A rule stated with MUST, MUST NOT, SHOULD or SHOULD NOT has a stable identifier.
Conformance tests cover provider behavior; checker tests cover declarations and requests;
matcher vectors cover matching.
[untested.yaml](untested.yaml) gives a reason for each rule that cannot be tested.
`make check` checks that every rule is covered or waived, that none is both, and that
coverage and waivers name existing rules. Checker and matcher tests use
`@pytest.mark.rule("<id>")`; matcher vectors carry a `rules` list.

## Running the tests against a provider

Use a clean Git checkout and the SDK's standard environment variables. Install the
provider's optional dependency, then run both `--suite core` and `--suite coverage`,
choosing outputs outside the checkout. Only a report that selected every current baseline
test shows the complete baseline. Pass the same external JSON fixture file with
`--fixtures` to both runs. Each suite selects the outbound-network baseline test, which
needs `reachable_url`, a public HTTPS URL reachable from the runner and guest.
The fixture file must contain valid JSON. Use `{}` when no fixtures are available; a
zero-byte file is invalid JSON and prevents the run from producing a report. Without
`reachable_url`, the outbound test is `not_run` and cannot establish a passing baseline.
Other selected tests need the fixtures listed below.

The fixture file is one JSON object with fixture names as top-level keys. For example,
`$runner.reachable_url` reads the `reachable_url` key directly; do not wrap the keys in
`runner` or `fixtures`. Values may be strings, numbers, lists or objects, as the fixture
tables specify. Keep the file outside the checkout. A minimal starting file contains
`{"reachable_url": "https://example.com/"}`. This is a runner fixture object, not a
specification request.

Replace the example URL with a public HTTPS endpoint that returns a successful
response directly, without redirecting, and is reachable from both the runner and an
unrestricted guest. This example
supplies the outbound-network baseline fixture; selected gate tests may need more fixtures.
`run_nonce` is reserved: the runner generates a fresh value for each run and overwrites
any supplied value. Omit it from the file.

```console
uv sync --locked --extra e2b --extra browser
uv run --locked --extra e2b --extra browser playwright install chromium
uv run --locked --extra e2b --extra browser sandbox-provider-spec run e2b --suite core \
  --fixtures /tmp/e2b-fixtures.json --live \
  --output /tmp/e2b-core-report.json
uv run --locked --extra e2b --extra browser sandbox-provider-spec run e2b --suite coverage \
  --fixtures /tmp/e2b-fixtures.json --live \
  --output /tmp/e2b-coverage-report.json
```

Desktop live-view tests need the runner's `browser` extra and Chromium on the runner
machine. Keep the same extras on each `uv run` command. On Linux, if Chromium's system
libraries are missing, use
`uv run --locked --extra e2b --extra browser playwright install --with-deps chromium`;
this may require administrator privileges.

For baseline and core evidence only, use two reports per provider and declaration class:
the full `--suite core` run, plus `--suite coverage --test baseline.` with the same SDK
versions and the fixture file. The latter selects all 17 current baseline tests. A full
coverage run already supplies that selection alongside its supplementary observations.

| Option | Meaning |
| --- | --- |
| `--live` | Required: creates native resources on the account. |
| `--output` | Required: the JSON report destination. Use a path outside the checkout. |
| `--class` | Declaration class; defaults to `default`. Driver notes describe class selection. Single-declaration providers omit class from the report. |
| `--test` | Test id or prefix; repeatable. Omit it to select every test. |
| `--fixtures` | External JSON object keyed by fixture name; only validated public proof quantities are recorded. |
| `--suite` | `core` (default) selects the core suite: gate, lifetime and fact tests, and all but one baseline test. `coverage` selects every baseline test and the supplementary tests. Run both suites for a provider. |

`run --help` lists the available drivers. An installed wheel supplies checker tools and
suite data; authoritative live reports currently require running the driver from the
clean source checkout whose revision they record.

### Supplementary coverage

[coverage.yaml](../conformance/coverage.yaml) adds environment facts, native access gates,
preview details, egress and lifecycle observations. Its `baseline.*` tests join the loader's
complete baseline set. A core-only selection that omits them reports its baseline as
`not_run`. Selecting `--suite coverage` includes every baseline test and every
supplementary test; it does not repeat the core gate tests. Its digest covers both files,
with their names and file boundaries, even though core gate tests are not selected.
A selection that omits any baseline test cannot establish the complete baseline.

The supplementary tests also use these driver operations:

| Operation | Inputs and native result |
| --- | --- |
| `run.as_root` | The same command inputs as `run`; the SDK's per-command user selector runs it as uid 0. |
| `network.update` | A policy and its `allow` or `deny` list; returns after the native policy call. |
| `fixture.coverage_allowlist` | `allowed_url`, `allowed_ip_url` and `denied_url`; first checks that all three controls are reachable outside the sandbox, then observes the listed name and address succeed and the unlisted URL fail inside the mixed allowlist sandbox. Returns `listed_name_allowed`, `listed_address_allowed` and `unlisted_denied`. |
| `fixture.coverage_deny_wins` | `allowed_url` and `denied_url` whose host names are both covered by the request's wildcard allow entry, with the denied URL's exact host in its deny entry. First checks both controls from the runner, then verifies the denied request is refused before reaching its receiver and the other request succeeds. Returns `denied_refused`, `allowed_succeeded` and `denied_receiver_not_reached`. |
| `fixture.coverage_http_rules` | `allowed_url`, `wrong_method_url` and `outside_path_url` on the same controlled HTTPS receiver; the request supplies that receiver's `http_rules_host`. Sends guest `GET /allowed/x` (matched by `/allowed/**`), `POST /allowed/x` and `GET /other` requests, validates the matching request and receiver before treating failures as denials, and returns whether only the matching request succeeded and reached the receiver. |
| `fixture.coverage_http_rule_deny` | `get_url` and `post_url` on the same controlled HTTPS receiver; the request supplies that receiver's `http_rules_host`. First checks both requests from the runner, then sends guest GET and POST requests and returns whether GET succeeded, POST was refused, and the receiver saw only GET. |
| `fixture.coverage_harness_health` | The controlled `egress_harness`; checks that its HTTP, HTTPS, TLS, TCP and UDP probes are reachable from the runner and returns `all_transports_healthy`. |
| `fixture.coverage_outbound_traffic` | `traffic` (`http`, `any_tcp` or `udp`) and the matching endpoint fixture; checks the endpoint from the runner, then from a sandbox created without `network_lockdown`. HTTP uses a direct 2xx response on port 80; TCP and UDP echo a unique per-run payload, with the TCP endpoint on a port other than 80 or 443. Returns `reached: true` only when both checks succeed. |
| `fixture.coverage_domain_traffic` | The controlled `egress_harness`; checks those five transports from the sandbox and rechecks the runner controls, then returns the observed class as `domain_traffic`: `https`, `http_and_https`, `tls`, `all` or `other` for any other observed combination. |
| `fixture.coverage_policy_change` | `changeable` or `switchable`, `allowed_url` and `new_policy`; `switchable` takes `reachable_before` and `reachable_after`, booleans for expected sandbox-side reachability of `allowed_url` before and after the update. Either may be false; the fixture must not require sandbox-side reachability before the update. It tries policies named in the create request's `switches_to` and probes the URL on both sides of the native update. `policy_changed` is true only when those observations match both expectations and differ. Repeated calls exercise other policies and a change back to the starting policy. Returns `policy_changed` and `source_preserved`. |
| `fixture.coverage_open_connection` | A `connection_harness`; opens and observes an HTTPS stream to its `stream_url`, returning an opaque live connection. |
| `fixture.coverage_connection_update` | A live `connection` and a same-kind `new_policy`; starts the ten-second observation window immediately before one native policy update and returns the connection with its deadline. |
| `fixture.coverage_connection_closed` | The updated `connection` and `window_seconds: 10`; returns whether the stream closed within the window. A false result requires stream data to continue after the window. |
| `fixture.coverage_secret_hosts` | Sandbox target, generated test-only `value`, `hosts` and matching HTTPS `urls`; sends one ordinary proxied request from the sandbox to each URL and checks that each controlled receiver got the secret. Runner reachability controls bound the endpoints; the result never includes the secret value. |
| `fixture.coverage_secret_wildcard` | Sandbox target, generated test-only `value`, an `inject_into` wildcard host and an HTTPS URL whose hostname is under that wildcard but is not its bare domain; sends one ordinary proxied request from the sandbox and checks that the controlled receiver got the secret. It returns only `wildcard_host_received` and never the secret value. |
| `fixture.coverage_secret_body` | A JSON field name and generated test-only secret; sends `POST`, `PUT` and `PATCH` JSON objects with other test fields from the sandbox to a controlled receiver, then checks that the named field holds the secret and all other fields are unchanged in all three requests. Returns only booleans and never the secret value. |
| `fixture.coverage_secret_header` | A header name and generated test-only secret; configures hidden-secret injection for that header and sends a request from the sandbox to a controlled receiver with the same header set to `dummy`. Returns `header_count` (the number of received values for the header) and `carries_secret` (whether its sole value is the generated secret), never the secret value. |
| `fixture.coverage_egress_proxy` | `probe` (`routes`, `any_tcp`, `transparent` or `fails_closed`) and the request requirements; creates and cleans up a short-lived sandbox, supplying the fixture proxy's address and credentials through the provider SDK at creation. A controlled proxy records carried connections and controlled HTTP, HTTPS and TCP destinations report their observed source address. Returns only booleans. The `fails_closed` probe uses an unreachable proxy and confirms HTTP and HTTPS connections fail without reaching a destination. Raw TCP is outside that probe because it requests `traffic: http`. |
| `fixture.coverage_identity_token` | `delivery` (`environment`, `injected` or `any`), optional `custom_audience` and `audience`; creates two test sandboxes with tokens configured at creation. For `any`, it uses a delivery mode offered by the tested variant. It reads each token from the documented environment variable or captures it at a controlled HTTPS receiver for injected delivery, and verifies the issuer's discovery document, published keys, signature and future `exp`. It confirms the two `sub` values differ, and for injected delivery confirms code cannot read the token. With `custom_audience: true`, it checks the token's `aud` against `audience`. Both the issuer URL and `jwks_uri` must use HTTPS and resolve only to globally routable addresses. Returns only `{verified: true, aud: <value>}`; tokens, subjects and receiver details never enter the report. |
| `ssh.access` | A `credential` kind; returns private connection material, the server public key as `host_key` when the SDK provides one, and an owned revocable native access handle. |
| `secret.rotate` | Existing secret binding, generated replacement `value`, running `sandbox` binding and `hosts`; updates the native vault or running injection policy without recreating the sandbox. |
| `tcp.link` | A listed guest port and TLS kind; returns a public host and port. |
| `fixture.coverage_private_network` | `members` (two or three sandbox bindings), optional `outside` sandbox binding and optional `ip_version`; starts a TCP echo listener on a random port in each member, obtains each listener's private endpoint from the provider SDK, and opens a TCP connection from every other member to it. With `outside`, confirms member connections first, then checks that sandbox cannot connect to those endpoints. With `ip_version`, resolves the SDK-provided endpoint as needed and checks its address family. Returns `members_reached`, `outside_blocked` when requested, and `ip_version_matches` when requested; private endpoints stay out of the report. |
| `terminal.disconnect`, `terminal.reattach` | Disconnect and reconnect to the same native terminal. |
| `desktop.start` | Sandbox target with no additional inputs; starts or checks the native desktop before the controlled workload. |
| `desktop.screenshot`, `desktop.click`, `desktop.type`, `desktop.key`, `desktop.live_link` | Native desktop observation, input and live-view access; `desktop.key` receives a `key`, such as `enter`. |
| `probe.ssh` | An `access` and `sandbox` binding; uses OpenSSH and `scp` with the binding's `host_key` pinned, and returns `shell_reached`, `file_copied`, `credential_is_account_key` and `scope_confirmed`. It does not connect when `host_key` is absent. |

`fixture.coverage_*` operations set up controlled guest workloads and compare their
observations. They never supply a missing provider feature. TCP and WebSocket probes
connect directly with standard sockets, ignoring proxy environment variables, and validate
the bytes returned. SSH probes use OpenSSH and `scp`. Native context cleanup confirms a
fresh context list no longer includes the owned context. Companion SDKs are pinned in the
provider extra and recorded in its SDK versions.

The `fixture.coverage_fact` probe `on_memory_exhausted` takes `memory_mib`, the sandbox's
allocated memory in MiB. It starts a background process that allocates 64 MiB per step until
it is killed or reaches twice `memory_mib`. It then waits ten seconds, calls `get`, and runs
`echo alive`. It returns `process_killed` when the sandbox is still running and the command
prints `alive`; otherwise it returns `sandbox_ended`.

The `fixture.coverage_fact` probe `allocation` takes `size`, the `larger_size` the sandbox
was created with, and observes the allocation from inside the guest. Its CPUs are the fewer of
the processors the probe may run on and the tightest cgroup CPU quota on it; its memory is the
smaller of `MemTotal` in `/proc/meminfo` and the tightest cgroup memory limit, in whole MiB.
Both cgroup v2 and v1 limits count, from the probe's own cgroup up to the mount. The test
records `observed_cpu` and `observed_memory_mib`, and passes when the guest sees at least
`cpu_min` CPUs and at least 90% of `memory_min_mib`, since the kernel keeps a little of the
memory a provider allocates. A guest that sees the provider's default size fails.

The [Docker coverage helpers](../src/sandbox_provider_spec/coverage_docker.py) do not build
an image and do not install Docker. They add `user: root` to `create`; Daytona maps that
input to its native `os_user`. The workload uses the engine the provider already runs.
The workload helper selects `run.as_root` only when `driver.provider` is `e2b`; other
providers use ordinary `run`. Implementing `run.as_root` for another driver does not change
this dispatch. Review the fixture and native-user mappings when adding a Docker-capable
driver; loader registration alone does not establish its Docker coverage.

The 600-second foreground and background tests prove only `{at_least: 600}`. Both give the
sandbox and client longer deadlines; the background workload records its own elapsed time
before writing its completion marker. A client deadline never proves an exact provider limit.

The checkout must have no modified or untracked files at the start and end, and its
revision must stay the same throughout the run. The loaded runner must belong to that
checkout. Writing a report inside it makes the next run refuse until that file is committed
or moved. After reviewing an outside report, copy it into `providers/<provider>/reports/`
and commit it with the declaration evidence that cites it, following
[the report evidence requirements](#committing-and-checking-report-evidence) below.

Fixtures provide external endpoints, artifacts and observation settings for either suite.
Missing fixtures produce `not_run`. In the core suite, network-lockdown tests use endpoint
and allowlist controls; preview lifetime tests use `link_lifetime_wait_seconds`; image
tests use image references and markers; mount-count tests use `max_mounts` and `volume_kind`.
Resize, allocation, GPU, lifetime and idle observations use their corresponding size and
timing fixtures. The hidden-secret tests generate their own test-only secret and receiver.
Common fixture names are below. Supplementary denylist tests also need the
[denylist proof fixtures](#denylist-proof-fixtures).

| Fixture | Shape and purpose |
| --- | --- |
| `reachable_url` | Public HTTPS URL reachable from the runner and an unrestricted guest, returning a 2xx response directly without a redirect. The runner checks it within `baseline.outbound_network`. |
| `outbound_http_url` | Public plain-HTTP URL on port 80 reachable from the runner and an unrestricted guest, returning a 2xx response directly without a redirect. |
| `outbound_tcp_echo` | An object with the host and port of a public raw TCP echo service. Its port is neither 80 nor 443, and it echoes the exact per-run payload. |
| `outbound_udp_echo` | An object with the host and port of a public UDP echo service. It echoes the exact per-run datagram. |
| `reserved_ports` | List of at most 64 distinct integer ports from 1 to 65535; an empty list is allowed. The coverage test checks each reservation refuses forwarding and checks common ports 3000, 5173, 8000 and 8080 serve, skipping any common port also listed as reserved. |
| `allowed_url`, `denied_url` | Distinct HTTP URLs on controlled receiver hosts reachable from the runner and an unrestricted guest. Each host serves `GET /records/<namespace>` for the per-run probe. The denied host must be outside every allowlist exercised by the test. Network tests check both URLs before allocating the restricted guest. |
| `deny_wins_allow_entry`, `deny_wins_deny_entry`, `deny_wins_allowed_url`, `deny_wins_denied_url` | One `*.` wildcard hostname, an exact hostname below it, and two distinct HTTPS receiver URLs whose hosts are both under the wildcard. The denied URL host equals the deny entry; the allowed URL host differs. Both receivers are reachable from the runner and an unrestricted guest before the restricted guest is allocated. |
| `allowed_domains`, `allowed_ips` | Lists of domains or CIDRs for the allowed endpoint; every address the fixture uses must be covered. |
| `allowed_mixed` | A host name that covers `allowed_url`, and an IPv4 address or range that covers `allowed_ip_url`. |
| `egress_harness` | Object with a host, a private token of at least 16 characters, and controlled HTTP, HTTPS, TLS, TCP and UDP endpoints; HTTP, HTTPS and TLS use ports 80, 443 and 8443. The runner must reach every endpoint before and after the restricted-sandbox probe. |
| `egress_harness_domains` | Nonempty list of host names that resolve to the controlled host in `egress_harness`; these names are the allowlist entries for domain-traffic coverage. |
| `connection_harness` | HTTPS `stream_url`, a private token, and optional `ca_pem`; its stream sends data often enough to observe whether an established connection remains open. |
| `connection_harness_domains` | The streaming host name used in the initial network policy. |
| `allowed_ip_url` | A literal-IP HTTP endpoint reachable from an unrestricted guest. IP allowlist, block-all and root-resistance tests exercise it without DNS or proxy settings. |
| `allowed_ip_range_url` | A second literal-IPv4 HTTP endpoint on a different address from `allowed_ip_url`, inside `allowed_ip_range`, reachable from an unrestricted guest. The range allowlist test probes both addresses. |
| `allowed_ip_range` | One IPv4 range with a prefix length of 24 or shorter (`/0` to `/24`) that covers the addresses of `allowed_ip_url` and `allowed_ip_range_url`. When `denied_url` uses a literal IPv4 address, that address must fall outside this range. A host name is not an address in the range. |
| `max_allow_entries`, `wildcard_domains` | Allowlist domain lists for limit and wildcard tests; the allowed endpoint must match and the denied endpoint must remain outside them. `max_allow_entries` must be a list of 1 through 32 distinct strings, compared case-sensitively, with one matching URL per entry in `max_allow_urls`. |
| `max_inject_into_hosts`, `max_inject_into_urls` | A nonempty list of distinct host names and same-length HTTPS URLs, with each URL's hostname exactly matching the host at the same position. The controlled endpoints record only whether that run's generated secret arrived; no secret value is returned or written to a report. |
| `hidden_secret_wildcard_host`, `hidden_secret_wildcard_urls` | One `*.` wildcard hostname for a controlled receiver domain and two HTTPS URLs resolving to the controlled receiver: one direct child and one deeper subdomain under the wildcard. The receiver records only whether that run's generated secret arrived at each host. |
| `oci_image`, `provider_artifact_image`, `image_marker` | An OCI reference or existing provider-native artifact, and expected controlled text in its `/etc/os-release`. Existing artifacts are borrowed and never deleted. |
| `private_oci_image`, `private_oci_username`, `private_oci_password`, `private_oci_marker` | A fresh, unique-per-run image in an isolated private registry that rejects anonymous pulls and cannot be read with provider-managed credentials; username and password are its only valid pull credentials. The image holds `/etc/sps-private-oci-marker` containing the run-unique `private_oci_marker` text, and needs whatever else the provider's evidence says an image must contain. The test supplies the credentials with `image.prepare` and verifies the sandbox started from that image, without prescribing whether the driver resolves the image then or at sandbox creation. Credentials are never recorded in reports. |
| `original_size`, `restored_size` | JSON resource-request mappings for resize using request-vocabulary keys such as `cpu_min`, `memory_min_mib` and `disk_min_mib`, not declaration size fields or provider-native option names. Each driver supports only a subset of resource keys. Both mappings must be present and must differ; each observed allocation must use the same keys and values as its corresponding mapping exactly. Live-resize tests require exactly `cpu_min` and `memory_min_mib`, with no other keys: `original_size` is smaller and `restored_size` is larger in both. |
| `test_size` | Nonempty native resource-request mapping using only `cpu_min`, `memory_min_mib` and `disk_min_mib`. Every supplied value must be a positive finite number, never a boolean; memory and disk must be integers. The `size_is_ceiling` probes require both `cpu_min` and `memory_min_mib`. The true probe adds `resources.size_is_ceiling: true` to this mapping; the false probe omits it. An exactly matching native allocation proves one concrete declaration size, never a range. |
| `larger_size` | Resource-request mapping with exactly `cpu_min` and `memory_min_mib`: a size inside the declaration's `sizes` and larger than the size the provider gives a sandbox created without one. `cpu_min` is a positive finite number and `memory_min_mib` a positive integer. `coverage.facts.sizes.delivered` creates a sandbox with it and observes the allocation in the guest. |
| `test_gpu` | Native resource-request mapping whose `gpu_model` is exactly a one-element list, for example `{"gpu_model": ["nvidia:h100"]}`. Its model must have a reviewed display-name mapping in [`GPU_NAMES`](../src/sandbox_provider_spec/proofs.py); registry membership alone is insufficient. The runner derives `gpu_model` and its native display-name pattern. A missing mapping or an alternatives list produces `not_run` with `gpu_identity_mapping_unavailable`, leaving GPU support unverified. |
| `max_mounts`, `volume_kind` | Positive mount count (at most 32) and `filesystem` or `object_store`; every distinct mounted artifact is written and read. |
| `wildcard_allowed_url`, `wildcard_denied_url` | Controlled receiver URLs reachable from the runner and an unrestricted guest; each host serves `GET /records/<namespace>`. The positive host must be a subdomain covered by `wildcard_domains`, and the denied host must be outside it. |
| `max_allow_urls` | List of reachable controlled receiver URL strings, with exactly as many items as `max_allow_entries`, in the same order. Each receiver serves `GET /records/<namespace>`, and each URL's parsed hostname (`urllib.parse.urlsplit(url).hostname`) must equal its corresponding domain string exactly; parsing lowercases hostname letters, so use lowercase domain entries. The test exercises all entries from both unrestricted and restricted guests. |
| `max_lifetime_seconds`, `max_lifetime_wait_ms` | Integer requested lifetime in seconds and integer observation wait in milliseconds (at least 1000). The requested lifetime must exceed the wait by more than 30 seconds. A passing continuous-lifetime observation proves only `{at_least: seconds waited}`, rounded down. Use a wait of at least 300000 milliseconds for an admissible declared lower bound. |
| `link_lifetime_wait_seconds` | Positive preview observation window; use 300 to establish a 300-second lower bound. Sandbox, server and issued-link lifetimes are derived with setup margins. |
| `idle_activity_settings` | Native `idle_shutdown` settings for observing a long-running command across the configured idle interval. |
| `expiry_options` | Native creation options with a 60-second resumable ending, for observing file survival after expiry. |
| `idle_before_wait_ms`, `idle_after_wait_ms`, `idle_lifetime_seconds`, `idle_process_timeout_ms` | Bounds for observing the effective native idle interval. The first wait is shorter than that interval; the second is longer. Sandbox and process lifetimes exceed the whole observation so an ordinary deadline cannot look like idle shutdown. These are runner delays, not requested idle settings; they must bracket the interval the native creation uses. |

The runner derives the following names for the tests that use them. Omit these from the
fixture file: independently supplied values are overwritten by the validated inputs.
`run_nonce` is generated separately for each run, as described above.

| Derived name | Source and shape |
| --- | --- |
| `link_lifetime_wait_ms`, `preview_link_lifetime_seconds`, `preview_sandbox_lifetime_seconds`, `preview_process_timeout_ms` | Integers derived from `link_lifetime_wait_seconds`: the wait in milliseconds, native link lifetime in seconds, sandbox lifetime in seconds rounded to whole minutes, and process timeout in milliseconds. Setup margins are added to the lifetimes and timeout. |
| `max_lifetime_observed_seconds` | Integer lower bound, `max_lifetime_wait_ms` divided by 1000 and rounded down. |
| `test_size_value` | One-element list of the concrete size from `test_size`, with `cpu_min`, `memory_min_mib` and optional `disk_min_mib` renamed to `cpu`, `memory_mib` and `disk_mib`. |
| `test_gpu_models`, `gpu_model`, `gpu_name_pattern` | One-element registry-model list from `test_gpu.gpu_model`, reviewed native display-name string, and display-name pattern string, respectively. |
| `max_allow_count`, `max_deny_count` | Integer counts of the distinct entries in validated `max_allow_entries` or `max_deny_entries`. |
| `max_inject_into_count` | Number of distinct hosts in `max_inject_into_hosts`. |

The tests that read the `egress_harness`, `connection_harness`, echo-endpoint and
private-registry fixtures need servers you operate. The repository does not include them. A
provider that cannot host them still gets every baseline, fact and non-network gate test: run
with `--test` and a prefix to select those, and leave the network gates undeclared. The tests
that need hosted endpoints have these ids: every `network_lockdown.` and
`coverage.network_lockdown.` test, every `coverage.facts.outbound_traffic.` test,
`coverage.custom_images.private_oci`, `coverage.hidden_secrets.max_inject_into` and
`coverage.hidden_secrets.wildcards`. Select the other tests by repeating `--test` for each
remaining prefix, such as `baseline.`, `processes.` or
`coverage.previews.`.

Omitting `reachable_url` makes `baseline.outbound_network` `not_run` with
`fixture_missing`. A value that is not an HTTPS URL, including plain HTTP, makes that
test `not_run` with `proof_fixture_invalid` before any guest command. Plain HTTP belongs
to `outbound_http_url` and the optional `coverage.facts.outbound_traffic.http` probe.
An HTTPS URL returning a non-2xx status, including a redirect, makes the baseline test
`differs`; a runner-side connection failure makes it `error` with
`probe_connection_failed`. These results do not establish a passing baseline; supplying
an unusable HTTPS fixture does not turn them into `not_run`. Complete full-baseline runs
retain their actual results under the [report-selection rules](#results-and-reports).

A shorter continuous-lifetime observation can pass as a diagnostic, but a declared
`resources.max_lifetime_seconds` must be at least 300 seconds. For example,
`max_lifetime_seconds: 200` with `max_lifetime_wait_ms: 120000` proves only
`{at_least: 120}`, which cannot supply that declaration fact. A 360-second requested
lifetime with a 300000-millisecond wait proves `{at_least: 300}`, an admissible lower
bound. Neither observation proves an exact maximum or ceiling; leave the fact undeclared
until admissible evidence exists.

Each test requests only the modes its rule needs. Idle state, persistence and wake tests
omit `custom_idle_time` and observe a native interval selected by the driver, or the
provider's fixed interval where customization is unavailable. The observation fixtures
bracket the effective interval; see Driver notes for native settings. Only customization
tests request `custom_idle_time`.
Idle persistence names `on_idle: paused` because the specification permits `keeps`
only with that state. Snapshot source and resize tests omit unrelated persistence
or source-state restrictions.
Volume sharing is tested for both kinds, and filesystem locking can be established with
one mounted writer. Public and private preview revocation and link lifetimes have separate
tests. All egress probes ignore proxy environment variables; a cooperative proxy filter
alone cannot establish network lockdown. The core suite's network-lockdown tests check
`reachable: true` on runner-side controls, so any HTTP response, including an HTTP
error, proves endpoint connectivity. Supplementary network-lockdown probes treat
HTTP 403 and 451 as unreachable because an egress proxy may have rejected the
request; other HTTP responses establish connectivity. A supplementary unrestricted
control returning 403 or 451 therefore makes the test `not_run` with
`network_unrestricted_control_unavailable`. Neither control path requires the
direct 2xx response that `baseline.outbound_network` does. A core suite certificate
verification failure is a probe defect; a supplementary TLS verification failure
is `not_run` with `network_tls_observation_ambiguous`. Network probes bound
the whole guest child process, including DNS resolution, to eight seconds; the SDK
command deadline is longer.
Their exit codes distinguish a reached endpoint (including HTTP errors), connection
failure or timeout, and probe defects. A defect cannot pass as denied traffic, and a
failed unrestricted guest control makes a network-lockdown test `not_run`.

Idle fixture validation reserves 30 seconds beyond the complete wait window for setup
and probes. It skips a test whose sandbox or process deadline is too short, and skips
an observation that overruns its safe window. Auto-wake tests first prove their single
preview link serves and request a link lifetime covering the observation. They
accept a compatible native idle mode. The wake assertion checks the sandbox state,
without requiring an exec server to survive an idle stop.
Paused-time facts require an authoritative native countdown observation; a resumable
state or successful resume alone does not prove whether the timer counted paused time.

Tests run serially. The runner releases owned resources in reverse allocation order,
including after assertions, missing capabilities, account errors or SDK failures. Cleanup
continues after one resource fails. Drivers confirm native deletion rather than assuming
it. When an artifact has no native delete call, only a known bounded provider expiry can
count as cleanup; its timezone-aware `expires_at` is recorded. A missing or unconfirmed
cleanup makes `clean` false.

### Shared accounts

Several runs may use one provider account at once, so a run never reads the account as a
whole. Each run has one **run id**: `SPS_RUN_ID` when set, otherwise
`<lane>-<UTC YYYYMMDDTHHMMSSZ>-<4 hex>` (`SPS_LANE` names the lane, default `run`).
The report records it as `run_id`. Every resource a driver creates carries the run in its
native name, `sps-r<8 hex of the run id's SHA-256>-<minutes since the epoch in base 36>-<unique
part>`, or in the native metadata where a provider keeps it. `clean` means every resource this
run created is confirmed gone. Other runs' resources in the account are expected: a run never
compares the account before and after, never requires it to be empty, and never deletes,
pauses or adopts a resource it did not create. The `list` observation only needs to
include the run's own sandbox.

`sandbox-provider-spec sweep <provider> --live [--ttl-hours 2]` removes what a crashed run
left behind. It deletes only resources whose name or metadata carries a run and whose age
exceeds the TTL (two hours by default), and nothing else.

A failed create that returns no identity can be released by a complete native sandbox
listing after a bounded settle period. This runner waits 120 seconds after the failed
call before that listing. The create call itself must carry a unique run reservation
marker, and the listing must cover every page and show no sandbox carrying that exact
marker. Any discovered owned allocation is deleted and its absence confirmed. An
incomplete or failed listing, or a create that cannot carry a marker, leaves cleanup
unconfirmed. This rule does not release markerless artifact or other operations. The
original failed test remains failed; separate later reconciliation never rewrites a
report's cleanup result.

## Results and reports

| Result | Meaning |
| --- | --- |
| `passed` | Every step passed; the test establishes its proof targets on the tested account and date. |
| `differs` | A native observation contradicts an assertion; the report records the bounded observation. |
| `unsupported` | The driver identifies a precise operation its SDK lacks. It establishes that absence, not the absence of unrelated features whose tests needed it. |
| `not_run` | A fixture, driver mapping, observation or account condition is missing. No provider conclusion follows. |
| `error` | Execution failed, for example because of quota, credentials or connectivity. No provider conclusion follows. |

[report-schema.json](report-schema.json) accepts the complete run format only. A report
records version, provider and declaration class, driver and SDK versions,
the run id (optional in older reports), timestamps, clean source revision, suite digest, `selected_tests`, `check_digests` (one digest per selected test; optional in older reports), and each test's result,
rule and proof targets, steps, observations and cleanup. Native handles,
account identities, authenticated URLs, headers and upstream exception messages are never
recorded.

`clean` has one report meaning: every owned resource was confirmed released or has a
recorded bounded expiry. `clean: true` does not guarantee that every resource was released
immediately; a resource with a recorded expiry may remain live until then. It does not mean
the tests passed: a run in which every test errored can still be `clean: true` if cleanup
was confirmed, or `clean: false` if cleanup failed. Read `baseline` and the per-test
results. Source cleanliness is a separate prerequisite for provenance;
it does not turn a failed test into a passing one. A clean report can contain any result.

The baseline summary uses the same five results. It is `not_run` for an incomplete baseline
selection. For a complete selection, precedence is `error`, `differs`, `unsupported`,
`not_run`, then `passed`. Thus `error` means execution is inconclusive; individual
contradictions remain visible. Only a complete set of passing baseline tests yields `passed`.
A declaration cites a report committed in this repository for the same provider and class.
For baseline evidence, the matcher selects the report with the greatest `finished_at`
among reports that selected every current baseline test for that provider and class.
Filename and Git commit order do not decide which is newest. The selected report must be
clean, pass every current baseline test and use the declaration's verified SDK versions.
A newer non-clean or failing full-baseline report displaces older clean evidence; the
matcher does not fall back to it. A focused report omitting baseline tests does not
replace the newest complete baseline report.

Commit every genuine provider run that selected every current baseline test to
`providers/<provider>/reports/`, including non-clean runs and runs whose baseline tests
failed or were not observed. This applies even when the run was intended as a diagnostic:
its purpose does not exempt a complete baseline selection. A newer such report displaces
earlier passing evidence and invalidates baseline eligibility if it is non-clean or any
current baseline test did not pass. `clean` alone never means baseline `passed`.

Focused diagnostics that omit any current baseline test may be kept separately. They
cannot establish a complete baseline or displace the newest full-baseline report. Keep
raw private ownership and cleanup ledgers outside the source repository; retain the
sanitized cleanup outcomes in the report. Preserve original results, timestamps and
cleanup status throughout report history, including the older E2B and Daytona diagnostics.
Do not delete, omit, retimestamp or relabel a complete baseline run to preserve an older
pass. Only an actual later clean, passing full-baseline report with the verified SDK
versions can restore baseline eligibility.

### Committing and checking report evidence

Checking a declaration requires a recognized conformance suite for every cited report and
every report considered for its complete baseline, including uncited baseline reports.
The CLI and `check_report` apply the same semantic verification before matching; schema
validation alone does not establish evidence. A report's `suite_digest` must match the core or coverage suite shipped
with this package, or a digest in
[historical-suite-rules.json](../conformance/historical-suite-rules.json). The checker also
compares each reported test id and rule list with that suite, requires exactly one result
per selected test, and requires any check-digest map to cover exactly those tests.
When the suite changes, record
the old suite's test ids and rules under its verified digest before its reports can remain
evidence; do not add a digest without checking the original suite bytes.

In a Git checkout, each cited source report must be committed in `HEAD` and have no staged or
unstaged changes. A source archive without Git uses the reports it ships. An installed
package uses its bundled reports even when its virtual environment is inside a Git checkout;
the enclosing project's Git index does not own those files. Build and distribution
provenance establishes that packaged files came from
committed source. The checker cannot authenticate an arbitrary copied directory without
Git metadata. The report's `revision` records the clean source that ran for auditing, but
it need not be a commit in the checkout that checks it. Preserve genuine report revisions
and results when integrating evidence; do not rewrite them to satisfy the checker.

## Suite format and driver operations

A step calls `op`, optionally on a binding named by `target`, with its `in` mapping. `as`
binds the returned observation for later steps. `$box.identity` reads a bound field;
`$box` passes the whole opaque binding; `$runner.reachable_url` reads a fixture. The runner
resolves references recursively in lists and mappings. A `wait_ms` step waits without
calling the SDK.

A check may label every step with a `lane` string to define independent programs
with separate bindings and cleanup. All lanes must pass for the check to pass;
one lane's observations cannot supply another lane's proof. The runner may overlap
explicit waits between single-sandbox programs, bounded by the positive integer
`max_live_sandboxes` runner fixture (default `1`, serial). Documented unsupported
operations are resolved before allocation. Checks without explicit waits run before
elapsed-time checks; fixture programs that can allocate extra resources stay serial.

```yaml
spec: sandbox-provider-spec/0.1
tests:
  - id: example.exit_status
    title: A completed command reports its native exit status.
    rules: []
    proves: []
    steps:
      - {op: create, as: box}
      - op: run
        target: box
        in: {bash_script: "exit 7"}
        expect: {equals: {exit_code: 7}}
```

`expect` supports `equals`, `not_equals`, and `contains` (a matching object within a returned
list), plus a classified native `error` code. Buffer assertions use `{utf8: text}`,
`{b64: base64}`, `{utf8_contains: text}` or `{utf8_absent: text}`; `{one_of: [values]}` checks
an enum. Text, bytes, bytearray and memoryview are compared mechanically, without capturing
or rewriting the guest output. `record` records only bounded controlled observations of
`stdout`, `stderr`, `state`, integer `exit_code` or `status`, or boolean `exists` or
`served`, or integer `retention_seconds`, such as the default guest user or reachability
of a preview after resume. Snapshot retention is recorded only if native metadata exposes
it, never copied from a requested TTL.
`unsupported: true` expects a precise native absence at that step; an absent prerequisite
still makes the test `unsupported`. `not_run_if: {exit_code: 77}` marks an unmet guest
precondition, such as unavailable root privileges, as `not_run` rather than proof.

`eventually_ms` retries only native observations until an assertion passes or its deadline
expires. Creation, deletion, command execution and other mutations cannot be retried this
way. SDK calls need their own native timeouts; polling does not interrupt a blocked call.
An elapsed observation bound is `not_run`; it does not establish a native command timeout or cancellation capability.

| Operation | Inputs | Native observation |
| --- | --- | --- |
| `create` | Optional `environment`, `lifetime_seconds`, `at_end`, `resources`, prepared `image`, `secret`, and `volumes` (`volume`, `path`, optional `read_only`); `read_only: true` mounts that volume read-only and requires `requirements.volumes.read_only_mounts: true`; `join` may name an earlier sandbox binding whose `private_network` the new sandbox joins; Docker coverage also supplies the driver-specific `user` input described above; gate tests supply `requirements`. | Owned `resource`, opaque `identity`; provider-specific opaque context can accompany it. |
| `resize` | Running sandbox target; `resources` selects a different declared CPU and memory size using the same resource-request shape as `create`. | Native resize operation returns after applying the new resources; later observations check allocation, running processes and files. |
| `get` | Sandbox target. | `state`: `active`, `paused`, `stopped`, or `destroyed`; `active` is the specification's `running`. |
| `list` | None. | `sandboxes`, a list containing opaque `identity` fields. |
| `destroy` | Sandbox target. | Confirmed cleanup result. |
| `run` | Sandbox target; `bash_script`, optional `cwd`, `environment`, `timeout_ms`, `separate_streams`, `run_as` (named guest user). | `stdout`, `stderr`, `exit_code`, where the native operation exposes them. Streams can be text or byte buffers. |
| `network.private_address` | Sandbox target; optional `ip_version` (`ipv4` or `ipv6`). | `{address, ip_version}` for the private endpoint other members use to reach the sandbox. `ip_version` is `4` or `6` for a literal endpoint and `null` when the SDK supplies a DNS name; fixtures resolve DNS names from a member sandbox when checking a requested family. |
| `files.mkdir`, `files.remove` | Sandbox target, `path`; remove can set `recursive`. | Native operation success. |
| `files.write` | Sandbox target, `path`, base64 `data`, optional `user` (named guest user). | Native operation success. Writing a file does not guarantee it remains executable. |
| `fixture.regular_write_usability` | Sandbox target; `case` one of `exact_bytes`, `create_parents`, `create_access`, `overwrite_access`, `authority`, `executable_effect`, `byte_bound`, `outcome`, `staging_cleanup`; optional `files_write_executable_effect`. | Isolated usability observations through the configured user's command interface. |
| `files.read_bytes` | Sandbox target, `path`. | `data`, a native byte buffer. |
| `files.link` | Sandbox target, absolute `path`, `operation` (`read` or `write`), `lifetime_seconds`, optional `user` (named guest user). | The native link: `url`, `method` (`GET`, `PUT` or `POST`; default `GET` for a read and `PUT` for a write), `headers` (text to text; default none) and, for a write sent as `multipart/form-data`, `form_field`. The URL and header values are secrets and never enter a report. |
| `files.revoke_links` | Sandbox target. | Native success after invalidating every outstanding link of the sandbox. |
| `files.write_stream` | Sandbox target, `path`, exact `size`, `chunks` (an iterable of byte chunks), optional `user`. | `written_bytes` after one native streamed write. |
| `files.read_stream` | Sandbox target, `path`. | `chunks`, an iterable of native byte chunks for one streamed read. |
| `fixture.file_links` | Sandbox target; `case` (see [File links](#file-links-and-streamed-transfer)); `operation` for cases that take one. | Runner-side HTTPS requests through the issued links, and guest observations of the file. |
| `fixture.file_stream` | Sandbox target; `operation` (`read` or `write`) and `size` (64 MiB, 1 GiB or 5 GiB). | One streamed transfer to or from the default user's home directory, hashed on the runner and in the guest. |
| `files.list`, `files.exists` | Sandbox target, `path`. | `names` or boolean `exists`. |
| `process.start` | Sandbox target, `bash_script`, optional `timeout_ms`, `run_as` (named guest user). | Owned native process binding and opaque `identity` when available. |
| `process.write_stdin` | Process target; base64 `data` for input. | Native write success. |
| `process.output`, `process.wait` | Process target. | Native streams or `exit_code`. |
| `process.status` | Process target. | Native execution `state` and nullable `exit_code`, observed independently of stream EOF. |
| `process.output` with `first_chunk: true` | Process target. | First native stream chunk before EOF. A clock bounds its observation before the workload can finish on its own. |
| `process.cancel`, `process.disconnect` | Process target. | Native cancellation or client disconnect success. |
| `process.reattach` | Sandbox target, native process `identity`. | Owned native reader binding. |
| `native.operation_absent` | An unconditional SDK `operation`. | Boolean `absent` from the audited driver absence map; an implemented operation returns false, an unmapped one is `not_run`. |
| `fixture.process_state` | Sandbox target and optional previously observed process `identity`. | Controlled cancellation workload state from guest `/proc`; PID reuse, malformed or missing initial identity fail the observation. |
| `environment.observe` | Sandbox target, `fact`: `default_user` or `default_cwd`. | Validated native guest default, without selecting an image, user or directory. |
| `fixture.coverage_fact` with `probe: kvm` | Sandbox target. | Opens `/dev/kvm` and reports `created_vm: true` only after creating a virtual machine inside the sandbox. |
| `fixture.coverage_kernel_feature` | Sandbox target; `feature`: `fuse`, `ebpf`, `nested_cgroups` or `netfilter`. | Runs as root through a way listed by `resources.root`; opens `/dev/fuse`, mounts and unmounts a temporary FUSE filesystem; loads and closes a socket-filter eBPF program with `bpf`; creates a child cgroup, moves a process into it, sets its memory limit and removes it; or adds and removes a netfilter rule, checking that it blocks a controlled outbound connection while active. It returns `{works: true}` only when the selected operation succeeds; without a usable root method the test is `not_run`. |
| `fixture.coverage_fact` with `probe: size_is_ceiling` | Sandbox target created with `test_size` (and `resources.size_is_ceiling: true` for the true case), and `size` set to the concrete `test_size_value`, including `cpu` and `memory_mib`. | Reads enforced cgroup v1 CPU quota/period and memory maximum, or v2 `cpu.max` and `memory.max`, from the current process's membership and every visible ancestor. Records the raw membership and file paths/values as `ceiling_evidence`. A finite CPU bound at most the requested CPU (compared as an exact rational) and a finite memory bound at most the requested MiB in bytes prove true, without destructive workloads or tolerance. Missing, unlimited, or larger bounds leave the fact unproven: a larger bound does not establish attainable use or exclude a tighter hidden limit. Malformed/unreadable observations, unsuccessful commands and timeouts never pass. CPU affinity (`nproc`), hypervisor/container markers, and `MemTotal` alone cannot prove whole-VM upper bounds; requested minus usable RAM is only an inferred deficit. A VM without authoritative bounds remains unknown. The false case remains unproven by these upper-bound reads. |
| `terminal.open` | Sandbox target; optional `rows`, `columns`. | Owned native terminal binding. |
| `terminal.write`, `terminal.output` | Terminal target; base64 `data` for input. `terminal.output` can set `first_chunk: true` to return after one chunk or `until_contains` to return as soon as the accumulated stream contains that text. A timeout bounds either observation. | Write success or byte/text `terminal` output. |
| `preview.link` | Sandbox target; `port`, `access` (`public` or `private`), optional `credential` (`link` or `header`) and `lifetime_seconds`. | `url` and request `headers`; a private link may also return `unauthorized_url` for the unauthenticated control. Newly allocated native previews or credentials return an owned resource binding. |
| `preview.revoke` | Preview-link target returned by `preview.link`; no additional inputs. | Native revocation success; subsequent `probe.http` steps check that the issued authority no longer opens the preview. |
| `pause`, `resume` | Sandbox target; optional `keeps` selects a native persistence mode. | Native operation success; subsequent steps inspect the result. |
| `snapshot.take`, `snapshot.delete` | Sandbox or snapshot target; `keeps` for take. | Owned snapshot binding or confirmed deletion. |
| `snapshot.restore` | Snapshot target; optional native creation options as for `create`. | Owned restored sandbox binding. |
| `snapshot.delete_again` | A deleted snapshot target. | `native_delete_attempted` after a second native deletion call; bypasses the ownership ledger's idempotency shortcut. |
| `snapshot.restore_begin`, `snapshot.restore_wait` | Snapshot or pending-restore target. | A native in-progress restore handle and its completed sandbox, where observable. No background wrapper pretends a synchronous SDK call exposes native progress. |
| `snapshot.retention` | Snapshot target. | Integer `retention_seconds` from native metadata; otherwise `not_run`. |
| `fixture.snapshot_ticker_start` | Source sandbox target. | A controlled 100 ms guest ticker and a stable two-second clock baseline. |
| `fixture.snapshot_ticker_observe` | Same source sandbox target and opaque `ticker` binding. | Longest gap across native snapshot creation, its `original_after` classification, and post-capture progress. |
| `image.prepare` | `source`: `oci`, `private_oci`, `dockerfile`, or `provider_artifact`; `image` reference or Dockerfile text; optional `resources` for the size sandboxes from this image will use; optional `context` map from a relative path to UTF-8 file text or `{base64: <text>}` for bytes, passed as the build context, with base64 values decoded to bytes before the SDK call; `username` and `password` for `private_oci`. | Owned image uses the driver's reserved per-run name and returns an opaque `identity`, stable `key` and `resources` (the fixed size, or `null` when the artifact can use any size); a `provider_artifact` input may remain borrowed. |
| `image.state` | Prepared image target; no additional inputs. | `state`: `absent`, `preparing`, `ready` or `failed`; otherwise `unsupported` with reason `lookup_unavailable`, reported as `not_run`. |
| `image.delete` | Prepared image target; no additional inputs. | Confirmed deletion; otherwise `unsupported` with reason `delete_unavailable`, reported as `not_run`. |
| `volume.create`, `volume.create_many` | Native volume `kind`, and `count` for multiple artifacts. | Owned native volume binding or a list of mount bindings. |
| `volume.observe_mounts` | Sandbox target and `mounts`. | `all_writable` from native observations. |
| `volume.observe_kind` | Volume target. | Native backing-store `kind` where observable; persistence alone does not classify storage. |
| `volume.read_bytes` | Volume target, volume-root `path`. | Native durable bytes and boolean `exists`, where the SDK offers direct volume reads. |
| `volume.reload` | Sandbox target; no additional inputs. | Native refresh of mounted volumes when needed by the visibility fixture, after both writers' markers are confirmed in durable storage. |
| `fixture.volume_visibility` | Volume and two live writable sandbox bindings with distinct controlled markers; `timeout_ms`. | Mutual cross-mount contents, allowing native background publication and a bounded native refresh. |
| `idle.select_duration` | Sandbox target, `idle_seconds`. | Native selector absence where observable. A default idle timeout alone cannot prove that customization is unavailable. |
| `fixture.secret_receiver` | Generated test-only `value`. | An owned native sandbox runs a controlled HTTP receiver; opaque per-run endpoints and observer headers stay out of reports. |
| `fixture.coverage_http_rules` | Sandbox target and the controlled receiver's `allowed_url`, `wrong_method_url` and `outside_path_url`. | Sends guest GET and POST requests to the HTTPS receiver, then confirms GET `/allowed/x` matched by `/allowed/**` succeeded, POST `/allowed/x` and GET `/other` failed, and only the matching request reached the receiver. It first checks that the receiver and matching request work outside the sandbox. |
| `fixture.coverage_http_rule_deny` | Sandbox target and the controlled receiver's `get_url` and `post_url`. | Checks both requests from the runner, then sends guest GET and POST requests and confirms GET succeeded, POST was refused, and the receiver saw only GET. |
| `fixture.root_attack` | Sandbox target. | Root attempts native Linux network mutations without requiring guest CLI tools; subsequent egress probes check enforcement. |
| `secret.create` | Generated test-only `value`. | Owned opaque native secret binding. Material is never a request setting or report field. |
| `lifetime.extend` | Sandbox target; `lifetime_seconds`. | Native timer extension success; the test observes survival past the original deadline. |
| `lifetime.observe_paused_countdown` | Paused sandbox target, `original_lifetime_seconds`. | Boolean `counts_paused_time` from authoritative native timer metadata or an expiry event, without resuming or resetting it. If pause and expiry have indistinguishable states and no timer observation exists, `not_run`. |
| `long_running.observe` | Sandbox target. | `idle_disabled` from authoritative native configuration; missing metadata is `not_run`. |
| `run.each_url` | Sandbox target, shared guest probe and URL fixtures. | All listed endpoints exercised through native guest commands. |
| `allocation.observe` | Sandbox target. | Native `allocation` for comparison with the requested resource fixture. |
| `clock.start`, `clock.observe` | Runner monotonic start binding and `limit_ms`. | Whether observation occurred before the self-ending streaming workload could complete. These are test timing, never provider speed guarantees. |
| `bindings.compare` | Two opaque bound fields, `left` and `right`. | Runner-only boolean `equal`; no SDK call or handle enters the report. |
| `probe.http` | Runner-side `url`, optional `headers` and URL-encoded `query`. | `status`, `reachable`, `served`, `body`; HTTP error responses remain reachable; no redirects or ambient proxy credentials. |

The shared tests do not call `process.close_stdin` or `snapshot.original_after`.
The `continues` and `briefly_paused` snapshot transition tests use ticker fixtures around
`snapshot.take`, through native process and file operations. The `stopped` and `terminated`
tests call `get` on the source after capture and expect `stopped` and `destroyed`, respectively.

`volume.create_many`, `volume.observe_mounts`, `fixture.volume_visibility`,
`fixture.process_state`, `environment.observe` and `run.each_url` are runner test
composition: they repeat native volume creation, file writes/reads, or guest commands.
They add no provider feature. The hidden-secret receiver is ordinary guest test code:
it records only this run's nonce and generated credential, never supplies the injection,
and its sandbox and process share the test's cleanup ledger. The streaming workload
prints a chunk, pauses and exits on its own; a runner clock checks that its first chunk
arrives before the workload can finish. Stdin belongs to the separate input test.
All allocated objects remain in the driver's cleanup ledger if a later item fails. Mount markers are distinct and all are written before
the writer is destroyed. A fresh sandbox remounts the same artifacts and reads every
marker, so ordinary guest directories and aliasing cannot satisfy the proof.

Object-store writer tests keep both writable mounts alive and write distinct markers in
each. Direct mutual visibility can pass without a publication or refresh API. Where a
native refresh is needed, the runner first reads both exact markers from durable volume
storage, then refreshes each sandbox once and checks cross-mount contents. This prevents
refresh from losing uncommitted local writes and does not require immediate consistency.
One overall observation deadline bounds the sequence. Missing necessary SDK observations
are inconclusive; unrelated SDK failures remain errors. Refresh is never part of generic
observation retries.

Snapshot source observations use a flushed 100 ms ticker on the original sandbox's
guest monotonic clock. A stable baseline has at least 21 records and no gap above
150 ms. The first read after the native default snapshot bounds the measurement;
the next tick checks for a pending gap, and three more establish that the source
still advances. A longest gap of
at least 250 ms proves `briefly_paused`; no gap above 150 ms proves `continues`.
An intermediate gap, changed clock or counter, missing baseline, or absent recovery
is inconclusive. A significant gap straddling the observation boundary is also
inconclusive. Later recovery-only gaps cannot prove a snapshot pause. Reports record
the baseline and longest gap in milliseconds and `capture: native_default`; this
evidence concerns the exercised native capture method. The source remains the
original native binding and is checked active after the observation.

Numeric knob and limit observations record lower bounds, such as
`{gate: previews, knob: link_lifetime_seconds, value: {at_least: 300}}`.
A finite observation establishes neither an exact maximum nor `unlimited`; unbounded
claims require dated provider documentation. Two exercised ports prove
`max_ports: {at_least: 2}`. The same rule applies to mount and allowlist counts.
`facts.max_lifetime` and `coverage.facts.max_lifetime.active` observe the same lifetime
fixture through the active-lifetime operation. A short baseline command before every
state check keeps the sandbox active; a paused or destroyed state still fails. Checks
are at most five seconds apart, apart from native call time. The runner's monotonic
clock must reach the complete observation window before the test passes. This proves
a lifetime lower bound under activity, without requiring `long_running` or changing
the native idle policy.
`long_running` requires native evidence that idle shutdown is disabled, in addition to
remaining active. The extension test first observes a separate unextended sandbox
reach its original deadline.

Process `false` tests establish unconditional absence from the pinned SDK surface through
the audited driver mapping. A missing mapping is inconclusive; context-dependent absence
must be exercised in that context. Cancellation observes the controlled guest process
alive before the native call and stopped afterwards, with the parent still active. PID
start time distinguishes reuse, and a timing bound excludes automatic expiry. Reattachment
uses a file-blocked workload and releases it only after native reconnection, so saved output
after an already-ended process cannot satisfy the test. With a request/response SDK,
disconnecting discards the observer, while reattaching reconstructs it through fresh
native getters and durable process/session identifiers. This makes no transport-close
claim and retains the original remote cleanup owner.

These are the suite's driver operations, not a standardized provider API. A classified
`NativeFailure("timeout")` comes from a native timeout exception or distinct native timeout
result. Other native exceptions produce `error` with only their class name. A driver's
explicit `Unsupported` has a fixed public reason; an unmapped method or missing field
produces `not_run`.

### File links and streamed transfer

The `file_links.v1.*` and `files.stream.v1.*` coverage tests prove the
[`file_links`](vocabulary.md#file_links) gate and the `file_stream_max_bytes` fact. They
create a sandbox without gate settings and use `files.link`, `files.revoke_links`,
`files.write_stream` and `files.read_stream`; a driver without one of them reports the test
`not_run`. The runner follows a link exactly as the driver describes it (URL, method,
headers, form field) from the runner machine, with no proxy, no redirect and no other
credential, and checks every file through guest commands as the default user (or the named
user), never through the link. A link is refused when the answer is a 4xx status that neither
returns the file's bytes nor changes it.

| Test | Rule | What it does |
| --- | --- | --- |
| `file_links.v1.credential.read`, `.write` | `file-links/own-credential` | Issues a link, checks that no provider account secret the runner holds appears in its URL or headers, and uses it with nothing else. Proves the gate and the operation. |
| `file_links.v1.read_exact` | `file-links/read-exact-bytes` | Reads an empty file and a 1 MiB binary file through read links and compares every byte. |
| `file_links.v1.write_exact` | `file-links/write-exact-bytes` | Writes an empty body, 1 MiB of random bytes, and a shorter body over a longer file; compares SHA-256 and size in the guest. |
| `file_links.v1.write_parents` | `file-links/write-parents` | Writes to a path three missing directories deep. |
| `file_links.v1.write_usable` | `file-links/write-usable` | Checks that the default user can read the new file and append to it. |
| `file_links.v1.one_path.read`, `.write` | `file-links/one-path` | Replaces the issued path, wherever it appears in the URL or headers as text, percent-encoded or base64, with a sibling path of the same length; the request must be refused and the sibling unchanged. A link that does not name its path at all cannot address another one, and the report records `path_in_link: false`. |
| `file_links.v1.one_operation` | `file-links/one-operation` | Sends a write, shaped as the provider's write links are, with a read link, and a read with a write link; both must be refused and the file unchanged. |
| `file_links.v1.expiry.read`, `.write` | `file-links/expiry` | Requests a 5-second link, uses it at once, and expects it refused 15 seconds after issue. |
| `file_links.v1.link_lifetime.read`, `.write` | `file-links/link-lifetime` | Requests a link for exactly `link_lifetime_wait_seconds` (11 to 3000) and uses it 5 seconds before that lifetime ends; a write link writes new bytes over different ones. Proves `link_lifetime_seconds: {at_least: N}`; without the fixture the test is `not_run`. |
| `file_links.v1.user_selection` | `file-links/user-selection` | As root, adds a user and a root-only file. Also adds a file only that user can read. A write link for that user must leave the exact bytes in a file the user owns, reads and writes (checked as that user); a read link for that user must return the user's file and be refused for the root-only file. Without root the test is `not_run`. |
| `file_links.v1.revocable.read`, `.write` | `file-links/revocable` | Issues two links, revokes the sandbox's links: both are refused and the file unchanged, a command still runs, and a new link works. |
| `file_links.v1.interrupted_write` | `file-links/interrupted-write` | Announces a 1 MiB body, sends half and closes the connection. Once three observations 3 seconds apart agree (within 30 seconds), the file must hold its previous content, no file, or a prefix of the body; a full write through a new link must then leave exactly its bytes. The report records which. |
| `files.stream.v1.write.64mib`, `.1gib`, `.5gib` | `facts/file-stream-write` | Streams random bytes in 1 MiB chunks to a file in the default user's home directory, hashing them as they are produced, and compares size and SHA-256 in the guest. Without free space for the file plus 256 MiB there, the test is `not_run`. Proves `file_stream_max_bytes.write: {at_least: N}`. |
| `files.stream.v1.read.64mib`, `.1gib`, `.5gib` | `facts/file-stream-read` | Writes random bytes to the same place in the guest and streams them out, hashing each chunk. Proves `file_stream_max_bytes.read: {at_least: N}`. |

The 1 GiB and 5 GiB stream tests run only with the `file_stream_large: true` fixture and
are otherwise `not_run`. A streamed size is proven only by a transfer of that size, so a
declaration's `file_stream_max_bytes` never exceeds the largest passing test.

## Choosing a conformance path

A new provider does not need a native driver in this repository. Reports from an adapter
or HTTP implementation can be the declaration's only test evidence. Run the same shared
suites, cite only observations that establish the declared values, and keep a complete
baseline report. The checker does not require a provider entry in the native CLI's driver
list. An adapter report retains its implementation identity, source digest and installed
package versions; do not strip them or relabel it as a native run. Consumers such as
Adapter Kit additionally validate that identity against the installed implementation.
A missing adapter mapping proves no native absence. Native capabilities beyond the tested
mapping stay unknown until separately established.

The bundled native drivers remain an independent measurement path for their providers;
Docker Engine remains the reference. The native `run` and `sweep` commands load only those
drivers. For adapter or HTTP reports, use the installed consumer's runner, for example
[the provider onboarding kit](../docs/how-to/provider-kit.md#honest-reporting).

## Writing a driver

This section applies when choosing to add an independent native SDK driver.

Drivers are Python modules in this repository, loaded by name. Provider identifiers in declarations
and reports keep their declared spelling; replace each hyphen with an underscore for the module
name, loader-list entry and CLI argument. For example, `provider: docker-engine` uses
`drivers/docker_engine.py` and `run docker_engine`. Create
`src/sandbox_provider_spec/drivers/<module_name>.py`. Subclass
[Driver](../src/sandbox_provider_spec/driver.py), replacing dots in operation names with
underscores. Export `make_driver(*, execution_class, fixtures)`, record `provider`, optional
`execution_class` and `sdk_versions`, and pin the SDK as an optional dependency. The command
finds implemented modules from its hard-coded provider-name list in
[conformance.py](../src/sandbox_provider_spec/conformance.py): `blaxel`, `daytona`,
`docker_engine`, `e2b`, `modal` and `vercel`. Add a name there only when adding a bundled native driver.
Report authors follow [the report evidence requirements](#committing-and-checking-report-evidence).
[E2B's driver](../src/sandbox_provider_spec/drivers/e2b.py) is an example.

Return only native observations and opaque bindings. Use `own()` immediately after an
allocation returns, before reading its properties or asserting anything. If an SDK creates
an object and then waits for readiness, reserve its unique native name with cleanup before
that call, so a readiness failure cannot strand it. Cleanup uses only that SDK and confirms
absence. Missing native capabilities are explicit `unsupported` operations; unfinished
mappings are `not_run`. `unobservable` supplies explicit `not_run` reasons where a native
SDK cannot expose the observation safely. No driver adds a bundled binary, timer, process
replay or API emulation.

Supplementary desktop tests use the provider's native desktop API and a small ordinary
X11 application. The application records pointer events and the exact generated text
received before Enter. Screenshot checks validate the PNG chunks and decoded row sizes.
Live-view checks launch Chromium and require both incoming WebSocket frames and the
application's pixels in a canvas; an HTTP 200 or a static matching canvas is insufficient.
The native URL may contain a sandbox credential, but never the account API key. Install
the runner's `browser` extra (included by `--all-extras`) and Chromium before a live
supplementary run:

```sh
uv run --locked --all-extras playwright install chromium
```

The browser runs on the runner's host. No logged-in browser or desktop account is needed.

<a id="denylist-proof-fixtures"></a>

Supplementary denylist tests take these fixtures:

| Runner fixture | Required contents |
| --- | --- |
| `denylist_names_entries` / `denylist_names_urls` | Every denied name and its HTTP/HTTPS pair, plus `denylist_allowed_urls` for unlisted positive controls. |
| `denylist_addresses_entries` / `denylist_addresses_urls` | Every denied IPv4 address or CIDR and its HTTP/HTTPS pair, plus the unlisted controls. |
| `denylist_mixed_entries` / `denylist_mixed_urls` | A nonempty list containing both controlled host names and IPv4 addresses or CIDRs, with one matching HTTP/HTTPS pair per entry. |
| `max_deny_entries` | Nonempty list of distinct host names, IPv4 addresses or ranges; every entry is exercised. |
| `max_deny_urls` | One HTTP/HTTPS URL pair per `max_deny_entries` item, following the shared pair rules below. |
| `denylist_allowed_urls` | Reachable unlisted positive-control URLs for both policy and entry-count tests. |

The same [`deny_pairs`](../src/sandbox_provider_spec/proofs.py) validation applies to
`denylist_names_entries` / `denylist_names_urls`,
`denylist_addresses_entries` / `denylist_addresses_urls`, and `max_deny_entries` / `max_deny_urls`.
Each entry list is nonempty and distinct case-insensitively, unlike the case-sensitive
`max_allow_entries` list. Each URL list has one two-element pair per entry, in entry
order: exactly one HTTP and one HTTPS URL, with no URL user information or explicit
port. For a host name, each parsed URL hostname must equal the lowercased entry; for an
IPv4 address or range, each URL hostname must be an IPv4 address inside that entry. Pairs
rejected by `deny_pairs` validation produce `not_run` with
`proof_fixture_invalid`.

The entry-count test proves `max_deny: {at_least: N}` for the number of distinct entries
actually exercised; it does not establish an exact maximum. Reserved-port fixtures are
listed in the main fixture table above.

Docker tests create a sandbox for the docker requirement and set `user: root`. They do not
build an image, install Docker, or start a daemon. The provider supplies the engine in its
default environment, in an image it publishes, or through an option or image the driver sets
at creation. The workload uses that engine's `docker` client, pulls a public image, and runs
a container. It inspects the actual container network mode, verifies outbound HTTP without
proxies, and reaches the container's server through a bridge published port or host loopback.
No privileged flag, network shim or replacement kernel is added. See Driver notes for native
runtime and user selectors. The exact owned container is removed and its absence checked, and
the runner releases the sandbox even on failure. An unavailable public pull or a missing
`docker` client is `not_run`, not evidence of absent container support. A client that cannot
reach the provider's engine fails the positive test and supplies no passing proof.

Hidden-secret request fixtures honour the sandbox's HTTP proxy variables. The
`transparent` tests first confirm ordinary injection, then issue the same request
with proxy variables ignored and compare authenticated receiver receipts. A bounded
connection refusal or timeout establishes no direct injection only after that
positive control; a failed receiver observation or broken fixture proves nothing.

Egress-proxy coverage supplies `egress_proxy_protocol` (`http` or `socks5`), a fixture
proxy address and test-only username and password, its expected outbound source address,
reachable HTTP and HTTPS receiver URLs, a TCP receiver host and port, and an intentionally
unreachable proxy address. The proxy records forwarded destinations; each receiver reports
the connecting source address. The helper checks receiver and proxy health from the runner
before creating a sandbox. It gives proxy details to the provider's native creation call,
never in the request, and records only booleans, never addresses or credentials. Its
`routes` probe checks HTTP and HTTPS, `any_tcp` checks an arbitrary TCP connection,
`transparent` sends HTTPS with proxy environment variables ignored, and `fails_closed`
checks HTTP and HTTPS against an unavailable proxy. Raw TCP stays outside that check
because the probe requests `traffic: http`. The helper removes the sandbox
and confirms cleanup after each probe.

Network-lockdown probes continue to ignore proxy variables. WebSocket fixtures use
an HTTP/1.1 upgrade and ordinary HTTP replies carry their content length.

## Driver notes

These describe native mappings and observation budgets, not exceptions to the rules.

### E2B

The [E2B driver](../src/sandbox_provider_spec/drivers/e2b.py) uses the native root user
selector for Docker workload commands. Its private ingress credential covers every port
of one sandbox. The private-preview test is therefore expected to report `differs` against
`previews/private-credential-is-its-own`, and E2B declares no private-preview variant.
The committed E2B reports predate this driver change and record `unsupported` for these
private-preview tests. They remain historical reports; neither result establishes private
preview support under this specification.

### Modal

The [Modal driver](../src/sandbox_provider_spec/drivers/modal.py) selects the native
`runtime="vm"` for Docker requests. Idle-shutdown tests select 60 seconds through
native creation settings; observation fixtures bracket that interval. The public
[`Sandbox.list()` API](https://modal.com/docs/sdk/py/latest/Sandbox) lists sandboxes but
does not expose allocation or idle-timeout metadata, so these observations are `not_run`.
It documents the method as: “List all Sandboxes for the current Environment or App ID
(if specified).”

### Daytona

The [Daytona driver](../src/sandbox_provider_spec/drivers/daytona.py) accepts
`--class container`, `--class vm` and `--class gpu`. Omitting `--class`, or explicitly
using `--class default`, selects `container`. Docker tests select `os_user="root"`. Idle-shutdown
tests select 60 seconds through native creation settings; default-period observations may
instead exercise its fifteen-minute interval.

Daytona snapshot tests allow a 180-second native capture wait and use a 300-second
source lifetime unless the test explicitly supplies another lifetime. The ticker
and its native process budget cover that window plus observation. These are bounded
test budgets, not performance or retention promises; expiry during capture cannot
establish a snapshot source-state value.
The Daytona driver uses the SDK's default event streaming with its automatic polling
fallback. The [Python SDK reference](https://www.daytona.io/docs/en/python-sdk/)
marks polling-only mode deprecated; the driver does not opt into it or replay a
timed-out capture.

Driver-specific fixtures are:

| Fixture | Shape and purpose |
| --- | --- |
| `daytona_vm_snapshot` | Optional native VM-class snapshot name; without it the driver looks for an active `linux-vm` artifact. |
| `daytona_container_snapshot` | Optional native container-class snapshot name. |
| `daytona_gpu_image` | Optional OCI image for a native GPU allocation. |
| `daytona_size_image` | Optional image-reference string for native resource-allocation snapshots; defaults to `python:3.12-slim`. |
| `daytona_container_target`, `daytona_vm_target`, `daytona_gpu_target` | Optional native SDK target for each declaration class. |
| `daytona_container_available`, `daytona_vm_available`, `daytona_gpu_available` | Optional boolean account-condition flags. Explicit `false` skips creation with `not_run`; use only after an account's condition is established independently. This is not evidence of a native absence. |

### Docker Engine

The [Docker Engine driver](../src/sandbox_provider_spec/drivers/docker_engine.py) bounds
the SDK's otherwise unbounded stream poll by shutting down its client transport.

| Fixture | Shape and purpose |
| --- | --- |
| `docker_image` | Optional image-reference string used when a create step provides no image; defaults to `python:3.12-slim`. An explicit image binding takes precedence. |
| `docker_engine_exclusive_daemon` | Explicit `true` only for a daemon used exclusively by this run. Dockerfile builds then own newly appearing native images, including intermediate and base images. Shared daemons skip builds because a final tag does not identify every artifact. |

### Blaxel

The [Blaxel driver](../src/sandbox_provider_spec/drivers/blaxel.py) observes deployment
status and the separate runtime state. A deployed sandbox in native standby is reported
as `paused`; its metadata read alone does not keep it active. The active-lifetime test
uses baseline command calls before each state observation.

### Vercel

The [Vercel driver](../src/sandbox_provider_spec/drivers/vercel.py) calls the native
`vercel-sandbox` Python SDK directly and records its version. Existing reports retain that
SDK identity. Current [Python SDK documentation](https://vercel.com/docs/sandbox/python-sdk-reference)
installs `vercel`; migration needs new native reports before the declaration can change
its SDK set. Its observations and explicit unsupported operations follow the same result
rules above. See [evidence scope](../providers/vercel/evidence.md).
