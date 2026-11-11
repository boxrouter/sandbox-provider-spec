# Modal declaration scope

## Network lockdown

The `network_lockdown` gate declares two allowlist variants. The
[sandbox networking guide](https://modal.com/docs/guide/sandbox-networking) lists
“IP-range allowlist `outbound_cidr_allowlist` Only allows traffic to the listed CIDR ranges (any
protocol)” and “Domain allowlist (Beta) `outbound_domain_allowlist` Only allows TLS traffic (port
443) to the listed domain names.” The adapter report `reports/adapter-default-core.json`
(modal 1.6.1) passes `network_lockdown.allowlist.names`, `network_lockdown.wildcards`,
`network_lockdown.max_allow` (32 names) and `network_lockdown.allowlist.addresses`.

The same report passes `network_lockdown.deny_all`, but the guide does not say which other
features a full block (`block_network=True`) rules out, so a `deny_all` variant, whose conflicts
would need that quote, stays undeclared.

## Sizes and the ceiling

`resources.sizes` declares a range because Modal sizes freely: a sandbox gets the CPU and memory it
asks for. The floor is the [documented](https://modal.com/docs/guide/resources) default request of
0.125 CPU cores and 128 MiB. That guide says a maximum is enforced at creation and rejects requests
above it, but it states no number, so each class declares the largest size a run has created:
4 CPU / 8192 MiB on `default` and 16 CPU / 32768 MiB on `vm`. `coverage.facts.sizes.delivered` in
`reports/adapter-default-size-ceiling.json` and `reports/adapter-vm-size-ceiling.json` observes those
sizes inside the guest. Modal may accept larger sizes; they stay undeclared until a run shows them.

`cpu` here is the value passed to Modal's `cpu` argument. Modal's guides call that argument physical
cores and say one core is two vCPUs, but what a sandbox may use is enforced as CPU time: a sandbox
created with `cpu=(2, 2)` has a quota of 2 CPU-seconds per second and sees 2 processors.

`resources.size_is_ceiling` holds when both ends of Modal's `(request, limit)` tuples are set to the
size; with plain numbers Modal sets a request and lets the sandbox burst. Each class's report above
passes `coverage.facts.size_is_ceiling.true` at 2 CPU / 4096 MiB. On `default` it reads the enforced
cgroup bounds. `vm` shows no cgroup bound, so the test takes its measured path: memory was held to the
size by a process kill. That path's CPU burn uses threads in one Python process, which cannot exceed
one CPU, so it does not test a 2 CPU limit; separately, eight busy processes in a `vm` sandbox of
2 CPUs measured 1.98 CPU-seconds per second on 2026-11-06.

## Lifetime cannot be extended

`resources.extendable_lifetime` stays unstated for both classes. Modal's
[Sandboxes guide](https://modal.com/docs/guide/sandboxes), read 2026-11-11, says “Sandboxes have a
default maximum lifetime of 5 minutes. You can change this by passing a timeout of up to 24 hours to
the Sandbox.create(...) function,” and, for longer work, to snapshot the filesystem and restore from
it in a later sandbox. The [`modal.Sandbox` reference](https://modal.com/docs/reference/modal.Sandbox)
(SDK 1.6.3, read 2026-11-11) lists no method that changes a running sandbox's timeout, and neither
does modal 1.6.1's `modal/sandbox.py`, whose gRPC stub has no sandbox call that updates a timeout
(`SandboxCreate`, `SandboxWait`, `SandboxTerminate`, `SandboxTagsSet` and the like only). That is an absence, not a statement that extending is impossible, so the fact is not declared
`false`; it becomes `true` only if Modal documents or ships an extend operation.
