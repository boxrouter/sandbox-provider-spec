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
