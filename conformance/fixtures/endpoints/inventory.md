# Runner fixture inventory

`suite.yaml` and `coverage.yaml` currently reference 78 distinct `$runner.*` names. The
40 endpoint-supplied values below are the keys a deployment of this endpoint service
supplies through the run's fixture file.
The other 38 values are run inputs or values the runner derives, as described below; they are
not values served by this endpoint service.

The `Dockerfile` and `fly.toml` beside this file build and configure one controlled
deployment. Wildcard fixtures use one-level names under the controlled DNS
zone configured at deployment; the zone's DNS record and wildcard certificate are part of
that deployment setup. Address fixtures use two distinct dedicated IPv4 addresses in one CIDR.

## Endpoint-supplied values (40)

| `$runner` key | What it must serve |
| --- | --- |
| `allowed_domains` | Domain entries that resolve to the HTTPS receiver used by allowlist tests. |
| `allowed_ip_range` | IPv4 CIDR `/0` through `/24` containing the dedicated addresses in `allowed_ip_url` and `allowed_ip_range_url`. A literal IPv4 host in `denied_url` must fall outside this CIDR. |
| `allowed_ip_range_url` | Second plain HTTP health endpoint on a different literal IPv4 inside `allowed_ip_range`. |
| `allowed_ip_url` | Plain HTTP health endpoint addressed by literal IPv4, without DNS or TLS. |
| `allowed_ips` | IPv4 address or CIDR entries covering the dedicated address. |
| `allowed_mixed` | Domain and IPv4 entries covering `allowed_url` and `allowed_ip_url`. |
| `allowed_url` | Reachable controlled HTTP or HTTPS request receiver for allowlist tests. |
| `connection_harness` | HTTPS `/stream` URL, a private test token, and optional CA bundle; stream emits `sps-connection-proof` lines at short intervals. |
| `connection_harness_domains` | The stream hostname used in the initial sandbox network policy. |
| `denied_url` | A second reachable controlled receiver URL outside the positive allowlist. |
| `deny_wins_allow_entry` | A wildcard host entry covering both deny-wins receiver names. |
| `deny_wins_allowed_url` | Reachable HTTPS receiver under the wildcard, on a host different from the denied host. |
| `deny_wins_denied_url` | Reachable HTTPS receiver whose exact hostname is also in the deny entry. |
| `deny_wins_deny_entry` | The exact hostname of `deny_wins_denied_url`. |
| `denylist_addresses_entries` | IPv4 address or CIDR entries denied by address-based tests. |
| `denylist_addresses_urls` | One HTTP/HTTPS pair per address entry, both URLs using literal IPs inside that entry. |
| `denylist_mixed_entries` | A nonempty list containing controlled host names and IPv4 address or CIDR entries. |
| `denylist_mixed_urls` | One HTTP/HTTPS pair per mixed entry, in entry order; host names and IPv4 destinations must match the corresponding entry. |
| `denylist_allowed_urls` | Reachable, unlisted HTTP/HTTPS controls for denylist and entry-count tests. |
| `denylist_names_entries` | Controlled hostname entries denied by name-based tests. |
| `denylist_names_urls` | One HTTP/HTTPS pair for each name entry, both using that exact controlled hostname. |
| `egress_harness` | One host and private token for `/probe` on HTTP 80 and HTTPS 443, TLS on 8443, and TCP/UDP proof exchanges. TCP and UDP use 7000 and 7001. |
| `egress_harness_domains` | Hostname list resolving to the egress harness for domain-traffic checks. |
| `egress_proxy_protocol` | Proxy protocol selected for egress-proxy tests: `http` or `socks5`; this service supports both. |
| `hidden_secret_wildcard_host` | One wildcard receiver hostname for hidden-secret injection. |
| `hidden_secret_wildcard_urls` | Two HTTPS request URLs: one for a direct child of the hidden-secret wildcard domain and one for a deeper subdomain. |
| `http_rules_allowed_url` | HTTPS `/allowed/x` URL on the controlled host used by HTTP-rule tests. |
| `http_rules_host` | Exact hostname of all three HTTP-rule URLs. |
| `http_rules_outside_path_url` | HTTPS `/other` URL on the HTTP-rule host. |
| `http_rules_wrong_method_url` | HTTPS `/allowed/x` URL on the HTTP-rule host; the test sends POST to it. |
| `max_allow_entries` | One through 32 distinct controlled hostnames used to prove allowlist entry limits. |
| `max_allow_urls` | Same-length reachable URLs whose hostnames match `max_allow_entries` in order. |
| `max_deny_entries` | Distinct controlled names or IPv4 ranges used to prove denylist entry limits. |
| `max_deny_urls` | One HTTP/HTTPS URL pair for each `max_deny_entries` value. |
| `max_inject_into_hosts` | Distinct receiver hostnames for generated-secret injection tests. |
| `max_inject_into_urls` | Same-length HTTPS receiver URLs, each with the corresponding host. |
| `outbound_http_url` | Direct plain-HTTP port 80 endpoint returning 2xx without a redirect. |
| `outbound_tcp_echo` | Dedicated IPv4 and port 7000, echoing arbitrary payloads unchanged. |
| `outbound_udp_echo` | Dedicated IPv4 and port 7001, echoing datagrams unchanged. |
| `wildcard_allowed_url` | Reachable positive HTTPS control under the wildcard allowlist name. |
| `wildcard_denied_url` | Reachable negative HTTPS control on a hostname outside the wildcard allowlist. |
| `wildcard_domains` | Wildcard hostname entries for the controlled one-level subdomains. |

The recorder stores methods, paths, request headers and bodies under `x-token` or
`X-SPS-Probe`. The HTTP and SOCKS5 proxies record authenticated test connections directly;
for unauthenticated TLS tunnels, the receiver associates the connection with the token on
the first request. Proxy destinations are restricted to the app hostname, configured
wildcard suffix, and fixture ports 80, 443, 8443, 7000 and 7001.

## Other runner inputs and derived values (38)

| `$runner` key | Purpose |
| --- | --- |
| `expiry_options` | Provider-specific creation options for the resumable expiry observation. |
| `gpu_model` | Derived display name corresponding to the single GPU model in `test_gpu`. |
| `gpu_name_pattern` | Derived regular expression for matching the GPU display name. |
| `idle_activity_settings` | Provider-native settings for the idle-shutdown activity test. |
| `idle_after_wait_ms` | Runner observation delay after the native idle interval. |
| `idle_before_wait_ms` | Runner observation delay shorter than the native idle interval. |
| `idle_lifetime_seconds` | Sandbox lifetime long enough to cover both idle observations. |
| `idle_process_timeout_ms` | Process deadline longer than the complete idle observation. |
| `image_marker` | Expected controlled marker text in an image's `/etc/os-release`. |
| `entrypoint_image` | `image.prepare` input for an image whose ENTRYPOINT or CMD creates a known marker. When Dockerfile preparation is supported, use `FROM python:3.11-slim` with `ENTRYPOINT ["/sps-entrypoint"]`, where `/sps-entrypoint` writes `/tmp/sps-entrypoint` then sleeps. Otherwise use the pinned public `docker.io/library/nginx:1.27` OCI image (or its prepared provider reference); its `/docker-entrypoint.sh` launches nginx, which writes `/run/nginx.pid`. |
| `entrypoint_marker` | `/tmp/sps-entrypoint` for the Dockerfile fixture or `/run/nginx.pid` for the nginx OCI fixture. The marker must be absent from the image layers and created only by startup. |
| `larger_size` | Resource request with `cpu_min` and `memory_min_mib` above the provider's default size. |
| `link_lifetime_wait_ms` | Derived milliseconds for the preview-link lifetime observation. |
| `link_lifetime_wait_seconds` | Preview-link observation interval, normally 300 seconds. |
| `max_allow_count` | Derived from the number of entries in `max_allow_entries`. |
| `max_deny_count` | Derived from the number of entries in `max_deny_entries`. |
| `max_inject_into_count` | Derived from the number of hosts in `max_inject_into_hosts`. |
| `max_lifetime_observed_seconds` | Derived lower bound from `max_lifetime_wait_ms`. |
| `max_lifetime_seconds` | Requested lifetime for the active-sandbox observation. |
| `max_lifetime_wait_ms` | Runner wait for the maximum-lifetime observation. |
| `max_mounts` | Positive mount count for volume coverage. |
| `oci_image` | Public OCI image used by image preparation and container tests. |
| `original_size` | Smaller provider resource request used by resize coverage. |
| `preview_link_lifetime_seconds` | Derived native preview-link lifetime with setup margin. |
| `preview_process_timeout_ms` | Derived process timeout with setup margin. |
| `preview_sandbox_lifetime_seconds` | Derived sandbox lifetime with setup margin. |
| `private_oci_image` | Fresh private registry image for authenticated-pull coverage. |
| `private_oci_password` | Run-specific credential for `private_oci_image`; never report it. |
| `private_oci_username` | Run-specific credential for `private_oci_image`. |
| `provider_artifact_image` | Existing provider-native artifact, borrowed and not deleted. |
| `reachable_url` | Run input: a public HTTPS health URL returning a direct 2xx response without a redirect. Choose a public host the provider's default network allows, such as a package index; do not use a controlled fixture endpoint. The endpoint service does not supply this value. |
| `reserved_ports` | List of guest ports reserved by port-forwarding coverage. |
| `restored_size` | Larger resource request used to restore a resized sandbox. |
| `run_nonce` | Runner-generated per-run marker; omit from fixture files. |
| `standard_base_dockerfile` | Run input: a Dockerfile on the provider's standard image for the standard-base build-context check. |
| `test_gpu` | Native resource request containing exactly one reviewed GPU model. |
| `test_gpu_models` | Derived one-element registry model list from `test_gpu`. |
| `test_size` | Native resource request for concrete size coverage. |
| `test_size_value` | Derived public resource mapping from `test_size`. |
| `volume_kind` | `filesystem` or `object_store`, matching the provider's mounted artifact type. |

For the Dockerfile source, use this fixture and set `entrypoint_marker` to
`/tmp/sps-entrypoint`:

```dockerfile
FROM python:3.11-slim
RUN printf '#!/bin/sh\nprintf started >/tmp/sps-entrypoint\nexec sleep 600\n' >/sps-entrypoint && chmod +x /sps-entrypoint
ENTRYPOINT ["/sps-entrypoint"]
```

For OCI, use `docker.io/library/nginx@sha256:fafd5f55296511cd0f1c991efa0cb85f323449bf643f3b6d760c6542f020d6e5`
and set `entrypoint_marker` to `/run/nginx.pid`. This pinned Linux/amd64 image has
`/docker-entrypoint.sh` as ENTRYPOINT and starts nginx as CMD; nginx creates that PID file.
The prepared provider reference can replace the public source in native drivers that only
accept provider-owned image references.

The runner derives count and preview/lifetime values from their source fixtures and generates
`run_nonce` per run. Those derived placeholders are listed because the suite references them,
but they are not endpoint-supplied values.
