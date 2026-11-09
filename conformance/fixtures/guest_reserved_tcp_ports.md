# Guest-reserved TCP-port fixture

The `fixture.guest_reserved_tcp_ports` operation has no implicit candidates. A runner must
explicitly provide a bounded candidate list and a provenance-backed list of provider-managed
executable SHA-256 identities. The committed schema describes that input. There is deliberately
no example owner or provider port: an `EADDRINUSE` result alone cannot establish provider
ownership.

The guest probe reads complete `/proc/net/tcp` and `/proc/net/tcp6` tables and maps listener
inodes to PIDs through `/proc/<pid>/fd`. It hashes the owning executable and compares that digest
with the supplied trusted identities. It never reads process command lines or environments.
For each explicit candidate only, it makes a bind attempt without `SO_REUSEADDR`, then takes a
second complete snapshot to detect socket or owner races. IPv4 and IPv6 candidates keep separate
addresses and family settings; IPv6 sets and verifies the candidate socket's `IPV6_V6ONLY` value,
and reports the requested and observed values separately.
`/proc/net/tcp6` does not expose that option for an existing listener, so a possible cross-family
overlap with an IPv6 listener whose option is unavailable remains unknown.

The report contains only the candidate tuple, classification, and errno. PID, inode, executable
hash, command line, environment, payloads and secrets are not emitted. A positive member means
only that this provider-owned listener blocked this exact tested bind tuple at that observation.
No candidates, an empty listener table, an incomplete owner map, a race, an unknown owner, an
ambiguous family result, or a bindable candidate produces no `[]` claim; the resource stays
unknown unless a positive member is established.
