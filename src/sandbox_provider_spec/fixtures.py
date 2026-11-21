# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The runner fixtures of the shared tests: what each is, and how `test --fixture` reads them.

A fixture is a value that the account being tested must supply, because the suite cannot invent
it: an image that a registry serves, a URL that a sandbox is allowed to reach, a size to ask
for. A test whose fixture is missing is `not_run` (`fixture_missing`), never failed.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import yaml

ENV_PREFIX = "env:"

# Names the tester sets itself, so a caller does not supply them.
RESERVED = {
    "reachable_url": "use --reachable-url",
    "run_nonce": "the run generates it",
}

# Every fixture name that the shared suites (`conformance/suite.yaml`, `conformance/coverage.yaml`)
# and the shared runner read, with what the test needs it to hold. Names are `snake_case`; a
# test that uses a missing one is `not_run`.
FIXTURES: Mapping[str, str] = {
    "address_families": (
        "A map `{ipv4_literal, ipv6_literal, port}` of one IPv4 and one IPv6 endpoint that an "
        "unrestricted sandbox can reach."
    ),
    "allowed_domains": "A list of domains or CIDRs that an allowlist for `allowed_url` holds.",
    "allowed_ip_range": (
        "One IPv4 range (`/0` to `/24`) that covers `allowed_ip_url` and `allowed_ip_range_url`."
    ),
    "allowed_ip_range_url": (
        "A second literal-IPv4 HTTP URL, inside `allowed_ip_range`, on another address than "
        "`allowed_ip_url`."
    ),
    "allowed_ip_url": (
        "A plain-HTTP literal-IPv4 URL that answers 2xx without a redirect and that a sandbox "
        "can reach, for the address allowlist, block-all and root-resistance tests."
    ),
    "allowed_ips": "A list of IP addresses or CIDRs that an allowlist for `allowed_ip_url` holds.",
    "allowed_mixed": (
        "A list holding a host name that covers `allowed_url` and an address that covers "
        "`allowed_ip_url`."
    ),
    "allowed_url": "A controlled HTTP(S) receiver URL that the allowlist tests expect to reach.",
    "connection_harness": (
        "A map `{stream_url, token, ca_pem?}` of an HTTPS stream that shows whether an open "
        "connection survives."
    ),
    "connection_harness_domains": (
        "A list holding the host name of `connection_harness`, used in the initial network policy."
    ),
    "denied_url": "A controlled receiver URL outside every allowlist, which a lockdown must block.",
    "denylist_addresses_entries": "Denylist entries that are IPv4 addresses or CIDRs.",
    "denylist_addresses_urls": (
        "One HTTP and one HTTPS URL per address entry, each using a literal IP inside that entry."
    ),
    "denylist_allowed_urls": (
        "Reachable URLs that no denylist entry names, which must stay reachable."
    ),
    "denylist_mixed_entries": "Denylist entries that are host names and addresses together.",
    "denylist_mixed_urls": "One HTTP and one HTTPS URL per mixed entry, in entry order.",
    "denylist_names_entries": "Denylist entries that are host names.",
    "denylist_names_urls": "One HTTP and one HTTPS URL per name entry, using that exact host name.",
    "egress_proxy": (
        "A map `{addresses: {http|socks5: <address>}}` of the proxy a sandbox is routed through."
    ),
    "egress_proxy_protocol": (
        "The proxy protocol (`http` or `socks5`) that the egress-proxy tests ask for."
    ),
    "entrypoint_image": "An `image.prepare` request for an image that has an entrypoint.",
    "entrypoint_marker": (
        "The path of the file that the entrypoint of `entrypoint_image` writes when it runs."
    ),
    "expiry_options": "A `create` request for a sandbox with a 60-second resumable ending.",
    "file_stream_large": (
        "`true` runs the streams of 1 GiB and more; the tester sets it, so give `false` to skip "
        "them."
    ),
    "file_transfer_lifetime_seconds": (
        "Optional lifetime, in seconds, of a sandbox in the file-link and 1 GiB transfer tests."
    ),
    "files_write_executable_effect": (
        "Whether a written file stays executable: `preserved`, `may_clear`, or `unverified` "
        "(default)."
    ),
    "fuse_mount_access_mode": (
        "The access mode of the mount that the provider-terminal handover tests make."
    ),
    "fuse_mount_controller": (
        "Python only: an object with the mount lifecycle methods; no command-line form."
    ),
    "fuse_mount_controller_digest": (
        "Python only: the digest of the source files of `fuse_mount_controller`."
    ),
    "fuse_mount_create": "A `create` request for a sandbox that can mount a FUSE volume.",
    "fuse_mount_handover_controller": (
        "Python only: an object that drives the provider-terminal handover; no command-line form."
    ),
    "fuse_mount_handover_controller_digest": (
        "Python only: the digest of the source files of the handover controller."
    ),
    "fuse_mount_prerequisites": (
        "What must hold before the mount tests run (the volume, its credentials and its kind)."
    ),
    "guest_reserved_tcp_ports": (
        "A map `{candidates, provider_executables}` naming the TCP ports the guest may reserve for "
        "itself."
    ),
    "hidden_secret_wildcard_host": (
        "One `*.` wildcard host name of a controlled receiver, for a hidden secret's `inject_into`."
    ),
    "hidden_secret_wildcard_urls": (
        "Two HTTPS URLs on that receiver: a direct child of the wildcard and a deeper subdomain."
    ),
    "idle_activity_settings": (
        "The `idle_shutdown` setting for observing a long-running command across the idle interval."
    ),
    "idle_after_wait_ms": (
        "Milliseconds to wait until after the effective idle interval, before reading state."
    ),
    "idle_before_wait_ms": (
        "Milliseconds to wait, shorter than the idle interval, while the sandbox must still be "
        "active."
    ),
    "idle_lifetime_seconds": "The lifetime, in seconds, of a sandbox in the idle-shutdown tests.",
    "idle_process_timeout_ms": (
        "The timeout, in milliseconds, of the process the idle-shutdown tests keep running."
    ),
    "image_marker": (
        "Controlled text that the image's `/etc/os-release` holds, proving its own files are there."
    ),
    "larger_size": (
        "A resource request with `cpu_min` and `memory_min_mib`, larger than the default size."
    ),
    "link_lifetime_wait_seconds": (
        "The preview or file link's observation window in seconds (300 proves a 300-second bound)."
    ),
    "max_allow_entries": (
        "One to 32 distinct controlled host names, to prove the allowlist entry limit."
    ),
    "max_allow_urls": "Reachable URLs, one per `max_allow_entries` item in the same order.",
    "max_deny_entries": (
        "Distinct controlled names or IPv4 ranges, to prove the denylist entry limit."
    ),
    "max_deny_urls": "One HTTP and one HTTPS URL for each `max_deny_entries` item.",
    "max_inject_into_hosts": "Distinct receiver host names, for the `inject_into` limit.",
    "max_inject_into_urls": (
        "HTTPS URLs, one per host of `max_inject_into_hosts` in the same order."
    ),
    "max_lifetime_seconds": (
        "The lifetime, in seconds, that the max-lifetime test asks `create` for."
    ),
    "max_lifetime_wait_ms": (
        "Milliseconds, at least 1000, that the max-lifetime test waits and then observes."
    ),
    "max_live_sandboxes": "How many sandboxes the runner may hold at once (an integer, default 1).",
    "max_mounts": "The count of volumes the max-mounts test mounts (at most 32).",
    "oci_image": "A public OCI image reference, pinned by digest, for the prepared-image tests.",
    "original_size": (
        "The resource request that a sandbox is created with before a snapshot resizes it."
    ),
    "outbound_http_url": "A public plain-HTTP URL on port 80 that returns 2xx without a redirect.",
    "outbound_tcp_echo": "A map `{host, port}` of a public TCP echo service (not port 80 or 443).",
    "outbound_udp_echo": "A map `{host, port}` of a public UDP echo service.",
    "private_oci_image": (
        "A private OCI image reference, pinned by digest, that needs the username and password "
        "below."
    ),
    "private_oci_marker": "Controlled text that the private image's `/etc/os-release` holds.",
    "private_oci_password": "The registry password for `private_oci_image` (give it as `env:VAR`).",
    "private_oci_username": "The registry username for `private_oci_image`.",
    "provider_artifact_image": (
        "The id of a provider image that the account already has, which a sandbox starts from."
    ),
    "reachable_url": (
        "Set by `--reachable-url`: an HTTPS URL that a sandbox can reach with a 2xx response."
    ),
    "reserved_ports": (
        "A list of at most 64 distinct ports that the provider reserves (may be empty)."
    ),
    "restored_size": "The resource request that a sandbox restored from a snapshot asks for.",
    "snapshot_keeps": (
        "What `snapshots.v1.get_and_list` takes and expects back: `files_only` or "
        "`files_and_memory`. The tester sets it from the class's `snapshots` variants "
        "(`files_only` unless the class lists only another value); a value given here pins it."
    ),
    "standard_base_dockerfile": (
        "A Dockerfile on the provider's standard image, with the four `COPY` and `ADD` lines the "
        "test names."
    ),
    "test_gpu": "A resource request `{gpu_model: [<registry model>]}` for the GPU sandbox.",
    "test_size": (
        "A resource request using `cpu_min`, `memory_min_mib` and optional `disk_min_mib`, for the "
        "size tests."
    ),
    "volume_kind": "The kind of volume the max-mounts test makes: `filesystem` or `object_store`.",
    "wildcard_allowed_url": (
        "A reachable HTTPS URL under `wildcard_domains`, which the wildcard allowlist must permit."
    ),
    "wildcard_denied_url": "A reachable HTTPS URL outside every wildcard, which must stay blocked.",
    "wildcard_domains": (
        "Wildcard host names (`*.example.com`) for an allowlist, covering `wildcard_allowed_url`."
    ),
    "workload_identity_receiver_health_url": (
        "An HTTPS health URL of the receiver (default: `/health` on the receiver's host)."
    ),
    "workload_identity_receiver_url": (
        "An HTTPS URL of a receiver that records the identity tokens a sandbox presents."
    ),
    "workload_identity_records_url": (
        "An HTTPS URL from which the tester reads what that receiver recorded."
    ),
}

# Names that the runner derives from a fixture above, each with its source. A value given for
# one is overwritten by the derived one, so a run refuses it.
DERIVED: Mapping[str, str] = {
    "gpu_model": "test_gpu",
    "gpu_name_pattern": "test_gpu",
    "link_lifetime_wait_ms": "link_lifetime_wait_seconds",
    "max_allow_count": "max_allow_entries",
    "max_deny_count": "max_deny_entries",
    "max_inject_into_count": "max_inject_into_hosts",
    "max_lifetime_observed_seconds": "max_lifetime_wait_ms",
    "preview_link_lifetime_seconds": "link_lifetime_wait_seconds",
    "preview_process_timeout_ms": "link_lifetime_wait_seconds",
    "preview_sandbox_lifetime_seconds": "link_lifetime_wait_seconds",
    "test_gpu_models": "test_gpu",
    "test_size_value": "test_size",
}


class FixtureError(ValueError):
    """A fixture could not be read; the message is one plain line for a person."""


def _resolve(value: Any, name: str) -> Any:
    """Replace each `env:VAR` string, at any depth, with the variable's value."""
    if isinstance(value, str) and value.startswith(ENV_PREFIX):
        variable = value[len(ENV_PREFIX) :]
        if variable not in os.environ:
            raise FixtureError(f"fixture {name} names environment variable {variable}, not set")
        return os.environ[variable]
    if isinstance(value, list):
        return [_resolve(item, name) for item in value]
    if isinstance(value, dict):
        return {key: _resolve(item, name) for key, item in value.items()}
    return value


def _literal(text: str) -> Any:
    """A command-line value: JSON when it is JSON (`5`, `true`, `["a"]`), else text."""
    try:
        return json.loads(text)
    except ValueError:
        return text


def _check_name(name: str, origin: str) -> None:
    if name in RESERVED:
        raise FixtureError(f"{origin}: fixture {name} is not supplied ({RESERVED[name]})")
    if name in DERIVED:
        raise FixtureError(f"{origin}: fixture {name} is derived from {DERIVED[name]}; give that")
    if name not in FIXTURES:
        raise FixtureError(
            f"{origin}: unknown fixture {name!r} (`sandbox-provider-spec test --help` lists them)"
        )


def _from_file(path: str) -> dict[str, Any]:
    try:
        document = yaml.safe_load(Path(path).read_text(encoding="utf-8"))  # JSON is YAML
    except (OSError, yaml.YAMLError) as error:
        raise FixtureError(f"--fixtures {path}: {error}") from None
    if not isinstance(document, dict) or not all(isinstance(key, str) for key in document):
        raise FixtureError(f"--fixtures {path}: expected a map of fixture name to value")
    for name in document:
        _check_name(name, f"--fixtures {path}")
    return dict(document)


def read_fixtures(pairs: Iterable[str], files: Iterable[str] = ()) -> dict[str, Any]:
    """The fixtures that a run is given: each `--fixtures FILE` in order, then each
    `--fixture NAME=VALUE` (which wins). A string `env:VAR`, at any depth, is replaced by the
    variable's value, so a secret stays in the environment; no message prints a value."""
    found: dict[str, Any] = {}
    for path in files:
        found.update(_from_file(path))
    for pair in pairs:
        name, separator, value = pair.partition("=")
        if not separator or not name:
            raise FixtureError(f"--fixture needs NAME=VALUE, got {name or pair!r}")
        _check_name(name, "--fixture")
        found[name] = _literal(value) if not value.startswith(ENV_PREFIX) else value
    return {name: _resolve(value, name) for name, value in found.items()}


def help_text() -> str:
    """The fixture table for `test --help`: one line each."""
    width = max(len(name) for name in FIXTURES)
    lines = [f"  {name.ljust(width)}  {what}" for name, what in FIXTURES.items()]
    derived = ", ".join(f"{name} (from {source})" for name, source in DERIVED.items())
    return (
        "fixtures (a test whose fixture is not supplied stays not_run):\n"
        + "\n".join(lines)
        + f"\n\nderived by the run from a fixture above, never supplied: {derived}"
    )
