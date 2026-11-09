# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The specification's vocabulary: gates, knobs, settings, limits and resources.

Transcribed from the specification's gate table, in its order, which is the order the
matcher searches in and reports in. The generated catalog is checked against this table by
the matcher tests so a divergence fails here rather than in a consumer.
"""

from __future__ import annotations

from typing import Any, Final, Literal, NamedTuple

Document = dict[str, Any]

ANY: Final = "any"
UNKNOWN: Final = "unknown"
UNLIMITED: Final = "unlimited"

Kind = Literal["pick", "all_of", "flag", "number"]
PICK: Final[Kind] = "pick"
#: The request lists values it needs, and a variant fits only when it offers every one.
ALL_OF: Final[Kind] = "all_of"
FLAG: Final[Kind] = "flag"
NUMBER: Final[Kind] = "number"


class Knob(NamedTuple):
    """One compared detail of a gate."""

    kind: Kind
    values: tuple[str, ...] = ()
    must_be_named: bool = False
    one_value: bool = False
    #: (knob, value) this knob only applies under; a request that names it with that knob
    #: outside the condition is refused. With one value it is compared, and granted, only in the
    #: variant where the condition holds. A tuple of values means the other knob holds one of
    #: them; the request is refused only when it names that knob with none of them, and the
    #: knob is compared plainly, so a variant that leaves it out does not fit.
    only_when: tuple[str, Any] | None = None
    #: This knob applies when any listed sibling knob has the required value.
    only_when_any: tuple[tuple[str, Any], ...] | None = None
    #: True: the condition holds only when that knob names exactly that value.
    only_when_exact: bool = True


class Gate(NamedTuple):
    knobs: dict[str, Knob]
    settings: tuple[str, ...] = ()
    limits: tuple[str, ...] = ()
    #: Keys a variant of this gate may carry beyond knobs, limits and the shared ones.
    variant_keys: tuple[str, ...] = ()


KEEPS: Final = ("files_only", "files_and_memory")
#: The directions a file link or a streamed transfer moves bytes in.
FILE_OPERATIONS: Final = ("read", "write")
#: The idle states a sandbox can be woken from.
WAKES: Final = ("paused", "stopped")
POLICIES: Final = (
    "deny_all",
    "allowlist",
    "denylist",
    "open",
)

#: Insertion order is the specification's gate table: gates are searched and reported in it.
GATES: Final[dict[str, Gate]] = {
    "fuse_mount": Gate({}),
    "idle_shutdown": Gate(
        knobs={
            "on_idle": Knob(PICK, ("paused", "stopped", "destroyed")),
            "custom_idle_time": Knob(FLAG),
            "auto_wake": Knob(FLAG, only_when=("on_idle", WAKES)),
        },
        settings=("idle_seconds",),
    ),
    "pause_resume": Gate(knobs={"keeps": Knob(PICK, KEEPS)}),
    "previews": Gate(
        knobs={
            "access": Knob(PICK, ("public", "private"), must_be_named=True),
            "credential": Knob(
                PICK, ("link", "header"), only_when=("access", "private"), only_when_exact=False
            ),
            "revocable": Knob(FLAG),
            "link_lifetime_seconds": Knob(NUMBER),
            "websocket": Knob(FLAG),
            "loopback": Knob(FLAG),
            "any_port": Knob(FLAG),
            "survives_pause": Knob(FLAG),
        },
        settings=("ports",),
        limits=("max_ports", "reserved_ports"),
    ),
    "network_lockdown": Gate(
        knobs={
            "policy": Knob(
                PICK,
                POLICIES,
                must_be_named=True,
                one_value=True,
            ),
            "changeable": Knob(FLAG, only_when=("policy", ("allowlist", "denylist"))),
            "switchable": Knob(FLAG),
        },
        settings=("allow", "deny", "switches_to"),
        limits=("max_allow", "max_deny", "allow_wildcards", "entry_kinds"),
    ),
    "hidden_secrets": Gate(
        knobs={
            "rotates": Knob(FLAG),
            "scrubs_responses": Knob(FLAG),
            "injection": Knob(PICK, ("sets_header",)),
            "header_templates": Knob(FLAG),
            "intercepts": Knob(PICK, ("injected_hosts", "all_https")),
            "transparent": Knob(FLAG),
        },
        settings=("inject_into", "headers"),
        limits=("max_inject_into", "inject_wildcards"),
    ),
    "snapshots": Gate(
        knobs={
            "keeps": Knob(PICK, KEEPS),
            "original_after": Knob(
                PICK, ("continues", "briefly_paused", "terminated"), must_be_named=True
            ),
            "deletable": Knob(FLAG),
            "retention_seconds": Knob(NUMBER),
        },
        variant_keys=("resizes_on_restore",),
    ),
    "volumes": Gate(
        knobs={
            "sharing": Knob(PICK, ("one_sandbox", "many_writers")),
            "read_only_mounts": Knob(FLAG),
            "kind": Knob(PICK, ("filesystem", "object_store"), must_be_named=True),
        },
        settings=("mounts",),
        limits=("max_mounts",),
    ),
    "custom_images": Gate(
        knobs={
            "source": Knob(PICK, ("oci", "private_oci", "dockerfile", "provider_artifact")),
            "prepared": Knob(FLAG),
            "runs_entrypoint": Knob(FLAG),
            "image_config": Knob(ALL_OF, ("env", "workdir", "user")),
            "build_context": Knob(FLAG, only_when=("source", "dockerfile")),
        },
        settings=("image",),
    ),
    "user_selection": Gate(
        knobs={"commands": Knob(FLAG), "files_write": Knob(FLAG), "process_start": Knob(FLAG)}
    ),
    "processes": Gate(knobs={"input": Knob(FLAG), "cancel": Knob(FLAG), "reattach": Knob(FLAG)}),
    "terminal": Gate(knobs={"reattach": Knob(FLAG)}),
    "docker": Gate(knobs={"networking": Knob(PICK, ("host",))}),
    "tcp_ports": Gate(
        knobs={"tls": Knob(PICK, ("none",), must_be_named=True)},
        settings=("ports",),
        limits=("max_tcp_ports",),
    ),
    "desktop": Gate(knobs={"live_view": Knob(FLAG)}),
    "file_links": Gate(
        knobs={
            "operations": Knob(ALL_OF, FILE_OPERATIONS),
            "user_selection": Knob(FLAG),
            "link_lifetime_seconds": Knob(NUMBER),
            "revocable": Knob(FLAG),
        }
    ),
}

#: Requests name these; each is compared only when asked for, except the lifetime.
RESOURCE_ASKS: Final = (
    "cpu_min",
    "memory_min_mib",
    "on_memory_exhausted",
    "disk_min_mib",
    "extendable_lifetime",
    "region",
    "gpu_count",
    "gpu_model",
    "kernel",
    "kernel_features",
    "long_running",
    "size_is_ceiling",
    "paused_retention_seconds",
    "root",
    "arch",
    "package_manager",
    "libc",
    "run_seconds",
    "process_seconds",
    "egress_ips",
    "outbound_traffic",
    "outbound_ip_families",
    "file_stream_bytes",
)
SIZE_ASKS: Final = {"cpu_min": "cpu", "memory_min_mib": "memory_mib", "disk_min_mib": "disk_mib"}
KERNELS: Final = ("shared", "filtered", "dedicated")
KERNEL_FEATURES: Final = ("fuse", "ebpf", "nested_cgroups", "netfilter")
#: The ways a command gets root, which a declaration lists and a request picks from.
ROOT_WAYS: Final = ("by_default", "sudo", "per_command")
#: Resources a request may not name together with an image, which decides them itself.
IMAGELESS_RESOURCES: Final = frozenset({"root", "package_manager", "libc", "kernel_features"})
#: Resources a request asks as one value or a list, and the values each may name.
PICK_RESOURCES: Final = {
    "kernel": KERNELS,
    "root": ROOT_WAYS,
    "arch": ("amd64", "arm64"),
    "package_manager": ("apt", "apk", "dnf", "pacman", "none"),
    "libc": ("glibc", "musl"),
    "on_memory_exhausted": ("process_killed", "sandbox_ended"),
    "egress_ips": ("published_ranges", "dedicated"),
}
OUTBOUND_TRAFFIC: Final = ("http", "any_tcp", "udp")
OUTBOUND_IP_FAMILIES: Final = ("ipv4", "ipv6")
ALL_OF_RESOURCES: Final = {
    "kernel_features": KERNEL_FEATURES,
    "outbound_traffic": OUTBOUND_TRAFFIC,
    "outbound_ip_families": OUTBOUND_IP_FAMILIES,
}
#: Resources a request can only ask for as `true`.
YES_RESOURCES: Final = frozenset({"extendable_lifetime", "long_running", "size_is_ceiling"})
#: Resources a request asks as a number of seconds, and the declared maximum each fits.
SECONDS_RESOURCES: Final = {
    "paused_retention_seconds": "paused_retention_seconds",
    "run_seconds": "max_run_seconds",
    "process_seconds": "max_process_seconds",
}
AT_END: Final = ("destroyed", "paused")
#: Resources asked per direction ({read: N, write: N}), and the declared fact each fits.
PER_OPERATION_RESOURCES: Final = {"file_stream_bytes": "file_stream_max_bytes"}

REQUEST_KEYS: Final = frozenset(
    {"lifetime_seconds", "at_end", "requirements", "resources", "image", "restores_need"}
)
#: Resources a request gives as whole numbers.
WHOLE_NUMBERS: Final = frozenset(
    {"memory_min_mib", "disk_min_mib", "gpu_count", "run_seconds", "process_seconds"}
)
#: What a `restores_need` may carry.
RESTORE_KEYS: Final = frozenset({"requirements", "resources", "lifetime_seconds"})

DECLARATION_KEYS: Final = frozenset(
    {
        "spec",
        "provider",
        "class",
        "verified",
        "resources",
        "lifetime_timer",
        "evidence",
        "gates",
    }
)
DECLARATION_RESOURCES: Final = frozenset(
    {
        "kernel",
        "kernel_features",
        "long_running",
        "size_is_ceiling",
        "max_lifetime_seconds",
        "sizes",
        "default_size",
        "disk_mib",
        "on_memory_exhausted",
        "regions",
        "located_in",
        "gpus",
        "max_gpus",
        "extendable_lifetime",
        "default_user",
        "default_cwd",
        "paused_retention_seconds",
        "root",
        "arch",
        "package_manager",
        "libc",
        "max_run_seconds",
        "max_process_seconds",
        "disk_in_memory",
        "egress_ips",
        "outbound_traffic",
        "outbound_ip_families",
        "guest_reserved_tcp_ports",
        "files_write_executable_effect",
        "file_stream_max_bytes",
        "ipv4_destination_reach",
        "needs",
        "unmet_limits",
    }
)
SIZE_KEYS: Final = frozenset({"cpu", "memory_mib", "disk_mib"})
SPEC_VERSION: Final = "sandbox-provider-spec/0.1"

#: The order failed checks are reported in (the API reference, "Exclusion reasons").
STAGES: Final = (
    "declaration",
    "baseline",
    "gate",
    "extra",
    "conflict",
    "resource",
    "restore",
)


def must_be_named(gate: str) -> str | None:
    for knob, definition in GATES[gate].knobs.items():
        if definition.must_be_named:
            return knob
    return None
