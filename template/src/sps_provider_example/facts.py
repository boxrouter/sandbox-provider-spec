# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""What Example Cloud offers: the facts behind discovery. No Example Cloud call returns them."""

from __future__ import annotations

from decimal import Decimal

from sandbox_provider_spec.v1 import (
    Discovery,
    Image,
    Limits,
    Price,
    ProviderInfo,
    SandboxClass,
    Size,
)

META_PATH = "/etc/sps-sandbox.json"  # the create-time facts, inside the machine
CLASS = "default"
REGION = "local"
IMAGE = "base"
SIZES = (Size(cpu=1, memory_mib=512), Size(cpu=2, memory_mib=2048))
DEFAULT_SIZE = SIZES[0]
HOURS_PER_MONTH = 730  # the standard's month
MAX_LIFETIME_S = 86400
MAX_RUN_S = 3600  # Example Cloud's exec timeout ceiling
MAX_WAIT_S = 60  # its job-log long-poll ceiling
LIST_LIMIT = 1000
COST_FINAL_WITHIN_S = 60  # Example Cloud's usage record closes when the machine ends
# Tags are readable only as list filters: enough to find a replayed key or filter by label.
TAG_IDEM, TAG_BODY, TAG_LABEL = "sps.idem", "sps.body", "l."  # label "k" is tag "l.k"
TAG_LABELS = "sps.labels"  # an image's labels as JSON: image tags cannot hold every label key
SNAPSHOTS = {"keeps": "files_only", "original_after": "continues", "deletable": True}
LIMITS = Limits(
    file_bytes=5368709120,
    run_timeout_ms=MAX_RUN_S * 1000,
    output_bytes=16777216,
    wait_ms=MAX_WAIT_S * 1000,
    process_output_bytes=4194304,
    process_retention_seconds=600,
    list_limit=LIST_LIMIT,
    cost_final_within_seconds=COST_FINAL_WITHIN_S,
)


def build_discovery(provider_id: str, provider_name: str) -> Discovery:
    klass = SandboxClass(
        id=CLASS,
        name="Linux container",
        ready=True,
        resources={
            "regions": [REGION],
            "located_in": "unknown",
            "sizes": [{"cpu": s.cpu, "memory_mib": s.memory_mib} for s in SIZES],
            "default_size": {"cpu": DEFAULT_SIZE.cpu, "memory_mib": DEFAULT_SIZE.memory_mib},
            "disk_mib": "unknown",
            "arch": "unknown",
            "max_lifetime_seconds": MAX_LIFETIME_S,
            "default_cwd": "/",
            "default_user": "root",
            "root": ["by_default"],
            "outbound_traffic": ["any_tcp", "udp"],
        },
        lifetime_timer={
            "enforced_by": "provider",
            "at_end": ["destroyed"],
            "counts_paused_time": False,
        },
        operations=("files.list", "files.mkdir", "files.remove", "files.exists"),
        images=(Image(IMAGE, True, "Debian slim with bash and python3"),),
        prices=(
            # Published list prices, as data. The adapter never multiplies them: `cost` reports
            # usage and the router prices it.
            Price("cpu", Decimal("0.000014"), "vcpu_second", "allocated"),
            Price("memory", Decimal("0.0000045"), "gib_second", "allocated"),
            Price("snapshot", Decimal("0.05"), "gib_month", "used"),
        ),
        # A snapshot is `docker commit` of the machine's container without pausing it, so the
        # machine keeps running (`continues`); Example Cloud can delete its images.
        gates={"snapshots": [SNAPSHOTS], "terminal": [{"reattach": False}]},
    )
    return Discovery(
        spec_version="1.0",
        provider=ProviderInfo(provider_id, provider_name, "https://docs.example.test"),
        limits=LIMITS,
        classes=(klass,),
    )
