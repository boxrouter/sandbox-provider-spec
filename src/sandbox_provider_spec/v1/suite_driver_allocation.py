# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The 1.0 driver with the `allocation.observe` step.

SPS 1.0 has no native allocation to read, and a provider's own record of a size can repeat what
the create asked, so the step measures the guest: the probe of `coverage.facts.sizes.delivered`
(`coverage_probe.guest`) gives the CPUs and the MiB of memory the guest sees, and a test compares
them exactly with the size it asked.

The step is a subclass of its own, not a method of `ProviderDriver`: the checks of the rows that use
the steps of `v1/suite_driver.py` digest that file, so an edit of it moves all of them. No row
digests this module (`allocation.observe` is a shared operation), so no committed report goes stale.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

from sandbox_provider_spec.coverage_probe import guest
from sandbox_provider_spec.driver import Inputs, NotRun, Observation
from sandbox_provider_spec.v1.provider import Provider
from sandbox_provider_spec.v1.suite_driver import SnapshotHandle
from sandbox_provider_spec.v1.suite_driver_stated_facts import StatedFactsDriver

SIZE_KEYS = ("cpu_min", "memory_min_mib", "disk_min_mib")
#: Why a request that names a disk, or lacks the CPU or the memory, is not observed.
CPU_AND_MEMORY_ONLY = "allocation_observed_for_cpu_and_memory_only"


class AllocationDriver(StatedFactsDriver):
    """The tester's driver plus the `allocation.observe` step."""

    def __init__(self, provider: Provider, **options: Any) -> None:
        super().__init__(provider, **options)
        self._asked: dict[str, Mapping[str, object]] = {}

    def _create(self, inputs: Inputs, *, snapshot: SnapshotHandle | None = None) -> Observation:
        """Create, and keep the `resources` the create asked beside the sandbox it made."""
        created = super()._create(inputs, snapshot=snapshot)
        self._asked[cast(str, created["identity"])] = cast(
            Mapping[str, object], inputs.get("resources", {})
        )
        return created

    def allocation_observe(self, target: object, inputs: Inputs) -> Observation:
        """The CPUs and MiB of memory the guest sees, named as the request that made it does."""
        del inputs
        asked = self._asked.get(self._sandbox(target), {})
        size = {key: asked[key] for key in SIZE_KEYS if key in asked}
        if set(size) != {"cpu_min", "memory_min_mib"}:
            raise NotRun(CPU_AND_MEMORY_ONLY)
        seen = guest(self, target, {"probe": "allocation", "size": size})
        return {
            "allocation": {
                "cpu_min": seen["observed_cpu"],
                "memory_min_mib": seen["observed_memory_mib"],
            }
        }
