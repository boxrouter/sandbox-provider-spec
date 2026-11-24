# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The 1.0 driver with the `cost.batch` step.

The step is a subclass of its own, not a method of `ProviderDriver`: the checks of the rows that use
the steps of `v1/suite_driver.py` digest that file, so an edit of it moves all of them. Only the
`cost.batch` row digests this module.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import cast

from sandbox_provider_spec import cost_batch_checks
from sandbox_provider_spec.driver import Inputs, Observation
from sandbox_provider_spec.v1.suite_driver_setup import SetupRetryDriver


class BatchProviderDriver(SetupRetryDriver):
    """The tester's driver (`SetupRetryDriver`) plus the steps added after it was written."""

    def cost_batch(self, target: object, inputs: Inputs) -> Observation:
        """Read the costs of the target and the sandboxes in `with` in one call, and each alone."""
        others = cast(Sequence[object], inputs.get("with", []))
        ids = [self._sandbox(target), *(self._sandbox(other) for other in others)]
        return cost_batch_checks.batch(self, ids, inputs)
