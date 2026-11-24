# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The `cost.batch` check of the 1.0 driver (contract section 10).

A module of its own, so that the checks of every other row keep their digests: the rows that use
`cost.final` and the other steps of `v1/suite_driver.py` digest `cost_checks.py` and that file, and
an edit of either moves every one of them. This one is digested by the `cost.batch` row alone.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Sequence
from typing import TYPE_CHECKING

from sandbox_provider_spec.cost_checks import _read_final, _wait_out_rate_limit, same_figures
from sandbox_provider_spec.driver import Inputs, NativeFailure, Observation, Unsupported
from sandbox_provider_spec.v1.types import Cost

if TYPE_CHECKING:
    from sandbox_provider_spec.v1.suite_driver import ProviderDriver


def _read_batch(driver: ProviderDriver, ids: Sequence[str]) -> Sequence[Cost]:
    """One `cost.batch` call, waiting out a rate limit within the same budget as a cost read."""
    started = time.monotonic()
    while True:
        try:
            return driver.wait(driver.api.cost_batch(list(ids))).costs
        except NativeFailure as error:
            if not _wait_out_rate_limit(error, started):
                raise


def batch(driver: ProviderDriver, sandbox_ids: Sequence[str], inputs: Inputs) -> Observation:
    """The costs of destroyed sandboxes read in one call are what each states alone (rule
    `provider-api/cost-batch-same`), the call holds each sandbox it finds and none that was not
    asked for, and a sandbox it does not hold is absent, not a zero cost (`cost-batch-complete`).
    Each sandbox is read alone until it is final first, so the figures cannot move between the
    reads. Sandboxes beyond `limits.cost_batch_max` are left out of the call."""
    limit = driver.wait(driver.api.discovery()).limits.cost_batch_max
    if limit is None:
        raise Unsupported("the provider does not state cost_batch_max")
    ids = list(sandbox_ids)[:limit]
    alone = {sandbox_id: _read_final(driver, sandbox_id, inputs)[0] for sandbox_id in ids}
    answered = list(_read_batch(driver, ids))
    by_id = {cost.sandbox_id: cost for cost in answered}
    unknown = f"sps-test-unknown-{uuid.uuid4().hex}"
    # A call at the limit has no room for a sandbox the provider does not hold.
    room = len(ids) < limit
    with_unknown = list(_read_batch(driver, [*ids, unknown])) if room else answered
    return {
        "same_sandboxes": len(answered) == len(by_id) and set(by_id) == set(ids),
        "same_costs": all(
            sandbox_id in by_id
            and by_id[sandbox_id].source == cost.source
            and same_figures(cost, by_id[sandbox_id])
            for sandbox_id, cost in alone.items()
        ),
        "none_unasked": all(cost.sandbox_id in {*ids, unknown} for cost in with_unknown),
        "unknown_absent": all(cost.sandbox_id != unknown for cost in with_unknown),
    }
