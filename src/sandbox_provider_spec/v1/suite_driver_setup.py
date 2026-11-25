# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""A row's `create` that the provider cannot serve right now (cloud#10041).

`unavailable` is "you cannot be served now, and the same call will work later"
(`docs/implement.md`). A row's `create` step that is answered so has not shown anything about the
row's check, so it is asked again, waiting what `retry_after_seconds` says (1 to 30 s), for up
to 180 s in all, under the SAME idempotency key: the first answer's `outcome` may be `unknown` and
the first call may have made a sandbox, which the repeat then finds instead of making another. A
create still refused when the budget ends is `not_run: provider_unavailable`, with the code,
outcome and retry hint in the step's `detail`; it is never an `error`, which would replace a
passing row with a verdict on nothing.

This is a subclass in its own module, installed by the tester, not an edit of `suite_driver.py`,
`driver.py` or `runner.py`: those are what the rows' check digests hash, so a change there stales
the rows of every provider's reports. This module is in no row's dependencies (cloud#9877).
"""

from __future__ import annotations

import sys
import time
from collections.abc import Callable

from sandbox_provider_spec.driver import (
    RATE_LIMIT_BUDGET_SECONDS,
    Inputs,
    NativeFailure,
    NotRun,
    Observation,
    Unsupported,
    rate_limit_pause,
)
from sandbox_provider_spec.v1 import suite_driver_cleanup
from sandbox_provider_spec.v1.suite_driver import ProviderDriver

NOT_RUN_REASON = "provider_unavailable"


def unavailable_detail(error: NativeFailure) -> str:
    """The code, outcome and retry hint of a refusal, never a provider message or an id: reports
    are committed and mirrored."""
    parts = [f"code={error.code}", f"outcome={getattr(error, 'outcome', 'unknown')}"]
    if error.retry_after_seconds is not None:
        parts.append(f"retry_after_seconds={error.retry_after_seconds}")
    return " ".join(parts)


class SetupRetryDriver(ProviderDriver):
    """The tester's driver: a `create` step answered `unavailable` is asked again, then not run."""

    #: How long one `create` step is asked again, in all. Tests set it (and `sleep` and `clock`)
    #: so that no test waits real time.
    setup_budget_seconds: float = RATE_LIMIT_BUDGET_SECONDS
    sleep: Callable[[float], None] = staticmethod(time.sleep)
    clock: Callable[[], float] = staticmethod(time.monotonic)
    _pinned_key: str | None = None
    #: Why discovery does not claim `image.prepare`, or None when it does (set by the tester).
    prepare_unclaimed: str | None = None

    def _key(self, inputs: Inputs) -> str:
        """The key of the create being retried, so every ask of it is the same request."""
        return self._pinned_key if self._pinned_key is not None else super()._key(inputs)

    def create(self, target: object, inputs: Inputs) -> Observation:
        pinned = self._pinned_key
        self._pinned_key = super()._key(inputs)
        ends = self.clock() + self.setup_budget_seconds
        try:
            while True:
                try:
                    return super().create(target, inputs)
                except NativeFailure as error:
                    if error.code != "unavailable":
                        raise
                    pause = rate_limit_pause(error)
                    if self.clock() + pause > ends:
                        detail = unavailable_detail(error)
                        print(f"setup create not run: {detail}", file=sys.stderr, flush=True)
                        raise NotRun(NOT_RUN_REASON, detail=detail) from None
                    self.sleep(pause)
        finally:
            self._pinned_key = pinned

    def image_prepare(self, target: object, inputs: Inputs) -> Observation:
        """The prepare of a `provider_artifact` borrows an image that the account already has and
        calls no provider operation, so it runs where discovery does not claim `image.prepare`:
        a class that creates from its own artifacts but prepares no image runs
        `custom_images.provider_artifact`. Every other source is unsupported there."""
        if self.prepare_unclaimed is not None and inputs.get("source") != "provider_artifact":
            raise Unsupported(self.prepare_unclaimed)
        return super().image_prepare(target, inputs)

    def _delete_snapshot(self, snapshot_id: str) -> Observation:
        """A snapshot delete that the provider answers `unavailable` is asked again (cloud#10080).

        A provider that is still capturing a snapshot does not delete it (one may undo a delete
        by finishing the capture as a new snapshot): it answers `unavailable` with a wait, and
        the same call works once the capture ends. The cleanup asks again under its shared
        budget, so a slow capture no longer reads as a snapshot that cannot be deleted."""
        delete = super()._delete_snapshot
        return suite_driver_cleanup.ask_until_free(
            lambda: delete(snapshot_id), self._cleanup_budget
        )
