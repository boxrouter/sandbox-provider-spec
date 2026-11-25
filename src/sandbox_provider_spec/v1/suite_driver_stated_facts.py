# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The 1.0 driver with the `create.stated_facts` step.

A router asks a class's facts in the create itself, for example `extendable_lifetime` of every
create whose lifetime it renews. The other rows ask only the floors and the facts their own claim
needs, so a provider could pass every row and still refuse every routed create. This step creates
once with every yes-or-no resource fact that the class states `true` (the request schema's
boolean `resources`), and a refusal of one of them fails the row.

The step is a subclass of its own, as `cost.batch` is: only the `contract.create_meets_stated_facts`
row digests this module.
"""

from __future__ import annotations

from collections.abc import Mapping

from sandbox_provider_spec.driver import Inputs, NativeFailure, NotRun, Observation, Unsupported
from sandbox_provider_spec.v1._spec_files import document
from sandbox_provider_spec.v1.suite_driver_cost_batch import BatchProviderDriver

#: Why the step does not run for a class that states none of the facts (the tester does not
#: count it).
NO_STATED_FACT = "the class states no yes-or-no resource fact"


def stated_asks(resources: Mapping[str, object]) -> dict[str, bool]:
    """The asks of a create that a class meets by its own statement: each boolean `resources` key
    of the request schema that the class's `resources` states `true`."""
    schema = document("request-schema.json")["$defs"]["resources"]["properties"]
    return {
        key: True
        for key, field in schema.items()
        if field.get("type") == "boolean" and resources.get(key) is True
    }


class StatedFactsDriver(BatchProviderDriver):
    """The tester's driver plus the `create.stated_facts` step."""

    #: The `resources` that discovery states for the class a test runs on (set by the tester), or
    #: None when discovery was not read.
    class_resources: Mapping[str, object] | None = None

    def create_stated_facts(self, target: object, inputs: Inputs) -> Observation:
        """Create with every yes-or-no fact the class states. A refusal as `unsupported` is the
        failure `stated_fact_refused`: the class stated that it meets the ask."""
        del target, inputs
        if self.class_resources is None:
            raise NotRun("discovery_not_read")
        asks = stated_asks(self.class_resources)
        if not asks:
            raise NotRun(NO_STATED_FACT)
        try:
            return self.create(None, {"resources": asks})
        except Unsupported:
            raise NativeFailure("stated_fact_refused") from None
