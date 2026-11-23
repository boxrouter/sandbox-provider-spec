# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""`Provider.image_recipe_revision`: empty by default, so a provider that does not state it behaves
as before, and a caller reads it from the class without an instance."""

from __future__ import annotations

import inspect

from sandbox_provider_spec.v1 import Provider


def test_a_provider_that_adds_nothing_to_an_image_states_no_revision() -> None:
    assert Provider.image_recipe_revision() == ""


def test_it_is_read_from_the_class_without_an_instance() -> None:
    assert isinstance(inspect.getattr_static(Provider, "image_recipe_revision"), classmethod)
