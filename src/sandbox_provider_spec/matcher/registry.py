# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The shared words for places and GPUs, passed in, never read from disk.

Region and GPU registries are versioned data. A caller loads the copies it has pinned and
hands them over; the matcher owns no copy of either list.
"""

from __future__ import annotations

from typing import Any

from sandbox_provider_spec.matcher.catalog import Document


class Registry:
    """Region identifiers, areas and GPU model names, as the registries publish them."""

    def __init__(
        self,
        *,
        areas: dict[str, frozenset[str]] | None = None,
        regions: dict[str, frozenset[str] | None] | None = None,
        countries: frozenset[str] | None = None,
        gpu_models: frozenset[str] = frozenset(),
    ) -> None:
        self.areas = areas or {}
        self.regions = regions or {}
        self.gpu_models = gpu_models
        self.countries = countries or frozenset(
            country
            for country_set in [*self.areas.values(), *self.regions.values()]
            if country_set is not None
            for country in country_set
        )

    @classmethod
    def from_documents(cls, regions: Document, gpu_models: Document) -> Registry:
        """From `regions.json` and `gpu-models.json` as their registries publish them."""

        def countries(entry: Any) -> frozenset[str] | None:
            listed = entry.get("countries")
            return None if listed is None else frozenset(listed)

        return cls(
            areas={
                name: frozenset(entry["countries"])
                for name, entry in regions.get("areas", {}).items()
                if entry.get("countries") is not None
            },
            regions={name: countries(entry) for name, entry in regions.get("regions", {}).items()},
            countries=frozenset(regions.get("countries", [])),
            gpu_models=frozenset(gpu_models.get("gpu_models", {})),
        )

    def knows_region(self, word: str) -> bool:
        return word in self.regions

    def knows_place(self, word: str) -> bool:
        """A region identifier, an area or a country: the three things `region` may name."""
        return word in self.regions or word in self.areas or word in self.countries

    def within(self, word: str) -> frozenset[str] | None:
        """The countries `word` allows, or None when the registry does not say where it places."""
        if word in self.areas:
            return self.areas[word]
        if word in self.regions:
            return self.regions[word]
        return frozenset({word}) if word in self.countries else None
