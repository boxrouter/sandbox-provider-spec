# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The one narrowing rule (`provider-api/discovery-within-static`): an account's discovery is
`within` the provider's static discovery when it offers the same classes or fewer, each with equal
or narrower values. The tester, Cloud's facts module and the declaration generator all use it."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from sandbox_provider_spec.v1.types import Discovery
from sandbox_provider_spec.v1.wire import to_json

# Numbers narrow downward (a smaller limit, fewer sizes), except these, where a larger number is the
# narrower promise: a provider that takes longer to settle a cost, a larger minimum lifetime.
_LARGER_IS_NARROWER = frozenset({"cost_final_within_seconds", "min_seconds"})
# A class lists its unavailable regions; naming more of them narrows what it offers.
_FREE_KEYS = frozenset({"unavailable_regions"})
# What a create gets when it names nothing can differ per account (a different plan, a different
# home region), so it is not compared with the static value: each is judged against its own
# discovery's offering instead (`_defaults`).
_DEFAULTS = frozenset({"default_region", "default_size", "default_user", "default_cwd"})


def within(discovery: Discovery, ceiling: Discovery) -> list[str]:
    """The paths at which `discovery` steps outside `ceiling`, one per line, empty when it is
    within: `classes.<id>.resources.regions: +eu-west` for a value the ceiling does not have,
    `limits.file_bytes: 2 (ceiling 1)` for a number past it."""
    live = to_json(discovery)
    top = to_json(ceiling)
    assert isinstance(live, Mapping) and isinstance(top, Mapping)
    found: list[str] = []
    if live["provider"] != top["provider"]:
        found.append("provider: changed")
    _mapping("limits", live["limits"], top["limits"], found)
    ceiling_classes = {item["id"]: item for item in top["classes"]}
    for item in live["classes"]:
        path = f"classes.{item['id']}"
        match = ceiling_classes.get(item["id"])
        if match is None:
            found.append(f"{path}: +class")
        else:
            _mapping(path, item, match, found)
        _defaults(f"{path}.resources", item.get("resources"), found)
    return found


def _defaults(path: str, resources: object, found: list[str]) -> None:
    """The defaults a class states must be ones it offers: `default_region` one of its `regions`
    and `default_size` one of its `sizes`, in the same discovery, never compared with the static
    discovery's default. `default_user` and `default_cwd` have no list to be one of."""
    if not isinstance(resources, Mapping):
        return
    region, regions = resources.get("default_region"), resources.get("regions")
    if isinstance(region, str) and isinstance(regions, Sequence) and region not in regions:
        found.append(f"{path}.default_region: {region!r} is not one of its regions")
    size, sizes = resources.get("default_size"), resources.get("sizes")
    if isinstance(size, Mapping) and isinstance(sizes, Sequence) and not isinstance(sizes, str):
        if not any(isinstance(entry, Mapping) and _covers(entry, size) for entry in sizes):
            found.append(f"{path}.default_size: {dict(size)!r} is not one of its sizes")


def _covers(entry: Mapping[str, object], size: Mapping[str, object]) -> bool:
    """Whether a listed size (a number or a `[low, high]` range per field) holds the default."""
    for name, wanted in size.items():
        have = entry.get(name)
        if isinstance(have, Sequence) and not isinstance(have, str) and len(have) == 2:
            if not (isinstance(wanted, (int, float)) and have[0] <= wanted <= have[1]):
                return False
        elif have != wanted:
            return False
    return True


def _mapping(path: str, live: object, ceiling: object, found: list[str]) -> None:
    if not isinstance(live, Mapping) or not isinstance(ceiling, Mapping):
        found.append(f"{path}: {live!r} (ceiling {ceiling!r})")
        return
    for key, value in live.items():
        if key in _FREE_KEYS or key in _DEFAULTS or value is None:
            continue
        where = f"{path}.{key}"
        if key not in ceiling or ceiling[key] is None:
            found.append(f"{path}: +{key}")
        else:
            _value(where, key, value, ceiling[key], found)


def _value(path: str, key: str, live: object, ceiling: object, found: list[str]) -> None:
    if isinstance(live, Mapping):
        _mapping(path, live, ceiling, found)
    elif isinstance(live, Sequence) and not isinstance(live, str):
        _sequence(path, live, ceiling, found)
    elif live is True and ceiling is False and key == "ready":
        found.append(f"{path}: +ready")
    elif isinstance(live, bool) or not isinstance(live, (int, float)):
        if live != ceiling and not (key == "ready" and live is False):
            found.append(f"{path}: {live!r} (ceiling {ceiling!r})")
    elif not isinstance(ceiling, (int, float)) or isinstance(ceiling, bool):
        found.append(f"{path}: {live!r} (ceiling {ceiling!r})")
    elif (live < ceiling) if key in _LARGER_IS_NARROWER else (live > ceiling):
        found.append(f"{path}: {live!r} (ceiling {ceiling!r})")


def _sequence(path: str, live: Sequence[object], ceiling: object, found: list[str]) -> None:
    if not isinstance(ceiling, Sequence) or isinstance(ceiling, str):
        found.append(f"{path}: {list(live)!r} (ceiling {ceiling!r})")
        return
    for entry in live:
        if isinstance(entry, Mapping):
            if not any(
                isinstance(other, Mapping) and not _outside(entry, other) for other in ceiling
            ):
                found.append(f"{path}: +{_name(entry)}")
        elif entry not in ceiling:
            found.append(f"{path}: +{entry}")


def _outside(live: Mapping[str, object], ceiling: Mapping[str, object]) -> list[str]:
    found: list[str] = []
    _mapping("", live, ceiling, found)
    return found


def _name(entry: Mapping[str, object]) -> str:
    """A short name for a list element that is a mapping: its `id`, `item` or the whole body."""
    for key in ("id", "item"):
        if key in entry:
            return f"{entry[key]}"
    return repr(dict(entry))
