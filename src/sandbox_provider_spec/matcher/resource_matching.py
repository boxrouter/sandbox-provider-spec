# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Matching list-valued resources whose request requires every listed value."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Literal

from sandbox_provider_spec.matcher.catalog import (
    ALL_OF_RESOURCES,
    PER_OPERATION_RESOURCES,
    UNKNOWN,
    Document,
)
from sandbox_provider_spec.matcher.declaration import number, offers


def fit_all_of_resources(
    asked: Document,
    resources: Document,
    fail: Callable[..., tuple[str, Any]],
) -> tuple[Document, list[tuple[str, Any]]]:
    """Return the all-of resources established by a declaration and any failures."""
    provisioned: Document = {}
    failed: list[tuple[str, Any]] = []
    for fact, known in ALL_OF_RESOURCES.items():
        if fact not in asked:
            continue
        declared = resources.get(fact)
        offered = (
            [value for value in declared if value in known] if isinstance(declared, list) else []
        )
        request_values = asked[fact]
        if all(value in offered for value in request_values):
            provisioned[fact] = list(request_values)
        else:
            failure: Literal["resource_mismatch", "resource_unknown"] = (
                "resource_mismatch" if isinstance(declared, list) else "resource_unknown"
            )
            failed.append(
                fail(
                    "resource",
                    failure,
                    f"{fact}: asked {request_values}, declared {resources.get(fact, UNKNOWN)}",
                    resource=fact,
                    asked=request_values,
                    offered=resources.get(fact, UNKNOWN),
                )
            )
    return provisioned, failed


def fit_per_operation_resources(
    asked: Document,
    resources: Document,
    fail: Callable[..., tuple[str, Any]],
) -> list[tuple[str, Any]]:
    """Each direction a request names must be offered by the declared fact for it."""
    failed: list[tuple[str, Any]] = []
    for ask, fact in PER_OPERATION_RESOURCES.items():
        if ask not in asked:
            continue
        declared = resources.get(fact)
        directions = declared if isinstance(declared, dict) else {}
        for operation, amount in asked[ask].items():
            raw = directions.get(operation, UNKNOWN)
            value = number(raw)
            if offers(value, amount):
                continue
            unknown = value is None or value[0] == "at_least"
            failed.append(
                fail(
                    "resource",
                    "resource_unknown" if unknown else "resource_mismatch",
                    f"{ask}.{operation}: asked {amount}, {fact}.{operation} declared {raw}",
                    resource=f"{ask}.{operation}",
                    asked=amount,
                    offered=raw,
                )
            )
    return failed
