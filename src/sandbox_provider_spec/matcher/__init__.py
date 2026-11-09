# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Reference matcher for provider declarations, requests and baseline run reports."""

from sandbox_provider_spec.matcher.catalog import GATES, RESOURCE_ASKS
from sandbox_provider_spec.matcher.conditions import KnobGrant
from sandbox_provider_spec.matcher.coverage import coverage, setting_backers
from sandbox_provider_spec.matcher.declaration import (
    Declaration,
    GateDeclaration,
    Variant,
    build_declaration,
)
from sandbox_provider_spec.matcher.matcher import (
    Declared,
    DeclaredFitResult,
    DeclaredProviderFit,
    MatchResult,
    Rejection,
    declared_fit,
    match,
    match_restore,
)
from sandbox_provider_spec.matcher.matching import (
    Failure,
    GateGrant,
    ProviderResult,
    Snapshot,
)
from sandbox_provider_spec.matcher.proof import Proof, Report
from sandbox_provider_spec.matcher.registry import Registry
from sandbox_provider_spec.matcher.request import GateAsk, Rejected, Request, validate_request

__all__ = [
    "GATES",
    "RESOURCE_ASKS",
    "ProviderResult",
    "Declaration",
    "Declared",
    "DeclaredFitResult",
    "DeclaredProviderFit",
    "Failure",
    "GateAsk",
    "GateDeclaration",
    "GateGrant",
    "KnobGrant",
    "MatchResult",
    "Proof",
    "Registry",
    "Rejected",
    "Rejection",
    "Report",
    "Request",
    "Snapshot",
    "Variant",
    "build_declaration",
    "coverage",
    "declared_fit",
    "match",
    "match_restore",
    "setting_backers",
    "validate_request",
]
