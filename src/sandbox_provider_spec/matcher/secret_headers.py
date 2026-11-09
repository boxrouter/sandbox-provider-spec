# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Validation for hidden-secret header templates in requests."""

from __future__ import annotations

import re
from typing import Any

from sandbox_provider_spec.matcher.secret_hosts import valid_secret_hostname

# Match the HTTP header token class, with hyphen as a literal final member.
HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")


def _has_forbidden_header_control(value: str) -> bool:
    """C0 controls other than HTAB, plus DEL and the C1 control range, are forbidden."""
    return any(
        (ord(character) < 32 and character != "\t") or 127 <= ord(character) <= 159
        for character in value
    )


def normalize_header_templates(raw: Any) -> tuple[list[dict[str, str]] | None, str | None]:
    """Validate selected secret headers and normalize omitted affixes to empty text."""
    if not isinstance(raw, list) or not raw:
        return None, "hidden_secrets.headers is a non-empty list of header templates"
    normalized: list[dict[str, str]] = []
    names: set[str] = set()
    for index, entry in enumerate(raw):
        path = f"requirements.hidden_secrets.headers[{index}]"
        if not isinstance(entry, dict):
            return None, f"{path} is an object"
        if set(entry) - {"name", "prefix", "suffix"}:
            return None, f"{path} has an unknown field"
        name = entry.get("name")
        if not isinstance(name, str) or HEADER_NAME.fullmatch(name) is None:
            return None, f"{path}.name is an HTTP token"
        folded = name.casefold()
        if folded in names:
            return None, "hidden_secrets.headers repeats a header name"
        names.add(folded)
        template: dict[str, str] = {"name": name}
        for part in ("prefix", "suffix"):
            value = entry.get(part, "")
            if not isinstance(value, str):
                return None, f"{path}.{part} is text"
            if _has_forbidden_header_control(value):
                return None, f"{path}.{part} contains a forbidden header character"
            template[part] = value
        normalized.append(template)
    return normalized, None


def exact_secret_hosts(hosts: Any) -> bool:
    """Selected header templates require exact DNS hostnames, without wildcards."""
    return (
        isinstance(hosts, list)
        and bool(hosts)
        and len({host.casefold() for host in hosts if isinstance(host, str)}) == len(hosts)
        and all(
            isinstance(host, str) and not host.startswith("*.") and valid_secret_hostname(host)
            for host in hosts
        )
    )
