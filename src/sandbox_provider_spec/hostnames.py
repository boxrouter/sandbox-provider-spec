# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Request hostname and HTTP-rule syntax shared by the checker and matcher."""

import re
from typing import Any

HOSTNAME = re.compile(
    r"(?=.{1,253}(?![\s\S]))"
    r"(?![0-9.]+(?![\s\S]))"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*(?![\s\S])"
)


def http_rule_malformed(rule: dict[str, Any]) -> bool:
    """Whether a structured allow entry has malformed host, method or path fields."""
    if set(rule) - {"host", "methods", "paths"} or "host" not in rule:
        return True
    host = rule["host"]
    if not isinstance(host, str) or not host:
        return True
    name = host[2:] if host.startswith("*.") else host
    if not HOSTNAME.fullmatch(name) or name.replace(".", "").isdigit():
        return True
    for key in ("methods", "paths"):
        if key not in rule:
            continue
        values = rule[key]
        if not isinstance(values, list) or not values:
            return True
        if any(not isinstance(value, str) for value in values):
            return True
        if len(values) != len(set(values)):
            return True
        if key == "methods" and any(re.fullmatch(r"[A-Z]+", value) is None for value in values):
            return True
        if key == "paths" and any(not value.startswith("/") for value in values):
            return True
    return False
