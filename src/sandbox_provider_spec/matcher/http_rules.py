# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""HTTP rule syntax and request refusals shared by the checker and matcher."""

import re
from collections.abc import Iterator
from typing import Any

from sandbox_provider_spec.hostnames import http_rule_malformed as hostname_rule_malformed

HTTP_METHOD = re.compile(r"[!#$%&'*+.^_`|~0-9A-Z-]+")


def http_rule_malformed(rule: dict[str, Any]) -> bool:
    """Whether a structured network entry has malformed hosts, methods or paths."""
    if set(rule) - {"hosts", "methods", "paths"} or "hosts" not in rule:
        return True
    hosts = rule["hosts"]
    if (
        not isinstance(hosts, list)
        or not hosts
        or any(not isinstance(host, str) or not host for host in hosts)
    ):
        return True
    if len(hosts) != len(set(hosts)):
        return True
    fields = {key: value for key, value in rule.items() if key not in {"hosts", "methods"}}
    if any(hostname_rule_malformed({"host": host, **fields}) for host in hosts):
        return True
    if "methods" in rule:
        methods = rule["methods"]
        if not isinstance(methods, list) or not methods:
            return True
        if any(not isinstance(method, str) for method in methods):
            return True
        if len(methods) != len(set(methods)):
            return True
        if any(HTTP_METHOD.fullmatch(method) is None for method in methods):
            return True
    return False


def http_rule_problem(rule: dict[str, Any], listing: str, enabled: bool) -> str | None:
    """The request refusal for a structured network entry, if any."""
    methods = rule.get("methods")
    hosts = rule.get("hosts")
    wildcard = isinstance(hosts, list) and any(
        isinstance(host, str) and host.startswith("*.") for host in hosts
    )
    return next(
        (
            problem
            for condition, problem in (
                (not enabled, "without_knob"),
                (http_rule_malformed(rule), "malformed"),
                ("paths" in rule and "methods" not in rule, "paths_or_any"),
                (
                    isinstance(methods, list) and "ANY" in methods and len(methods) > 1,
                    "paths_or_any",
                ),
                (listing == "allow" and "methods" in rule and wildcard, "allow_wildcard"),
                (listing == "deny" and wildcard, "deny_wildcard"),
            )
            if condition
        ),
        None,
    )


def http_rule_problem_message(problem: str) -> str:
    """The request refusal text for a structured network entry problem."""
    return {
        "without_knob": "an HTTP rule unless http_rules is true",
        "paths_or_any": "paths without methods, or ANY with other methods",
        "allow_wildcard": "a wildcard host in an allow entry with methods",
        "deny_wildcard": "a wildcard in deny",
        "malformed": "an HTTP rule whose hosts, methods or paths are malformed",
    }.get(problem, "an HTTP rule whose hosts, methods or paths are malformed")


def network_entry_hosts(entries: Any) -> Iterator[str]:
    """Yield hosts from plain network entries and structured HTTP rules."""
    if isinstance(entries, list):
        for entry in entries:
            yield from network_entry_hosts(entry)
    elif isinstance(entries, dict):
        hosts = entries.get("hosts")
        if isinstance(hosts, list):
            yield from (host for host in hosts if isinstance(host, str))
    elif isinstance(entries, str):
        yield entries
