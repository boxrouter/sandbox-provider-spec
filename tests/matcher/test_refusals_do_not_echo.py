# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""A refusal of an unrecognised word never repeats the submitted word; it lists the allowed ones.

A caller may paste a credential into any field, so the message, `details`, fix and path carry the
field (or its parent object) and the words it accepts, not the value or the key (QA-255, QA-306).
"""

from typing import Any

import pytest

from sandbox_provider_spec.matcher.registry import Registry
from sandbox_provider_spec.matcher.request import Rejected, validate_request

SENTINEL = "sk-sentinel-4f9a"

BODIES: dict[str, dict[str, Any]] = {
    "knob value": {"requirements": {"tcp_ports": {"tls": [SENTINEL]}}},
    "knob or setting": {"requirements": {"tcp_ports": {SENTINEL: 1}}},
    "switches_to policy": {
        "requirements": {
            "network_lockdown": {
                "policy": "allowlist",
                "allow": ["pypi.org"],
                "switchable": True,
                "switches_to": [SENTINEL],
            }
        }
    },
    "resource value": {"resources": {"arch": [SENTINEL]}},
    "file direction": {"resources": {"file_stream_bytes": {SENTINEL: 5}}},
    "request key": {SENTINEL: 1},
    "at_end": {"at_end": SENTINEL},
    "gate": {"requirements": {SENTINEL: {}}},
    "resource key": {"resources": {SENTINEL: 1}},
}


@pytest.mark.parametrize("site", list(BODIES))
def test_the_refusal_lists_the_allowed_words_and_not_the_submitted_one(site: str) -> None:
    with pytest.raises(Rejected) as caught:
        validate_request(BODIES[site], registry=Registry())
    refusal = caught.value
    assert refusal.code == "unrecognised_word"
    assert SENTINEL not in refusal.message
    assert SENTINEL not in repr(refusal.details)
    assert SENTINEL not in str(refusal.fix)
    assert SENTINEL not in str(refusal.path)
    assert refusal.details["known"]
