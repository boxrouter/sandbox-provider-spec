# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""How large an environment (`Env` in the Provider API) may be."""

ENVIRONMENT_MAX_BYTES = 65536
"""The most UTF-8 bytes an environment's names and values take together."""


def environment_bytes(name: str, value: str) -> int:
    """The UTF-8 bytes one variable counts toward `ENVIRONMENT_MAX_BYTES`: its name and its value.

    Raises `UnicodeEncodeError` for text that has no UTF-8 form, such as a lone surrogate.
    """
    return len(name.encode("utf-8")) + len(value.encode("utf-8"))
