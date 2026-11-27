# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""How large one `argv` element of `run` and `process.start` is guaranteed to travel."""

ARGV_ELEMENT_QUOTED_BYTES = 32768
"""The most bytes that an `argv` element may take after POSIX shell quoting (`shlex.quote` in
Python) and still reach the program unchanged on every provider."""
