# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The lifetime a create asks for when it names none."""

DEFAULT_LIFETIME_SECONDS = 300
"""Seconds a create that names no `lifetime_seconds` asks for on a provider with a lifetime timer.

Every native driver sends it, and an adapter whose create has a default lifetime reads it, so a
conformance create that names no lifetime sends the same request whichever driver runs it.
`check_digests.historical_check_digest` relies on that.
"""
