# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Compatibility import for the installed SPS HTTP reference endpoint."""

from sandbox_provider_spec.http_reference.endpoint import Backend, Endpoint, Failure, Output

__all__ = ["Backend", "Endpoint", "Failure", "Output"]
