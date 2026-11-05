# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Compatibility wrapper that builds the installed HTTP starter application eagerly.

Run with an existing WSGI server configured for ``starter:application`` after
setting the ``SPS_HTTP_*`` operator environment described by the installed factory,
``sandbox_provider_spec.http_reference.starter:create_application``. Importing this
module fails closed unless all values are configured.
"""

from __future__ import annotations

from sandbox_provider_spec.http_reference.starter import create_application

application = create_application()
