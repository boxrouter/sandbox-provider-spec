# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""python -m sandbox_provider_spec <command> ..."""

from __future__ import annotations

import sys

from sandbox_provider_spec.cli import main

sys.exit(main())
