# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Build a WSGI endpoint around a provider's native Backend implementation.

Load ``create_application`` from an existing WSGI server that supports application
factories, after setting ``SPS_HTTP_BACKEND_FACTORY`` to ``module:factory``. The factory
returns the provider's native implementation of the ``Backend`` protocol. Importing
this module reads no configuration; calling ``create_application`` does. Operator-owned
state and credential configuration are required; this module does not start a listener
or supply defaults.
"""

from __future__ import annotations

import importlib
import os
from pathlib import Path
from typing import Any, cast

from sandbox_provider_spec.http_reference import Backend, Endpoint, EndpointSettings


def _factory(path: str) -> Any:
    module_name, separator, attribute = path.partition(":")
    if not separator or not module_name or not attribute:
        raise RuntimeError("SPS_HTTP_BACKEND_FACTORY must use module:factory syntax")
    return getattr(importlib.import_module(module_name), attribute)


def create_application() -> Endpoint:
    """Read required operator configuration and build the WSGI callable."""
    factory_path = os.environ.get("SPS_HTTP_BACKEND_FACTORY")
    state_path = os.environ.get("SPS_HTTP_STATE_PATH")
    endpoint_origin = os.environ.get("SPS_HTTP_ENDPOINT_ORIGIN")
    if not factory_path or not state_path or not endpoint_origin:
        raise RuntimeError(
            "Configure SPS_HTTP_BACKEND_FACTORY, SPS_HTTP_STATE_PATH, and SPS_HTTP_ENDPOINT_ORIGIN"
        )
    buffered_mode = os.environ.get("SPS_HTTP_BUFFERED_COMMANDS", "0")
    if buffered_mode not in ("0", "1"):
        raise RuntimeError("SPS_HTTP_BUFFERED_COMMANDS must be 0 or 1")
    binding_version = os.environ.get("SPS_HTTP_BINDING_VERSION")
    if binding_version not in (None, "0.1", "0.2", "0.3"):
        raise RuntimeError("SPS_HTTP_BINDING_VERSION must be 0.1, 0.2, or 0.3")
    if binding_version == "0.2" and buffered_mode != "1":
        raise RuntimeError("Binding 0.2 requires SPS_HTTP_BUFFERED_COMMANDS=1")
    if binding_version == "0.1" and buffered_mode == "1":
        raise RuntimeError("Binding 0.1 cannot enable SPS_HTTP_BUFFERED_COMMANDS")
    settings: dict[str, Any] = {}
    if buffered_mode == "1" or binding_version == "0.3":
        try:
            output_bytes = int(
                os.environ.get("SPS_HTTP_BUFFERED_COMMAND_OUTPUT_BYTES", str(16 * 1024 * 1024))
            )
            execution_default = "60000" if binding_version == "0.3" else "30000"
            execution_ms = int(os.environ.get("SPS_HTTP_EXECUTION_MS", execution_default))
            control_response_bytes = int(
                os.environ.get("SPS_HTTP_CONTROL_RESPONSE_BYTES", str(4 * 1024 * 1024))
            )
        except ValueError as error:
            raise RuntimeError("HTTP reference caps must be decimal integers") from error
        settings = {
            "buffered_commands": True,
            "buffered_command_output_bytes": output_bytes,
            "execution_ms": execution_ms,
        }
        if binding_version == "0.3":
            settings["control_response_cap"] = control_response_bytes
            # Discovery publishes this as limits.observation_ms; Core requires at least 60000.
            settings["operation_timeout_ms"] = 60000
    settings["binding_version"] = binding_version
    backend = cast(Backend, _factory(factory_path)())
    if binding_version == "0.3":
        missing = [
            name
            for name in ("offerings", "create_admitted", "observe_admitted", "run_buffered")
            if not callable(getattr(backend, name, None))
        ]
        if missing:
            raise RuntimeError(
                "Binding 0.3 requires AdmissionBackend methods "
                "(offerings, create_admitted, observe_admitted) and run_buffered; "
                f"missing: {', '.join(missing)}"
            )
    tokens_factory = os.environ.get("SPS_HTTP_ACCOUNT_TOKENS_FACTORY")
    if not tokens_factory:
        raise RuntimeError("Configure SPS_HTTP_ACCOUNT_TOKENS_FACTORY")
    account_tokens = cast(dict[str, str], _factory(tokens_factory)())
    if not account_tokens:
        raise RuntimeError("Operator credential mapping must not be empty")
    return Endpoint(
        backend,
        Path(state_path),
        account_tokens,
        settings=EndpointSettings(endpoint_origin, **settings),
    )
