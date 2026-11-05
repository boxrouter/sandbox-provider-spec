# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Probe listed reserved ports without requiring unrelated simultaneous-port limits."""

from __future__ import annotations

import json
import shlex
import subprocess
import sys
from collections.abc import Mapping

from sandbox_provider_spec.coverage_probe import server
from sandbox_provider_spec.driver import Driver, NativeFailure, NotRun, Unsupported
from sandbox_provider_spec.suite import suite_path


def observe(driver: Driver, inputs: Mapping[str, object]) -> Mapping[str, object]:
    reserved, common = inputs["reserved"], inputs["common"]
    if not isinstance(reserved, list) or not isinstance(common, list):
        raise ValueError("port fixtures must be lists")
    if any(
        not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535
        for port in [*reserved, *common]
    ):
        raise ValueError("invalid probe port")
    if (
        len(reserved) > 64
        or len(common) > 64
        or not common
        or len(set(reserved)) != len(reserved)
        or len(set(common)) != len(common)
    ):
        raise ValueError("invalid port fixture set")
    common = [port for port in common if port not in reserved]
    if not common:
        raise NotRun("reserved_port_common_control_missing")
    refused, served = [], []
    for port in dict.fromkeys([*common, *reserved]):
        try:
            box = driver.call(
                "create",
                None,
                {
                    "requirements": {"previews": {"access": "public", "ports": [port]}},
                    "lifetime_seconds": 300,
                },
            )
        except Unsupported:
            if port in common:
                raise
            refused.append(True)
            continue
        code = (
            "import socket,json,errno; sock=socket.socket(); "
            f"port={port}\n"
            "try:\n sock.bind(('0.0.0.0',port)); print(json.dumps({'available':True}))\n"
            "except OSError as error:\n"
            " if error.errno not in {errno.EADDRINUSE,errno.EACCES}: raise\n"
            " print(json.dumps({'available':False}))\n"
            "finally: sock.close()"
        )
        result = driver.call("run", box, {"bash_script": "python3 -c " + shlex.quote(code)})
        if result.get("exit_code") != 0:
            raise NativeFailure("port_bind_probe_failed")
        payload = result.get("stdout")
        if not isinstance(payload, (bytes, str)):
            raise NativeFailure("port_bind_probe_invalid")
        available = json.loads(payload).get("available")
        if not isinstance(available, bool):
            raise NativeFailure("port_bind_probe_invalid")
        reached = False
        if available:
            server(driver, box, {"protocol": "http", "ports": [port]})
            try:
                link = driver.call("preview.link", box, {"port": port, "access": "public"})
                reached = preview(link)
            except Unsupported:
                if port in common:
                    raise
                reached = False
        if port in reserved:
            refused.append(not reached)
        if port in common:
            served.append(reached)
    return {"reserved_refused": all(refused), "common_served": all(served)}


def preview(link: Mapping[str, object]) -> bool:
    """Include DNS in the deadline; unavailable transport proves no reservation."""
    try:
        result = subprocess.run(
            [sys.executable, "-I", str(suite_path().parent / "fixtures/external_observer.py")],
            input=json.dumps({"probe": "preview", "url": link["url"]}).encode(),
            capture_output=True,
            timeout=12,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise NotRun("reserved_port_forwarding_unobservable") from None
    if result.returncode != 0:
        raise NotRun("reserved_port_forwarding_unobservable")
    if len(result.stdout) > 1024:
        raise NativeFailure("port_preview_probe_invalid")
    payload = json.loads(result.stdout)
    if not isinstance(payload, dict) or not isinstance(payload.get("matched"), bool):
        raise NativeFailure("port_preview_probe_invalid")
    # A different program's response is not proof that forwarding was refused.
    if not payload["matched"]:
        raise NotRun("reserved_port_forwarding_unobservable")
    return True
