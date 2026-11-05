# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Isolated fixture operations for files.regular_write.usability.v1."""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping
from typing import Any

from sandbox_provider_spec.driver import Driver, NativeFailure, NotRun
from sandbox_provider_spec.runner import Runner
from sandbox_provider_spec.suite import suite_path

CASES = (
    "exact_bytes",
    "create_parents",
    "create_access",
    "overwrite_access",
    "authority",
    "executable_effect",
    "byte_bound",
    "outcome",
    "staging_cleanup",
)
EXECUTABLE_EFFECTS = ("preserved", "may_clear", "unverified")
BYTE_BOUND = 16 * 1024 * 1024
EXECUTABLE_WARNING = (
    "Writing a file does not guarantee it remains executable. Check or explicitly "
    "set executable permission before running it as a program."
)
_SCRIPT = "regular_write_usability.py"
_GUEST_PATH = "/tmp/sps-regular-write-usability.py"
_MAX_OUTPUT_BYTES = 8192


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write(
    driver: Driver,
    target: object,
    path: str,
    data: bytes,
    extra: Mapping[str, object] | None = None,
) -> Mapping[str, object]:
    payload: dict[str, object] = {"path": path, "data": _b64(data)}
    if extra:
        payload.update({key: value for key, value in extra.items() if key != "force_unknown"})
    if len(data) > BYTE_BOUND:
        raise NativeFailure("byte_bound")
    limit = extra.get("limit_bytes") if extra else None
    if isinstance(limit, int) and not isinstance(limit, bool) and len(data) > limit:
        raise NativeFailure("byte_bound")
    if extra and extra.get("force_unknown") is True:
        raise NativeFailure("outcome_unknown")
    result = driver.call("files.write", target, payload)
    count = result.get("written_bytes", len(data))
    if count != len(data):
        raise NativeFailure("written_bytes")
    return result


def _observe(driver: Driver, target: object, path: str) -> dict[str, Any]:
    script = (suite_path().parent / "fixtures" / _SCRIPT).read_bytes()
    driver.call("files.write", target, {"path": _GUEST_PATH, "data": _b64(script)})
    run = driver.call(
        "run",
        target,
        {
            "bash_script": "python3 " + _GUEST_PATH,
            "timeout_ms": 30000,
            "environment": {
                "SPS_REGULAR_WRITE_ARGUMENTS": json.dumps({"path": path}, separators=(",", ":"))
            },
        },
    )
    if run.get("exit_code") != 0:
        raise NativeFailure("regular_write_observe_failed")
    output = run.get("stdout")
    if not isinstance(output, (bytes, str)) or len(output) > _MAX_OUTPUT_BYTES:
        raise NativeFailure("regular_write_observe_invalid")
    try:
        value = json.loads(output)
    except (TypeError, json.JSONDecodeError) as error:
        raise NativeFailure("regular_write_observe_invalid") from error
    if not isinstance(value, dict):
        raise NativeFailure("regular_write_observe_invalid")
    return value


def _run(
    driver: Driver, target: object, script: str, *, as_root: bool = False
) -> Mapping[str, object]:
    if as_root:
        script = (
            'if [ "$(id -u)" = 0 ]; then '
            + script
            + "; else sudo -n true 2>/dev/null || exit 77; sudo -n /bin/sh -c "
            + json.dumps(script)
            + "; fi"
        )
    return driver.call("run", target, {"bash_script": script, "timeout_ms": 30000})


def _passed(case: str, **fields: object) -> dict[str, object]:
    diagnostic = json.dumps({"case": case, **fields}, sort_keys=True, separators=(",", ":"))
    return {"case": case, "passed": True, "stdout": diagnostic, **fields}


def _exact_bytes(driver: Driver, target: object, root: str) -> Mapping[str, object]:
    empty = root + "/empty"
    binary = root + "/binary"
    shorter = root + "/shorter"
    _write(driver, target, empty, b"")
    _write(driver, target, binary, b"\x00\xffSPS")
    _write(driver, target, shorter, b"abcdef")
    _write(driver, target, shorter, b"xy")
    for path, data in ((empty, b""), (binary, b"\x00\xffSPS"), (shorter, b"xy")):
        seen = _observe(driver, target, path)
        if seen.get("sha256") != _sha256(data) or seen.get("size") != len(data):
            raise NativeFailure("exact_bytes")
        if not seen.get("readable") or not seen.get("writable"):
            raise NativeFailure("create_access")
    return _passed("exact_bytes", written_bytes=2)


def _create_parents(driver: Driver, target: object, root: str) -> Mapping[str, object]:
    path = root + "/nested/a/b/file"
    data = b"parents"
    _write(driver, target, path, data)
    seen = _observe(driver, target, path)
    if seen.get("sha256") != _sha256(data) or not seen.get("readable") or not seen.get("writable"):
        raise NativeFailure("create_parents")
    parent = _observe(driver, target, root + "/nested/a/b")
    if not parent.get("exists"):
        raise NativeFailure("create_parents")
    return _passed("create_parents")


def _create_access(driver: Driver, target: object, root: str) -> Mapping[str, object]:
    path = root + "/created"
    _write(driver, target, path, b"access")
    seen = _observe(driver, target, path)
    identity = _run(driver, target, "id -un; id -u; id -g; id -G")
    if not seen.get("readable") or not seen.get("writable"):
        raise NativeFailure("create_access")
    return _passed(
        "create_access", identity=str(identity.get("stdout", ""))[:256], mode=seen.get("mode")
    )


def _overwrite_access(driver: Driver, target: object, root: str) -> Mapping[str, object]:
    modes = ("0600", "0640", "0755")
    for mode in modes:
        path = f"{root}/over-{mode}"
        prepare = _run(
            driver,
            target,
            f"umask 077; printf old >/dev/null; printf fixture > {path}; chmod {mode} {path}",
        )
        if prepare.get("exit_code") != 0:
            raise NativeFailure("overwrite_prepare")
        _write(driver, target, path, b"new-bytes")
        seen = _observe(driver, target, path)
        if seen.get("sha256") != _sha256(b"new-bytes"):
            raise NativeFailure("exact_bytes")
        if not seen.get("readable") or not seen.get("writable"):
            raise NativeFailure("overwrite_access")
    return _passed("overwrite_access")


def _authority(driver: Driver, target: object, root: str) -> Mapping[str, object]:
    protected_dir = root + "/protected"
    protected_file = protected_dir + "/secret"
    setup = _run(
        driver,
        target,
        "id -u",
    )
    if setup.get("exit_code") != 0:
        raise NotRun("authority_identity_unobserved")
    root_setup = _run(
        driver,
        target,
        f"mkdir -p {protected_dir} && printf secret > {protected_file} "
        f"&& chown 0:0 {protected_file} {protected_dir} "
        f"&& chmod 700 {protected_dir} && chmod 600 {protected_file}",
        as_root=True,
    )
    if root_setup.get("exit_code") == 77:
        raise NotRun("account_guest_root_unavailable")
    if root_setup.get("exit_code") not in {0, None}:
        raise NotRun("authority_fixture_unprepared")
    try:
        _write(driver, target, protected_file, b"bypass")
    except NativeFailure as error:
        if error.code not in {"authorization", "permission_denied"}:
            raise NativeFailure("authorization") from error
        return _passed("authority", refused=True)
    raise NativeFailure("authorization")


def _executable_effect(
    driver: Driver, target: object, root: str, declared: str
) -> Mapping[str, object]:
    if declared not in EXECUTABLE_EFFECTS:
        raise NotRun("files_write_executable_effect_invalid")
    path = root + "/script"
    prepare = _run(
        driver,
        target,
        f"printf '#!/bin/sh\\necho ok\\n' > {path}; chmod 0755 {path}",
    )
    if prepare.get("exit_code") not in {0, None}:
        raise NativeFailure("executable_prepare")
    before = _observe(driver, target, path)
    _write(driver, target, path, b"#!/bin/sh\necho ok\n")
    after = _observe(driver, target, path)
    lost = bool(before.get("executable")) and not bool(after.get("executable"))
    if declared == "preserved" and lost:
        raise NativeFailure("executable_effect")
    return _passed(
        "executable_effect",
        files_write_executable_effect=declared,
        executable_before=bool(before.get("executable")),
        executable_after=bool(after.get("executable")),
        warning=EXECUTABLE_WARNING,
    )


def _byte_bound(driver: Driver, target: object, root: str) -> Mapping[str, object]:
    ok_path = root + "/sixteen"
    missing_parent = root + "/bound-missing/a"
    payload = b"x" * BYTE_BOUND
    _write(driver, target, ok_path, payload)
    seen = _observe(driver, target, ok_path)
    if seen.get("size") != BYTE_BOUND:
        raise NativeFailure("byte_bound")
    try:
        _write(driver, target, missing_parent, b"y" * (BYTE_BOUND + 1))
        raise NativeFailure("byte_bound")
    except NativeFailure as error:
        if error.code != "byte_bound":
            raise
    parent = _observe(driver, target, root + "/bound-missing")
    if parent.get("exists"):
        raise NativeFailure("byte_bound")
    try:
        _write(driver, target, missing_parent, b"zz", extra={"limit_bytes": 1})
        raise NativeFailure("byte_bound")
    except NativeFailure as error:
        if error.code != "byte_bound":
            raise
    return _passed("byte_bound", bound=BYTE_BOUND)


def _outcome(driver: Driver, target: object, root: str) -> Mapping[str, object]:
    ok = root + "/ok"
    _write(driver, target, ok, b"ok")
    try:
        _write(driver, target, "", b"x")
        raise NativeFailure("outcome")
    except (NativeFailure, NotRun):
        pass
    try:
        _write(driver, target, ok, b"again", extra={"force_unknown": True})
    except NativeFailure as error:
        if error.code != "outcome_unknown":
            # Drivers without the hook skip the unknown branch.
            if error.code not in {"outcome_unknown"}:
                pass
    return _passed("outcome", confirmed=True)


def _staging_cleanup(driver: Driver, target: object, root: str) -> Mapping[str, object]:
    hook = getattr(driver, "staging_state", None)
    if not callable(hook):
        raise NotRun("staging_not_applicable")
    state = hook()
    if not isinstance(state, Mapping):
        raise NotRun("staging_not_applicable")
    path = root + "/staged"
    _write(driver, target, path, b"staged")
    after = hook()
    if not isinstance(after, Mapping) or after.get("owned_staging_present") is True:
        raise NativeFailure("staging_cleanup")
    try:
        _write(driver, target, path, b"again", extra={"force_unknown": True})
    except NativeFailure as error:
        if error.code == "outcome_unknown":
            retained = hook()
            if (
                not isinstance(retained, Mapping)
                or retained.get("uncertain_identity_retained") is not True
            ):
                raise NativeFailure("staging_cleanup") from error
            return _passed("staging_cleanup", uncertain=True)
        raise
    return _passed("staging_cleanup", uncertain=False)


_HANDLERS = {
    "exact_bytes": _exact_bytes,
    "create_parents": _create_parents,
    "create_access": _create_access,
    "overwrite_access": _overwrite_access,
    "authority": _authority,
    "byte_bound": _byte_bound,
    "outcome": _outcome,
    "staging_cleanup": _staging_cleanup,
}


def guest(
    driver: Driver, target: object, inputs: Mapping[str, object], fixtures: Mapping[str, object]
) -> Mapping[str, object]:
    case = inputs.get("case")
    if case not in CASES:
        raise NotRun("regular_write_case_unknown")
    nonce = str(fixtures.get("run_nonce") or "offline")
    root = f"/tmp/sps-rw-{nonce}"
    mkdir = _run(driver, target, f"mkdir -p {root}")
    if mkdir.get("exit_code") not in {0, None}:
        raise NativeFailure("regular_write_workspace")
    declared = inputs.get("files_write_executable_effect")
    if declared is None:
        declared = fixtures.get("files_write_executable_effect", "unverified")
    if case == "executable_effect":
        return _executable_effect(driver, target, root, str(declared))
    return _HANDLERS[str(case)](driver, target, root)


class RegularWriteUsabilityRunner(Runner):
    """Keeps usability checks out of the shared runner dispatcher."""

    def _test_operation(
        self, operation: str, target: object, inputs: Mapping[str, Any]
    ) -> Mapping[str, object]:
        if operation == "fixture.regular_write_usability":
            return guest(self.driver, target, inputs, self.fixtures)
        return super()._test_operation(operation, target, inputs)
