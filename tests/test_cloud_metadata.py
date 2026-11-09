# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Host metadata detection rejects cloud identity, not sandbox metadata."""

from __future__ import annotations

import json
import runpy
import socket
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import cast

import pytest

from sandbox_provider_spec.suite import suite_path


@pytest.mark.parametrize(
    ("path", "body", "headers", "expected"),
    [
        ("/", {"sandbox_id": "fixture", "region": "fixture"}, {}, False),
        ("/latest/dynamic/instance-identity/document", {"sandbox_id": "fixture"}, {}, False),
        (
            "/latest/dynamic/instance-identity/document",
            {"instanceId": "fixture", "accountId": "fixture", "region": "fixture"},
            {},
            True,
        ),
        (
            "/latest/meta-data/iam/security-credentials/fixture",
            {"AccessKeyId": "fixture", "SecretAccessKey": "fixture", "Token": "fixture"},
            {},
            True,
        ),
        (
            "/metadata/instance?api-version=2021-02-01",
            {"compute": {"vmId": "fixture", "subscriptionId": "fixture"}},
            {},
            True,
        ),
        (
            "/metadata/identity/oauth2/token",
            {"access_token": "fixture", "token_type": "Bearer"},
            {},
            True,
        ),
        (
            "/computeMetadata/v1/instance/service-accounts/default/token",
            {"access_token": "fixture", "token_type": "Bearer"},
            {"Metadata-Flavor": "Google"},
            True,
        ),
        ("/computeMetadata/v1/instance/id", 1234, {"Metadata-Flavor": "Google"}, True),
        ("/computeMetadata/v1/instance/id", {"sandbox": "fixture"}, {}, False),
        ("/", {"access_token": "provider-sandbox-placeholder", "token_type": "Bearer"}, {}, False),
    ],
)
def test_only_host_cloud_identity_or_credentials_fail_candidate(
    path: str, body: object, headers: dict[str, str], expected: bool
) -> None:
    module = runpy.run_path(str(suite_path().parent / "fixtures/cloud_metadata.py"))
    classify = cast(Callable[[str, bytes, dict[str, str]], bool], module["identifies_host"])
    assert classify(path, json.dumps(body).encode(), headers) is expected


class _Reply:
    def __init__(self, body: bytes, headers: dict[str, str] | None = None) -> None:
        self._body, self.headers = body, headers or {}

    def __enter__(self) -> _Reply:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def read(self, _limit: int) -> bytes:
        return self._body


class _Opener:
    """A scripted link-local host: `table` maps (method, path, token header) to a reply."""

    def __init__(self, table: dict[tuple[str, str, str | None], bytes], hang: bool = False) -> None:
        self.table, self.hang, self.seen = table, hang, 0

    def open(self, req: urllib.request.Request, timeout: float) -> _Reply:
        self.seen += 1
        if self.hang:
            time.sleep(timeout)
            raise TimeoutError
        key = (
            req.get_method(),
            req.selector,
            req.get_header("X-aws-ec2-metadata-token"),
        )
        if key not in self.table:
            raise urllib.error.URLError("refused")
        return _Reply(self.table[key])


def _exposed(monkeypatch: pytest.MonkeyPatch, opener: _Opener) -> bool:
    module = runpy.run_path(str(suite_path().parent / "fixtures/cloud_metadata.py"))
    monkeypatch.setattr(urllib.request, "build_opener", lambda *_: opener)
    monkeypatch.setattr(
        socket, "create_connection", lambda *_, **__: (_ for _ in ()).throw(OSError)
    )
    return cast(bool, module["exposed"]())


_IDENTITY = json.dumps({"instanceId": "i", "accountId": "a", "region": "r"}).encode()
_CREDENTIALS = json.dumps({"AccessKeyId": "k", "SecretAccessKey": "s", "Token": "t"}).encode()
_DOCUMENT = "/latest/dynamic/instance-identity/document"
_ROLES = "/latest/meta-data/iam/security-credentials/"


def test_unreachable_link_local_address_fits_one_observation_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every request hangs for its whole timeout; the probe still ends inside five seconds."""
    opener = _Opener({}, hang=True)
    started = time.monotonic()
    assert _exposed(monkeypatch, opener) is False
    assert time.monotonic() - started < 4.0
    assert opener.seen >= 8  # every documented path was still asked


@pytest.mark.parametrize(
    "table",
    [
        {("GET", _DOCUMENT, None): _IDENTITY},
        {
            ("PUT", "/latest/api/token", None): b"tok",
            ("GET", _DOCUMENT, "tok"): _IDENTITY,
        },
        {
            ("PUT", "/latest/api/token", None): b"tok",
            ("GET", _ROLES, "tok"): b"role-a",
            ("GET", _ROLES + "role-a", "tok"): _CREDENTIALS,
        },
        {("GET", _ROLES, None): b"role-a", ("GET", _ROLES + "role-a", None): _CREDENTIALS},
        {
            (
                "GET",
                "/computeMetadata/v1/instance/service-accounts/default/token",
                None,
            ): json.dumps({"access_token": "x", "token_type": "Bearer"}).encode()
        },
    ],
)
def test_exposure_is_still_found_concurrently(
    monkeypatch: pytest.MonkeyPatch, table: dict[tuple[str, str, str | None], bytes]
) -> None:
    assert _exposed(monkeypatch, _Opener(table)) is True


def test_a_host_that_answers_nothing_identifying_is_hidden(monkeypatch: pytest.MonkeyPatch) -> None:
    table: dict[tuple[str, str, str | None], bytes] = {
        ("GET", _DOCUMENT, None): json.dumps({"sandbox_id": "s"}).encode()
    }
    assert _exposed(monkeypatch, _Opener(table)) is False
