# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Offline coverage for workload identity and egress proxy fixtures."""

from __future__ import annotations

import base64
import hashlib
import json
import socket
import socketserver
import threading
import time
from collections.abc import Mapping
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, cast
from uuid import uuid4

import pytest

from sandbox_provider_spec import coverage_v5 as probe
from sandbox_provider_spec.driver import Differs, Driver, Inputs, NativeFailure, NotRun, Observation

_N = int(
    "a65be933292f4719a6a6ee58e85a88f06988e2be3cdadc9dc5c2cd0486a1be3bb7b30c8a04849d9f76c992e34a1af00d06bf8d12b4f6ec691cc86ff3e361b8f5451bf7cacbc49876484c276bd140d22d5a832b61d79df81e09c5c408a26e1a55a70c1173b089a5be11076faa1014472dd554702f8298dc8a8a7d2d4e633ef0c36a5807ab3c34feb577c2be66b886db895b1eaa8ef6f36f46c858421c6159c463a24a0b5eda99ba5a213b08588aa1f6b2a896d4f35fe759700fad62567d137f0506e4955159dd1522c243421e622472254cd7af332549807b283721974efa9d692c9c9fa0fa2fc74eb81559725adf90051ff4c20814f75d6e886c85666b305279",
    16,
)
_D = int(
    "339a650f0aa270b2a3403ac4f76645fe152e71ef42df3cf9efc34a6731fff00b8423152ba6d52033bbdc312531f2832df73ee9dab8a9b391b36cf55538de324a5aa29f4d97c1a6ed61e5c580ab4b29270a618fce6cdcc27f46d6c2c54ee54a63f14a4c0b8fe252b84f7df8044fb28a95cc0bc234ea94d22c63630aefbad76645276ed5e0143f058df2ac7e6455c15df71679fb3fd45330d29989ac508b2d10294346fdce9126c8e55e4806e89306cb8417c77195d551b43aa9f45d730cdb44e9cb2184d9058956124e8759f60cef6f2a46b8b44f60fdde2f866ac81ef3333aac1bfd35908dd68308464ad1113012646895241e5ad19c2a8129a99c078a5a8e05",
    16,
)
_ISSUER = "https://issuer.example"
_AUDIENCE = "urn:sandbox-provider-spec:coverage:workload-identity"
_TEST_RSA_SIGNATURES = {
    "RS256": (hashlib.sha256, bytes.fromhex("3031300d060960864801650304020105000420")),
    "RS384": (hashlib.sha384, bytes.fromhex("3041300d060960864801650304020205000430")),
    "RS512": (hashlib.sha512, bytes.fromhex("3051300d060960864801650304020305000440")),
}


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _jwt(
    subject: str,
    audience: str | list[str] = _AUDIENCE,
    *,
    expired: bool = False,
    algorithm: str = "RS256",
) -> str:
    header = _b64(json.dumps({"alg": algorithm, "kid": "test-key"}, separators=(",", ":")).encode())
    claims = _b64(
        json.dumps(
            {
                "iss": _ISSUER,
                "sub": subject,
                "aud": audience,
                "exp": time.time() - 1 if expired else time.time() + 600,
            },
            separators=(",", ":"),
        ).encode()
    )
    signing_input = (header + "." + claims).encode()
    digest, digest_info_prefix = _TEST_RSA_SIGNATURES[algorithm]
    digest_info = digest_info_prefix + digest(signing_input).digest()
    size = (_N.bit_length() + 7) // 8
    encoded = b"\x00\x01" + b"\xff" * (size - len(digest_info) - 3) + b"\x00" + digest_info
    signature = pow(int.from_bytes(encoded, "big"), _D, _N).to_bytes(size, "big")
    return header + "." + claims + "." + _b64(signature)


def _issuer_document(url: str) -> Mapping[str, object]:
    if url == _ISSUER + "/.well-known/openid-configuration":
        return {"issuer": _ISSUER, "jwks_uri": _ISSUER + "/keys"}
    if url == _ISSUER + "/keys":
        modulus = _N.to_bytes((_N.bit_length() + 7) // 8, "big")
        return {
            "keys": [
                {
                    "kid": "test-key",
                    "kty": "RSA",
                    "use": "sig",
                    "n": _b64(modulus),
                    "e": _b64((65537).to_bytes(3, "big")),
                }
            ]
        }
    raise AssertionError(f"unexpected issuer URL: {url}")


def _allow_public_identity_fetch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(probe, "_public_https_url", probe._https_url)


def _local_issuer() -> tuple[ThreadingHTTPServer, threading.Thread, object]:
    documents = {
        "/.well-known/openid-configuration": {
            "issuer": _ISSUER,
            "jwks_uri": _ISSUER + "/keys",
        },
        "/keys": _issuer_document(_ISSUER + "/keys"),
    }

    class Issuer(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            return

        def do_GET(self) -> None:
            document = documents.get(self.path)
            if document is None:
                self.send_error(404)
                return
            body = json.dumps(document).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Issuer)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"

    def fetch(url: str) -> Mapping[str, object]:
        path = (
            "/.well-known/openid-configuration"
            if url.endswith("/.well-known/openid-configuration")
            else "/keys"
        )
        status, _, body = probe._direct_request(origin + path)
        assert status == 200
        return probe._json_bytes(body)

    return server, thread, fetch


class IdentityDriver(Driver):
    workload_identity_deliveries = ("environment", "injected")

    def __init__(self, tokens: list[str]) -> None:
        super().__init__()
        self.tokens = iter(tokens)
        self.created: list[dict[str, object]] = []

    def call(self, operation: str, target: object, inputs: Inputs) -> Observation:
        del target
        if operation == "create":
            self.created.append(dict(inputs))
            owned = self.own("sandbox", object(), lambda: {"result": "deleted"})
            return {
                "resource": owned,
                "identity": f"sandbox-{len(self.created)}",
                "workload_identity": {"environment_variable": "SPS_IDENTITY_TOKEN"},
            }
        if operation == "files.write":
            return {}
        if operation == "run":
            script = str(inputs["bash_script"])
            if script == "python3 /tmp/sps-v5-identity-token.py":
                return {"exit_code": 0, "stdout": next(self.tokens)}
            return {"exit_code": 0, "stdout": '{"readable":false}'}
        raise AssertionError(operation)


class EgressDriver(Driver):
    def __init__(self) -> None:
        super().__init__()
        self.created: list[dict[str, object]] = []

    def call(self, operation: str, target: object, inputs: Inputs) -> Observation:
        del target
        if operation != "create":
            return {}
        self.created.append(dict(inputs))
        owned = self.own("sandbox", object(), lambda: {"result": "deleted"})
        return {"resource": owned, "identity": "sandbox"}


def _record_server(
    empty: bool = False, *, record_tcp: bool | None = None
) -> tuple[ThreadingHTTPServer, threading.Thread]:
    seen_tcp = not empty if record_tcp is None else record_tcp

    class Records(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            return

        def do_GET(self) -> None:
            token = self.path.rsplit("/", 1)[-1]
            value: dict[str, object] = {}
            if not empty and token.endswith(("-http", "-https")):
                value = {"requests": [{"source_address": "198.51.100.7"}]}
            elif seen_tcp and token.endswith("-tcp"):
                value = {"tcp": [{"source_address": "198.51.100.7"}]}
            elif not empty:
                value = {"connections": [{"destination": "fixture"}]}
            body = json.dumps(value).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Records)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _egress_fixtures(records_url: str) -> dict[str, object]:
    return {
        "egress_proxy_protocol": "http",
        "egress_proxy": {
            "addresses": {
                "http": "http://127.0.0.1:3128",
                "socks5": "socks5://127.0.0.1:1080",
            },
            "unreachable_address": "http://127.0.0.1:1",
            "health_url": "https://controlled.invalid/health",
            "http_url": "http://controlled.invalid/receiver/http",
            "https_url": "https://controlled.invalid/receiver/https",
            "tcp_host": "127.0.0.1",
            "tcp_port": 7000,
            "source_address": "198.51.100.7",
            "password": "test-only-password",
            "records_url": records_url,
        },
    }


@pytest.mark.parametrize("protocol", ["http", "socks5"])
@pytest.mark.loopback
@pytest.mark.integration
def test_preflight_proxy_checks_local_listener_reachability(protocol: str) -> None:
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    host, port = listener.getsockname()
    value = {"addresses": {protocol: f"{protocol}://{host}:{port}"}}
    try:
        probe._check_proxy_socket(value["addresses"][protocol])
    finally:
        listener.close()


@pytest.mark.loopback
@pytest.mark.integration
def test_preflight_proxy_requires_active_proxy_and_unreachable_control() -> None:
    active = socket.socket()
    active.bind(("127.0.0.1", 0))
    active.listen()
    host, port = active.getsockname()
    try:
        probe._check_proxy_socket(f"http://{host}:{port}")
        with pytest.raises(NotRun, match="egress_unreachable_proxy_control_reachable"):
            probe._check_proxy_socket(f"http://{host}:{port}", must_be_unreachable=True)
    finally:
        active.close()

    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        unused_port = reservation.getsockname()[1]
    with pytest.raises(NativeFailure, match="egress_proxy_unhealthy"):
        probe._check_proxy_socket(f"http://127.0.0.1:{unused_port}")
    probe._check_proxy_socket(f"http://127.0.0.1:{unused_port}", must_be_unreachable=True)


def test_fails_closed_preflight_does_not_require_tcp_echo(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(probe, "_direct_request", lambda *_args: (200, {}, b""))
    monkeypatch.setattr(probe, "_check_proxy_socket", lambda *_args, **_kwargs: None)

    def reject_tcp(*_args: object) -> None:
        raise AssertionError("fails_closed must not preflight the TCP echo endpoint")

    monkeypatch.setattr(probe, "_check_tcp_echo", reject_tcp)
    value = _egress_fixtures("https://controlled.invalid/records")["egress_proxy"]
    assert isinstance(value, dict)
    value["tcp_host"] = None
    value["tcp_port"] = None
    probe._preflight_proxy({}, "http", value, check_tcp=False)


@pytest.mark.loopback
@pytest.mark.integration
def test_identity_tokens_verify_issuer_signature_expiry_and_audience(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _allow_public_identity_fetch(monkeypatch)
    server, thread, fetch = _local_issuer()
    monkeypatch.setattr(probe, "_direct_json", fetch)
    try:
        subject, audience = probe.verify_identity_token(_jwt("subject-one"), audience=_AUDIENCE)
        assert (subject, audience) == ("subject-one", _AUDIENCE)
        for algorithm in ("RS384", "RS512"):
            assert probe.verify_identity_token(
                _jwt("subject-one", algorithm=algorithm), audience=_AUDIENCE
            ) == ("subject-one", _AUDIENCE)
        with pytest.raises(Differs, match="identity_token_expired"):
            probe.verify_identity_token(_jwt("expired", expired=True), audience=_AUDIENCE)
        with pytest.raises(Differs, match="identity_token_audience_mismatch"):
            probe.verify_identity_token(_jwt("wrong-audience", "other"), audience=_AUDIENCE)
        token = _jwt("tampered")
        parts = token.split(".")
        signature = parts[2]
        changed = "A" if signature[10] != "A" else "B"
        parts[2] = signature[:10] + changed + signature[11:]
        with pytest.raises(Differs, match="identity_token_signature_invalid"):
            probe.verify_identity_token(".".join(parts))
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


def test_rsa_key_accepts_matching_jwk_algorithm_and_rejects_mismatch() -> None:
    jwk = {
        "kty": "RSA",
        "n": _b64(_N.to_bytes((_N.bit_length() + 7) // 8, "big")),
        "e": _b64((65537).to_bytes(3, "big")),
    }

    assert probe._rsa_key({**jwk, "alg": "RS256"}, "RS256") == (_N, 65537)

    with pytest.raises(ValueError, match="key algorithm differs"):
        probe._rsa_key({**jwk, "alg": "RS384"}, "RS256")


def test_identity_token_rejects_private_issuer_and_jwks_destinations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = probe._public_https_url

    def reject_private(value: object, **kwargs: str) -> object:
        if "private" in str(value):
            raise ValueError("private destination")
        return original(value, **kwargs)

    monkeypatch.setattr(probe, "_public_https_url", reject_private)
    with pytest.raises(Differs, match="identity_issuer_invalid"):
        probe.verify_identity_token(
            _jwt("private-issuer"),
            fetch_json=lambda url: {"issuer": _ISSUER, "jwks_uri": _ISSUER + "/keys"},
        )

    def reject_internal_jwks(value: object, **kwargs: str) -> object:
        if "internal.example" in str(value):
            raise ValueError("private destination")
        return original(value, **kwargs)

    monkeypatch.setattr(probe, "_public_https_url", reject_internal_jwks)
    with pytest.raises(Differs, match="identity_issuer_invalid"):
        probe.verify_identity_token(
            _jwt("subject"),
            fetch_json=lambda url: (
                {
                    "issuer": _ISSUER,
                    "jwks_uri": "https://internal.example/keys",
                }
                if url.endswith("openid-configuration")
                else {}
            ),
        )


@pytest.mark.loopback
@pytest.mark.integration
def test_identity_token_fixture_creates_two_unique_sandboxes_and_returns_only_claim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _allow_public_identity_fetch(monkeypatch)
    server, thread, fetch = _local_issuer()
    monkeypatch.setattr(probe, "_direct_json", fetch)
    tokens = [_jwt("subject-one"), _jwt("subject-two")]
    driver = IdentityDriver(tokens)
    try:
        result = probe.identity_token(
            driver,
            {"delivery": "environment", "custom_audience": True, "audience": _AUDIENCE},
            {},
        )
    finally:
        server.shutdown()
        thread.join()
        server.server_close()
    assert result == {"verified": True, "aud": _AUDIENCE}
    assert len(driver.created) == 2
    for create in driver.created:
        assert cast(str, create["name"]).startswith("sps-v5-")
        assert create["requirements"] == {
            "workload_identity": {"delivery": "environment", "custom_audience": True}
        }
        assert create["workload_identity"] == {"audience": _AUDIENCE}
    assert len(driver.resources) == 2
    assert all(token not in json.dumps(result) for token in tokens)


@pytest.mark.loopback
@pytest.mark.integration
def test_any_identity_delivery_uses_a_mode_offered_by_driver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _allow_public_identity_fetch(monkeypatch)
    server, thread, fetch = _local_issuer()
    monkeypatch.setattr(probe, "_direct_json", fetch)
    driver = IdentityDriver([_jwt("subject-one"), _jwt("subject-two")])
    try:
        assert probe.identity_token(driver, {"delivery": "any"}, {}) == {
            "verified": True,
            "aud": _AUDIENCE,
        }
    finally:
        server.shutdown()
        thread.join()
        server.server_close()
    assert all(
        cast(
            Mapping[str, object],
            cast(Mapping[str, object], item["requirements"])["workload_identity"],
        )["delivery"]
        == "environment"
        for item in driver.created
    )


@pytest.mark.loopback
@pytest.mark.integration
def test_injected_identity_checks_receiver_and_token_visibility(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _allow_public_identity_fetch(monkeypatch)
    server, thread, fetch = _local_issuer()
    monkeypatch.setattr(probe, "_direct_json", fetch)
    monkeypatch.setattr(probe, "_receiver_health", lambda *_args: (200, {}, b"ok"))
    monkeypatch.setattr(
        probe, "_injected_token", lambda *_args, **_kwargs: _jwt("injected" + str(uuid4()))
    )
    monkeypatch.setattr(probe, "_token_is_environment_readable", lambda *_args: False)
    driver = IdentityDriver([])
    try:
        result = probe.identity_token(
            driver,
            {"delivery": "injected", "custom_audience": True, "audience": _AUDIENCE},
            {
                "workload_identity_receiver_url": "https://receiver.example/token",
                "workload_identity_records_url": "https://receiver.example/records",
            },
        )
    finally:
        server.shutdown()
        thread.join()
        server.server_close()
    assert result == {"verified": True, "aud": _AUDIENCE}
    assert all(
        cast(Mapping[str, object], item["workload_identity"])
        == {"audience": _AUDIENCE, "hosts": ["receiver.example"], "header": "Authorization"}
        for item in driver.created
    )


def test_token_visibility_probe_checks_procfs_environ() -> None:
    class ProcfsDriver:
        def __init__(self) -> None:
            self.files: dict[str, bytes] = {}

        def call(self, operation: str, _box: object, arguments: Mapping[str, object]) -> object:
            if operation == "files.write":
                self.files[cast(str, arguments["path"])] = base64.b64decode(
                    cast(str, arguments["data"])
                )
                return {}
            return {"exit_code": 0, "stdout": json.dumps({"readable": True})}

    driver = ProcfsDriver()
    assert probe._token_is_environment_readable(cast(Any, driver), object(), "secret-token") is True
    script = driver.files["/tmp/sps-v5-identity-visible.py"].decode()
    assert "'/proc/self/environ'" in script
    assert "'/proc/'+entry+'/'+name" in script
    assert "'cmdline'" in script and "'mem'" in script


@pytest.mark.parametrize(
    ("probe_name", "requirements", "guest", "expected"),
    [
        (
            "routes",
            {"protocol": "http", "traffic": "http"},
            {"http_reached": True, "https_reached": True},
            {
                "http_reached": True,
                "https_reached": True,
                "http_source_is_proxy": True,
                "https_source_is_proxy": True,
            },
        ),
        (
            "any_tcp",
            {"protocol": "http", "traffic": "any_tcp"},
            {"tcp_echo_received": True},
            {"tcp_echo_received": True, "tcp_source_is_proxy": True},
        ),
        (
            "transparent",
            {"protocol": "http", "traffic": "http", "transparent": True},
            {"https_reached": True},
            {"https_reached": True, "https_source_is_proxy": True},
        ),
        (
            "fails_closed",
            {"protocol": "http", "traffic": "http", "fails_closed": True},
            {
                "http_outbound_failed": True,
                "https_outbound_failed": True,
            },
            {
                "http_outbound_failed": True,
                "destination_unseen": True,
            },
        ),
    ],
)
@pytest.mark.loopback
@pytest.mark.integration
def test_egress_proxy_probes_use_owned_sandboxes_and_return_boolean_observations(
    monkeypatch: pytest.MonkeyPatch,
    probe_name: str,
    requirements: dict[str, object],
    guest: dict[str, object],
    expected: dict[str, bool],
) -> None:
    server, thread = _record_server(
        empty=probe_name == "fails_closed",
        record_tcp=True if probe_name == "fails_closed" else None,
    )
    monkeypatch.setattr(probe, "_preflight_proxy", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(probe, "_guest_proxy", lambda *_args: guest)
    try:
        driver = EgressDriver()
        fixtures = _egress_fixtures(f"http://127.0.0.1:{server.server_port}/records")
        if probe_name == "fails_closed":
            proxy_fixture = cast(dict[str, object], fixtures["egress_proxy"])
            proxy_fixture.pop("tcp_host")
            proxy_fixture.pop("tcp_port")
        result = probe.egress_proxy(
            driver,
            {"probe": probe_name, "requirements": {"egress_proxy": requirements}},
            fixtures,
        )
    finally:
        server.shutdown()
        thread.join()
        server.server_close()
    assert result == expected
    assert len(driver.created) == 1
    create = driver.created[0]
    assert cast(str, create["name"]).startswith("sps-v5-")
    assert "password" not in cast(Mapping[str, object], create["requirements"])
    assert cast(Mapping[str, object], create["egress_proxy"])["password"] == "test-only-password"
    assert all(isinstance(value, bool) for value in result.values())


@pytest.mark.parametrize(
    ("probe_name", "requirements", "expected_check_tcp"),
    [
        ("routes", {"protocol": "http", "traffic": "http"}, True),
        (
            "fails_closed",
            {"protocol": "http", "traffic": "http", "fails_closed": True},
            False,
        ),
    ],
)
@pytest.mark.loopback
@pytest.mark.integration
def test_egress_proxy_selects_tcp_preflight_by_probe(
    monkeypatch: pytest.MonkeyPatch,
    probe_name: str,
    requirements: dict[str, object],
    expected_check_tcp: bool,
) -> None:
    server, thread = _record_server(empty=probe_name == "fails_closed")
    calls: list[bool] = []
    driver = EgressDriver()

    def preflight(
        _fixtures: Mapping[str, object],
        _protocol: str,
        _value: Mapping[str, object],
        *,
        check_tcp: bool = True,
    ) -> None:
        calls.append(check_tcp)

    monkeypatch.setattr(probe, "_preflight_proxy", preflight)
    monkeypatch.setattr(
        probe,
        "_guest_proxy",
        lambda *_args: (
            {"http_outbound_failed": True, "https_outbound_failed": True}
            if probe_name == "fails_closed"
            else {"http_reached": True, "https_reached": True}
        ),
    )
    try:
        fixtures = _egress_fixtures(f"http://127.0.0.1:{server.server_port}/records")
        if probe_name == "fails_closed":
            proxy_fixture = cast(dict[str, object], fixtures["egress_proxy"])
            proxy_fixture.pop("tcp_host")
            proxy_fixture.pop("tcp_port")
        probe.egress_proxy(
            driver,
            {"probe": probe_name, "requirements": {"egress_proxy": requirements}},
            fixtures,
        )
    finally:
        server.shutdown()
        thread.join()
        server.server_close()

    assert calls == [expected_check_tcp]
    assert len(driver.resources) == 1


@pytest.mark.loopback
@pytest.mark.integration
def test_fails_closed_fails_when_https_reaches_a_destination(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server, thread = _record_server()
    monkeypatch.setattr(probe, "_preflight_proxy", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        probe,
        "_guest_proxy",
        lambda *_args: {
            "http_outbound_failed": True,
            "https_outbound_failed": False,
        },
    )
    try:
        result = probe.egress_proxy(
            EgressDriver(),
            {
                "probe": "fails_closed",
                "requirements": {
                    "egress_proxy": {"protocol": "http", "traffic": "http", "fails_closed": True}
                },
            },
            _egress_fixtures(f"http://127.0.0.1:{server.server_port}/records"),
        )
    finally:
        server.shutdown()
        thread.join()
        server.server_close()
    assert result == {
        "http_outbound_failed": False,
        "destination_unseen": False,
    }


@pytest.mark.loopback
@pytest.mark.integration
def test_record_lookup_uses_local_controlled_service() -> None:
    server, thread = _record_server()
    try:
        document = probe._records(
            {"records_url": f"http://127.0.0.1:{server.server_port}/records"}, "sps-v5-test-http"
        )
    finally:
        server.shutdown()
        thread.join()
        server.server_close()
    assert probe._has_destination(document)
    assert probe._has_source(document, "198.51.100.7")


@pytest.mark.parametrize(
    ("failure", "reason"),
    [
        (NativeFailure("egress_fixture_unhealthy"), "egress_fixture_unavailable"),
        (ValueError("invalid fixture URL"), "egress_fixture_invalid"),
        (TypeError("invalid fixture type"), "egress_fixture_invalid"),
    ],
)
def test_broken_egress_controls_are_not_run(
    monkeypatch: pytest.MonkeyPatch, failure: Exception, reason: str
) -> None:
    monkeypatch.setattr(
        probe,
        "_preflight_proxy",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(failure),
    )
    with pytest.raises(NotRun, match=f"^{reason}$"):
        probe.egress_proxy(
            EgressDriver(),
            {
                "probe": "routes",
                "requirements": {"egress_proxy": {"protocol": "http", "traffic": "http"}},
            },
            _egress_fixtures("http://127.0.0.1/records"),
        )


@pytest.mark.loopback
@pytest.mark.integration
def test_identity_header_capture_uses_local_controlled_service() -> None:
    token = _jwt("receiver-subject")

    class Receiver(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            return

        def do_GET(self) -> None:
            body = json.dumps(
                {
                    "requests": [
                        {
                            "headers": {
                                "X-Token": "test-run",
                                "Authorization": "Bearer " + token,
                            }
                        }
                    ]
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, _, body = probe._direct_request(
            f"http://127.0.0.1:{server.server_port}/records/test-run"
        )
        assert status == 200
        record = probe._json_bytes(body)
        headers = probe._headers_from_record(record, "test-run")
        assert probe._token_header(headers) == token
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


class Echo(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        while data := self.request.recv(4096):
            self.request.sendall(data)


@pytest.mark.loopback
@pytest.mark.integration
def test_guest_proxy_script_is_valid_python_and_tcp_fixture_is_local() -> None:
    compile(probe._guest_proxy_script(), "coverage_v5_guest.py", "exec")
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    payload = b"sps-v5-local-echo"
    try:
        with socket.socket() as client:
            client.settimeout(3)
            client.connect(server.server_address)
            client.sendall(payload)
            assert client.recv(len(payload)) == payload
    finally:
        server.shutdown()
        thread.join()
        server.server_close()
