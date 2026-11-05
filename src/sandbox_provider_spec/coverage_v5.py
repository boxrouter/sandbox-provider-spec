# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Provider-neutral identity-token and egress-proxy conformance fixtures.

Injected identity fixtures use ``workload_identity_receiver_url`` and
``workload_identity_records_url`` (plus an optional health URL). Egress fixtures use an
``egress_proxy`` mapping with ``addresses`` by protocol, ``unreachable_address``,
``health_url``, HTTP/HTTPS receiver URLs, a TCP echo host/port, ``source_address``,
test-only ``password`` and a ``records_url`` base.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import math
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from typing import Any, cast
from uuid import uuid4

from sandbox_provider_spec.driver import Differs, Driver, NativeFailure, NotRun, resource

MAX_DOCUMENT = 1_048_576
MAX_TOKEN = 65_536
PROXY_PAYLOAD = b"sps-v5-egress-probe\x00\xff\n"
_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,254}$")
_RSA_SIGNATURES = {
    "RS256": (hashlib.sha256, bytes.fromhex("3031300d060960864801650304020105000420")),
    "RS384": (hashlib.sha384, bytes.fromhex("3041300d060960864801650304020205000430")),
    "RS512": (hashlib.sha512, bytes.fromhex("3051300d060960864801650304020305000440")),
}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        del args, kwargs


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _json_bytes(data: bytes) -> Mapping[str, object]:
    if len(data) > MAX_DOCUMENT:
        raise ValueError("JSON document is too large")
    value = json.loads(data, object_pairs_hook=_unique_object)
    if not isinstance(value, Mapping):
        raise ValueError("JSON document must be an object")
    return cast(Mapping[str, object], value)


def _direct_request(
    url: str, *, headers: Mapping[str, str] | None = None, limit: int = MAX_DOCUMENT
) -> tuple[int, Mapping[str, str], bytes]:
    request = urllib.request.Request(url, headers=dict(headers or {}))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        response = opener.open(request, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    except (urllib.error.URLError, TimeoutError, OSError):
        raise NativeFailure("controlled_endpoint_unreachable") from None
    with response:
        body = response.read(limit + 1)
        if len(body) > limit:
            raise NativeFailure("controlled_endpoint_response_too_large")
        status = cast(int, getattr(response, "status", getattr(response, "code", 0)))
        return status, dict(response.headers.items()), body


def _direct_json(url: str) -> Mapping[str, object]:
    status, _, body = _direct_request(url)
    if status != 200:
        raise NativeFailure("identity_issuer_unavailable")
    try:
        return _json_bytes(body)
    except (ValueError, json.JSONDecodeError):
        raise NativeFailure("identity_issuer_response_invalid") from None


def _receiver_health(url: str) -> tuple[int, Mapping[str, str], bytes]:
    return _direct_request(url)


def _https_url(value: object, *, failure: str) -> urllib.parse.SplitResult:
    if not isinstance(value, str) or len(value) > 4096:
        raise ValueError(f"{failure} must be a URL")
    url = urllib.parse.urlsplit(value)
    if (
        url.scheme != "https"
        or not url.hostname
        or url.username is not None
        or url.password is not None
        or url.fragment
    ):
        raise ValueError(f"{failure} must be HTTPS without user information or a fragment")
    return url


def _public_https_url(value: object, *, failure: str) -> urllib.parse.SplitResult:
    """Accept HTTPS URLs only when their resolved addresses are globally routable."""
    url = _https_url(value, failure=failure)
    try:
        if url.hostname is None:
            raise ValueError
        try:
            literal = ipaddress.ip_address(url.hostname)
        except ValueError:
            literal = None
        if literal is not None:
            addresses = [literal]
        else:
            port = url.port or 443
            addresses = [
                ipaddress.ip_address(address[4][0])
                for address in socket.getaddrinfo(url.hostname, port, type=socket.SOCK_STREAM)
            ]
        if not addresses or any(not address.is_global for address in addresses):
            raise ValueError
    except (OSError, ValueError):
        raise ValueError(f"{failure} must resolve only to public addresses") from None
    return url


def _b64url(value: object) -> bytes:
    if not isinstance(value, str) or not _B64URL.fullmatch(value):
        raise ValueError("invalid base64url value")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _jwt(
    token: str,
) -> tuple[Mapping[str, object], Mapping[str, object], bytes, bytes, str]:
    if not isinstance(token, str) or not 1 <= len(token) <= MAX_TOKEN:
        raise Differs("identity_token_invalid")
    parts = token.split(".")
    if len(parts) != 3:
        raise Differs("identity_token_invalid")
    try:
        header = _json_bytes(_b64url(parts[0]))
        claims = _json_bytes(_b64url(parts[1]))
        signature = _b64url(parts[2])
    except (ValueError, json.JSONDecodeError):
        raise Differs("identity_token_invalid") from None
    algorithm = header.get("alg")
    if not isinstance(algorithm, str) or algorithm not in _RSA_SIGNATURES:
        raise NotRun("identity_token_algorithm_unmapped")
    if header.get("kid") is not None and not isinstance(header.get("kid"), str):
        raise Differs("identity_token_invalid")
    return header, claims, signature, (parts[0] + "." + parts[1]).encode("ascii"), algorithm


def _rsa_key(jwk: Mapping[str, object], algorithm: str) -> tuple[int, int]:
    if jwk.get("kty") != "RSA" or jwk.get("use", "sig") != "sig":
        raise ValueError("key is not an RSA signing key")
    if jwk.get("alg", algorithm) != algorithm:
        raise ValueError("key algorithm differs")
    if "verify" not in cast(list[object], jwk.get("key_ops", ["verify"])):
        raise ValueError("key cannot verify signatures")
    n, e = (
        int.from_bytes(_b64url(jwk.get("n")), "big"),
        int.from_bytes(_b64url(jwk.get("e")), "big"),
    )
    if not 512 <= n.bit_length() <= 8192 or e < 3 or e % 2 == 0:
        raise ValueError("RSA key size or exponent is invalid")
    return n, e


def _verify_rsa_signature(
    signing_input: bytes, signature: bytes, jwk: Mapping[str, object], algorithm: str
) -> bool:
    try:
        digest, digest_info_prefix = _RSA_SIGNATURES[algorithm]
        modulus, exponent = _rsa_key(jwk, algorithm)
    except (ValueError, TypeError):
        return False
    size = (modulus.bit_length() + 7) // 8
    if len(signature) != size or int.from_bytes(signature, "big") >= modulus:
        return False
    decoded = pow(int.from_bytes(signature, "big"), exponent, modulus).to_bytes(size, "big")
    digest_info = digest_info_prefix + digest(signing_input).digest()
    padding_length = size - len(digest_info) - 3
    return (
        padding_length >= 8
        and decoded == b"\x00\x01" + b"\xff" * padding_length + b"\x00" + digest_info
    )


def verify_identity_token(
    token: str,
    *,
    audience: str | None = None,
    now: float | None = None,
    fetch_json: Callable[[str], Mapping[str, object]] | None = None,
) -> tuple[str, object]:
    """Verify an OIDC JWT without retaining its token or subject in observations."""
    header, claims, signature, signing_input, algorithm = _jwt(token)
    fetch = fetch_json or _direct_json
    issuer = claims.get("iss")
    if not isinstance(issuer, str):
        raise Differs("identity_issuer_invalid")
    try:
        issuer_url = _https_url(issuer, failure="issuer")
    except ValueError:
        raise Differs("identity_issuer_invalid") from None
    if issuer_url.query:
        raise Differs("identity_issuer_invalid")
    try:
        _public_https_url(issuer, failure="issuer")
    except ValueError:
        raise Differs("identity_issuer_invalid") from None
    discovery_url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    try:
        discovery = fetch(discovery_url)
    except NativeFailure:
        raise
    except Exception:  # pylint: disable=broad-exception-caught
        raise NativeFailure("identity_issuer_unavailable") from None
    if discovery.get("issuer") != issuer:
        raise Differs("identity_issuer_mismatch")
    jwks_url = discovery.get("jwks_uri")
    try:
        _public_https_url(jwks_url, failure="jwks_uri")
        jwks = fetch(cast(str, jwks_url))
    except NativeFailure:
        raise
    except ValueError:
        raise Differs("identity_issuer_keys_invalid") from None
    except Exception:  # pylint: disable=broad-exception-caught
        raise NativeFailure("identity_issuer_keys_unavailable") from None
    keys = jwks.get("keys")
    if not isinstance(keys, list) or len(keys) > 100:
        raise Differs("identity_issuer_keys_invalid")
    key_id = header.get("kid")
    selected = [
        key
        for key in keys
        if isinstance(key, Mapping) and (key_id is None or key.get("kid") == key_id)
    ]
    if (
        sum(_verify_rsa_signature(signing_input, signature, key, algorithm) for key in selected)
        != 1
    ):
        raise Differs("identity_token_signature_invalid")
    if claims.get("iss") != issuer or not isinstance(claims.get("sub"), str) or not claims["sub"]:
        raise Differs("identity_token_claims_invalid")
    current = time.time() if now is None else now
    expiry = claims.get("exp")
    if (
        not isinstance(expiry, (int, float))
        or isinstance(expiry, bool)
        or (isinstance(expiry, float) and not math.isfinite(expiry))
        or expiry <= current
    ):
        raise Differs("identity_token_expired")
    not_before = claims.get("nbf")
    if (
        isinstance(not_before, (int, float))
        and not isinstance(not_before, bool)
        and not_before > current
    ):
        raise Differs("identity_token_not_yet_valid")
    actual_audience = claims.get("aud")
    if isinstance(actual_audience, list):
        if not actual_audience or any(not isinstance(item, str) for item in actual_audience):
            raise Differs("identity_token_audience_invalid")
        observed_audience: object = actual_audience
        audience_matches = audience in actual_audience if audience is not None else True
    elif isinstance(actual_audience, str) and actual_audience:
        observed_audience = actual_audience
        audience_matches = audience is None or actual_audience == audience
    else:
        raise Differs("identity_token_audience_invalid")
    if not audience_matches:
        raise Differs("identity_token_audience_mismatch")
    return cast(str, claims["sub"]), observed_audience


def _record_url(base: str, token: str) -> str:
    return base.rstrip("/") + "/" + urllib.parse.quote(token, safe="")


def _headers_from_record(document: Mapping[str, object], token: str) -> Mapping[str, object]:
    records: list[Mapping[str, object]] = []
    for field in ("requests", "receivers", "events", "records"):
        value = document.get(field)
        if isinstance(value, list):
            records.extend(item for item in value if isinstance(item, Mapping))
    if not records and isinstance(document.get("headers"), Mapping):
        return cast(Mapping[str, object], document["headers"])
    matching: list[Mapping[str, object]] = []
    for record in records:
        headers = record.get("headers")
        if not isinstance(headers, Mapping):
            continue
        marker = next((v for k, v in headers.items() if str(k).lower() == "x-token"), None)
        if marker == token:
            matching.append(cast(Mapping[str, object], headers))
    if len(matching) != 1:
        raise NativeFailure("identity_receiver_observation_invalid")
    return matching[0]


def _token_header(headers: Mapping[str, object]) -> str:
    value = next((v for k, v in headers.items() if str(k).lower() == "authorization"), None)
    if isinstance(value, list) and len(value) == 1:
        value = value[0]
    if not isinstance(value, str) or len(value) > MAX_TOKEN + 16:
        raise Differs("identity_token_not_injected")
    prefix, _, token = value.partition(" ")
    return token if prefix.lower() == "bearer" and token else value


def _token_environment(driver: Driver, box: object, name: str) -> str:
    script = (
        "import os,sys\n"
        f"value=os.environ.get({json.dumps(name)})\n"
        "if not value or len(value)>65536 or any(c.isspace() for c in value):\n"
        " sys.exit(41)\n"
        "sys.stdout.write(value)\n"
    )
    driver.call(
        "files.write",
        box,
        {
            "path": "/tmp/sps-v5-identity-token.py",
            "data": base64.b64encode(script.encode()).decode(),
        },
    )
    result = driver.call(
        "run", box, {"bash_script": "python3 /tmp/sps-v5-identity-token.py", "timeout_ms": 15000}
    )
    value = result.get("stdout")
    if result.get("exit_code") != 0 or not isinstance(value, (str, bytes)):
        raise Differs("identity_token_unavailable")
    token = value.decode("utf-8") if isinstance(value, bytes) else value
    if not 1 <= len(token) <= MAX_TOKEN or any(char.isspace() for char in token):
        raise Differs("identity_token_invalid")
    return token


def _token_is_environment_readable(driver: Driver, box: object, token: str) -> bool:
    digest = hashlib.sha256(token.encode()).hexdigest()
    script = (
        "import hashlib,json,os,re,sys\n"
        "target=json.load(open('/tmp/sps-v5-identity-check.json'))['sha256']\n"
        "def matches(data):\n"
        " candidates=re.split(rb'[\\x00-\\x20\\\"\\\\\\',;:=<>]+',data)\n"
        " return any(hashlib.sha256(part).hexdigest()==target for part in candidates if part)\n"
        "readable=any(hashlib.sha256(v.encode()).hexdigest()==target "
        "for v in os.environ.values())\n"
        "if not readable:\n"
        " try: readable=matches(open('/proc/self/environ','rb').read())\n"
        " except OSError: pass\n"
        "if not readable:\n"
        " for entry in os.listdir('/proc'):\n"
        "  if not entry.isdigit(): continue\n"
        "  for name in ('environ','cmdline','mem'):\n"
        "   try:\n"
        "    with open('/proc/'+entry+'/'+name,'rb') as stream: data=stream.read(1048576)\n"
        "    if matches(data):\n"
        "     readable=True; break\n"
        "   except (OSError, PermissionError): pass\n"
        "  if readable: break\n"
        "print(json.dumps({'readable':readable}))\n"
    )
    driver.call(
        "files.write",
        box,
        {
            "path": "/tmp/sps-v5-identity-check.json",
            "data": base64.b64encode(json.dumps({"sha256": digest}).encode()).decode(),
        },
    )
    driver.call(
        "files.write",
        box,
        {
            "path": "/tmp/sps-v5-identity-visible.py",
            "data": base64.b64encode(script.encode()).decode(),
        },
    )
    result = driver.call(
        "run", box, {"bash_script": "python3 /tmp/sps-v5-identity-visible.py", "timeout_ms": 15000}
    )
    output = result.get("stdout")
    if result.get("exit_code") != 0 or not isinstance(output, (str, bytes)) or len(output) > 128:
        raise NativeFailure("identity_token_visibility_probe_failed")
    try:
        decoded = json.loads(output)
    except (ValueError, json.JSONDecodeError):
        raise NativeFailure("identity_token_visibility_probe_invalid") from None
    if not isinstance(decoded, Mapping) or not isinstance(decoded.get("readable"), bool):
        raise NativeFailure("identity_token_visibility_probe_invalid")
    return cast(bool, decoded["readable"])


def _identity_delivery(driver: Driver, requested: object) -> str:
    if isinstance(requested, str) and requested in {"environment", "injected"}:
        return requested
    if requested != "any":
        raise ValueError("unknown workload identity delivery")
    modes = getattr(driver, "workload_identity_deliveries", ())
    if not isinstance(modes, (list, tuple)) or not modes:
        raise NotRun("workload_identity_delivery_unmapped")
    return (
        next((mode for mode in ("environment", "injected") if mode in modes), "")
        or _unsupported_delivery()
    )


def _unsupported_delivery() -> str:
    raise NotRun("workload_identity_delivery_unmapped")


def _create_identity(
    driver: Driver,
    *,
    delivery: str,
    custom_audience: bool,
    audience: str | None,
    receiver_host: str | None,
) -> Mapping[str, object]:
    requirement: dict[str, object] = {"delivery": delivery}
    if custom_audience:
        requirement["custom_audience"] = True
    settings: dict[str, object] = {}
    if audience is not None:
        settings["audience"] = audience
    if delivery == "injected":
        if receiver_host is None:
            raise NotRun("fixture_missing")
        settings.update(hosts=[receiver_host], header="Authorization")
    created = driver.call(
        "create",
        None,
        {
            "name": f"sps-v5-{uuid4().hex}",
            "requirements": {"workload_identity": requirement},
            "workload_identity": settings,
        },
    )
    resource(created)
    return created


def _injected_token(
    driver: Driver,
    box: object,
    *,
    receiver_url: str,
    records_url: str,
) -> str:
    nonce = uuid4().hex
    parts = urllib.parse.urlsplit(receiver_url)
    query = urllib.parse.urlencode({"sps_run": nonce})
    target = urllib.parse.urlunsplit(parts._replace(query=query))
    script = (
        "import json,urllib.error,urllib.request\n"
        f"request=urllib.request.Request({json.dumps(target)},headers={{'X-Token':{json.dumps(nonce)}}})\n"
        "try:\n response=urllib.request.build_opener().open(request,timeout=10)\n"
        "except urllib.error.HTTPError as error:\n response=error\n"
        "print(json.dumps({'status':response.code}))\n"
    )
    driver.call(
        "files.write",
        box,
        {
            "path": "/tmp/sps-v5-identity-request.py",
            "data": base64.b64encode(script.encode()).decode(),
        },
    )
    result = driver.call(
        "run", box, {"bash_script": "python3 /tmp/sps-v5-identity-request.py", "timeout_ms": 20000}
    )
    output = result.get("stdout")
    if result.get("exit_code") != 0 or not isinstance(output, (str, bytes)) or len(output) > 128:
        raise NativeFailure("identity_receiver_request_failed")
    try:
        status = json.loads(output).get("status")
    except (ValueError, json.JSONDecodeError, AttributeError):
        raise NativeFailure("identity_receiver_request_invalid") from None
    if not isinstance(status, int) or isinstance(status, bool) or not 200 <= status < 300:
        raise Differs("identity_receiver_request_failed")
    record_status, _, body = _direct_request(
        _record_url(records_url, nonce), headers={"X-Token": nonce}
    )
    if record_status != 200:
        raise NativeFailure("identity_receiver_observation_failed")
    try:
        headers = _headers_from_record(_json_bytes(body), nonce)
    except (ValueError, json.JSONDecodeError):
        raise NativeFailure("identity_receiver_observation_invalid") from None
    return _token_header(headers)


def identity_token(
    driver: Driver, inputs: Mapping[str, object], fixtures: Mapping[str, object]
) -> Mapping[str, object]:
    """Create two sandboxes and verify current, distinct-subject OIDC tokens."""
    delivery = _identity_delivery(driver, inputs.get("delivery"))
    custom_audience = inputs.get("custom_audience", False)
    audience = inputs.get("audience")
    if not isinstance(custom_audience, bool):
        raise ValueError("custom_audience must be boolean")
    if custom_audience and (not isinstance(audience, str) or not audience or len(audience) > 2048):
        raise ValueError("custom audience must be bounded text")
    if not custom_audience and audience is not None:
        raise ValueError("audience requires custom_audience")
    receiver_url: str | None = None
    records_url: str | None = None
    receiver_host: str | None = None
    if delivery == "injected":
        receiver_value = fixtures.get("workload_identity_receiver_url")
        records_value = fixtures.get("workload_identity_records_url")
        if not isinstance(receiver_value, str) or not isinstance(records_value, str):
            raise NotRun("fixture_missing")
        receiver_url = receiver_value
        records_url = records_value
        receiver = _https_url(receiver_url, failure="workload_identity_receiver_url")
        _https_url(records_url, failure="workload_identity_records_url")
        receiver_host = receiver.hostname
        health_value = fixtures.get("workload_identity_receiver_health_url")
        health_url = (
            health_value
            if isinstance(health_value, str)
            else urllib.parse.urlunsplit(("https", receiver.netloc, "/health", "", ""))
        )
        _https_url(health_url, failure="workload_identity_receiver_health_url")
        health_status, _, _ = _receiver_health(health_url)
        if not 200 <= health_status < 300:
            raise NativeFailure("identity_receiver_unhealthy")
    tokens: list[tuple[str, object]] = []
    for _index in range(2):
        created = _create_identity(
            driver,
            delivery=delivery,
            custom_audience=custom_audience,
            audience=cast(str | None, audience),
            receiver_host=receiver_host,
        )
        if delivery == "environment":
            context = created.get("workload_identity")
            name = context.get("environment_variable") if isinstance(context, Mapping) else None
            if not isinstance(name, str) or not _ENV_NAME.fullmatch(name):
                raise NotRun("workload_identity_environment_unmapped")
            token = _token_environment(driver, created, name)
        else:
            token = _injected_token(
                driver,
                created,
                receiver_url=cast(str, receiver_url),
                records_url=cast(str, records_url),
            )
        tokens.append(
            verify_identity_token(
                token, audience=cast(str | None, audience) if custom_audience else None
            )
        )
        if delivery == "injected" and _token_is_environment_readable(driver, created, token):
            raise Differs("identity_token_readable_in_sandbox")
    if tokens[0][0] == tokens[1][0]:
        raise Differs("identity_subject_not_unique")
    result: dict[str, object] = {"verified": True}
    if custom_audience:
        result["aud"] = audience
    else:
        result["aud"] = tokens[0][1]
    return result


def _proxy_fixture(fixtures: Mapping[str, object], protocol: str) -> Mapping[str, object]:
    value = fixtures.get("egress_proxy")
    if not isinstance(value, Mapping):
        raise NotRun("fixture_missing")
    addresses = value.get("addresses")
    if not isinstance(addresses, Mapping) or not isinstance(addresses.get(protocol), str):
        raise NotRun("fixture_missing")
    return value


def _tcp_endpoint(value: Mapping[str, object]) -> tuple[str, int]:
    host, port = value.get("tcp_host"), value.get("tcp_port")
    if (
        not isinstance(host, str)
        or not host
        or not isinstance(port, int)
        or isinstance(port, bool)
        or not 1 <= port <= 65535
    ):
        raise ValueError("invalid controlled TCP endpoint")
    return host, port


def _check_tcp_echo(host: str, port: int, payload: bytes) -> None:
    try:
        with socket.create_connection((host, port), timeout=8) as connection:
            connection.settimeout(8)
            connection.sendall(payload)
            received = bytearray()
            while len(received) < len(payload):
                chunk = connection.recv(len(payload) - len(received))
                if not chunk:
                    break
                received.extend(chunk)
    except OSError:
        raise NativeFailure("egress_fixture_unhealthy") from None
    if bytes(received) != payload:
        raise NativeFailure("egress_fixture_unhealthy")


def _check_proxy_socket(address: str, *, must_be_unreachable: bool = False) -> None:
    parsed = urllib.parse.urlsplit(address)
    if parsed.scheme not in {"http", "socks5"} or not parsed.hostname:
        raise ValueError("proxy address must use http or socks5")
    port = parsed.port or (1080 if parsed.scheme == "socks5" else 3128)
    try:
        connection = socket.create_connection((parsed.hostname, port), timeout=5)
        connection.close()
    except OSError:
        if must_be_unreachable:
            return
        raise NativeFailure("egress_proxy_unhealthy") from None
    if must_be_unreachable:
        raise NotRun("egress_unreachable_proxy_control_reachable")


def _preflight_proxy(
    fixtures: Mapping[str, object],
    protocol: str,
    value: Mapping[str, object],
    *,
    check_tcp: bool = True,
) -> None:
    health_url = value.get("health_url")
    http_url = value.get("http_url")
    https_url = value.get("https_url")
    for field, url in (
        ("health_url", health_url),
        ("http_url", http_url),
        ("https_url", https_url),
    ):
        parsed = (
            _https_url(url, failure=field)
            if field != "http_url"
            else urllib.parse.urlsplit(cast(str, url))
        )
        if field == "http_url" and (parsed.scheme != "http" or not parsed.hostname):
            raise ValueError("http_url must be a controlled HTTP URL")
        if not isinstance(url, str):
            raise ValueError(f"{field} must be a URL")
        status, _, _ = _direct_request(url)
        if not 200 <= status < 300:
            raise NativeFailure("egress_fixture_unhealthy")
    if check_tcp:
        host, port = _tcp_endpoint(value)
        _check_tcp_echo(host, port, PROXY_PAYLOAD + uuid4().hex.encode())
    addresses = value.get("addresses")
    if not isinstance(addresses, Mapping) or not isinstance(addresses.get(protocol), str):
        raise ValueError("proxy addresses must map protocol names to URLs")
    _check_proxy_socket(addresses[protocol])
    unreachable = value.get("unreachable_address")
    if not isinstance(unreachable, str):
        raise ValueError("unreachable_address must be a URL")
    _check_proxy_socket(unreachable, must_be_unreachable=True)
    try:
        ipaddress.ip_address(cast(str, value.get("source_address")))
    except ValueError:
        raise ValueError("source_address must be an IP address") from None
    if not isinstance(value.get("password"), str) or not value["password"]:
        raise ValueError("proxy password fixture is required")
    _https_url(value.get("records_url"), failure="records_url")
    del fixtures


def _guest_proxy_script() -> bytes:
    source = """import json,socket,ssl,sys,urllib.error,urllib.parse,urllib.request
c=json.load(open("/tmp/sps-v5-egress.json"))
tcp_payload=bytes.fromhex(c["tcp_payload"])
ignore=c["ignore_proxy"]
no_redirect=type("NoRedirect",(urllib.request.HTTPRedirectHandler,),
 {"redirect_request":lambda *a,**k:None})()
proxy_url=c.get("proxy_url","")
proxy_scheme=urllib.parse.urlsplit(proxy_url).scheme
proxy_handler=(urllib.request.ProxyHandler({}) if ignore or proxy_scheme=="socks5"
               else urllib.request.ProxyHandler())
opener=urllib.request.build_opener(proxy_handler,no_redirect)
def socks5_request(url,token):
 target=urllib.parse.urlsplit(url); proxy=urllib.parse.urlsplit(proxy_url)
 try:
  with socket.create_connection((proxy.hostname,proxy.port or 1080),timeout=10) as s:
   s.settimeout(10); s.sendall(b"\\x05\\x02\\x00\\x02")
   method=s.recv(2)
   if len(method)!=2 or method[0]!=5 or method[1]==255: return False
   if method[1]==2:
    user=c["proxy_username"].encode(); password=c["proxy_password"].encode()
    if len(user)>255 or len(password)>255: return False
    s.sendall(b"\\x01"+bytes((len(user),))+user+bytes((len(password),))+password)
    auth=s.recv(2)
    if len(auth)!=2 or auth!=b"\\x01\\x00": return False
   elif method[1]!=0: return False
   host=target.hostname.encode("idna")
   if len(host)>255: return False
   port=target.port or (443 if target.scheme=="https" else 80)
   s.sendall(b"\\x05\\x01\\x00\\x03"+bytes((len(host),))+host+port.to_bytes(2,"big"))
   head=s.recv(4)
   if len(head)!=4 or head[:2]!=b"\\x05\\x00": return False
   if head[3]==1: size=4
   elif head[3]==4: size=16
   elif head[3]==3:
    length=s.recv(1)
    if len(length)!=1: return False
    size=length[0]
   else: return False
   remaining=size+2
   while remaining:
    part=s.recv(remaining)
    if not part: return False
    remaining-=len(part)
   if target.scheme=="https":
    s=ssl.create_default_context().wrap_socket(s,server_hostname=target.hostname)
   path=target.path or "/"
   if target.query: path+="?"+target.query
   request=("GET "+path+" HTTP/1.1\\r\\nHost: "+target.netloc+
            "\\r\\nX-Token: "+token+"\\r\\nConnection: close\\r\\n\\r\\n").encode()
   s.sendall(request); status=s.recv(4096).split(b"\\r\\n",1)[0].split()
   return len(status)>1 and status[1].isdigit() and 200<=int(status[1])<300
 except (OSError,ValueError,ssl.SSLError): return False
def request(url, token):
 if not ignore and proxy_scheme=="socks5": return socks5_request(url,token)
 try:
  response=opener.open(urllib.request.Request(url,headers={"X-Token":token}),timeout=10)
  with response: return 200 <= response.status < 300
 except (urllib.error.URLError,urllib.error.HTTPError,TimeoutError,OSError): return False
def tcp():
 try:
  with socket.create_connection((c["tcp_host"],c["tcp_port"]),timeout=8) as s:
   s.settimeout(8); s.sendall(tcp_payload); got=b""
   while len(got)<len(tcp_payload):
    part=s.recv(len(tcp_payload)-len(got))
    if not part: break
    got+=part
   return got==tcp_payload
 except OSError: return False
out={}
if c["probe"] in ("routes","transparent"):
 if c["probe"]=="routes": out["http_reached"]=request(c["http_url"],c["http_token"])
 out["https_reached"]=request(c["https_url"],c["https_token"])
elif c["probe"]=="any_tcp": out["tcp_echo_received"]=tcp()
else:
 out["http_outbound_failed"]=not request(c["http_url"],c["http_token"])
 out["https_outbound_failed"]=not request(c["https_url"],c["https_token"])
print(json.dumps(out,separators=(",",":")))
"""
    return source.encode()


def _guest_proxy(
    driver: Driver, target: object, config: Mapping[str, object]
) -> Mapping[str, object]:
    driver.call(
        "files.write",
        target,
        {"path": "/tmp/sps-v5-egress.py", "data": base64.b64encode(_guest_proxy_script()).decode()},
    )
    driver.call(
        "files.write",
        target,
        {
            "path": "/tmp/sps-v5-egress.json",
            "data": base64.b64encode(json.dumps(dict(config)).encode()).decode(),
        },
    )
    result = driver.call(
        "run", target, {"bash_script": "python3 /tmp/sps-v5-egress.py", "timeout_ms": 60000}
    )
    output = result.get("stdout")
    if result.get("exit_code") != 0 or not isinstance(output, (str, bytes)) or len(output) > 1024:
        raise NativeFailure("egress_guest_probe_failed")
    try:
        value = json.loads(output)
    except (ValueError, json.JSONDecodeError):
        raise NativeFailure("egress_guest_probe_invalid") from None
    if not isinstance(value, Mapping) or any(not isinstance(item, bool) for item in value.values()):
        raise NativeFailure("egress_guest_probe_invalid")
    return cast(Mapping[str, object], value)


def _records(value: Mapping[str, object], token: str) -> Mapping[str, object]:
    url = value.get("records_url")
    if not isinstance(url, str):
        raise ValueError("records_url must be text")
    status, _, body = _direct_request(_record_url(url, token), headers={"X-Token": token})
    if status != 200:
        raise NativeFailure("egress_receiver_observation_failed")
    try:
        return _json_bytes(body)
    except (ValueError, json.JSONDecodeError):
        raise NativeFailure("egress_receiver_observation_invalid") from None


def _event_lists(document: Mapping[str, object]) -> list[Mapping[str, object]]:
    events: list[Mapping[str, object]] = []
    for field in ("requests", "receivers", "tcp", "connections", "events", "records"):
        value = document.get(field)
        if isinstance(value, list):
            events.extend(item for item in value if isinstance(item, Mapping))
    if not events and any(k in document for k in ("source_ip", "source_address", "remote_ip")):
        events.append(document)
    return events


def _has_source(document: Mapping[str, object], expected: str) -> bool:
    names = {"source_ip", "source_address", "remote_ip", "remote_address"}
    return any(
        str(value) == expected
        for item in _event_lists(document)
        for key, value in item.items()
        if key in names
    )


def _has_destination(document: Mapping[str, object]) -> bool:
    return any(
        field in document and isinstance(document[field], list) and bool(document[field])
        for field in ("requests", "receivers", "tcp")
    )


def _proxy_recorded(document: Mapping[str, object]) -> bool:
    return any(
        isinstance(document.get(field), list) and bool(document[field])
        for field in ("connections", "proxy_connections")
    )


def egress_proxy(
    driver: Driver, inputs: Mapping[str, object], fixtures: Mapping[str, object]
) -> Mapping[str, object]:
    """Probe the configured proxy in a disposable sandbox and return booleans only."""
    probe = inputs.get("probe")
    if not isinstance(probe, str) or probe not in {
        "routes",
        "any_tcp",
        "transparent",
        "fails_closed",
    }:
        raise ValueError("unknown egress-proxy probe")
    requirements = inputs.get("requirements")
    if not isinstance(requirements, Mapping) or not isinstance(
        requirements.get("egress_proxy"), Mapping
    ):
        raise ValueError("egress-proxy requirements are required")
    requested = cast(Mapping[str, object], requirements["egress_proxy"])
    protocol = requested.get("protocol")
    traffic = requested.get("traffic")
    if (
        not isinstance(protocol, str)
        or protocol not in {"http", "socks5"}
        or protocol != fixtures.get("egress_proxy_protocol")
    ):
        raise NotRun("egress_proxy_protocol_unmapped")
    expected_traffic = {
        "routes": "http",
        "any_tcp": "any_tcp",
        "transparent": "http",
        "fails_closed": "http",
    }[probe]
    if traffic != expected_traffic:
        raise ValueError("egress-proxy probe does not match its named requirements")
    if probe == "transparent" and requested.get("transparent") is not True:
        raise ValueError("transparent probe requires the named gate")
    if probe == "fails_closed" and requested.get("fails_closed") is not True:
        raise ValueError("fails_closed probe requires the named gate")
    value = _proxy_fixture(fixtures, protocol)
    try:
        _preflight_proxy(fixtures, protocol, value, check_tcp=probe != "fails_closed")
    except NativeFailure:
        raise NotRun("egress_fixture_unavailable") from None
    except (TypeError, ValueError):
        raise NotRun("egress_fixture_invalid") from None
    token = "sps-v5-" + uuid4().hex
    addresses = cast(Mapping[str, object], value["addresses"])
    active_address = cast(str, addresses[protocol])
    address = cast(str, value["unreachable_address"]) if probe == "fails_closed" else active_address
    proxy_config = {
        "protocol": protocol,
        "address": address,
        "username": token,
        "password": value["password"],
    }
    created = driver.call(
        "create",
        None,
        {
            "name": f"sps-v5-{uuid4().hex}",
            "requirements": dict(requirements),
            "egress_proxy": proxy_config,
        },
    )
    resource(created)
    host, port = (None, None) if probe == "fails_closed" else _tcp_endpoint(value)
    http_token, https_token, tcp_token = token + "-http", token + "-https", token + "-tcp"
    tcp_payload = ("sps-token=" + token + "-tcp;").encode() + PROXY_PAYLOAD
    guest_config = {
        "probe": probe,
        "proxy_url": address,
        "proxy_username": token,
        "proxy_password": value["password"],
        "ignore_proxy": probe == "transparent",
        "http_url": value["http_url"],
        "https_url": value["https_url"],
        "tcp_host": host,
        "tcp_port": port,
        "http_token": http_token,
        "https_token": https_token,
        "tcp_payload": tcp_payload.hex(),
    }
    observed = _guest_proxy(driver, created, guest_config)
    records = _records(value, token)
    source_address = cast(str, value["source_address"])
    proxy_recorded = _proxy_recorded(records)
    if probe == "routes":
        http_records = _records(value, http_token)
        https_records = _records(value, https_token)
        return {
            "http_reached": observed.get("http_reached") is True and _has_destination(http_records),
            "https_reached": observed.get("https_reached") is True
            and _has_destination(https_records),
            "http_source_is_proxy": proxy_recorded and _has_source(http_records, source_address),
            "https_source_is_proxy": proxy_recorded and _has_source(https_records, source_address),
        }
    if probe == "transparent":
        https_records = _records(value, https_token)
        return {
            "https_reached": observed.get("https_reached") is True
            and _has_destination(https_records),
            "https_source_is_proxy": proxy_recorded and _has_source(https_records, source_address),
        }
    if probe == "any_tcp":
        tcp_records = _records(value, tcp_token)
        return {
            "tcp_echo_received": observed.get("tcp_echo_received") is True
            and _has_destination(tcp_records),
            "tcp_source_is_proxy": proxy_recorded and _has_source(tcp_records, source_address),
        }
    http_records = _records(value, http_token)
    https_records = _records(value, https_token)
    # This probe requests traffic http, so a raw TCP connection is outside the gate.
    http_failed = (
        observed.get("http_outbound_failed") is True
        and observed.get("https_outbound_failed") is True
        and not _has_destination(http_records)
        and not _has_destination(https_records)
    )
    return {
        "http_outbound_failed": http_failed,
        "destination_unseen": http_failed,
    }
