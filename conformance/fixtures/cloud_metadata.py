# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Read documented host IMDS paths; emit no identity or credential values."""

import concurrent.futures
import json
import socket
import time
import urllib.error
import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *arguments, **keywords):
        return None


def identifies_host(path, body, headers):
    """Recognize cloud identity formats, allowing a provider's own metadata."""
    try:
        value = json.loads(body)
    except (ValueError, UnicodeError):
        value = None
    if isinstance(value, dict):
        if {"instanceId", "accountId", "region"} <= value.keys():
            return True
        if {"AccessKeyId", "SecretAccessKey", "Token"} <= value.keys():
            return True
        compute = value.get("compute")
        if isinstance(compute, dict) and {"vmId", "subscriptionId"} <= compute.keys():
            return True
        if (
            path.startswith(("/metadata/identity/", "/computeMetadata/v1/"))
            and {"access_token", "token_type"} <= value.keys()
        ):
            return True
    if (
        path.startswith("/computeMetadata/v1/")
        and headers.get("Metadata-Flavor", "").lower() == "google"
    ):
        return bool(body.strip())
    return False


REQUEST_TIMEOUT_S = 2.0
CONNECT_TIMEOUT_S = 0.25
BUDGET_S = 3.5
"""Wall-clock bound on the whole probe.

The baseline runs this inside one ordinary command whose observation window can be as short as
five seconds. An unreachable link-local address silently drops packets, so a serial probe of
many requests, each waiting out its own timeout, would outlast that window and report only a
failed exchange. The requests are independent, so they run concurrently in a few phases, and no
request starts a wait that would pass the budget. Every path the serial probe asked is still
asked; a request that cannot be sent in time counts as not exposed, as a timeout always did."""

_AWS_ROLES = "/latest/meta-data/iam/security-credentials/"
_PATHS = [
    ("/computeMetadata/v1/instance/id", {"Metadata-Flavor": "Google"}),
    ("/computeMetadata/v1/project/project-id", {"Metadata-Flavor": "Google"}),
    ("/computeMetadata/v1/instance/service-accounts/default/token", {"Metadata-Flavor": "Google"}),
    ("/metadata/instance?api-version=2021-02-01", {"Metadata": "true"}),
    (
        "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F",
        {"Metadata": "true"},
    ),
]
_AWS_DOCUMENT = "/latest/dynamic/instance-identity/document"


def exposed():
    started = time.monotonic()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)

    def remaining():
        return BUDGET_S - (time.monotonic() - started)

    def request(host, path, headers=None, method="GET"):
        wait = min(REQUEST_TIMEOUT_S, remaining())
        if wait <= 0.05:
            return b"", {}
        req = urllib.request.Request("http://" + host + path, headers=headers or {}, method=method)
        try:
            with opener.open(req, timeout=wait) as response:
                return response.read(65536), response.headers
        except (urllib.error.URLError, TimeoutError, OSError):
            return b"", {}

    def answers(host, calls):
        """Run independent requests concurrently; return their results in order."""
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(calls))) as pool:
            return list(pool.map(lambda call: request(host, *call), calls))

    def listens(address):
        try:
            with socket.create_connection((address, 80), timeout=CONNECT_TIMEOUT_S):
                return True
        except OSError:
            return False

    def role_names(body):
        try:
            names = body.decode().splitlines()
        except UnicodeError:
            return []
        # A role listing is not itself a credential; read its documented path.
        return [
            name
            for name in names[:4]
            if name and len(name) <= 128 and all(c.isalnum() or c in "-_.+=,@" for c in name)
        ]

    def host_exposed(host):
        # First wave: the token request and every request that needs no token. The AWS document
        # and role listing are asked without a token too, which is what an IMDSv1 service
        # answers; with a token they are asked again in the second wave.
        wave = [
            (_AWS_DOCUMENT, {}),
            (_AWS_ROLES, {}),
            *_PATHS,
            (
                "/latest/api/token",
                {"X-aws-ec2-metadata-token-ttl-seconds": "60"},
                "PUT",
            ),
        ]
        *results, (token, _) = answers(host, wave)
        calls = [(path, headers) for (path, headers), _ in zip(wave[:-1], results, strict=True)]
        checked = list(
            zip(calls, [body for body, _ in results], [h for _, h in results], strict=True)
        )
        names = role_names(results[1][0])
        if token and len(token) <= 2048 and all(33 <= c <= 126 for c in token):
            aws_headers = {"X-aws-ec2-metadata-token": token.decode("ascii")}
            again = [(_AWS_DOCUMENT, aws_headers), (_AWS_ROLES, aws_headers)]
            second = answers(host, again)
            checked += [
                (call, body, headers) for call, (body, headers) in zip(again, second, strict=True)
            ]
            names = names or role_names(second[1][0])
            role_headers = aws_headers
        else:
            role_headers = {}
        role_calls = [
            (_AWS_ROLES + urllib.parse.quote(name, safe=""), role_headers) for name in names
        ]
        for call, (body, headers) in zip(role_calls, answers(host, role_calls), strict=True):
            checked.append((call, body, headers))
        return any(identifies_host(call[0], body, headers) for call, body, headers in checked)

    hosts = ["169.254.169.254"]
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        v6 = ("fd00:ec2::254", "fd20:ce::254")
        hosts += ["[" + a + "]" for a, up in zip(v6, pool.map(listens, v6), strict=True) if up]
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(hosts)) as pool:
        return any(pool.map(host_exposed, hosts))
