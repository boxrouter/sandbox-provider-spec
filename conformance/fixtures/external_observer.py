# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Bounded outside observer; input is private and output contains no credential."""

import hashlib
import json
import socket
import ssl
import sys
import urllib.parse
import urllib.request

config = json.load(sys.stdin)
url = config["url"]
if config["probe"] == "counts":
    request = urllib.request.Request(url, headers=config["headers"])
    context = ssl.create_default_context()
    if config.get("ca_pem"):
        context.load_verify_locations(cadata=config["ca_pem"])
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context)
    )
    with opener.open(request, timeout=5) as response:
        print(json.dumps({"counts": json.loads(response.read(1024))["counts"]}))
elif config["probe"] == "preview":
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url, timeout=5) as response:
        print(json.dumps({"matched": response.read(256) == b"sps-preview-proof"}))
elif config["probe"] == "certificate":
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("HTTPS fixture required")
    with socket.create_connection((parsed.hostname, parsed.port or 443), timeout=5) as plain:
        with ssl.create_default_context().wrap_socket(
            plain, server_hostname=parsed.hostname
        ) as peer:
            print(
                json.dumps(
                    {
                        "digest": hashlib.sha256(peer.getpeercert(binary_form=True)).hexdigest(),
                        "issuer": repr(peer.getpeercert()["issuer"]),
                    }
                )
            )
else:
    raise ValueError("unknown observer")
