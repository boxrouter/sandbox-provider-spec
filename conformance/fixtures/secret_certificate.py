# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Observe the verified TLS peer along the ordinary client's proxy path."""

import hashlib
import http.client
import json
import ssl
import urllib.request
from pathlib import Path

peer = {}


class Connection(http.client.HTTPSConnection):
    def connect(self):
        super().connect()
        peer.update(
            digest=hashlib.sha256(self.sock.getpeercert(binary_form=True)).hexdigest(),
            issuer=repr(self.sock.getpeercert()["issuer"]),
        )


class HTTPS(urllib.request.HTTPSHandler):
    def https_open(self, request):
        return self.do_open(Connection, request, context=self._context)


url = json.loads(Path("/tmp/sps-secret-certificate.json").read_text())["url"]
opener = urllib.request.build_opener(
    urllib.request.ProxyHandler(), HTTPS(context=ssl.create_default_context())
)
with opener.open(url, timeout=5):
    print(json.dumps(peer))
