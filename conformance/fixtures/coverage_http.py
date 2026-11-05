# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Proxy-free HTTP reachability with DNS inside an outer process deadline."""

import json
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


def request(url):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(url, timeout=5) as response:
            response.read(1)
            return {"reached": 200 <= response.status < 300, "ambiguous": False}
    except urllib.error.HTTPError:
        # A non-2xx response does not prove an allowed request reached its
        # intended endpoint; native egress proxies may generate the response.
        return {"reached": False, "ambiguous": False}
    except urllib.error.URLError as error:
        return {
            "reached": False,
            "ambiguous": isinstance(error.reason, ssl.SSLCertVerificationError),
        }
    except (TimeoutError, ConnectionError, socket.gaierror):
        return {"reached": False, "ambiguous": False}


if __name__ == "__main__":
    if len(sys.argv) == 2:
        print(json.dumps(request(sys.argv[1])))
    else:
        results = []
        for url in json.load(sys.stdin)["urls"]:
            try:
                result = subprocess.run(
                    [sys.executable, __file__, url],
                    capture_output=True,
                    timeout=8,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                results.append({"reached": False, "ambiguous": False})
                continue
            if result.returncode != 0 or len(result.stdout) > 256:
                raise RuntimeError("invalid HTTP probe")
            results.append(json.loads(result.stdout))
        print(json.dumps({"results": results}))
