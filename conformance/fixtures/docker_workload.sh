#!/usr/bin/env bash
# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
set -u

mode="$1"
image="$2"
url="$3"

if ! command -v docker >/dev/null 2>&1; then
    printf '{"not_run":"docker_fixture_cli_missing"}\n'
    exit 0
fi

name="sps-$(cat /proc/sys/kernel/random/uuid | tr -d '-')"
port=38741
marker="sps-docker-$(cat /proc/sys/kernel/random/uuid | tr -d '-')"
created=false

cleanup() {
    if [ "$created" = true ]; then
        removal_failed=false
        if ! timeout 30 docker rm --force "$name" >/dev/null 2>&1; then
            removal_failed=true
        fi
        if ! remaining="$(timeout 30 docker container ls --all --quiet --filter "name=^/${name}$")"; then
            echo 'owned Docker container cleanup not confirmed' >&2
            exit 1
        fi
        if [ "$removal_failed" = true ] || [ -n "$remaining" ]; then
            echo 'owned Docker container cleanup not confirmed' >&2
            exit 1
        fi
    fi
}
trap cleanup EXIT

deadline=$((SECONDS + 60))
until timeout 5 docker info >/dev/null 2>&1; do
    if [ "$SECONDS" -ge "$deadline" ]; then
        printf '{"outbound":false,"published_reachable":false,"network_mode_matches":false}\n'
        exit 0
    fi
    sleep 1
done

if ! timeout 120 docker pull "$image" >/dev/null 2>&1; then
    printf '{"not_run":"docker_fixture_image_unavailable"}\n'
    exit 0
fi

server="from http.server import BaseHTTPRequestHandler,HTTPServer; H=type('H',(BaseHTTPRequestHandler,),{'do_GET':lambda s:(s.send_response(200),s.end_headers(),s.wfile.write(b'$marker')),'log_message':lambda *a:None}); HTTPServer(('0.0.0.0',$port),H).serve_forever()"
options=(--network "$mode")
if [ "$mode" = bridge ]; then
    options+=(--publish "127.0.0.1:$port:$port")
fi
created=true
if ! timeout 30 docker run --detach --name "$name" "${options[@]}" "$image" python3 -c "$server" >/dev/null; then
    printf '{"outbound":false,"published_reachable":false,"network_mode_matches":false}\n'
    exit 0
fi
created=true

selected="$(timeout 30 docker inspect --format '{{.HostConfig.NetworkMode}}' "$name" 2>/dev/null || true)"
if [ "$selected" = "$mode" ]; then mode_matches=true; else mode_matches=false; fi

reachable=false
for _ in {1..30}; do
    if exec 3<>"/dev/tcp/127.0.0.1/$port" 2>/dev/null; then
        printf 'GET / HTTP/1.0\r\n\r\n' >&3
        response="$(timeout 2 cat <&3 2>/dev/null || true)"
        exec 3>&-
        if [[ "$response" == *"$marker"* ]]; then
            reachable=true
            break
        fi
    fi
    sleep 0.2
done

if timeout 30 docker exec -e "SPS_URL=$url" "$name" python3 -c 'import os,urllib.request; urllib.request.build_opener(urllib.request.ProxyHandler({})).open(os.environ["SPS_URL"],timeout=10).read(1)' >/dev/null 2>&1; then
    outbound=true
else
    outbound=false
fi
printf '{"outbound":%s,"published_reachable":%s,"network_mode_matches":%s}\n' "$outbound" "$reachable" "$mode_matches"
