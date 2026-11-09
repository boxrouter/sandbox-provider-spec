# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Ordinary guest test code: root tries native Linux network mutations."""

import errno
import os
import shutil
import socket
import struct
import subprocess

if os.geteuid() != 0:
    raise SystemExit(77)
for program, arguments in [("iptables", ["-F"]), ("nft", ["flush", "ruleset"])]:
    if shutil.which(program):
        subprocess.run([program, *arguments], timeout=5, capture_output=True, check=False)

# Root's route mutations use stdlib netlink, so missing CLI tools cannot skip
# the attempted privileged operation. A native EPERM is a valid refusal.
try:
    net = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
    net.settimeout(2)
    net.bind((0, 0))
    net.send(
        struct.pack("IHHII", 28, 26, 0x301, 1, 0)
        + struct.pack("BBBBBBBBI", 2, 0, 0, 0, 254, 0, 0, 0, 0)
    )
    routes = []
    done = False
    while not done:
        packet = net.recv(65536)
        while packet:
            length, kind, flags, sequence, pid = struct.unpack("IHHII", packet[:16])
            body = packet[16:length]
            if kind in (2, 3):
                done = True
            elif kind == 24 and body[0] == 2 and body[1] == 0:
                routes.append(body)
            packet = packet[(length + 3) & ~3 :]
    for sequence, body in enumerate(routes, 2):
        net.send(struct.pack("IHHII", len(body) + 16, 25, 5, sequence, 0) + body)
        reply = net.recv(65536)
        if struct.unpack("IHHII", reply[:16])[1] == 2 and struct.unpack("i", reply[16:20])[0] == 0:
            # Restore the route: the test targets lockdown, not accidental loss of
            # all connectivity caused by its own routing change.
            net.send(struct.pack("IHHII", len(body) + 16, 24, 0x605, sequence + 100, 0) + body)
            restored = net.recv(65536)
            if (
                struct.unpack("IHHII", restored[:16])[1] != 2
                or struct.unpack("i", restored[16:20])[0] != 0
            ):
                raise RuntimeError("route restoration was not confirmed")
    net.close()
except OSError as error:
    if error.errno not in {
        errno.EPERM,
        errno.EACCES,
        errno.EOPNOTSUPP,
        errno.EPROTONOSUPPORT,
        errno.EAFNOSUPPORT,
        errno.ENODEV,
        errno.ENOSYS,
    }:
        raise

try:
    with open("/etc/resolv.conf") as resolver:
        original = resolver.read()
    with open("/etc/resolv.conf", "w") as resolver:
        resolver.write("nameserver 1.1.1.1\n")
    with open("/etc/resolv.conf", "w") as resolver:
        resolver.write(original)
except OSError as error:
    if error.errno not in {errno.EPERM, errno.EACCES, errno.EROFS}:
        raise
print("root-attempted")
