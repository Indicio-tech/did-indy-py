#!/usr/bin/env python
"""Healthcheck."""

import socket
import sys

if len(sys.argv) < 3:
    print("USAGE: python healthcheck.py <HOST> <PORT>")

host = sys.argv[1]
port = int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sys.exit(s.connect_ex((host, port)))
