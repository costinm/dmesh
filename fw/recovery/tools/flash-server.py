#!/usr/bin/env python3
"""Run the persistent DMesh resource/flash server.

With no arguments this serves ``target/flash`` with ``main`` as the fallback
target on port 3336 and keeps listening for successive connections. New
clients select Main, Recovery, stage2, or a named module in their HELLO;
older clients use the fallback. Additional arguments select the image root,
target, bind address, and transport policy.
"""

from __future__ import annotations

import sys

from recovery_tcp_server import main as protocol_main


if __name__ == "__main__":
    once = "--once" in sys.argv[1:]
    if once:
        sys.argv.remove("--once")
    if not once and "--forever" not in sys.argv[1:]:
        sys.argv.append("--forever")
    if "--fast-unsigned" not in sys.argv[1:] and "--signing-key" not in sys.argv[1:]:
        sys.argv.append("--fast-unsigned")
    raise SystemExit(protocol_main())
