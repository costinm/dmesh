#!/usr/bin/env python3
"""Run the persistent Main firmware flash server.

With no arguments this serves ``target/flash`` for ``main`` on port 3336 and
keeps listening for successive Recovery connections. Additional arguments use
the same options as recovery_tcp_server.py. ``--once`` is available for the
legacy per-board test helpers.
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
