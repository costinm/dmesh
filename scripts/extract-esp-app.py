#!/usr/bin/env python3
"""Extract one raw ESP application image from a merged flash image."""

from __future__ import annotations

import argparse
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("merged", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--offset", type=lambda value: int(value, 0), required=True)
    args = parser.parse_args()

    data = args.merged.read_bytes()
    if args.offset >= len(data) or data[args.offset] != 0xE9:
        raise SystemExit(f"no ESP image header at 0x{args.offset:x} in {args.merged}")
    app = data[args.offset:]
    while app and app[-1] == 0xFF:
        app = app[:-1]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(app)
    print(f"extracted {len(app)} bytes: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
