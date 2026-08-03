#!/usr/bin/env python3
"""Wrap a relocation-free flat module in the DMesh module header."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

MAGIC = 0x444F4D44  # little-endian bytes: DMOD
ABI_VERSION = 1
HEADER_SIZE = 64


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--name", default="hello")
    args = parser.parse_args()
    name = args.name.encode("ascii")
    if not name or len(name) > 15 or not all(32 <= byte < 127 for byte in name):
        raise SystemExit("module name must be 1..15 printable ASCII bytes")
    code = args.input.read_bytes()
    if not code:
        raise SystemExit("module code is empty")
    image_size = HEADER_SIZE + len(code)
    header = struct.pack("<IHHII16s32x", MAGIC, ABI_VERSION, HEADER_SIZE,
                         HEADER_SIZE, image_size, name + b"\0")
    image = header + code
    image += b"\xff" * ((-len(image)) % 4)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(image)


if __name__ == "__main__":
    main()
