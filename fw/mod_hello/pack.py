#!/usr/bin/env python3
"""Wrap a relocation-free flat module in the DMesh module header."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

MAGIC = 0x444F4D44  # little-endian bytes: DMOD
ABI_VERSION = 2
HEADER_SIZE = 64
DEFAULT_STACK_WORDS = 4096


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--name", default="hello")
    parser.add_argument("--stack-words", type=int, default=DEFAULT_STACK_WORDS)
    parser.add_argument("--flags", type=lambda value: int(value, 0), default=0)
    parser.add_argument("--entry-offset", type=lambda value: int(value, 0),
                        default=HEADER_SIZE,
                        help="linked entry offset in the flat image (default: 0x40)")
    args = parser.parse_args()
    name = args.name.encode("ascii")
    if not name or len(name) > 15 or not all(32 <= byte < 127 for byte in name):
        raise SystemExit("module name must be 1..15 printable ASCII bytes")
    code = args.input.read_bytes()
    if not code:
        raise SystemExit("module code is empty")
    if args.stack_words < 1 or args.stack_words > 32768:
        raise SystemExit("--stack-words must be between 1 and 32768")
    if (args.entry_offset < HEADER_SIZE or args.entry_offset % 4 or
            args.entry_offset >= HEADER_SIZE + len(code)):
        raise SystemExit("--entry-offset must be aligned, inside the image, and after the header")
    image_size = HEADER_SIZE + len(code)
    header = struct.pack("<IHHII16sIII20x", MAGIC, ABI_VERSION, HEADER_SIZE,
                         args.entry_offset, image_size, name + b"\0",
                         args.stack_words, 0, args.flags)
    image = header + code
    image += b"\xff" * ((-len(image)) % 4)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(image)


if __name__ == "__main__":
    main()
