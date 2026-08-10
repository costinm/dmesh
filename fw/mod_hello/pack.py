#!/usr/bin/env python3
"""Wrap a relocation-free flat module in the DMesh module header."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

MAGIC = 0x444F4D44  # little-endian bytes: DMOD
ABI_VERSION = 4
HEADER_SIZE = 64
DEFAULT_STACK_WORDS = 4096


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--service-tag", type=int, required=True)
    parser.add_argument("--slot-count", type=int, default=1)
    parser.add_argument("--code-vma", type=lambda value: int(value, 0), default=0)
    parser.add_argument("--data-vma", type=lambda value: int(value, 0), default=0)
    parser.add_argument("--stack-words", type=int, default=DEFAULT_STACK_WORDS)
    parser.add_argument("--flags", type=lambda value: int(value, 0), default=0)
    parser.add_argument("--entry-offset", type=lambda value: int(value, 0),
                        default=HEADER_SIZE,
                        help="linked entry offset in the flat image (default: 0x40)")
    args = parser.parse_args()
    if not 43 <= args.service_tag <= 100:
        raise SystemExit("--service-tag must be in the reserved range 43..100")
    if args.slot_count < 1 or args.slot_count > 0xffff:
        raise SystemExit("--slot-count must be positive")
    code = args.input.read_bytes()
    if not code:
        raise SystemExit("module code is empty")
    if args.stack_words < 1 or args.stack_words > 32768:
        raise SystemExit("--stack-words must be between 1 and 32768")
    if (args.entry_offset < HEADER_SIZE or args.entry_offset % 4 or
            args.entry_offset >= HEADER_SIZE + len(code)):
        raise SystemExit("--entry-offset must be aligned, inside the image, and after the header")
    image_size = HEADER_SIZE + len(code)
    header = struct.pack("<IHHIIHHIIIII24x", MAGIC, ABI_VERSION, HEADER_SIZE,
                         args.entry_offset, image_size, args.service_tag,
                         args.slot_count, args.code_vma, args.data_vma,
                         args.stack_words, 0, args.flags)
    image = header + code
    image += b"\xff" * ((-len(image)) % 4)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(image)


if __name__ == "__main__":
    main()
