#!/usr/bin/env python3
import argparse
import struct
from pathlib import Path

MAGIC = 0x444F4D44
ABI_VERSION = 4

def main():
    p = argparse.ArgumentParser()
    p.add_argument("input", type=Path)
    p.add_argument("output", type=Path)
    p.add_argument("--service-tag", type=int, default=45)
    p.add_argument("--slot-count", type=int, default=1)
    p.add_argument("--code-vma", type=lambda x: int(x, 0), default=0)
    p.add_argument("--data-vma", type=lambda x: int(x, 0), default=0)
    p.add_argument("--entry-offset", type=lambda x: int(x, 0), required=True)
    p.add_argument("--flags", type=lambda x: int(x, 0), default=0)
    args = p.parse_args()
    code = args.input.read_bytes()
    image_size = 64 + len(code)
    if not 43 <= args.service_tag <= 100:
        raise SystemExit("--service-tag must be in the reserved range 43..100")
    if args.slot_count < 1 or args.slot_count > 0xffff:
        raise SystemExit("--slot-count must be positive")
    header = struct.pack("<IHHIIHHIIIII24x", MAGIC, ABI_VERSION, 64,
                         args.entry_offset, image_size, args.service_tag,
                         args.slot_count, args.code_vma, args.data_vma,
                         8192, 0, args.flags)
    image = header + code
    image += b"\xff" * ((-len(image)) % 4)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(image)

if __name__ == "__main__":
    main()
