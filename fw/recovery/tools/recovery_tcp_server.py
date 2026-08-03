#!/usr/bin/env python3
"""Serve a negotiated sparse image update to Main or Recovery."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import struct
import time
from pathlib import Path
from typing import Any

from device_flash_archive import append_event, device_dir, update_device, utc_now, write_json

ROOT = Path(__file__).resolve().parents[3]
MAGIC = 0x44525332  # DRS2
BLOCK_SIZE = 4096
MAX_BLOCKS = 1024
TYPES = {
    "hello": 1, "read-table": 2, "table": 3, "hash-query": 4,
    "hash-list": 5, "manifest": 6, "missing": 7, "block": 8,
    "ack": 9, "done": 10, "read-block": 11, "block-data": 12,
    "fast-unsigned": 15, "fast-ready": 16,
    "error": 255,
}
TARGETS = {"boot": 1, "stage2": 1, "partition": 2, "partition-table": 2,
           "recovery": 3, "nvs": 4, "data": 5, "main": 6, "module": 7}
LABELS = {"main": "main", "recovery": "recovery_app", "nvs": "nvs", "data": "data", "module": "data"}


def recv_all(sock: socket.socket, length: int) -> bytes:
    result = bytearray()
    while len(result) < length:
        part = sock.recv(length - len(result))
        if not part:
            raise RuntimeError("device closed the flash connection")
        result.extend(part)
    return bytes(result)


def frame(sock: socket.socket, kind: int, payload: bytes = b"") -> None:
    sock.sendall(struct.pack("!IHH", MAGIC, kind, len(payload)) + payload)


def read_frame(sock: socket.socket) -> tuple[int, bytes]:
    magic, kind, length = struct.unpack("!IHH", recv_all(sock, 8))
    if magic != MAGIC or kind == 0:
        raise RuntimeError(f"invalid DRS2 frame magic=0x{magic:08x} kind={kind}")
    return kind, recv_all(sock, length)


def parse_info(payload: bytes) -> dict[str, object]:
    if len(payload) not in (69, 71):
        raise RuntimeError(f"invalid DEVICE_INFO length={len(payload)}")
    info = {
        "model": payload[0], "revision": payload[1], "mac": payload[2:8].hex(":"),
        "role": payload[69] if len(payload) >= 71 else 0,
        "partition": payload[70] if len(payload) >= 71 else 0,
        "cpu_mhz": struct.unpack_from("!I", payload, 8)[0],
        "xtal_mhz": struct.unpack_from("!I", payload, 12)[0],
        "flash_size": struct.unpack_from("!I", payload, 16)[0],
        "dram_total": struct.unpack_from("!I", payload, 20)[0],
        "dram_free": struct.unpack_from("!I", payload, 24)[0],
        "psram_total": struct.unpack_from("!I", payload, 28)[0],
        "psram_free": struct.unpack_from("!I", payload, 32)[0],
        "key_present": bool(payload[36]), "key_sha256": payload[37:69].hex(),
    }
    return info


def parse_partitions(table: bytes, flash_size: int) -> list[dict[str, object]]:
    if len(table) != 0x1000:
        raise RuntimeError(f"invalid partition table length={len(table)}")
    partitions: list[dict[str, object]] = []
    for offset in range(0, 0xC00, 32):
        magic, part_type, subtype = struct.unpack_from("<HBB", table, offset)
        # ESP-IDF appends an MD5 checksum record after the partition entries.
        if magic in (0xFFFF, 0xEBEB):
            break
        if magic != 0x50AA:
            raise RuntimeError(f"invalid partition entry magic at 0x{offset:x}")
        address, size = struct.unpack_from("<II", table, offset + 4)
        label = table[offset + 12:offset + 28].split(b"\0", 1)[0].decode("ascii", "replace")
        if address + size > flash_size:
            raise RuntimeError(f"partition {label} exceeds flash size")
        partitions.append({"label": label, "type": part_type, "subtype": subtype,
                           "address": address, "size": size})
    return partitions


def parse_table(table: bytes, flash_size: int, target: str) -> tuple[int, int]:
    wanted = LABELS.get(target)
    if wanted is None:
        return 0, 0
    for partition in parse_partitions(table, flash_size):
        if partition["label"] == wanted:
            address = int(partition["address"])
            size = int(partition["size"])
            # The table reserves the first 256 KiB of data at the 4 MiB
            # boundary. On larger chips the remaining physical flash is also
            # available to Main/Recovery's explicit raw-data path; it is not a
            # different partition layout or image-selection namespace.
            if target in ("data", "module"):
                size = flash_size - address
            return address, size
    # Early 4 MiB boards reserve the final 256 KiB as the DRS2 raw module
    # area without a partition-table entry.  Match the firmware transport
    # rather than rejecting those deployed tables.
    if target in ("data", "module") and flash_size > 0x3C0000:
        return 0x3C0000, flash_size - 0x3C0000
    raise RuntimeError(f"partition {wanted!r} not found in device table")


def archive_initial(info: dict[str, object], hello: bytes, table: bytes) -> Path:
    mac = str(info["mac"])
    path = device_dir(mac)
    (path / "initial-message.bin").write_bytes(hello)
    (path / "partition-table.bin").write_bytes(table)
    update_device(mac, mac=mac, initial_message_length=len(hello),
                  last_seen=utc_now(), hello=info,
                  partitions=parse_partitions(table, int(info["flash_size"])),
                  partition_table_sha256=hashlib.sha256(table).hexdigest())
    return path


ACTIVE_FLASH: tuple[str, Path] | None = None


def finish_active(status: str, **fields: object) -> None:
    global ACTIVE_FLASH
    if ACTIVE_FLASH is None:
        return
    mac, path = ACTIVE_FLASH
    record = json.loads(path.read_text(encoding="utf-8"))
    record.update(fields, status=status, finished_at=utc_now())
    write_json(path, record)
    if status != "success":
        update_device(mac, last_flash_status=status)
    ACTIVE_FLASH = None


def load_signer(path: Path | None) -> tuple[bytes, Any | None]:
    if path is None:
        return bytes(32), None
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise RuntimeError("signing key must be a PEM P-256 private key")
    public = key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return hashlib.sha256(public).digest(), key


def sign_manifest(manifest: bytes, key: Any | None) -> bytes:
    if key is None:
        return bytes(64)
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    der = key.sign(manifest, ec.ECDSA(hashes.SHA256()))
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def target_image(path: Path, info: dict[str, object], target: str) -> Path:
    if path.is_file():
        return path
    if not path.is_dir():
        raise RuntimeError(f"image path is neither a file nor directory: {path}")
    model = int(info["model"])
    flash_size = int(info["flash_size"])
    chip = "esp32s3" if model == 9 else "esp32"
    # The Recovery/stage2 partition layout is always the canonical 4 MiB
    # layout. Physical flash size is reported for diagnostics and optional
    # Main raw-data use, not used to select a different image.
    keys = [chip]
    if target in ("boot", "stage2"):
        filenames = ["bootloader.bin", "stage2.bin", "boot.bin"]
    elif target in ("partition", "partition-table"):
        filenames = ["partition-table.bin", "partition.bin"]
    elif target == "main":
        filenames = ["main-app.bin", "main.bin"]
    elif target == "recovery":
        filenames = ["recovery.bin", "recovery-app.bin"]
    else:
        filenames = [f"{target}.bin", f"{target}-app.bin"]
    if target == "main":
        filenames.insert(0, "main-app.bin")
    candidates: list[Path] = []
    for key in keys:
        candidates.extend(path / key / filename for filename in filenames)
        candidates.extend([path / f"{key}-{filename}" for filename in filenames])
    # Keep the existing names working while making the processor/flash-size
    # directories above the preferred convention.
    for key in (f"recovery-{chip}", chip):
        candidates.extend(path / key / filename for filename in filenames)
    candidates.extend(path / target / f"{key}.bin" for key in keys)
    for candidate in candidates:
        if candidate.is_file():
            print(f"image-select chip={chip} physical_flash={flash_size} target={target} "
                  f"selected={candidate}", flush=True)
            return candidate
    tried = ", ".join(str(candidate.relative_to(path)) for candidate in candidates)
    raise RuntimeError(f"no image for chip={chip} physical_flash={flash_size} target={target} "
                       f"under {path}; tried: {tried}")


def update(sock: socket.socket, image_path: Path, target: str, signer_path: Path | None,
           sparse: bool = False, force_all: bool = False,
           fast_unsigned: bool = False, per_block_acks: bool = False) -> None:
    global ACTIVE_FLASH
    started_monotonic = time.monotonic()
    kind, hello = read_frame(sock)
    if kind != TYPES["hello"]:
        raise RuntimeError("device did not start with DEVICE_INFO")
    info = parse_info(hello)
    print("device", info, flush=True)
    # Recovery executes from recovery_app and must never be asked to overwrite
    # that same partition.  Main is the updater for Recovery; rejecting this
    # before sending a manifest keeps a bad target selection from turning into
    # a self-erasing device.
    if target == "recovery" and int(info.get("role", 0)) == 2:
        raise RuntimeError("refusing recovery self-update; start this transfer from Main")
    frame(sock, TYPES["read-table"])
    kind, table = read_frame(sock)
    if kind != TYPES["table"]:
        raise RuntimeError("device did not return partition table")
    archive_path = archive_initial(info, hello, table)
    peer = sock.getpeername()
    update_device(str(info["mac"]), last_recovery_ip=peer[0],
                  last_recovery_peer=repr(peer))
    session_path = archive_path / "flashes" / f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}.json"
    session_path.parent.mkdir(exist_ok=True)
    record: dict[str, object] = {"started_at": utc_now(), "status": "started",
                                 "target": target, "peer": repr(sock.getpeername()),
                                 "image_request": str(image_path)}
    write_json(session_path, record)
    ACTIVE_FLASH = (str(info["mac"]), session_path)
    address, partition_size = parse_table(table, int(info["flash_size"]), target)
    image = target_image(image_path, info, target)
    image_size = image.stat().st_size
    if target not in ("boot", "stage2", "partition", "partition-table") and image_size > partition_size:
        raise RuntimeError(f"image {image_size} exceeds {target} partition {partition_size}")
    if image_size == 0 or image_size > MAX_BLOCKS * BLOCK_SIZE or image_size % 4:
        raise RuntimeError(f"unsupported image size={image_size}")
    count = (image_size + BLOCK_SIZE - 1) // BLOCK_SIZE
    table_sha = hashlib.sha256(table).digest()
    block_hashes: list[bytes] = []
    full = hashlib.sha256()
    blocks: list[bytes] = []
    with image.open("rb") as stream:
        for _ in range(count):
            block = stream.read(BLOCK_SIZE)
            if not block:
                raise RuntimeError("image ended before expected block count")
            blocks.append(block); full.update(block)
            block_hashes.append(hashlib.sha256(block).digest()[:4])
    key_fp, key = load_signer(signer_path)
    query = struct.pack("!B3xIIII", TARGETS[target], 0, BLOCK_SIZE, count, image_size)
    fast_mode = fast_unsigned and not bool(info["key_present"])
    if fast_mode:
        # Unsigned bootstrap extension: the device has no trust root, so it
        # intentionally accepts the complete image without hash-list or
        # per-block SHA/readback work. This is never selected for a keyed
        # device, and the legacy path remains available for old Recovery.
        manifest_head = struct.pack(
            "!BBBBIIII", TARGETS[target], 0, 0, 0, 0, BLOCK_SIZE, count, image_size
        ) + table_sha + full.digest() + bytes(32)
        frame(sock, TYPES["fast-unsigned"], manifest_head)
        kind, ready = read_frame(sock)
        if kind != TYPES["fast-ready"] or len(ready) != 4 or struct.unpack("!I", ready)[0] != count:
            raise RuntimeError("invalid unsigned-fast acknowledgement")
        missing = [True] * count
        protocol = "unsigned-fast"
    else:
        frame(sock, TYPES["hash-query"], query)
        kind, hashes_payload = read_frame(sock)
        if kind != TYPES["hash-list"] or hashes_payload[:20] != query or len(hashes_payload) != 20 + count * 4:
            raise RuntimeError("invalid device hash list")
        device_hashes = [hashes_payload[20 + i * 4:24 + i * 4] for i in range(count)]
        device_hashes_sha = hashlib.sha256(hashes_payload[20:]).hexdigest()
        write_json(archive_path / "current-hashes.json", {
            "captured_at": utc_now(), "target": target, "address": address,
            "block_size": BLOCK_SIZE, "count": count, "image_size": image_size,
            "short_sha256": device_hashes_sha,
            "block_sha256_truncated": [value.hex() for value in device_hashes],
        })
        missing = [force_all or device_hashes[index] != block_hashes[index] for index in range(count)]
        protocol = "sparse" if sparse else "legacy"
    if not fast_mode and sparse:
        # Extension manifest: fixed header, then only changed entries. Each
        # entry signs a relative byte offset, length, and truncated SHA-256.
        manifest_head = struct.pack(
            "!BBBBIIIII", TARGETS[target], 0, 1 if not per_block_acks else 0, 0, 0, BLOCK_SIZE, count,
            image_size, sum(missing)
        )
        manifest_head += table_sha + full.digest() + key_fp
        manifest_body = manifest_head + b"".join(
            struct.pack("!II", index * BLOCK_SIZE, len(blocks[index])) + block_hashes[index]
            for index in range(count) if missing[index]
        )
        frame(sock, 13, manifest_body + sign_manifest(manifest_body, key))
        kind, ready = read_frame(sock)
        if kind != 14 or len(ready) != 4 or struct.unpack("!I", ready)[0] != sum(missing):
            raise RuntimeError("invalid sparse manifest acknowledgement")
    elif not fast_mode:
        manifest_head = struct.pack(
            "!BBBBIIII", TARGETS[target], 0, 1 if not per_block_acks else 0,
            0, 0, BLOCK_SIZE, count, image_size
        )
        manifest_head += table_sha + full.digest() + key_fp
        manifest_body = manifest_head + b"".join(block_hashes)
        frame(sock, TYPES["manifest"], manifest_body + sign_manifest(manifest_body, key))
        kind, missing_payload = read_frame(sock)
        if kind != TYPES["missing"] or missing_payload[:20] != query:
            raise RuntimeError(
                "invalid device missing-block response "
                f"kind={kind} length={len(missing_payload)} "
                f"head={missing_payload[:32].hex()} expected={query.hex()}"
            )
        missing = [bool(missing_payload[20 + i // 8] & (1 << (i % 8))) for i in range(count)]
    print(f"image={image} target={target} protocol={protocol} "
          f"address=0x{address:x} size={image_size} "
          f"missing={sum(missing)}/{count} key_sha256={key_fp.hex()}", flush=True)
    # Stream all missing blocks without waiting for an ACK after each one.
    # Recovery still receives, verifies, erases, and writes one block at a
    # time; TCP flow control limits how far the host can get ahead. This
    # avoids a host/device round trip for every 4 KiB block without requiring
    # a multi-block buffer in Recovery.
    sent_indices: list[int] = []
    for index, block in enumerate(blocks):
        if not missing[index]:
            continue
        payload = struct.pack("!B3xII", TARGETS[target], index, len(block)) + block
        frame(sock, TYPES["block"], payload)
        sent_indices.append(index)
    if per_block_acks and not fast_mode:
        for expected in sent_indices:
            kind, ack = read_frame(sock)
            if kind != TYPES["ack"] or len(ack) < 5 or struct.unpack_from("!I", ack)[0] != expected:
                raise RuntimeError(f"device rejected block {expected}")
    if not fast_mode:
        # The first hash list selects missing blocks. Query again after writing
        # and compare every block explicitly; this is an independent check.
        frame(sock, TYPES["hash-query"], query)
        kind, verified_payload = read_frame(sock)
        if kind != TYPES["hash-list"] or verified_payload[:20] != query:
            raise RuntimeError("invalid post-write device hash list")
        if len(verified_payload) != 20 + count * 4:
            raise RuntimeError("truncated post-write device hash list")
        verified = [verified_payload[20 + i * 4:24 + i * 4] for i in range(count)]
        if verified != block_hashes:
            mismatches = [i for i, (actual, expected) in enumerate(zip(verified, block_hashes))
                          if actual != expected]
            raise RuntimeError(f"post-write block SHA mismatch at blocks {mismatches[:8]}")
        print(f"post-write block SHA verification passed: {count} blocks", flush=True)
    else:
        print("unsigned-fast mode: SHA verification skipped", flush=True)
    frame(sock, TYPES["done"])
    kind, result = read_frame(sock)
    if kind != TYPES["done"]:
        raise RuntimeError(f"device final verification failed: frame={kind} payload={result!r}")
    image_sha = full.digest().hex()
    (archive_path / "current.sha256").write_text(image_sha + "\n", encoding="ascii")
    update_device(str(info["mac"]), last_seen=utc_now(), last_flash=utc_now(),
                  last_flash_status="success", current_sha256=image_sha,
                  current_target=target, current_size=image_size)
    finish_active("success", image_sha256=image_sha, image_size=image_size,
                  blocks=count, blocks_sent=sum(missing), address=address,
                  partition_size=partition_size, image=str(image),
                  elapsed_sec=round(time.monotonic() - started_monotonic, 3))
    elapsed_sec = time.monotonic() - started_monotonic
    print(f"negotiated transfer complete: {image_size} bytes, {sum(missing)} blocks sent "
          f"elapsed={elapsed_sec:.3f}s rate={image_size * 8 / elapsed_sec / 1000:.1f} kbit/s", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", nargs="?", type=Path, default=ROOT / "target" / "flash",
                        help="image file or top-level image directory (default: target/flash)")
    parser.add_argument("--target", default="main", choices=sorted(TARGETS))
    parser.add_argument("--signing-key", type=Path)
    parser.add_argument("--sparse", action="store_true",
                        help="use the host-selected sparse-manifest extension; legacy is default")
    parser.add_argument("--force-all", action="store_true",
                        help="diagnostic: rewrite every image block even when hashes match")
    parser.add_argument("--fast-unsigned", action="store_true",
                        help="when the device has no trust key, send all blocks without SHA verification")
    parser.add_argument("--per-block-acks", action="store_true",
                        help="legacy compatibility: wait for an ACK after every block")
    parser.add_argument("--bind", default="10.78.0.1")
    parser.add_argument("--port", type=int, default=3336)
    parser.add_argument("--forever", action="store_true",
                        help="keep the listener running for successive board updates")
    parser.add_argument("--socket-activation", action="store_true",
                        help="use systemd LISTEN_FDS descriptor 3 instead of binding")
    args = parser.parse_args()
    activated = args.socket_activation or (
        os.environ.get("LISTEN_PID") == str(os.getpid()) and
        int(os.environ.get("LISTEN_FDS", "0")) >= 1
    )
    if activated:
        if os.environ.get("LISTEN_PID") not in (None, str(os.getpid())):
            raise RuntimeError("systemd LISTEN_PID does not match flash server")
        server = socket.fromfd(3, socket.AF_INET, socket.SOCK_STREAM)
        print(f"using systemd listener fd=3 for negotiated {args.target}", flush=True)
    else:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((args.bind, args.port)); server.listen(8)
        print(f"listening on {args.bind}:{args.port} for negotiated {args.target}", flush=True)
    with server:
        while True:
            client, peer = server.accept()
            with client:
                client.settimeout(180.0)
                print(f"accepted {peer}", flush=True)
                try:
                    update(client, args.image, args.target, args.signing_key,
                           args.sparse, args.force_all, args.fast_unsigned,
                           args.per_block_acks)
                except Exception as error:  # noqa: BLE001 - daemon must survive one bad device
                    finish_active("failed", error=str(error))
                    print(f"update failed for {peer}: {error}", flush=True)
                    if not args.forever:
                        raise
            if not args.forever:
                break
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
