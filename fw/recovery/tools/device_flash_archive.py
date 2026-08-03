#!/usr/bin/env python3
"""Small shared archive helpers for per-device flash diagnostics."""

from __future__ import annotations

import json
import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
ARCHIVE_ROOT = Path(
    os.environ.get("DMESH_FLASH_ARCHIVE_DIR", str(ROOT / "target" / "flash-devices"))
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def mac_key(mac: str) -> str:
    """Return a filesystem-safe, stable MAC directory name."""
    return mac.lower().replace(":", "").replace("-", "")


def device_dir(mac: str) -> Path:
    path = ARCHIVE_ROOT / mac_key(mac)
    path.mkdir(parents=True, exist_ok=True)
    return path


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def update_device(device_mac: str, **fields: Any) -> Path:
    path = device_dir(device_mac) / "device.json"
    value = read_json(path, {})
    if not isinstance(value, dict):
        value = {}
    value.update(fields)
    write_json(path, value)
    return path


def append_event(mac: str, event: dict[str, Any]) -> Path:
    path = device_dir(mac) / "flash-history.jsonl"
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(event, sort_keys=True) + "\n")
    return path


def record_flash(mac: str, target: str, images: list[tuple[str, Path]]) -> None:
    """Record verified flash inputs and expose their SHA-256 values."""
    now = utc_now()
    entries = []
    lines = []
    for offset, image in images:
        digest = hashlib.sha256(image.read_bytes()).hexdigest()
        size = image.stat().st_size
        entries.append({"offset": offset, "path": str(image), "size": size, "sha256": digest})
        lines.append(f"{target} {offset} {digest} {size} {image}\n")
    path = device_dir(mac)
    (path / "current.sha256").write_text("".join(lines), encoding="ascii")
    update_device(mac, last_flash=now, last_flash_status="success",
                  current_target=target, current_images=entries)
    append_event(mac, {"event": "flash", "at": now, "status": "success",
                        "target": target, "images": entries})
