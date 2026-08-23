#!/usr/bin/env bash
# Local module flashing uses the same verified esptool path as Main.
set -euo pipefail
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$repo_dir/env.sh"
exec python3 "$repo_dir/scripts/flash-device.py" \
  "${1:-lora4}" module --module "${2:-lora}"
