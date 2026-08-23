#!/usr/bin/env bash
# Main-image USB flashing is intentionally disabled.
#
# Main and module updates use the verified local flasher for attached boards.
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$repo_dir/env.sh"

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    echo "Main/module flashing:"
    echo "  scripts/flash-device.py <role> main"
    echo "  scripts/flash-device.py <role> module --module lora"
    echo "Stage-2 USB provisioning:"
    echo "  scripts/flash-device.py <role> stage"
    echo "Rust Recovery USB provisioning is frozen (emergency rollback only)."
    exit 0
fi

echo "Usage: scripts/flash-device.py <role> main|module [--module NAME]" >&2
exit 2
