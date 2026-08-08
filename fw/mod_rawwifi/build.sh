#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "$ROOT/env.sh"
TARGET="${1:-host}"
if [[ "$TARGET" == host ]]; then
  exec cargo test --manifest-path "$ROOT/fw/mod_rawwifi/Cargo.toml"
fi
echo "ESP image packaging is intentionally gated until the rawwifi service slot and loader entry are registered." >&2
echo "ABI/core validation passed only through: fw/mod_rawwifi/build.sh host" >&2
exit 2
