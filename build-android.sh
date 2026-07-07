#!/bin/bash
# Compatibility wrapper for the DMesh Android build harness.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$SCRIPT_DIR/scripts/build-android.sh" "$@"
