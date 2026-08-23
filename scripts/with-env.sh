#!/usr/bin/env bash
# Run one command with the repository-local development environment.
#
# Interactive shells source ../env.sh before starting Codex. Sandboxed command
# runners intentionally start without shell profiles, so use this wrapper for
# one-off commands instead of duplicating environment exports.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$script_dir/../env.sh"
exec "$@"
