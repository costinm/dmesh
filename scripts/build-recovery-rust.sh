#!/usr/bin/env bash
# fw/recovery-rust was removed on 2026-10-10 (history: git log -- fw/recovery-rust). Its README,
# settings and size notes are archived in the esp-wifi-loader repository
# (docs/recovery-rust-lessons.md); the loader that replaces it builds there with scripts/build.sh.
echo "build-recovery-rust.sh: fw/recovery-rust no longer exists; build the loader in esp-wifi-loader (scripts/build.sh)" >&2
exit 1
