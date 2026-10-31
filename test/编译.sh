#!/bin/sh
set -e

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
NDK_BUILD_BIN="${NDK_BUILD:-ndk-build}"

"$NDK_BUILD_BIN" NDK_PROJECT_PATH="$SCRIPT_DIR" -j"$(nproc)" "$@"
