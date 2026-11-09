#!/usr/bin/env bash
# Runs the unit tests (Swift Testing). Extra arguments go to `swift test`, e.g. ./test.sh --filter Version
set -euo pipefail
cd "$(dirname "$0")"

source Scripts/select-sdk.sh

# With Command Line Tools 27.2, Swift Build sometimes fails to load the Swift Testing macro plugin
# ("plugin for module 'TestingMacros' not found") for a few files, then compiles them fine on the
# next run. Retry only that failure, at most twice.
LOG=$(mktemp)
trap 'rm -f "$LOG"' EXIT
for ATTEMPT in 1 2 3; do
    if swift test "$@" 2>&1 | tee "$LOG"; then
        exit 0
    fi
    if (( ATTEMPT == 3 )) || ! grep -q "plugin for module 'TestingMacros' not found" "$LOG"; then
        exit 1
    fi
    echo "Note: Swift Build couldn't load the Swift Testing macro plugin; building again (attempt $((ATTEMPT + 1)) of 3)."
done
