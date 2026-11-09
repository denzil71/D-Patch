#!/usr/bin/env bash
# Runs D-Patch against generated demo data, so the UI can be tested without real CVEs.
# Usage: Scripts/demo.sh [--build] [--scan-only] [--home DIR] [--fixtures DIR]
#   --build        rebuild build/D-Patch.app first (otherwise only builds when it is missing)
#   --scan-only    generate and scan the demo data, then exit without opening the app
#   --home DIR     demo data home (default: build/demo/home)
#   --fixtures DIR demo fixture directory (default: build/demo/fixtures)
set -euo pipefail
cd "$(dirname "$0")/.."

BUILD=0
SCAN_ONLY=0
DEMO_DIR="build/demo"
FIXTURES=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --build) BUILD=1; shift ;;
        --scan-only) SCAN_ONLY=1; shift ;;
        --home)
            DEMO_DIR="$2"
            shift 2
            ;;
        --fixtures)
            FIXTURES="$2"
            shift 2
            ;;
        -h | --help)
            sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

case "$DEMO_DIR" in /*) ;; *) DEMO_DIR="$PWD/$DEMO_DIR" ;; esac
FIXTURES="${FIXTURES:-$DEMO_DIR/fixtures}"
case "$FIXTURES" in /*) ;; *) FIXTURES="$PWD/$FIXTURES" ;; esac

APP_DIR="$PWD/build/D-Patch.app"
APP="$APP_DIR/Contents/MacOS/DPatch"
HOME_DIR="$DEMO_DIR/home"

if ((BUILD)) || [[ ! -x "$APP" ]]; then
    ./build.sh
fi

rm -rf "$HOME_DIR" "$FIXTURES"
mkdir -p "$HOME_DIR" "$FIXTURES"

echo "==> Generating demo data"
swift Scripts/demo-data.swift "$FIXTURES"

echo "==> Scanning demo data"
DPATCH_HOME="$HOME_DIR" DPATCH_FIXTURES="$FIXTURES" "$APP" --scan

if ((SCAN_ONLY)); then
    echo
    echo "Demo results: $HOME_DIR/results.json"
    echo "Demo fixtures: $FIXTURES"
    exit 0
fi

echo "==> Opening D-Patch with demo data"
open -n "$APP_DIR" --args --home "$HOME_DIR" --fixtures "$FIXTURES"
