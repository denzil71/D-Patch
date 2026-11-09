#!/usr/bin/env bash
# Checks formatting (swift-format, configured in .swift-format) and code quality (SwiftLint,
# configured in .swiftlint.yml). Usage: Scripts/lint.sh [--fix]
#   --fix  reformat the code first, then check
set -euo pipefail
cd "$(dirname "$0")/.."

PATHS=(Package.swift Sources Scripts Tests)

if [[ "${1:-}" == "--fix" ]]; then
    swift format --in-place --recursive "${PATHS[@]}"
fi

echo "==> swift format lint"
swift format lint --strict --recursive "${PATHS[@]}"

echo "==> swiftlint"
if ! command -v swiftlint >/dev/null; then
    if [[ -n "${CI:-}" ]]; then
        echo "error: swiftlint isn't installed" >&2
        exit 1
    fi
    echo "SwiftLint isn't installed (brew install swiftlint), so only formatting was checked." >&2
    exit 0
fi
# SwiftLint loads SourceKit from Xcode; with only the Command Line Tools, point it at theirs.
if [[ "$(xcode-select -p)" == *CommandLineTools* ]]; then
    export TOOLCHAIN_DIR="${TOOLCHAIN_DIR:-/Library/Developer/CommandLineTools}"
fi
# Warnings are reported (as annotations on GitHub) but only errors fail.
swiftlint lint --quiet ${GITHUB_ACTIONS:+--reporter github-actions-logging}
