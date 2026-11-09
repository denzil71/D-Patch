#!/usr/bin/env bash
# Builds a universal (Apple Silicon + Intel) D-Patch.app into ./build.
# Usage: ./build.sh [--install] [--dmg]
#   --install  also copy it to /Applications
#   --dmg      also package it as dist/D-Patch-<version>.dmg (unsigned)
set -euo pipefail
cd "$(dirname "$0")"

VERSION="0.4.1"
BUILD_NUMBER="5"
APP="build/D-Patch.app"

INSTALL=0
DMG=0
for arg in "$@"; do
    case "$arg" in
        --install) INSTALL=1 ;;
        --dmg) DMG=1 ;;
        *) echo "Unknown option: $arg" >&2; exit 1 ;;
    esac
done

# The app is assembled and signed outside the project: in an iCloud-synced folder (e.g. ~/Documents)
# the File Provider can re-add Finder info to the bundle, which codesign rejects.
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# Command Line Tools 27.2 ship a macOS SDK in which SwiftUI's @State is a macro, but not the
# SwiftUIMacros plugin that implements it (Xcode has it), so every @State fails with "plugin for
# module 'SwiftUIMacros' not found". In that case, build against the newest installed SDK that
# doesn't need the plugin. Setting SDKROOT yourself skips this.
declares_state_macro() {
    grep -rqs 'macro State()' "$1/System/Library/Frameworks/SwiftUICore.framework"
}
has_swiftui_macros() {
    local dir
    for dir in "$1/usr/lib/swift/host/plugins" "$(xcrun --show-sdk-path)/usr/lib/swift/host/plugins"; do
        compgen -G "$dir/*SwiftUIMacros*" >/dev/null && return 0
    done
    return 1
}
TOOLS=$(xcode-select -p)
if [[ -z "${SDKROOT:-}" && "$TOOLS" == *CommandLineTools* ]] \
    && declares_state_macro "$(xcrun --show-sdk-path)" && ! has_swiftui_macros "$TOOLS"; then
    for CANDIDATE in $(ls -d "$TOOLS"/SDKs/MacOSX[0-9]*.sdk 2>/dev/null | sort -rV); do
        if ! declares_state_macro "$CANDIDATE"; then
            export SDKROOT="$CANDIDATE"
            break
        fi
    done
    if [[ -z "${SDKROOT:-}" ]]; then
        echo "error: these Command Line Tools can't build SwiftUI apps (no SwiftUIMacros plugin)," >&2
        echo "and no older macOS SDK is installed. Install Xcode, or see README › If the build fails." >&2
        exit 1
    fi
    echo "Note: building against $(basename "$SDKROOT"): the default SDK needs a SwiftUI macro plugin these Command Line Tools don't include."
fi

# One build per architecture, then merged with lipo (a multi-arch `swift build` needs full Xcode).
# Each binary is copied out straight away: newer SwiftPM (Swift Build) writes every architecture
# to the same output path.
BINS=()
for TRIPLE in arm64-apple-macosx14.0 x86_64-apple-macosx14.0; do
    swift build -c release --triple "$TRIPLE"
    BIN="$WORK/DPatch-${TRIPLE%%-*}"
    cp "$(swift build -c release --triple "$TRIPLE" --show-bin-path)/DPatch" "$BIN"
    BINS+=("$BIN")
done

SIGNED="$WORK/D-Patch.app"
mkdir -p "$SIGNED/Contents/MacOS" "$SIGNED/Contents/Resources"
lipo -create "${BINS[@]}" -output "$SIGNED/Contents/MacOS/DPatch"

ICONSET="$WORK/AppIcon.iconset"
swift Scripts/make-icon.swift "$ICONSET"
iconutil -c icns "$ICONSET" -o "$SIGNED/Contents/Resources/AppIcon.icns"

cat > "$SIGNED/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDisplayName</key><string>D-Patch</string>
    <key>CFBundleName</key><string>D-Patch</string>
    <key>CFBundleExecutable</key><string>DPatch</string>
    <key>CFBundleIdentifier</key><string>com.damonmatthews.dpatch</string>
    <key>CFBundleIconFile</key><string>AppIcon</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>${VERSION}</string>
    <key>CFBundleVersion</key><string>${BUILD_NUMBER}</string>
    <key>LSMinimumSystemVersion</key><string>14.0</string>
    <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
    <key>NSHighResolutionCapable</key><true/>
    <key>NSPrincipalClass</key><string>NSApplication</string>
</dict>
</plist>
PLIST

codesign --force --sign - "$SIGNED"

rm -rf "$APP"
mkdir -p build
ditto "$SIGNED" "$APP"
echo "Built $APP"

if (( DMG )); then
    DMG_PATH="dist/D-Patch-$VERSION.dmg"
    # Disk image with the app and an Applications shortcut to drag it onto.
    STAGE=$(mktemp -d)
    ditto "$SIGNED" "$STAGE/D-Patch.app"
    ln -s /Applications "$STAGE/Applications"
    mkdir -p dist
    hdiutil create -volname "D-Patch $VERSION" -srcfolder "$STAGE" -format UDZO -ov "$DMG_PATH" >/dev/null
    rm -rf "$STAGE"
    echo "Built $DMG_PATH"
fi

if (( INSTALL )); then
    rm -rf "/Applications/D-Patch.app"
    ditto "$SIGNED" /Applications/D-Patch.app
    echo "Installed /Applications/D-Patch.app"
fi
