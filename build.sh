#!/usr/bin/env bash
# Builds a universal (Apple Silicon + Intel) D-Patch.app into ./build.
# Usage: ./build.sh [--install] [--dmg]
#   --install  also copy it to /Applications
#   --dmg      also package it as dist/D-Patch-<version>.dmg (unsigned)
set -euo pipefail
cd "$(dirname "$0")"

VERSION="0.4.3"
BUILD_NUMBER="7"
MIN_MACOS="14.0"
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

source Scripts/select-sdk.sh

# Swift Build links with the toolchain's clang directly, which stamps the deployment target as the
# SDK version in LC_BUILD_VERSION. macOS picks the app's appearance from that stamp, so a macOS 14
# stamp makes the whole UI fall back to the pre-Tahoe design (no Liquid Glass sidebar). Pass the
# real SDK version to the linker explicitly.
SDK_VERSION="$(
    /usr/libexec/PlistBuddy -c 'Print :Version' "${SDKROOT:-$(xcrun --show-sdk-path)}/SDKSettings.plist" 2>/dev/null \
        || xcrun --show-sdk-version
)"
LINK_FLAGS=(-Xlinker -platform_version -Xlinker macos -Xlinker "$MIN_MACOS" -Xlinker "$SDK_VERSION")

# One build per architecture, then merged with lipo (a multi-arch `swift build` needs full Xcode).
# Each binary is copied out straight away: newer SwiftPM (Swift Build) writes every architecture
# to the same output path.
BINS=()
BIN_DIRS=()
for TRIPLE in arm64-apple-macosx$MIN_MACOS x86_64-apple-macosx$MIN_MACOS; do
    swift build -c release --triple "$TRIPLE" "${LINK_FLAGS[@]}"
    BIN_DIR="$(swift build -c release --triple "$TRIPLE" --show-bin-path)"
    BIN="$WORK/DPatch-${TRIPLE%%-*}"
    cp "$BIN_DIR/DPatch" "$BIN"
    BINS+=("$BIN")
    BIN_DIRS+=("$BIN_DIR")
done

SIGNED="$WORK/D-Patch.app"
mkdir -p "$SIGNED/Contents/MacOS" "$SIGNED/Contents/Resources"
lipo -create "${BINS[@]}" -output "$SIGNED/Contents/MacOS/DPatch"

ICONSET="$WORK/AppIcon.iconset"
swift Scripts/make-icon.swift "$ICONSET"
iconutil -c icns "$ICONSET" -o "$SIGNED/Contents/Resources/AppIcon.icns"

# SwiftPM dependency resource bundles (e.g. HighlightSwift's highlight.js) sit next to the built
# products. Which paths the generated Bundle.module accessor searches depends on the toolchain:
# the Swift Build backend looks in the app's Contents/Resources, while classic SwiftPM with an
# explicit --triple (as on CI) generates an accessor that only looks next to the app bundle and
# at the build machine's absolute path — and fatalErrors when it finds neither, killing the app
# the first time it highlights a script. Ship the bundles in both places, then verify.
if grep -aqE '\.build/[A-Za-z0-9_.-]+/(release|debug)/[A-Za-z0-9_]+\.bundle' "$SIGNED/Contents/MacOS/DPatch"; then
    ACCESSOR_LOOKS_AT_ROOT=1
else
    ACCESSOR_LOOKS_AT_ROOT=0
fi

BUNDLES=0
for DIR in "${BIN_DIRS[@]}"; do
    for BUNDLE in "$DIR"/*.bundle; do
        [ -e "$BUNDLE" ] || continue
        NAME=$(basename "$BUNDLE")
        ditto "$BUNDLE" "$SIGNED/Contents/Resources/$NAME"
        if (( ACCESSOR_LOOKS_AT_ROOT )); then
            ditto "$BUNDLE" "$SIGNED/$NAME"
        fi
        BUNDLES=$((BUNDLES + 1))

        FOUND=0
        for PLACE in "$SIGNED/Contents/Resources/$NAME" "$SIGNED/$NAME"; do
            if [ -d "$PLACE" ] && [ -n "$(find "$PLACE" -type f -print -quit)" ]; then
                FOUND=1
                break
            fi
        done
        if (( ! FOUND )); then
            echo "Resource bundle is not reachable by the app: $NAME" >&2
            exit 1
        fi
    done
done

# The binary uses SwiftPM resource accessors, so it must ship at least one resource bundle.
if (( BUNDLES == 0 )) && grep -aq resource_bundle_accessor "$SIGNED/Contents/MacOS/DPatch"; then
    echo "The binary references SwiftPM resource bundles but none were copied into the app" >&2
    exit 1
fi

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
