#!/usr/bin/env bash
# Builds a universal (Apple Silicon + Intel) D-Patch.app into ./build.
# Usage: ./build.sh [--install] [--dmg]
#   --install  also copy it to /Applications
#   --dmg      also package it as dist/D-Patch-<version>.dmg (unsigned)
set -euo pipefail
cd "$(dirname "$0")"

# Temporary CI diagnostics: report any failing command as a run annotation.
trap 'echo "::error::build.sh failed at line $LINENO: $BASH_COMMAND (exit $?)"' ERR

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

# SwiftPM has two build engines, and they differ in how they handle resources: the Swift Build
# engine emits a proper resource bundle and generates a Bundle.module accessor that searches the
# app's Contents/Resources, while the classic engine generates an accessor that only searches
# next to the app bundle and at the build machine's absolute path — and fatalErrors when it
# finds neither, killing the app the first time it highlights a script. Those locations cannot
# be packaged for the app root (codesign rejects unsealed contents in the bundle root), so the
# app must be built with the Swift Build engine. Use it when the toolchain has it and fail the
# build if the binary still carries the classic engine's accessor.
SWIFT_BUILD_ARGS=()
if swift build --build-system swiftbuild --show-bin-path >/dev/null 2>&1; then
    SWIFT_BUILD_ARGS=(--build-system swiftbuild)
else
    echo "warning: toolchain has no Swift Build engine (--build-system swiftbuild); falling back to the classic engine" >&2
fi

# Temporary CI diagnostics: surface the toolchain and engine choice as run annotations.
if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
    echo "::notice::swift=$(swift --version 2>&1 | tr '\n' ' ')"
    echo "::notice::engine=${SWIFT_BUILD_ARGS[*]-classic-default}"
fi

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
    if ! swift build -c release --triple "$TRIPLE" "${LINK_FLAGS[@]}" ${SWIFT_BUILD_ARGS[@]+"${SWIFT_BUILD_ARGS[@]}"} 2>&1 | tee "$WORK/build-$TRIPLE.log"; then
        echo "::error::swift build failed for $TRIPLE: $(tail -5 "$WORK/build-$TRIPLE.log" | tr '\n' ' ')"
        exit 1
    fi
    BIN_DIR="$(swift build -c release --triple "$TRIPLE" --show-bin-path ${SWIFT_BUILD_ARGS[@]+"${SWIFT_BUILD_ARGS[@]}"})"
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
# products and Bundle.module finds them in the app's Contents/Resources. Verify that every bundle
# is actually there: a missing one cannot be worked around, because the only other place an
# accessor searches is next to the app bundle, where codesign rejects unsealed contents.
if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
    for DIR in "${BIN_DIRS[@]}"; do
        echo "::notice::bin-dir=$DIR: $(ls "$DIR" | tr '\n' ' ')"
    done
fi

BUNDLES=0
for DIR in "${BIN_DIRS[@]}"; do
    for BUNDLE in "$DIR"/*.bundle; do
        [ -e "$BUNDLE" ] || continue
        ditto "$BUNDLE" "$SIGNED/Contents/Resources/$(basename "$BUNDLE")"
        BUNDLES=$((BUNDLES + 1))
        if [ -z "$(find "$SIGNED/Contents/Resources/$(basename "$BUNDLE")" -type f -print -quit)" ]; then
            echo "Resource bundle was copied but is empty: $(basename "$BUNDLE")" >&2
            exit 1
        fi
    done
done

# The binary uses SwiftPM resource accessors, so it must ship at least one resource bundle.
if (( BUNDLES == 0 )) && grep -aq resource_bundle_accessor "$SIGNED/Contents/MacOS/DPatch"; then
    echo "::error::the binary references SwiftPM resource bundles but none were copied into the app"
    echo "The binary references SwiftPM resource bundles but none were copied into the app" >&2
    exit 1
fi

# A binary built with the classic engine carries a resource accessor that only searches next to
# the app bundle and at the build machine's absolute path. It can never find its bundle in an
# installed app and fatalErrors the first time a script is highlighted, so fail instead of
# shipping a crash.
if grep -aq 'could not load resource bundle' "$SIGNED/Contents/MacOS/DPatch"; then
    echo "::error::binary carries the classic SwiftPM resource accessor, which can never find its bundle in an installed app"
    cat >&2 <<'EOF'
The binary uses the classic SwiftPM resource accessor, which only searches next to the app
bundle and at the build machine's absolute path. It cannot find its bundle in an installed app
and fatalErrors the first time a script is highlighted. Build with the Swift Build engine
(swift build --build-system swiftbuild) instead.
EOF
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
