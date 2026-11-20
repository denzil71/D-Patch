#!/usr/bin/env bash
# Builds D-Patch.app for Apple Silicon (arm64) into ./build.
# Usage: ./build.sh [--install] [--dmg]
#   --install  also copy it to /Applications
#   --dmg      also package it as dist/D-Patch-<version>.dmg
#
# Signing: ad hoc by default. Set SIGN_IDENTITY (e.g. "Developer ID Application: Name (TEAMID)")
# to sign with a Developer ID and the hardened runtime. With --dmg, the app and the DMG are also
# notarized and stapled when notarytool credentials are set: either NOTARY_PROFILE (a keychain
# profile from `xcrun notarytool store-credentials`) or NOTARY_KEY_PATH, NOTARY_KEY_ID and
# NOTARY_ISSUER_ID (an App Store Connect API key).
set -euo pipefail
cd "$(dirname "$0")"

VERSION="0.6.3"
BUILD_NUMBER="13"
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

# On CI, report a failing command as an annotation so it is visible without reading the whole log.
trap '[[ -n "${GITHUB_ACTIONS:-}" ]] && echo "::error::build.sh failed at line $LINENO: $BASH_COMMAND (exit $?)"' ERR

# Surface a failure as a CI annotation when running on GitHub Actions.
report_failure() {
    if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
        echo "::error::$1"
    fi
}

SIGN_IDENTITY="${SIGN_IDENTITY:--}"
NOTARY_ARGS=()
if [[ -n "${NOTARY_PROFILE:-}" ]]; then
    NOTARY_ARGS=(--keychain-profile "$NOTARY_PROFILE")
elif [[ -n "${NOTARY_KEY_PATH:-}" ]]; then
    NOTARY_ARGS=(--key "$NOTARY_KEY_PATH" --key-id "${NOTARY_KEY_ID:?NOTARY_KEY_ID is required with NOTARY_KEY_PATH}" \
        --issuer "${NOTARY_ISSUER_ID:?NOTARY_ISSUER_ID is required with NOTARY_KEY_PATH}")
fi
if (( ${#NOTARY_ARGS[@]} )) && [[ "$SIGN_IDENTITY" == "-" ]]; then
    echo "Notarization needs a Developer ID: set SIGN_IDENTITY as well" >&2
    exit 1
fi

# Submits a file to Apple's notary service, waits for the verdict and staples the ticket to $2
# (the submitted file itself unless given). On rejection, prints Apple's log of the problems.
notarize() {
    local submit="$1" staple="${2:-$1}" result="$WORK/notary.plist" id status
    echo "Notarizing $(basename "$staple")…"
    xcrun notarytool submit "$submit" "${NOTARY_ARGS[@]}" --wait --output-format plist >"$result" || true
    id=$(/usr/libexec/PlistBuddy -c 'Print :id' "$result" 2>/dev/null || true)
    status=$(/usr/libexec/PlistBuddy -c 'Print :status' "$result" 2>/dev/null || true)
    if [[ -z "$id" ]]; then
        report_failure "could not submit $(basename "$staple") for notarization"
        echo "Could not submit $(basename "$staple") for notarization" >&2
        exit 1
    fi
    if [[ "$status" != "Accepted" ]]; then
        xcrun notarytool log "$id" "${NOTARY_ARGS[@]}" >&2 || true
        report_failure "notarization of $(basename "$staple") was rejected (submission $id)"
        echo "Notarization of $(basename "$staple") was rejected (submission $id)" >&2
        exit 1
    fi
    xcrun stapler staple "$staple"
}

source Scripts/select-sdk.sh

# SwiftPM has two build engines, and they differ in how they handle resources: the Swift Build
# engine emits a proper dependency resource bundle and generates a Bundle.module accessor that
# searches the app's Contents/Resources, while the classic engine generates an accessor that only
# searches next to the app bundle and at the build machine's absolute path — and fatalErrors when
# it finds neither, killing the app the first time it highlights a script. Those locations cannot
# be packaged for the app root (codesign rejects unsealed contents in the bundle root), so the
# binary must be built with the Swift Build engine; the check below fails the build if not.
# Apple Silicon only: there's no Intel Mac to test an x86_64 build on.
BUILD_ARGS=(-c release --arch arm64 --build-system swiftbuild)

# Swift Build links with the toolchain's clang directly, which stamps the deployment target as the
# SDK version in LC_BUILD_VERSION. macOS picks the app's appearance from that stamp, so a macOS 14
# stamp makes the whole UI fall back to the pre-Tahoe design (no Liquid Glass sidebar). Pass the
# real SDK version to the linker explicitly.
SDK_VERSION="$(
    /usr/libexec/PlistBuddy -c 'Print :Version' "${SDKROOT:-$(xcrun --show-sdk-path)}/SDKSettings.plist" 2>/dev/null \
        || xcrun --show-sdk-version
)"
LINK_FLAGS=(-Xlinker -platform_version -Xlinker macos -Xlinker "$MIN_MACOS" -Xlinker "$SDK_VERSION")

# One build for arm64 (the package's platforms declare macOS 14).
swift build "${BUILD_ARGS[@]}" "${LINK_FLAGS[@]}"
BIN_DIR="$(swift build "${BUILD_ARGS[@]}" --show-bin-path)"

SIGNED="$WORK/D-Patch.app"
mkdir -p "$SIGNED/Contents/MacOS" "$SIGNED/Contents/Resources"
cp "$BIN_DIR/DPatch" "$SIGNED/Contents/MacOS/DPatch"

ICONSET="$WORK/AppIcon.iconset"
swift Scripts/make-icon.swift "$ICONSET"
iconutil -c icns "$ICONSET" -o "$SIGNED/Contents/Resources/AppIcon.icns"

# SwiftPM dependency resource bundles (e.g. HighlightSwift's highlight.js) sit next to the built
# products and Bundle.module finds them in the app's Contents/Resources. Verify that every bundle
# is actually there: a missing one cannot be worked around, because the only other place an
# accessor searches is next to the app bundle, where codesign rejects unsealed contents.
BUNDLES=0
for BUNDLE in "$BIN_DIR"/*.bundle; do
    [ -e "$BUNDLE" ] || continue
    ditto "$BUNDLE" "$SIGNED/Contents/Resources/$(basename "$BUNDLE")"
    BUNDLES=$((BUNDLES + 1))
    if [ -z "$(find "$SIGNED/Contents/Resources/$(basename "$BUNDLE")" -type f -print -quit)" ]; then
        report_failure "resource bundle was copied but is empty: $(basename "$BUNDLE")"
        echo "Resource bundle was copied but is empty: $(basename "$BUNDLE")" >&2
        exit 1
    fi
done

# The binary uses SwiftPM resource accessors, so it must ship at least one resource bundle.
if (( BUNDLES == 0 )) && grep -aq resource_bundle_accessor "$SIGNED/Contents/MacOS/DPatch"; then
    report_failure "the binary references SwiftPM resource bundles but none were copied into the app"
    echo "The binary references SwiftPM resource bundles but none were copied into the app" >&2
    exit 1
fi

# A binary built with the classic engine carries a resource accessor that only searches next to
# the app bundle and at the build machine's absolute path. It can never find its bundle in an
# installed app and fatalErrors the first time a script is highlighted, so fail instead of
# shipping a crash.
if grep -aq 'could not load resource bundle' "$SIGNED/Contents/MacOS/DPatch"; then
    report_failure "binary carries the classic SwiftPM resource accessor, which can never find its bundle in an installed app"
    echo "The binary uses the classic SwiftPM resource accessor, which only searches next to the app bundle and at the build machine's absolute path. Build with the Swift Build engine (--build-system swiftbuild) instead." >&2
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
    <key>LSMinimumSystemVersion</key><string>${MIN_MACOS}</string>
    <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
    <key>NSHighResolutionCapable</key><true/>
    <key>NSPrincipalClass</key><string>NSApplication</string>
</dict>
</plist>
PLIST

if [[ "$SIGN_IDENTITY" == "-" ]]; then
    codesign --force --sign - "$SIGNED"
else
    # The hardened runtime and a secure timestamp are required for notarization. The app needs no
    # entitlements: osascript only posts notifications, Terminal is opened through Launch Services
    # and JavaScriptCore runs without JIT.
    codesign --force --options runtime --timestamp --sign "$SIGN_IDENTITY" "$SIGNED"
    codesign --verify --strict --deep "$SIGNED"
    if (( DMG )) && (( ${#NOTARY_ARGS[@]} )); then
        ditto -c -k --keepParent "$SIGNED" "$WORK/D-Patch.zip"
        notarize "$WORK/D-Patch.zip" "$SIGNED"
    fi
fi

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
    if [[ "$SIGN_IDENTITY" != "-" ]]; then
        codesign --force --timestamp --sign "$SIGN_IDENTITY" "$DMG_PATH"
        if (( ${#NOTARY_ARGS[@]} )); then
            notarize "$DMG_PATH"
            spctl --assess --type open --context context:primary-signature -v "$DMG_PATH"
        fi
    fi
    echo "Built $DMG_PATH"
fi

if (( INSTALL )); then
    rm -rf "/Applications/D-Patch.app"
    ditto "$SIGNED" /Applications/D-Patch.app
    echo "Installed /Applications/D-Patch.app"
fi
