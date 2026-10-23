#!/usr/bin/env bash
# Builds build/D-Patch.app. Usage: ./build.sh [--install]   (--install copies it to /Applications)
set -euo pipefail
cd "$(dirname "$0")"

VERSION="0.1.0"
BUILD_NUMBER="1"
APP="build/D-Patch.app"

swift build -c release
BIN="$(swift build -c release --show-bin-path)/DPatch"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/DPatch"

ICONSET="build/AppIcon.iconset"
rm -rf "$ICONSET"
swift Scripts/make-icon.swift "$ICONSET"
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/AppIcon.icns"

cat > "$APP/Contents/Info.plist" <<PLIST
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

codesign --force --sign - "$APP"
echo "Built $APP"

if [[ "${1:-}" == "--install" ]]; then
    rm -rf "/Applications/D-Patch.app"
    cp -R "$APP" /Applications/
    echo "Installed /Applications/D-Patch.app"
fi
