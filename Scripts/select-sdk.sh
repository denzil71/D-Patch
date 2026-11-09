# Sourced by build.sh and test.sh to pick a macOS SDK that can build SwiftUI code.
#
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
