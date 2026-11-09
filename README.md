# D-Patch

A macOS app that checks the software on this Mac against CVEs from the NVD (National Vulnerability Database) and lists the ones that have an installable fix. Tick the CVEs you want to patch and click **Patch Selected** to install the updates.

## Features

### Scanning
- **Inventory** — Homebrew formulae and casks, apps in `/Applications`, `/Applications/Utilities` and `~/Applications` (including Mac App Store apps), and macOS itself.
- **CVE source** — the NVD 2.0 API, filtered to the CVSS v3 severity levels ticked in **Settings › Severity** (Critical and High by default; Medium and Low optional), for CVEs published in the last 30–365 days (90 by default). Downloads are cached in `~/Library/Application Support/D-Patch/nvd-cache.json`, so later scans fetch only what is new or changed; ticking another level fetches just that level, and unticking one drops it from the cache.
- **Matching** — CVE product names (from NVD CPE configurations and the CNA's affected-product data) are matched to installed items, and the installed version must fall inside an affected range.
- **Fixes only** — a CVE is listed only if an update exists that moves the item past the fixed version:
  - Homebrew formula or cask → `brew upgrade`
  - App installed outside Homebrew that has a cask → `brew install --cask --force`
  - Mac App Store app → `mas upgrade`
  - macOS, Safari and other Apple software → `softwareupdate --install`

### Window
- **Left** — dates on which CVEs were published, each with a count of CVEs per severity: critical (red), high (orange), medium (yellow) and low (grey). **All dates** shows everything.
- **Right** — the CVEs for the selected date. Expand one to see its description, the installed version, the fixed version, the fix, its CVSS vector and links. Search by CVE ID, app or keyword.
- **Filters** — above the list: severity chips (click one to hide or show that level), a **Fix** menu (Homebrew, App Store or Apple Software Update) and **Hide major macOS upgrades** (CVEs whose only fix is a new major macOS version). The date counts follow the filters. Ticked CVEs that a filter hides stay ticked and are still patched; the list header says how many are not shown.
- **Patch Selected** — lists the updates that will close the ticked CVEs (one update can close several), with any warnings (apps to quit, administrator password, restart, major macOS upgrade). **Patch Now** runs them in your terminal app, so you can follow the output and answer password prompts; when it finishes, D-Patch rescans and the list updates by itself. **Save Script…** saves the same steps as a bash script to run later (it asks before changing anything; `-y` skips the prompt). Run scripts are kept in `~/Library/Application Support/D-Patch/runs`.

### Automatic scan
**Settings › Automatic scan** schedules a daily scan at a chosen time through a LaunchAgent (`~/Library/LaunchAgents/com.damonmatthews.dpatch.autoscan.plist`) that runs `D-Patch --scan --notify`. It runs even when the app is closed and can post a notification when it finishes. Output goes to `~/Library/Application Support/D-Patch/autoscan.log`.

### NVD API key
Without a key the NVD allows 5 requests per 30 seconds. A free key ([request one](https://nvd.nist.gov/developers/request-an-api-key)) entered in **Settings** raises that to 50.

## Building

### What you need

- **macOS 14 or later.**
- **Xcode**, free from the Mac App Store. The Command Line Tools alone aren't enough: the HighlightSwift package used for the Patch sheet's script highlighting needs SwiftUI macro plugins (`@Entry`, `#Preview`) that only Xcode includes. When Xcode asks which platforms to install, **macOS** is all you need. It takes about 10–12 GB once installed, and the install needs more free space than that while it unpacks.

You don't need an Apple Developer account, because the app is signed ad hoc. You don't need Homebrew or Rosetta to build either; the Intel half of the universal app is compiled but never run during the build. The first build downloads HighlightSwift from GitHub, so it needs an internet connection.

After installing Xcode, make it the active toolchain and accept its licence (both ask for your password), then let it finish setting up:

```bash
sudo xcode-select --switch /Applications/Xcode.app
sudo xcodebuild -license accept
xcodebuild -runFirstLaunch
```

Check it's active. Both commands should print a result without an error:

```bash
xcode-select -p    # should be /Applications/Xcode.app/Contents/Developer
swift --version    # should be 5.9 or later
```

Known to work with Xcode 27.2 (Swift 6.4.2) and, on GitHub Actions, Xcode 26.6.

### Build

```bash
git clone https://github.com/denzil71/D-Patch.git
cd D-Patch
./build.sh            # builds a universal (Apple Silicon + Intel) build/D-Patch.app
./build.sh --install  # also copies it to /Applications
./build.sh --dmg      # also packages dist/D-Patch-<version>.dmg (unsigned)
```

The first build takes a minute or so, because it compiles for each architecture.

### If the build fails

- **`plugin for module 'SwiftUIMacros' not found`** or **`plugin for module 'PreviewsMacros' not found`** (with `external macro implementation type ... could not be found`) — the Command Line Tools are the active toolchain, not Xcode. Install Xcode, then run `sudo xcode-select --switch /Applications/Xcode.app`. Check with `xcode-select -p`.
- **`xcrun: error: invalid active developer path`, or `No developer tools were found`** — the active developer folder is missing, for example because Xcode was moved or deleted. Run `sudo xcode-select --switch /Applications/Xcode.app` (or wherever Xcode is).
- **`this SDK is not supported by the compiler`, or `failed to build module`** — the compiler and the macOS SDK don't match, which usually happens after a macOS update. Update Xcode in the App Store, then delete the build folder with `rm -rf .build build` and build again.
- **`lipo: same architectures (x86_64) found`** — an older `build.sh` with Swift 6.4's SwiftPM, which writes both architectures to the same file. Update to the current `build.sh`.
- **`package ... is using Swift tools version 5.9.0 but the installed version is ...`** — Xcode is too old. Update it in the App Store.
- **`You have not agreed to the Xcode license agreements`** — run `sudo xcodebuild -license accept`.
- **An error about cloning or fetching `HighlightSwift`** — the first build couldn't download it from GitHub. Check your internet connection and build again.
- **`compiled module was created by a different version of the compiler`, or `PCH was compiled with module cache path`** — the build folder is left over from other tools or another location. Delete it with `rm -rf .build build`, then build again.
- **`Permission denied` running `./build.sh`** — run `chmod +x build.sh`, or `bash build.sh`.
- **`Permission denied` with `--install`** — writing to `/Applications` needs an administrator account. Copy `build/D-Patch.app` there in Finder, which asks for a password.

### Tests, formatting and lint

```bash
./test.sh              # unit tests (Swift Testing)
Scripts/lint.sh        # checks formatting (swift-format) and lint (SwiftLint)
Scripts/lint.sh --fix  # reformats the code first, then checks
```

Formatting follows `.swift-format`; lint rules are in `.swiftlint.yml`. `swift format` comes with the Swift toolchain; SwiftLint is optional locally (`brew install swiftlint`) and is skipped with a note if it isn't installed. SwiftLint warnings are reported but only errors fail.

GitHub Actions (`.github/workflows/ci.yml`) runs the format check, lint, tests and a build on every push and pull request, and keeps the built app as a downloadable artifact for 7 days.

### Releasing

1. In a pull request, bump `VERSION` and `BUILD_NUMBER` at the top of `build.sh`, and merge it.
2. Tag the merged commit on `main` and push the tag. The tag's message becomes the top of the release notes:

   ```bash
   git switch main && git pull
   git tag -a v0.4.2 -m "Short summary of what's new"
   git push origin v0.4.2
   ```

GitHub Actions (`.github/workflows/release.yml`) then checks the tag matches `VERSION` in `build.sh`, runs the tests, builds the DMG and publishes the release. Its notes are the tag's message, GitHub's list of merged pull requests, then the install instructions from `.github/release-footer.md` with the DMG's SHA-256. Only tags of the form `vX.Y.Z` trigger a release.

### Running without the window

Command-line scan, without the window:

```bash
build/D-Patch.app/Contents/MacOS/DPatch --scan
```

Patch script for every finding of the last scan (`--no-confirm` drops the prompt and rescans at the end):

```bash
build/D-Patch.app/Contents/MacOS/DPatch --script > patch.sh
```

Set `DPATCH_HOME` to keep the cache and results somewhere other than `~/Library/Application Support/D-Patch`.

### Demo data

To exercise the UI without waiting for a scan, or when this Mac has no matching CVEs:

```bash
Scripts/demo.sh
```

It builds the app if needed, writes dummy CVEs and software to `build/demo`, scans them and opens D-Patch. Use `--scan-only` to stop before opening the app, or `--build` to rebuild first. The app reads the fixtures from `--fixtures` (or `DPATCH_FIXTURES`) and keeps its results under `--home` (or `DPATCH_HOME`); **Patch Now** is disabled while demo data is loaded.
