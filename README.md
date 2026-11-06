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
- **Apple's Command Line Tools**, which provide everything `build.sh` uses (`swift`, `lipo`, `codesign`). Full Xcode isn't needed, but it works too. `Package.swift` needs Swift 5.9 or later, so use Command Line Tools 15 or later.

That's all. The project has no package dependencies, and you don't need an Apple Developer account because the app is signed ad hoc. You don't need Homebrew or Rosetta to build; the Intel half of the universal app is compiled but never run during the build.

To install the tools, run this and click **Install** in the dialog that appears:

```bash
xcode-select --install
```

If it says the tools are already installed, check that they work. Both commands should print a result without an error:

```bash
xcode-select -p    # the active tools, e.g. /Library/Developer/CommandLineTools
swift --version    # should be 5.9 or later
```

Known to work with Command Line Tools 26.2 (Swift 6.2.3).

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

- **`xcrun: error: invalid active developer path`, or `No developer tools were found`** — the tools are missing or were removed. Run `xcode-select --install`.
- **`this SDK is not supported by the compiler`, or `failed to build module`** — the compiler and the macOS SDK don't match, which usually happens after a macOS update. Install any Command Line Tools update in **System Settings › General › Software Update**. If none is offered, reinstall the tools:

  ```bash
  sudo rm -rf /Library/Developer/CommandLineTools
  xcode-select --install
  ```

- **`package ... is using Swift tools version 5.9.0 but the installed version is ...`** — the tools are too old. Update them as above.
- **`You have not agreed to the Xcode license agreements`** — Xcode is the active toolchain and its licence hasn't been accepted. Run `sudo xcodebuild -license accept`, or switch to the Command Line Tools with `sudo xcode-select --switch /Library/Developer/CommandLineTools`.
- **`compiled module was created by a different version of the compiler`, or `PCH was compiled with module cache path`** — the build folder is left over from other tools or another location. Delete it with `rm -rf .build build`, then build again.
- **`resource fork, Finder information, or similar detritus not allowed`** — `codesign` rejected the app because iCloud re-tagged it, which can happen when the project is in an iCloud-synced folder such as `~/Documents` or `~/Desktop`. Clone the project to a folder outside iCloud, such as `~/Developer`, and build there.
- **`Permission denied` running `./build.sh`** — run `chmod +x build.sh`, or `bash build.sh`.
- **`Permission denied` with `--install`** — writing to `/Applications` needs an administrator account. Copy `build/D-Patch.app` there in Finder, which asks for a password.

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
