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
- **Patch Selected** — lists the updates that will close the ticked CVEs (one update can close several), with any warnings (apps to quit, administrator password, restart, major macOS upgrade). **Patch Now** runs them in your terminal app, so you can follow the output and answer password prompts; when it finishes, D-Patch rescans and the list updates by itself. **Save Script…** saves the same steps as a bash script to run later (it asks before changing anything; `-y` skips the prompt). Run scripts are kept in `~/Library/Application Support/D-Patch/runs`.

### Automatic scan
**Settings › Automatic scan** schedules a daily scan at a chosen time through a LaunchAgent (`~/Library/LaunchAgents/com.damonmatthews.dpatch.autoscan.plist`) that runs `D-Patch --scan --notify`. It runs even when the app is closed and can post a notification when it finishes. Output goes to `~/Library/Application Support/D-Patch/autoscan.log`.

### NVD API key
Without a key the NVD allows 5 requests per 30 seconds. A free key ([request one](https://nvd.nist.gov/developers/request-an-api-key)) entered in **Settings** raises that to 50.

## Building

```bash
./build.sh            # builds a universal (Apple Silicon + Intel) build/D-Patch.app
./build.sh --install  # also copies it to /Applications
./build.sh --dmg      # also packages dist/D-Patch-<version>.dmg (unsigned)
```

Command-line scan, without the window:

```bash
build/D-Patch.app/Contents/MacOS/DPatch --scan
```

Patch script for every finding of the last scan (`--no-confirm` drops the prompt and rescans at the end):

```bash
build/D-Patch.app/Contents/MacOS/DPatch --script > patch.sh
```

Set `DPATCH_HOME` to keep the cache and results somewhere other than `~/Library/Application Support/D-Patch`.

Requires macOS 14 or later and the Xcode command line tools.
