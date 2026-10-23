# D-Patch

A macOS app that checks the software on this Mac against critical and high CVEs from the NVD (National Vulnerability Database) and lists the ones that have an installable fix. Tick the CVEs you want to patch and click **Generate** to get a bash script that installs the updates.

## Features

### Scanning
- **Inventory** — Homebrew formulae and casks, apps in `/Applications`, `/Applications/Utilities` and `~/Applications` (including Mac App Store apps), and macOS itself.
- **CVE source** — the NVD 2.0 API, filtered to CVSS v3 `CRITICAL` and `HIGH`, for CVEs published in the last 30–365 days (90 by default). Downloads are cached in `~/Library/Application Support/D-Patch/nvd-cache.json`, so later scans fetch only what is new or changed.
- **Matching** — CVE product names (from NVD CPE configurations and the CNA's affected-product data) are matched to installed items, and the installed version must fall inside an affected range.
- **Fixes only** — a CVE is listed only if an update exists that moves the item past the fixed version:
  - Homebrew formula or cask → `brew upgrade`
  - App installed outside Homebrew that has a cask → `brew install --cask --force`
  - Mac App Store app → `mas upgrade`
  - macOS, Safari and other Apple software → `softwareupdate --install`

### Window
- **Left** — dates on which CVEs were published, each with a count of critical (red) and high (orange) CVEs. **All dates** shows everything.
- **Right** — the CVEs for the selected date. Expand one to see its description, the installed version, the fixed version, the fix, its CVSS vector and links. Search by CVE ID, app or keyword.
- **Generate** — builds a bash script for the ticked CVEs. Review it, copy it or save it (to `~/Downloads` by default) and run it in Terminal. It lists the updates and asks before it changes anything (`-y` skips the prompt); a failed update does not stop the rest.

### Automatic scan
**Settings › Automatic scan** schedules a daily scan at a chosen time through a LaunchAgent (`~/Library/LaunchAgents/com.damonmatthews.dpatch.autoscan.plist`) that runs `D-Patch --scan --notify`. It runs even when the app is closed and can post a notification when it finishes. Output goes to `~/Library/Application Support/D-Patch/autoscan.log`.

### NVD API key
Without a key the NVD allows 5 requests per 30 seconds. A free key ([request one](https://nvd.nist.gov/developers/request-an-api-key)) entered in **Settings** raises that to 50.

## Building

```bash
./build.sh            # builds build/D-Patch.app
./build.sh --install  # also copies it to /Applications
```

Command-line scan, without the window:

```bash
build/D-Patch.app/Contents/MacOS/DPatch --scan
```

Set `DPATCH_HOME` to keep the cache and results somewhere other than `~/Library/Application Support/D-Patch`.

Requires macOS 14 or later and the Xcode command line tools.
