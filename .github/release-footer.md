## Install
Download **D-Patch-{{VERSION}}.dmg** below, open it and drag **D-Patch** onto **Applications** (replace the old copy; your scan results and settings are kept). Requires macOS 14 or later; runs on Apple Silicon and Intel Macs.

The app isn't signed with an Apple Developer ID, so macOS blocks it the first time. To open it, right-click it in Applications → **Open** → **Open**, or go to **System Settings → Privacy & Security → Open Anyway**. If macOS says it "is damaged", run:

```sh
xattr -dr com.apple.quarantine /Applications/D-Patch.app
```

If you use Automatic scan, open the new copy once so the schedule points at it.

SHA-256: `{{SHA256}}`
