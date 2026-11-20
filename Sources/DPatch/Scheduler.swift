import Foundation

/// Daily autoscan through a per-user LaunchAgent that runs `D-Patch --scan --notify`.
enum Scheduler {
    static let label = "com.damonmatthews.dpatch.autoscan"

    static var plistURL: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents/\(label).plist")
    }

    static func plist(executable: String, hour: Int, minute: Int) -> [String: Any] {
        [
            "Label": label,
            "ProgramArguments": [executable, "--scan", "--notify"],
            "StartCalendarInterval": ["Hour": hour, "Minute": minute],
            "StandardOutPath": Storage.logURL.path,
            "StandardErrorPath": Storage.logURL.path,
            "ProcessType": "Background",
            "LowPriorityIO": true,
        ]
    }

    /// Why launchd can't run the app from `path`, or nil if it can. A quarantined app opened from
    /// the disk image or Downloads runs from a temporary App Translocation copy, and macOS kills a
    /// scheduled launch of that path (or of a disk image that's later ejected).
    static func unsupportedLocation(_ path: String) -> String? {
        if path.contains("/AppTranslocation/") || path.hasPrefix("/Volumes/") {
            return "Move D-Patch to the Applications folder and open it from there to schedule a scan."
        }
        return nil
    }

    /// Writes or removes the LaunchAgent to match the preferences, then reloads it.
    static func apply() throws {
        // Leave an existing agent alone when this copy can't be scheduled, so opening a stray copy
        // (e.g. from the disk image) doesn't remove a working schedule.
        if Prefs.autoscanEnabled, let exe = Bundle.main.executablePath, let message = unsupportedLocation(exe) {
            throw NSError(domain: "Scheduler", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
        }
        let uid = getuid()
        _ = try? launchctl(["bootout", "gui/\(uid)/\(label)"])
        guard Prefs.autoscanEnabled else {
            try? FileManager.default.removeItem(at: plistURL)
            return
        }
        guard let exe = Bundle.main.executablePath else { return }
        try FileManager.default.createDirectory(
            at: plistURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        let data = try PropertyListSerialization.data(
            fromPropertyList: plist(executable: exe, hour: Prefs.autoscanHour, minute: Prefs.autoscanMinute),
            format: .xml, options: 0)
        try data.write(to: plistURL, options: .atomic)
        let status = try launchctl(["bootstrap", "gui/\(uid)", plistURL.path])
        if status != 0 {
            throw NSError(
                domain: "Scheduler", code: Int(status),
                userInfo: [NSLocalizedDescriptionKey: "launchctl bootstrap failed (\(status))"])
        }
    }

    /// True when the installed agent points at a different copy of the app (e.g. it was moved).
    static var needsRepair: Bool {
        guard Prefs.autoscanEnabled else { return false }
        if let exe = Bundle.main.executablePath, unsupportedLocation(exe) != nil { return false }
        guard let p = NSDictionary(contentsOf: plistURL),
            let args = p["ProgramArguments"] as? [String]
        else { return true }
        return args.first != Bundle.main.executablePath
    }

    @discardableResult
    private static func launchctl(_ args: [String]) throws -> Int32 {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        p.arguments = args
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        try p.run()
        p.waitUntilExit()
        return p.terminationStatus
    }
}
