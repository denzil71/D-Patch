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

    /// Writes or removes the LaunchAgent to match the preferences, then reloads it.
    static func apply() throws {
        let uid = getuid()
        _ = try? launchctl(["bootout", "gui/\(uid)/\(label)"])
        guard Prefs.autoscanEnabled else {
            try? FileManager.default.removeItem(at: plistURL)
            return
        }
        guard let exe = Bundle.main.executablePath else { return }
        try FileManager.default.createDirectory(at: plistURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        let data = try PropertyListSerialization.data(
            fromPropertyList: plist(executable: exe, hour: Prefs.autoscanHour, minute: Prefs.autoscanMinute),
            format: .xml, options: 0)
        try data.write(to: plistURL, options: .atomic)
        let status = try launchctl(["bootstrap", "gui/\(uid)", plistURL.path])
        if status != 0 {
            throw NSError(domain: "Scheduler", code: Int(status),
                          userInfo: [NSLocalizedDescriptionKey: "launchctl bootstrap failed (\(status))"])
        }
    }

    /// True when the installed agent points at a different copy of the app (e.g. it was moved).
    static var needsRepair: Bool {
        guard Prefs.autoscanEnabled else { return false }
        guard let p = NSDictionary(contentsOf: plistURL),
              let args = p["ProgramArguments"] as? [String] else { return true }
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
