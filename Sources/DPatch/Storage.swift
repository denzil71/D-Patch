import Foundation

enum Storage {
    /// ~/Library/Application Support/D-Patch, or $DPATCH_HOME / --home when set.
    static let base: URL = {
        let url = baseURL(arguments: CommandLine.arguments, environment: ProcessInfo.processInfo.environment)
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }()

    /// `--home`, then `$DPATCH_HOME`, then ~/Library/Application Support/D-Patch. With demo data
    /// loaded (`--fixtures` / `$DPATCH_FIXTURES`) and no home given, its Demo subfolder instead, so
    /// a demo scan never replaces the real results.
    static func baseURL(arguments args: [String], environment: [String: String]) -> URL {
        if let i = args.firstIndex(of: "--home"), i + 1 < args.count, !args[i + 1].isEmpty {
            return URL(fileURLWithPath: args[i + 1])
        }
        if let home = environment["DPATCH_HOME"], !home.isEmpty {
            return URL(fileURLWithPath: home)
        }
        let standard = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("D-Patch")
        if FixtureData.directory(arguments: args, environment: environment) != nil {
            return standard.appendingPathComponent("Demo")
        }
        return standard
    }

    static var cacheURL: URL { base.appendingPathComponent("nvd-cache.json") }
    static var resultsURL: URL { base.appendingPathComponent("results.json") }
    static var logURL: URL { base.appendingPathComponent("autoscan.log") }

    static func load<T: Decodable>(_ type: T.Type, from url: URL) -> T? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return try? d.decode(T.self, from: data)
    }

    static func save<T: Encodable>(_ value: T, to url: URL) throws {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .iso8601
        try e.encode(value).write(to: url, options: .atomic)
    }
}

/// User preferences, shared by the app and the scheduled headless scan.
enum Prefs {
    private static var d: UserDefaults { .standard }

    static var autoscanEnabled: Bool {
        get { d.bool(forKey: "autoscanEnabled") }
        set { d.set(newValue, forKey: "autoscanEnabled") }
    }
    static var autoscanHour: Int {
        get { d.object(forKey: "autoscanHour") as? Int ?? 9 }
        set { d.set(newValue, forKey: "autoscanHour") }
    }
    static var autoscanMinute: Int {
        get { d.object(forKey: "autoscanMinute") as? Int ?? 0 }
        set { d.set(newValue, forKey: "autoscanMinute") }
    }
    static var lookbackDays: Int {
        get { d.object(forKey: "lookbackDays") as? Int ?? 90 }
        set { d.set(newValue, forKey: "lookbackDays") }
    }
    /// CVE severity levels to scan for, stored as "CRITICAL,HIGH".
    static var severities: [Severity] {
        get {
            let list = (d.string(forKey: "severities") ?? "").split(separator: ",").compactMap {
                Severity(rawValue: String($0))
            }
            return list.isEmpty ? Severity.defaults : list.sorted(by: >)
        }
        set { d.set(newValue.sorted(by: >).map(\.rawValue).joined(separator: ","), forKey: "severities") }
    }
    static var nvdAPIKey: String {
        get { d.string(forKey: "nvdAPIKey") ?? "" }
        set { d.set(newValue, forKey: "nvdAPIKey") }
    }
    static var notifyAfterAutoscan: Bool {
        get { d.object(forKey: "notifyAfterAutoscan") as? Bool ?? true }
        set { d.set(newValue, forKey: "notifyAfterAutoscan") }
    }
}
