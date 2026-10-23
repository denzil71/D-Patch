import Foundation

enum Storage {
    /// ~/Library/Application Support/D-Patch, or $DPATCH_HOME when set.
    static let base: URL = {
        let url: URL
        if let home = ProcessInfo.processInfo.environment["DPATCH_HOME"], !home.isEmpty {
            url = URL(fileURLWithPath: home)
        } else {
            url = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
                .appendingPathComponent("D-Patch")
        }
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }()

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
    static var nvdAPIKey: String {
        get { d.string(forKey: "nvdAPIKey") ?? "" }
        set { d.set(newValue, forKey: "nvdAPIKey") }
    }
    static var notifyAfterAutoscan: Bool {
        get { d.object(forKey: "notifyAfterAutoscan") as? Bool ?? true }
        set { d.set(newValue, forKey: "notifyAfterAutoscan") }
    }
}
