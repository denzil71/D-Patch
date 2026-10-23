import Foundation

/// Collects what is installed: Homebrew formulae and casks, apps in /Applications, and macOS itself.
enum Inventory {
    /// Extra CVE product names for formulae whose Homebrew name differs from the CPE/CNA name.
    /// Keys and values are normalized; values may be vendor+product.
    static let formulaAliases: [String: [String]] = [
        "node": ["nodejs", "nodejsnodejs"],
        "curl": ["libcurl"],
        "go": ["golanggo"],
        "python": ["cpython", "pythonpython"],
        "openjdk": ["jdk"],
        "httpd": ["apachehttpserver", "httpserver"],
        "xz": ["tukaanixz", "xzutils"],
        "jq": ["jqlangjq", "stedolanjq"],
        "gnupg": ["gnupggnupg", "gpg"],
        "libssh2": ["libssh2libssh2"],
        "ffmpeg": ["ffmpegffmpeg"],
    ]

    static let genericBundleParts: Set<String> = ["app", "desktop", "client", "mac", "macos", "osx", "application", "main", "helper"]

    static func collect(warnings: inout [String]) async -> [InventoryItem] {
        var items: [InventoryItem] = [macOSItem()]
        var caskApps: [String: (token: String, latest: String)] = [:]   // "Firefox.app" -> cask

        if let brew = Shell.brewPath {
            do {
                let out = try await Shell.run(brew, ["info", "--json=v2", "--installed"], timeout: 180)
                let info = try JSONDecoder().decode(BrewInfo.self, from: out.stdout)
                for f in info.formulae {
                    guard let installed = f.installed.last?.version else { continue }
                    let base = f.name.split(separator: "@").first.map(String.init) ?? f.name
                    let n = normalizeName(base)
                    items.append(InventoryItem(kind: .formula, name: f.name, version: installed,
                                               aliases: [n] + (formulaAliases[n] ?? []),
                                               latestVersion: f.versions.stable))
                }
                for c in info.casks {
                    guard let installed = c.installed else { continue }
                    let apps = c.artifacts.flatMap { $0.app ?? [] }
                    if apps.isEmpty {
                        items.append(InventoryItem(kind: .cask, name: c.token, version: installed,
                                                   aliases: [normalizeName(c.token)],
                                                   caskToken: c.token, latestVersion: c.version))
                    }
                    for a in apps { caskApps[a] = (c.token, c.version) }
                }
            } catch {
                warnings.append("Could not read Homebrew inventory: \(error.localizedDescription)")
            }
        } else {
            warnings.append("Homebrew not found; formulae and casks were not checked.")
        }

        let home = FileManager.default.homeDirectoryForCurrentUser.path
        for dir in ["/Applications", "/Applications/Utilities", "\(home)/Applications"] {
            for app in appBundles(in: dir) {
                guard var item = appItem(at: app) else { continue }
                if let cask = caskApps[(app as NSString).lastPathComponent] {
                    item.caskToken = cask.token
                    item.latestVersion = cask.latest
                    item.aliases.append(normalizeName(cask.token))
                }
                items.append(item)
            }
        }
        return items
    }

    static func macOSItem() -> InventoryItem {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        let version = v.patchVersion > 0 ? "\(v.majorVersion).\(v.minorVersion).\(v.patchVersion)"
                                         : "\(v.majorVersion).\(v.minorVersion)"
        return InventoryItem(kind: .macos, name: "macOS", version: version,
                             aliases: ["macos", "macosx"], vendorHint: "apple", bundleID: "com.apple.macos")
    }

    static func appBundles(in dir: String) -> [String] {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? []
        return names.filter { $0.hasSuffix(".app") }.map { "\(dir)/\($0)" }
    }

    static func appItem(at path: String) -> InventoryItem? {
        guard let plist = NSDictionary(contentsOfFile: "\(path)/Contents/Info.plist") as? [String: Any],
              let version = (plist["CFBundleShortVersionString"] ?? plist["CFBundleVersion"]) as? String,
              Version(version) != nil
        else { return nil }
        let file = ((path as NSString).lastPathComponent as NSString).deletingPathExtension
        let display = (plist["CFBundleDisplayName"] as? String) ?? (plist["CFBundleName"] as? String) ?? file
        let bundleID = plist["CFBundleIdentifier"] as? String

        var aliases = [normalizeName(display), normalizeName(file)]
        var vendor: String?
        if let id = bundleID {
            let parts = id.split(separator: ".").map(String.init)
            if parts.count >= 3 { vendor = normalizeName(parts[1]) }
            if let last = parts.last.map(normalizeName), last.count >= 3, !genericBundleParts.contains(last) {
                aliases.append(last)
            }
        }
        let isAppStore = FileManager.default.fileExists(atPath: "\(path)/Contents/_MASReceipt/receipt")
        return InventoryItem(kind: .app, name: display, version: version,
                             aliases: Array(Set(aliases.filter { !$0.isEmpty })).sorted(),
                             vendorHint: vendor, bundleID: bundleID, path: path, isAppStore: isAppStore)
    }
}

private struct BrewInfo: Decodable {
    struct Formula: Decodable {
        struct Versions: Decodable { var stable: String? }
        struct Installed: Decodable { var version: String }
        var name: String
        var versions: Versions
        var installed: [Installed]
    }
    struct Cask: Decodable {
        struct Artifact: Decodable {
            var app: [String]?
            init(from decoder: Decoder) throws {
                // Artifacts are a mixed bag of shapes; only {"app": [...]} matters here.
                let c = try? decoder.container(keyedBy: Key.self)
                app = try? c?.decode([String].self, forKey: .app)
            }
            enum Key: String, CodingKey { case app }
        }
        var token: String
        var version: String
        var installed: String?
        var artifacts: [Artifact]
    }
    var formulae: [Formula]
    var casks: [Cask]
}
