import Foundation

/// Finds an installable update that moves an item out of every affected range.
/// Sources are loaded lazily, once per scan, and only when an item needs them.
final class FixResolver {
    private struct SoftwareUpdate { var label: String; var title: String; var version: String }
    private struct CaskEntry { var token: String; var version: String }

    private var softwareUpdates: [SoftwareUpdate]?
    private var caskByApp: [String: CaskEntry]?
    private var appStore: [String: (id: Int, version: String)?] = [:]
    var warnings: [String] = []

    func fix(for item: InventoryItem, ranges: [ProductRange]) async -> Fix? {
        guard let installed = Version(item.version) else { return nil }
        func fixes(_ candidate: String?) -> String? {
            guard let c = candidate, let v = Version(c), v > installed,
                  !ranges.contains(where: { $0.contains(v) }) else { return nil }
            return c
        }

        switch item.kind {
        case .formula:
            guard let to = fixes(item.latestVersion) else { return nil }
            return Fix(method: .brewFormula, target: item.name, toVersion: to,
                       summary: "Homebrew: upgrade formula \(item.name) \(item.version) → \(to)")
        case .cask:
            guard let token = item.caskToken, let to = fixes(item.latestVersion) else { return nil }
            return Fix(method: .brewCask, target: token, toVersion: to,
                       summary: "Homebrew: upgrade cask \(token) \(item.version) → \(Self.plain(to))")
        case .macos:
            return await softwareUpdateFix(item, matching: { $0.hasPrefix("macOS") }, fixes)
        case .app:
            if let token = item.caskToken {
                guard let to = fixes(item.latestVersion) else { return nil }
                return Fix(method: .brewCask, target: token, toVersion: to,
                           summary: "Homebrew: upgrade cask \(token) \(item.version) → \(Self.plain(to))")
            }
            if item.isAppStore {
                guard let id = item.bundleID, let entry = await appStoreEntry(bundleID: id),
                      let to = fixes(entry.version) else { return nil }
                return Fix(method: .appStore, target: String(entry.id), toVersion: to,
                           summary: "Mac App Store: update \(item.name) \(item.version) → \(to)")
            }
            if item.bundleID?.hasPrefix("com.apple.") == true {
                return await softwareUpdateFix(item, matching: { $0.localizedCaseInsensitiveContains(item.name) }, fixes)
            }
            guard let file = item.path.map({ ($0 as NSString).lastPathComponent }),
                  let cask = await caskCatalog()[file], let to = fixes(cask.version) else { return nil }
            return Fix(method: .brewCaskReplace, target: cask.token, toVersion: to,
                       summary: "Homebrew: install cask \(cask.token) over the existing app, \(item.version) → \(Self.plain(to))")
        }
    }

    /// Cask versions carry a build after a comma ("4.95.0,242831"); show only the version.
    static func plain(_ v: String) -> String { v.split(separator: ",").first.map(String.init) ?? v }

    private func softwareUpdateFix(_ item: InventoryItem, matching: (String) -> Bool,
                                   _ fixes: (String?) -> String?) async -> Fix? {
        for u in await loadSoftwareUpdates() where matching(u.title) {
            if let to = fixes(u.version) {
                return Fix(method: .softwareUpdate, target: u.label, toVersion: to,
                           summary: "Apple Software Update: install “\(u.title)” (\(item.version) → \(to))")
            }
        }
        return nil
    }

    private func loadSoftwareUpdates() async -> [SoftwareUpdate] {
        if let s = softwareUpdates { return s }
        var list: [SoftwareUpdate] = []
        do {
            let out = try await Shell.run("/usr/sbin/softwareupdate", ["--list"], timeout: 240)
            // * Label: macOS Tahoe 26.7-25H5
            // \tTitle: macOS Tahoe 26.7, Version: 26.7, Size: 7G, Recommended: YES, Action: restart,
            var label: String?
            for line in (out.text + "\n" + out.stderr).split(separator: "\n") {
                let t = line.trimmingCharacters(in: .whitespaces)
                if t.hasPrefix("* Label:") {
                    label = t.dropFirst("* Label:".count).trimmingCharacters(in: .whitespaces)
                } else if t.hasPrefix("Title:"), let l = label {
                    var fields: [String: String] = [:]
                    for part in t.split(separator: ",") {
                        let kv = part.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
                        if kv.count == 2 { fields[kv[0]] = kv[1] }
                    }
                    if let title = fields["Title"], let v = fields["Version"] {
                        list.append(SoftwareUpdate(label: l, title: title, version: v))
                    }
                    label = nil
                }
            }
        } catch {
            warnings.append("softwareupdate failed: \(error.localizedDescription)")
        }
        softwareUpdates = list
        return list
    }

    private func appStoreEntry(bundleID: String) async -> (id: Int, version: String)? {
        if let cached = appStore[bundleID] { return cached }
        struct Lookup: Decodable { struct R: Decodable { var trackId: Int; var version: String }; var results: [R] }
        var result: (Int, String)?
        var c = URLComponents(string: "https://itunes.apple.com/lookup")!
        c.queryItems = [URLQueryItem(name: "bundleId", value: bundleID), URLQueryItem(name: "entity", value: "macSoftware"),
                        URLQueryItem(name: "country", value: Locale.current.region?.identifier ?? "US")]
        if let (data, _) = try? await URLSession.shared.data(from: c.url!),
           let r = try? JSONDecoder().decode(Lookup.self, from: data).results.first {
            result = (r.trackId, r.version)
        }
        appStore[bundleID] = result
        return result
    }

    /// App bundle file name -> cask, from Homebrew's public cask index (cached for a day).
    private func caskCatalog() async -> [String: CaskEntry] {
        if let c = caskByApp { return c }
        struct Cask: Decodable {
            struct Artifact: Decodable {
                var app: [String]?
                init(from decoder: Decoder) throws {
                    let c = try? decoder.container(keyedBy: Key.self)
                    // Entries are strings or {"target": ...} objects; keep the strings.
                    app = (try? c?.decode([LossyString].self, forKey: .app))?.compactMap(\.value)
                }
                enum Key: String, CodingKey { case app }
            }
            var token: String
            var version: String
            var artifacts: [Artifact]
        }
        let url = Storage.base.appendingPathComponent("cask.json")
        let age = (try? url.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate)
            .map { Date().timeIntervalSince($0) } ?? .infinity
        if age > 86_400 {
            do {
                let (data, resp) = try await URLSession.shared.data(from: URL(string: "https://formulae.brew.sh/api/cask.json")!)
                if (resp as? HTTPURLResponse)?.statusCode == 200 { try data.write(to: url, options: .atomic) }
            } catch {
                warnings.append("Could not download the Homebrew cask index: \(error.localizedDescription)")
            }
        }
        var map: [String: CaskEntry] = [:]
        if let data = try? Data(contentsOf: url), let casks = try? JSONDecoder().decode([Cask].self, from: data) {
            for c in casks where c.version != "latest" {
                for app in c.artifacts.flatMap({ $0.app ?? [] }) where map[app] == nil {
                    map[app] = CaskEntry(token: c.token, version: c.version)
                }
            }
        }
        caskByApp = map
        return map
    }
}

private struct LossyString: Decodable {
    var value: String?
    init(from decoder: Decoder) throws { value = try? decoder.singleValueContainer().decode(String.self) }
}
