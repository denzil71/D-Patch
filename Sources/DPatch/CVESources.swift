import Foundation

/// CVE databases D-Patch consults. NVD is always used (it supplies the CVEs and affected versions);
/// the others are optional cross-checks that record where else each found CVE appears.
enum CVESource: String, Codable, CaseIterable, Identifiable, Comparable {
    case nvd, kev, osv, euvd

    var id: String { rawValue }

    /// Short label for badges.
    var name: String {
        switch self {
        case .nvd: "NVD"
        case .kev: "KEV"
        case .osv: "OSV"
        case .euvd: "EUVD"
        }
    }

    var fullName: String {
        switch self {
        case .nvd: "NIST National Vulnerability Database"
        case .kev: "CISA Known Exploited Vulnerabilities"
        case .osv: "OSV.dev (includes GitHub Advisories)"
        case .euvd: "ENISA EU Vulnerability Database"
        }
    }

    /// The optional sources, in the order they're listed and shown.
    static let optional: [CVESource] = [.kev, .osv, .euvd]

    static func < (a: CVESource, b: CVESource) -> Bool {
        allCases.firstIndex(of: a)! < allCases.firstIndex(of: b)!
    }
}

/// One database's entry for a CVE.
struct SourceRecord: Codable, Hashable {
    var source: CVESource
    /// The database's own IDs for it, e.g. GHSA-… or EUVD-…; empty when it uses the CVE ID.
    var ids: [String] = []
    var url: String
    /// Extra detail worth showing, e.g. when CISA added it to the exploited list.
    var note: String?
}

/// Looks up found CVEs in the enabled optional databases.
/// KEV is one catalogue download; OSV.dev and EUVD are one request per CVE, cached for a day.
final class SourceChecker {
    private let enabled: Set<CVESource>
    private let progress: (String) -> Void
    private(set) var warnings: [String] = []

    private static let kevURL = URL(
        string: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")!
    private static let kevMaxAge: TimeInterval = 12 * 60 * 60
    private static let lookupMaxAge: TimeInterval = 24 * 60 * 60
    private static let parallelLookups = 6

    /// Per-CVE answers from OSV.dev and EUVD: the record, or nil when the CVE isn't listed there.
    private struct CachedLookup: Codable {
        var checked: Date
        var record: SourceRecord?
    }
    private var cache: [String: CachedLookup] = [:]
    private var cacheURL: URL { Storage.base.appendingPathComponent("sources-cache.json") }

    init(enabled: Set<CVESource>, progress: @escaping (String) -> Void) {
        self.enabled = enabled
        self.progress = progress
    }

    /// The NVD record, plus one record for each enabled database that lists the CVE, per CVE ID.
    func records(for cveIDs: [String]) async -> [String: [SourceRecord]] {
        var result: [String: [SourceRecord]] = [:]
        for id in cveIDs { result[id] = [Self.nvdRecord(id)] }
        guard !cveIDs.isEmpty else { return result }

        if enabled.contains(.kev) {
            progress("Checking \(cveIDs.count) CVEs against CISA's known exploited list…")
            if let kev = await loadKEV() {
                for id in cveIDs { if let r = kev[id] { result[id]?.append(r) } }
            }
        }
        let lookups = [CVESource.osv, .euvd].filter { enabled.contains($0) }
        if !lookups.isEmpty {
            cache = Storage.load([String: CachedLookup].self, from: cacheURL) ?? [:]
            for source in lookups {
                progress("Checking \(cveIDs.count) CVEs in \(source.fullName)…")
                let found = await lookUp(cveIDs, in: source)
                for (id, record) in found { result[id]?.append(record) }
            }
            // Drop stale answers so the cache doesn't grow without bound.
            let cutoff = Date().addingTimeInterval(-Self.lookupMaxAge)
            cache = cache.filter { $0.value.checked > cutoff }
            try? Storage.save(cache, to: cacheURL)
        }
        return result
    }

    static func nvdRecord(_ cveID: String) -> SourceRecord {
        SourceRecord(source: .nvd, url: "https://nvd.nist.gov/vuln/detail/\(cveID)")
    }

    // MARK: CISA KEV

    private func loadKEV() async -> [String: SourceRecord]? {
        let url = Storage.base.appendingPathComponent("kev.json")
        let age = (try? url.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate)
            .map { Date().timeIntervalSince($0) }
        if let age, age < Self.kevMaxAge, let data = try? Data(contentsOf: url), let kev = Self.parseKEV(data) {
            return kev
        }
        do {
            let (data, response) = try await URLSession.shared.data(
                for: URLRequest(url: Self.kevURL, timeoutInterval: 60))
            guard (response as? HTTPURLResponse)?.statusCode == 200, let kev = Self.parseKEV(data) else {
                throw URLError(.badServerResponse)
            }
            try? data.write(to: url, options: .atomic)
            return kev
        } catch {
            // An older copy is better than none.
            if let data = try? Data(contentsOf: url), let kev = Self.parseKEV(data) {
                warnings.append("CISA's known exploited list couldn't be updated; using the copy from earlier.")
                return kev
            }
            warnings.append("CISA's known exploited list couldn't be downloaded, so KEV is missing from this scan.")
            return nil
        }
    }

    /// CVE ID → KEV record, from CISA's catalogue JSON.
    static func parseKEV(_ data: Data) -> [String: SourceRecord]? {
        struct Catalog: Decodable {
            struct Entry: Decodable {
                let cveID: String
                let dateAdded: String?
                let knownRansomwareCampaignUse: String?
            }
            let vulnerabilities: [Entry]
        }
        guard let catalog = try? JSONDecoder().decode(Catalog.self, from: data) else { return nil }
        var result: [String: SourceRecord] = [:]
        for e in catalog.vulnerabilities {
            var note = "Known to be exploited in the wild"
            if let added = e.dateAdded { note += " (listed \(added))" }
            if e.knownRansomwareCampaignUse?.caseInsensitiveCompare("Known") == .orderedSame {
                note += "; used in ransomware campaigns"
            }
            result[e.cveID] = SourceRecord(
                source: .kev,
                url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=\(e.cveID)",
                note: note + ".")
        }
        return result
    }

    // MARK: OSV.dev and EUVD

    private func lookUp(_ ids: [String], in source: CVESource) async -> [String: SourceRecord] {
        var found: [String: SourceRecord] = [:]
        var pending: [String] = []
        let cutoff = Date().addingTimeInterval(-Self.lookupMaxAge)
        for id in ids {
            if let hit = cache[Self.cacheKey(id, source)], hit.checked > cutoff {
                if let r = hit.record { found[id] = r }
            } else {
                pending.append(id)
            }
        }
        var failures = 0
        // At most `parallelLookups` requests in flight; each child returns (id, record, failed).
        await withTaskGroup(of: (String, SourceRecord?, Bool).self) { group in
            var nextIndex = 0
            while nextIndex < min(Self.parallelLookups, pending.count) {
                let id = pending[nextIndex]
                nextIndex += 1
                group.addTask { await Self.lookUp(id, in: source) }
            }
            while let (id, record, failed) = await group.next() {
                if failed {
                    failures += 1
                } else {
                    cache[Self.cacheKey(id, source)] = CachedLookup(checked: Date(), record: record)
                    if let record { found[id] = record }
                }
                if nextIndex < pending.count {
                    let id = pending[nextIndex]
                    nextIndex += 1
                    group.addTask { await Self.lookUp(id, in: source) }
                }
            }
        }
        if failures > 0 {
            warnings.append("\(source.fullName) couldn't be reached for \(failures) of \(ids.count) CVEs.")
        }
        return found
    }

    private static func cacheKey(_ id: String, _ source: CVESource) -> String { "\(source.rawValue):\(id)" }

    /// One lookup that never throws: (id, record or nil when not listed, true when it couldn't be reached).
    private static func lookUp(_ id: String, in source: CVESource) async -> (String, SourceRecord?, Bool) {
        do {
            return (id, try await fetch(id, from: source), false)
        } catch {
            return (id, nil, true)
        }
    }

    /// The record for `id`, or nil when the database doesn't list it. Throws when it can't be reached.
    private static func fetch(_ id: String, from source: CVESource) async throws -> SourceRecord? {
        let url: URL
        switch source {
        case .osv:
            url = URL(string: "https://api.osv.dev/v1/vulns/\(id)")!
        case .euvd:
            var c = URLComponents(string: "https://euvdservices.enisa.europa.eu/api/search")!
            c.queryItems = [URLQueryItem(name: "text", value: id), URLQueryItem(name: "size", value: "5")]
            url = c.url!
        case .nvd, .kev:
            return nil
        }
        let (data, response) = try await URLSession.shared.data(for: URLRequest(url: url, timeoutInterval: 20))
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        if source == .osv, status == 404 { return nil }
        guard status == 200 else { throw URLError(.badServerResponse) }
        return source == .osv ? parseOSV(data, cveID: id) : parseEUVD(data, cveID: id)
    }

    /// OSV.dev's record for a CVE, with any GitHub Advisory IDs among its aliases.
    static func parseOSV(_ data: Data, cveID: String) -> SourceRecord? {
        struct Vuln: Decodable {
            let id: String
            let aliases: [String]?
        }
        guard let v = try? JSONDecoder().decode(Vuln.self, from: data) else { return nil }
        let ghsa = (v.aliases ?? []).filter { $0.hasPrefix("GHSA-") }.sorted()
        return SourceRecord(
            source: .osv, ids: ghsa, url: "https://osv.dev/vulnerability/\(v.id)",
            note: ghsa.isEmpty ? nil : "Also in the GitHub Advisory Database.")
    }

    /// The EUVD entry whose aliases include exactly this CVE (the search matches text loosely).
    static func parseEUVD(_ data: Data, cveID: String) -> SourceRecord? {
        struct Page: Decodable {
            struct Item: Decodable {
                let id: String
                let aliases: String?
            }
            let items: [Item]
        }
        guard let page = try? JSONDecoder().decode(Page.self, from: data),
            let item = page.items.first(where: { item in
                (item.aliases ?? "").split(whereSeparator: \.isNewline)
                    .contains { $0.trimmingCharacters(in: .whitespaces) == cveID }
            })
        else { return nil }
        return SourceRecord(
            source: .euvd, ids: [item.id], url: "https://euvd.enisa.europa.eu/vulnerability/\(item.id)")
    }
}
