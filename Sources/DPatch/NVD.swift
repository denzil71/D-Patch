import Foundation

/// Fetches CVEs from the NVD 2.0 API and keeps a local, incrementally updated cache.
///
/// Every CVE in the window is downloaded, whatever its severity, and filtered by severity locally.
/// NVD's `cvssV3Severity` filter only matches CVEs NVD has scored itself, and with its analysis
/// backlog most new CVEs only carry a CISA (ADP) or vendor (CNA) score for weeks — filtering on the
/// server hid almost all of them, including Apple's fixes the day they ship.
struct NVDClient {
    var apiKey: String?
    var severities: [Severity]
    var progress: (String) -> Void

    static let endpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    static let maxRangeDays = 120  // NVD limit for one date range
    static let pageSize = 2000  // NVD maximum
    /// Bump when the cache's contents change meaning, so older caches are rebuilt.
    static let cacheFormat = 3
    private static var lastRequest = Date.distantPast

    struct Cache: Codable {
        var windowStart: Date
        var fetchedThrough: Date
        /// Every scored CVE in the window with version data, of any severity.
        var records: [String: CVERecord]
        /// Only in caches written before format 2, which held just these levels.
        var severities: [Severity]?
        /// nil for caches written before format 2.
        var format: Int?
    }

    /// Returns cached + fresh CVEs published within the last `lookbackDays`, at the chosen severities.
    func update(lookbackDays: Int) async throws -> [CVERecord] {
        let now = Date()
        let start = Calendar.current.date(byAdding: .day, value: -lookbackDays, to: now)!
        var cache: Cache
        if let old = Storage.load(Cache.self, from: Storage.cacheURL), old.format == Self.cacheFormat,
            now.timeIntervalSince(old.fetchedThrough) < Double(Self.maxRangeDays) * 86_400
        {
            cache = old
            // Extend the window backwards by publish date when the look-back grew.
            if start < cache.windowStart {
                for r in try await fetch(field: "pub", from: start, to: cache.windowStart) {
                    cache.records[r.id] = r
                }
            }
            // Then pick up everything published or changed since the last scan.
            for r in try await fetch(field: "lastMod", from: cache.fetchedThrough.addingTimeInterval(-3600), to: now)
            where r.published >= start {
                cache.records[r.id] = r
            }
        } else {
            // No cache, a stale one, or one from before format 2 (which missed CVEs NVD hadn't scored).
            cache = Cache(windowStart: start, fetchedThrough: now, records: [:], format: Self.cacheFormat)
            for r in try await fetch(field: "pub", from: start, to: now) {
                cache.records[r.id] = r
            }
        }
        cache.windowStart = start
        cache.fetchedThrough = now
        cache.severities = nil
        cache.format = Self.cacheFormat
        cache.records = cache.records.filter { $0.value.published >= start }
        try Storage.save(cache, to: Storage.cacheURL)
        return Self.select(Array(cache.records.values), severities: severities)
    }

    /// The records at the chosen levels, plus every unscored one: there's no level to judge it by yet.
    static func select(_ records: [CVERecord], severities: [Severity]) -> [CVERecord] {
        let wanted = Set(severities + [.unscored])
        return records.filter { wanted.contains($0.severity) }
    }

    private func fetch(field: String, from: Date, to: Date) async throws -> [CVERecord] {
        var out: [CVERecord] = []
        var chunkStart = from
        while chunkStart < to {
            let chunkEnd = min(to, chunkStart.addingTimeInterval(Double(Self.maxRangeDays) * 86_400))
            var index = 0
            while true {
                let page = try await request(field: field, from: chunkStart, to: chunkEnd, startIndex: index)
                out += page.vulnerabilities.compactMap { CVERecord(nvd: $0.cve) }
                index += page.resultsPerPage
                progress(
                    "Downloading CVEs \(Self.dayFormatter.string(from: chunkStart))–\(Self.dayFormatter.string(from: chunkEnd)): \(min(index, page.totalResults)) of \(page.totalResults)"
                )
                if page.resultsPerPage == 0 || index >= page.totalResults { break }
            }
            chunkStart = chunkEnd
        }
        return out
    }

    private func request(field: String, from: Date, to: Date, startIndex: Int) async throws
        -> NVDResponse
    {
        var c = URLComponents(string: Self.endpoint)!
        c.queryItems = [
            URLQueryItem(name: "\(field)StartDate", value: Self.isoFormatter.string(from: from)),
            URLQueryItem(name: "\(field)EndDate", value: Self.isoFormatter.string(from: to)),
            URLQueryItem(name: "resultsPerPage", value: String(Self.pageSize)),
            URLQueryItem(name: "startIndex", value: String(startIndex)),
            URLQueryItem(name: "noRejected", value: nil),
        ]
        var req = URLRequest(url: c.url!, timeoutInterval: 120)
        req.setValue("D-Patch/1.0", forHTTPHeaderField: "User-Agent")
        if let key = apiKey, !key.isEmpty { req.setValue(key, forHTTPHeaderField: "apiKey") }

        // NVD allows 5 requests / 30 s without a key, 50 with one.
        let pause: TimeInterval = (apiKey?.isEmpty ?? true) ? 6.5 : 0.7
        var attempt = 0
        while true {
            let wait =
                attempt == 0 ? pause - Date().timeIntervalSince(Self.lastRequest) : pause * Double(attempt + 1) * 2
            if wait > 0 { try await Task.sleep(nanoseconds: UInt64(wait * 1_000_000_000)) }
            Self.lastRequest = Date()
            do {
                let (data, resp) = try await URLSession.shared.data(for: req)
                let status = (resp as? HTTPURLResponse)?.statusCode ?? 0
                if status == 200 {
                    // NVD occasionally answers 200 with an empty or cut-off body; retry those.
                    do { return try JSONDecoder().decode(NVDResponse.self, from: data) } catch let e as DecodingError {
                        if attempt >= 3 {
                            throw NSError(
                                domain: "NVD", code: 0,
                                userInfo: [
                                    NSLocalizedDescriptionKey:
                                        "Unexpected NVD response (\(data.count) bytes): \(Self.describe(e))"
                                ])
                        }
                        attempt += 1
                        progress("NVD sent an incomplete response, retrying (\(attempt)/3)…")
                        continue
                    }
                }
                if attempt >= 3 || ![403, 429, 500, 502, 503, 504].contains(status) {
                    throw NSError(
                        domain: "NVD", code: status,
                        userInfo: [
                            NSLocalizedDescriptionKey:
                                "NVD returned HTTP \(status)" + (status == 404 ? " (check the API key)" : "")
                        ])
                }
            } catch let e as URLError where attempt < 3 {
                progress("NVD request failed (\(e.code.rawValue)), retrying…")
            }
            attempt += 1
            progress("NVD is rate limiting, retrying (\(attempt)/3)…")
        }
    }

    static func describe(_ e: DecodingError) -> String {
        let path: [CodingKey]
        let detail: String
        switch e {
        case .keyNotFound(let k, let c): (path, detail) = (c.codingPath + [k], "missing")
        case .typeMismatch(_, let c), .valueNotFound(_, let c), .dataCorrupted(let c):
            (path, detail) = (c.codingPath, c.debugDescription)
        @unknown default: return e.localizedDescription
        }
        return path.map { $0.intValue.map(String.init) ?? $0.stringValue }.joined(separator: ".") + " — " + detail
    }

    static let isoFormatter: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        f.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"
        return f
    }()

    static let nvdDateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        f.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
        return f
    }()

    static let dayFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "d MMM"
        return f
    }()
}

// MARK: - NVD JSON

struct NVDResponse: Decodable {
    var resultsPerPage: Int
    var startIndex: Int
    var totalResults: Int
    var vulnerabilities: [Wrapper]
    struct Wrapper: Decodable { var cve: NVDCVE }
}

struct NVDCVE: Decodable {
    struct Text: Decodable {
        var lang: String
        var value: String
    }
    struct Metric: Decodable {
        struct Data: Decodable {
            var baseScore: Double
            var baseSeverity: String?
            var vectorString: String?
        }
        var type: String?
        var cvssData: Data
    }
    struct Metrics: Decodable {
        var cvssMetricV31: [Metric]?
        var cvssMetricV40: [Metric]?
        var cvssMetricV30: [Metric]?
    }
    struct CPEMatch: Decodable {
        var vulnerable: Bool
        var criteria: String
        var versionStartIncluding: String?
        var versionStartExcluding: String?
        var versionEndIncluding: String?
        var versionEndExcluding: String?
    }
    struct Node: Decodable { var cpeMatch: [CPEMatch]? }
    struct Configuration: Decodable { var nodes: [Node] }
    struct Affected: Decodable {
        struct Data: Decodable {
            struct V: Decodable {
                var version: String?
                var lessThan: String?
                var lessThanOrEqual: String?
                var status: String?
                var versionType: String?
            }
            var vendor: String?
            var product: String?
            var versions: [V]?
        }
        var affectedData: [Data]?
    }
    struct Reference: Decodable { var url: String }

    var id: String
    var published: String
    var lastModified: String
    var vulnStatus: String?
    var descriptions: [Text]?
    var metrics: Metrics?
    var configurations: [Configuration]?
    var affected: [Affected]?
    var references: [Reference]?
}

extension CVERecord {
    init?(nvd c: NVDCVE) {
        guard c.vulnStatus != "Rejected",
            let published = NVDClient.nvdDateFormatter.date(from: c.published)
        else { return nil }
        // Prefer NVD's own (Primary) score, then the CNA's, newest CVSS version first. A CVE no one
        // has scored yet is kept as unscored: it can still name versions that are installed here.
        let metrics = [c.metrics?.cvssMetricV31, c.metrics?.cvssMetricV40, c.metrics?.cvssMetricV30].compactMap { $0 }
            .flatMap { $0 }.filter { $0.cvssData.baseSeverity.flatMap(Severity.init(rawValue:)) != nil }
        let m = metrics.first(where: { $0.type == "Primary" }) ?? metrics.first
        let sev = m?.cvssData.baseSeverity.flatMap(Severity.init(rawValue:)) ?? .unscored

        var ranges = Set<ProductRange>()
        for node in (c.configurations ?? []).flatMap(\.nodes) {
            for m in node.cpeMatch ?? [] where m.vulnerable {
                if let r = Self.range(cpe: m) { ranges.insert(r) }
            }
        }
        var cnaRanges: [ProductRange] = []
        for a in (c.affected ?? []).flatMap({ $0.affectedData ?? [] }) {
            guard let vendor = a.vendor, let product = a.product else { continue }
            for v in a.versions ?? [] where v.status == "affected" {
                if let r = Self.range(vendor: vendor, product: product, v) { cnaRanges.append(r) }
            }
        }
        ranges.formUnion(Self.releaseLines(cnaRanges))
        guard !ranges.isEmpty else { return nil }

        self.init(
            id: c.id, published: published,
            lastModified: NVDClient.nvdDateFormatter.date(from: c.lastModified) ?? published,
            severity: sev, score: m?.cvssData.baseScore ?? 0, vector: m?.cvssData.vectorString ?? "",
            summary: c.descriptions?.first(where: { $0.lang == "en" })?.value ?? "",
            references: Array((c.references ?? []).map(\.url).prefix(8)),
            ranges: Array(ranges))
    }

    /// cpe:2.3:part:vendor:product:version:update:... with optional version bounds, or naming one
    /// version ("assimp:6.0.3") when there are none.
    static func range(cpe m: NVDCVE.CPEMatch) -> ProductRange? {
        let f = m.criteria.split(separator: ":", omittingEmptySubsequences: false).map {
            $0.replacingOccurrences(of: "\\", with: "")
        }
        guard f.count > 5 else { return nil }
        let any: Set<String> = ["*", "-", ""]
        let end = m.versionEndExcluding ?? m.versionEndIncluding
        guard let end, Version(end) != nil, !Version.looksLikeCommit(end) else {
            // One version, and no update qualifier ("9.8:p1") the installed version couldn't be told apart by.
            guard m.versionStartIncluding == nil, m.versionStartExcluding == nil, !any.contains(f[5]),
                Version(f[5]) != nil, f.count < 7 || any.contains(f[6])
            else { return nil }
            return ProductRange(
                nvd: true, vendor: f[3], product: f[4], start: f[5], startInclusive: true, end: f[5], endInclusive: true
            )
        }
        return ProductRange(
            nvd: true, vendor: f[3], product: f[4],
            start: m.versionStartIncluding ?? m.versionStartExcluding,
            startInclusive: m.versionStartExcluding == nil,
            end: end, endInclusive: m.versionEndExcluding == nil)
    }

    /// Vendors list a fix per release line as ranges that all start at 0: macOS "< 15.8.3",
    /// "< 26.7.3", "< 27.2.1". Taken literally, a fully updated 26.7.3 falls inside "< 27.2.1". Each
    /// range after the lowest therefore starts at its own line: the end's version up to its first
    /// part that differs from the next-lower end ("26" for 26.7.3 after 15.8.3, "1.3" for 1.3.2
    /// after 1.2.5). Ranges with their own start, and lone ranges, are left as they are.
    static func releaseLines(_ ranges: [ProductRange]) -> [ProductRange] {
        let open = ranges.filter { $0.start == nil }
        let grouped = Dictionary(grouping: open) { "\($0.vendor.lowercased())|\($0.product.lowercased())" }
        var result = ranges.filter { $0.start != nil }
        for (_, group) in grouped {
            let sorted = group.sorted { Version.isLess($0.end, $1.end) }
            for (i, range) in sorted.enumerated() {
                var range = range
                if i > 0 {
                    let lower = sorted[i - 1].end.split(separator: ".")
                    let parts = range.end.split(separator: ".")
                    let differ = parts.indices.first { $0 >= lower.count || parts[$0] != lower[$0] }
                    if let differ, differ < parts.count {
                        range.start = parts[...differ].joined(separator: ".")
                        range.startInclusive = true
                    }
                }
                result.append(range)
            }
        }
        return result
    }

    /// CNA "affected" entries: {version, lessThan|lessThanOrEqual} or free text like ">= 3.0, < 3.9".
    static func range(vendor: String, product: String, _ v: NVDCVE.Affected.Data.V) -> ProductRange? {
        let openStarts: Set<String> = ["0", "*", "unspecified", "n/a", ""]
        func start(_ s: String?) -> String? {
            guard let s, !openStarts.contains(s.lowercased()), Version(s) != nil else { return nil }
            return s
        }
        // Commits can't be compared with an installed version.
        guard v.versionType != "git" else { return nil }
        var r: ProductRange?
        if let lt = v.lessThan ?? v.lessThanOrEqual, let end = Version.firstToken(in: lt) {
            r = ProductRange(
                nvd: false, vendor: vendor, product: product, start: start(v.version), startInclusive: true,
                end: end, endInclusive: v.lessThan == nil)
        } else if let text = v.version {
            let upper = text.range(of: #"<=?\s*v?(\d[0-9A-Za-z.\-_]*)"#, options: .regularExpression)
            if let upper {
                let bound = String(text[upper])
                let lower = text.range(of: #">=?\s*v?(\d[0-9A-Za-z.\-_]*)"#, options: .regularExpression).map {
                    String(text[$0])
                }
                r = ProductRange(
                    nvd: false, vendor: vendor, product: product,
                    start: lower.flatMap(Version.firstToken(in:)),
                    startInclusive: lower.map { $0.hasPrefix(">=") } ?? true,
                    end: Version.firstToken(in: bound) ?? bound,
                    endInclusive: bound.hasPrefix("<="))
            } else if let m = text.range(of: #"^\s*(\d+(\.\d+)*)\s*-\s*(\d+(\.\d+)*)\s*$"#, options: .regularExpression)
            {
                let sides = text[m].split(separator: "-").map { $0.trimmingCharacters(in: .whitespaces) }
                r = ProductRange(
                    nvd: false, vendor: vendor, product: product, start: sides[0], startInclusive: true,
                    end: sides[1], endInclusive: true)
            } else if let exact = start(text), !text.contains(" "), !text.contains("*"), !Version.looksLikeCommit(text)
            {
                // One listed version ("6.0.3"); commit hashes and wildcards can't be compared.
                return ProductRange(
                    nvd: false, vendor: vendor, product: product, start: exact, startInclusive: true,
                    end: exact, endInclusive: true)
            }
        }
        guard var range = r, let ev = Version(range.end), !Version.looksLikeCommit(range.end) else { return nil }
        // Some CNAs repeat the fixed version as the start ("155.0" lessThan "155.0"); treat it as open.
        if let s = range.start, let sv = Version(s), sv >= ev { range.start = nil }
        return range
    }
}
