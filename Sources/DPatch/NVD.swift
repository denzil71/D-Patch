import Foundation

/// Fetches HIGH/CRITICAL CVEs from the NVD 2.0 API and keeps a local, incrementally updated cache.
struct NVDClient {
    var apiKey: String?
    var progress: (String) -> Void

    static let endpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    static let maxRangeDays = 120   // NVD limit for one date range
    private static var lastRequest = Date.distantPast

    struct Cache: Codable {
        var windowStart: Date
        var fetchedThrough: Date
        var records: [String: CVERecord]
    }

    /// Returns cached + fresh CVEs published within the last `lookbackDays`.
    func update(lookbackDays: Int) async throws -> [CVERecord] {
        let now = Date()
        let start = Calendar.current.date(byAdding: .day, value: -lookbackDays, to: now)!
        var cache: Cache
        if let old = Storage.load(Cache.self, from: Storage.cacheURL), !old.records.isEmpty,
           now.timeIntervalSince(old.fetchedThrough) < Double(Self.maxRangeDays) * 86_400 {
            cache = old
            // Extend the window backwards by publish date when the look-back grew.
            if start < cache.windowStart {
                for r in try await fetch(field: "pub", from: start, to: cache.windowStart) { cache.records[r.id] = r }
            }
            // Then pick up everything published or changed since the last scan.
            for r in try await fetch(field: "lastMod", from: cache.fetchedThrough.addingTimeInterval(-3600), to: now)
            where r.published >= start {
                cache.records[r.id] = r
            }
        } else {
            cache = Cache(windowStart: start, fetchedThrough: now, records: [:])
            for r in try await fetch(field: "pub", from: start, to: now) { cache.records[r.id] = r }
        }
        cache.windowStart = start
        cache.fetchedThrough = now
        cache.records = cache.records.filter { $0.value.published >= start }
        try Storage.save(cache, to: Storage.cacheURL)
        return Array(cache.records.values)
    }

    private func fetch(field: String, from: Date, to: Date) async throws -> [CVERecord] {
        var out: [CVERecord] = []
        // Filtering by severity on the server keeps downloads small (all CVEs are ~20x more).
        for severity in ["CRITICAL", "HIGH"] {
            var chunkStart = from
            while chunkStart < to {
                let chunkEnd = min(to, chunkStart.addingTimeInterval(Double(Self.maxRangeDays) * 86_400))
                var index = 0
                while true {
                    let page = try await request(field: field, severity: severity, from: chunkStart, to: chunkEnd, startIndex: index)
                    out += page.vulnerabilities.compactMap { CVERecord(nvd: $0.cve) }
                    index += page.resultsPerPage
                    progress("Downloading \(severity.lowercased()) CVEs \(Self.dayFormatter.string(from: chunkStart))–\(Self.dayFormatter.string(from: chunkEnd)): \(min(index, page.totalResults)) of \(page.totalResults)")
                    if page.resultsPerPage == 0 || index >= page.totalResults { break }
                }
                chunkStart = chunkEnd
            }
        }
        return out
    }

    private func request(field: String, severity: String, from: Date, to: Date, startIndex: Int) async throws -> NVDResponse {
        var c = URLComponents(string: Self.endpoint)!
        c.queryItems = [
            URLQueryItem(name: "\(field)StartDate", value: Self.isoFormatter.string(from: from)),
            URLQueryItem(name: "\(field)EndDate", value: Self.isoFormatter.string(from: to)),
            URLQueryItem(name: "cvssV3Severity", value: severity),
            URLQueryItem(name: "resultsPerPage", value: "1000"),
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
            let wait = attempt == 0 ? pause - Date().timeIntervalSince(Self.lastRequest) : pause * Double(attempt + 1) * 2
            if wait > 0 { try await Task.sleep(nanoseconds: UInt64(wait * 1_000_000_000)) }
            Self.lastRequest = Date()
            do {
                let (data, resp) = try await URLSession.shared.data(for: req)
                let status = (resp as? HTTPURLResponse)?.statusCode ?? 0
                if status == 200 {
                    // NVD occasionally answers 200 with an empty or cut-off body; retry those.
                    do { return try JSONDecoder().decode(NVDResponse.self, from: data) } catch let e as DecodingError {
                        if attempt >= 3 {
                            throw NSError(domain: "NVD", code: 0, userInfo: [NSLocalizedDescriptionKey:
                                "Unexpected NVD response (\(data.count) bytes): \(Self.describe(e))"])
                        }
                        attempt += 1
                        progress("NVD sent an incomplete response, retrying (\(attempt)/3)…")
                        continue
                    }
                }
                if attempt >= 3 || ![403, 429, 500, 502, 503, 504].contains(status) {
                    throw NSError(domain: "NVD", code: status, userInfo: [NSLocalizedDescriptionKey:
                        "NVD returned HTTP \(status)" + (status == 404 ? " (check the API key)" : "")])
                }
            } catch let e as URLError where attempt < 3 {
                progress("NVD request failed (\(e.code.rawValue)), retrying…")
            }
            attempt += 1
            progress("NVD is rate limiting, retrying (\(attempt)/3)…")
        }
    }

    static func describe(_ e: DecodingError) -> String {
        let path: [CodingKey], detail: String
        switch e {
        case .keyNotFound(let k, let c): (path, detail) = (c.codingPath + [k], "missing")
        case .typeMismatch(_, let c), .valueNotFound(_, let c), .dataCorrupted(let c): (path, detail) = (c.codingPath, c.debugDescription)
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
    struct Text: Decodable { var lang: String; var value: String }
    struct Metric: Decodable {
        struct Data: Decodable { var baseScore: Double; var baseSeverity: String?; var vectorString: String? }
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
              let published = NVDClient.nvdDateFormatter.date(from: c.published) else { return nil }
        // Prefer NVD's own (Primary) score, then the CNA's, newest CVSS version first.
        let metrics = [c.metrics?.cvssMetricV31, c.metrics?.cvssMetricV40, c.metrics?.cvssMetricV30].compactMap { $0 }.flatMap { $0 }
        guard let m = metrics.first(where: { $0.type == "Primary" }) ?? metrics.first,
              let sev = m.cvssData.baseSeverity.flatMap(Severity.init(rawValue:)) else { return nil }

        var ranges = Set<ProductRange>()
        for node in (c.configurations ?? []).flatMap(\.nodes) {
            for m in node.cpeMatch ?? [] where m.vulnerable {
                if let r = Self.range(cpe: m) { ranges.insert(r) }
            }
        }
        for a in (c.affected ?? []).flatMap({ $0.affectedData ?? [] }) {
            guard let vendor = a.vendor, let product = a.product else { continue }
            for v in a.versions ?? [] where v.status == "affected" {
                if let r = Self.range(vendor: vendor, product: product, v) { ranges.insert(r) }
            }
        }
        guard !ranges.isEmpty else { return nil }

        self.init(id: c.id, published: published,
                  lastModified: NVDClient.nvdDateFormatter.date(from: c.lastModified) ?? published,
                  severity: sev, score: m.cvssData.baseScore, vector: m.cvssData.vectorString ?? "",
                  summary: c.descriptions?.first(where: { $0.lang == "en" })?.value ?? "",
                  references: Array((c.references ?? []).map(\.url).prefix(8)),
                  ranges: Array(ranges))
    }

    /// cpe:2.3:part:vendor:product:version:... with optional version bounds.
    static func range(cpe m: NVDCVE.CPEMatch) -> ProductRange? {
        let f = m.criteria.split(separator: ":", omittingEmptySubsequences: false).map {
            $0.replacingOccurrences(of: "\\", with: "")
        }
        guard f.count > 5 else { return nil }
        let end = m.versionEndExcluding ?? m.versionEndIncluding
        guard let end, Version(end) != nil else { return nil }
        return ProductRange(nvd: true, vendor: f[3], product: f[4],
                            start: m.versionStartIncluding ?? m.versionStartExcluding,
                            startInclusive: m.versionStartExcluding == nil,
                            end: end, endInclusive: m.versionEndExcluding == nil)
    }

    /// CNA "affected" entries: {version, lessThan|lessThanOrEqual} or free text like ">= 3.0, < 3.9".
    static func range(vendor: String, product: String, _ v: NVDCVE.Affected.Data.V) -> ProductRange? {
        let openStarts: Set<String> = ["0", "*", "unspecified", "n/a", ""]
        func start(_ s: String?) -> String? {
            guard let s, !openStarts.contains(s.lowercased()), Version(s) != nil else { return nil }
            return s
        }
        var r: ProductRange?
        if let lt = v.lessThan ?? v.lessThanOrEqual, let end = Version.firstToken(in: lt) {
            r = ProductRange(nvd: false, vendor: vendor, product: product, start: start(v.version), startInclusive: true,
                             end: end, endInclusive: v.lessThan == nil)
        } else if let text = v.version {
            let upper = text.range(of: #"<=?\s*v?(\d[0-9A-Za-z.\-_]*)"#, options: .regularExpression)
            if let upper {
                let bound = String(text[upper])
                let lower = text.range(of: #">=?\s*v?(\d[0-9A-Za-z.\-_]*)"#, options: .regularExpression).map { String(text[$0]) }
                r = ProductRange(nvd: false, vendor: vendor, product: product,
                                 start: lower.flatMap(Version.firstToken(in:)),
                                 startInclusive: lower.map { $0.hasPrefix(">=") } ?? true,
                                 end: Version.firstToken(in: bound) ?? bound,
                                 endInclusive: bound.hasPrefix("<="))
            } else if let m = text.range(of: #"^\s*(\d+(\.\d+)*)\s*-\s*(\d+(\.\d+)*)\s*$"#, options: .regularExpression) {
                let sides = text[m].split(separator: "-").map { $0.trimmingCharacters(in: .whitespaces) }
                r = ProductRange(nvd: false, vendor: vendor, product: product, start: sides[0], startInclusive: true,
                                 end: sides[1], endInclusive: true)
            }
        }
        guard var range = r, let ev = Version(range.end) else { return nil }
        // Some CNAs repeat the fixed version as the start ("155.0" lessThan "155.0"); treat it as open.
        if let s = range.start, let sv = Version(s), sv >= ev { range.start = nil }
        return range
    }
}
