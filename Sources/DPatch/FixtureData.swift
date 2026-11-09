import Foundation

/// Runs the matcher against a fixed CVE and inventory set instead of this Mac's software and NVD.
/// Enabled by `--fixtures <dir>` or `$DPATCH_FIXTURES`; the directory holds `cves.json`,
/// `inventory.json` and an optional `fixes.json` keyed by `Finding.id` for fixes that would
/// otherwise need the network or `softwareupdate`.
enum FixtureData {
    static var directory: URL? {
        directory(arguments: CommandLine.arguments, environment: ProcessInfo.processInfo.environment)
    }

    static func directory(arguments args: [String], environment: [String: String]) -> URL? {
        if let i = args.firstIndex(of: "--fixtures"), i + 1 < args.count, !args[i + 1].isEmpty {
            return URL(fileURLWithPath: args[i + 1])
        }
        if let path = environment["DPATCH_FIXTURES"], !path.isEmpty {
            return URL(fileURLWithPath: path)
        }
        return nil
    }

    static var isActive: Bool { directory != nil }

    static func makeResult(from directory: URL, progress: (String) -> Void) async throws -> ScanResult {
        let cves = try load([CVERecord].self, from: directory.appendingPathComponent("cves.json"))
        let items = try load([InventoryItem].self, from: directory.appendingPathComponent("inventory.json"))
        let explicitFixes =
            (try? load([String: Fix].self, from: directory.appendingPathComponent("fixes.json"))) ?? [:]

        progress("Demo data: matching \(cves.count) CVEs against \(items.count) installed items…")
        let matcher = Matcher(cves: cves)
        let resolver = FixResolver()
        var findings: [Finding] = []
        for item in items {
            let hits = matcher.hits(for: item)
            guard !hits.isEmpty else { continue }
            guard let installed = Version(item.version) else { continue }
            for hit in hits {
                guard
                    let range = hit.ranges.filter({ $0.contains(installed) })
                        .min(by: { Version.isLess($0.end, $1.end) })
                else { continue }
                let id = "\(hit.cve.id)|\(item.key)"
                let fix: Fix?
                if let explicit = explicitFixes[id] {
                    fix = explicit
                } else {
                    fix = await resolver.fix(for: item, ranges: hit.ranges, references: hit.cve.references)
                }
                guard let fix else { continue }
                findings.append(Finding(cve: hit.cve, item: item, fixedIn: range.fixedInDescription, fix: fix))
            }
        }
        findings.sort { ($0.cve.published, $0.cve.score) > ($1.cve.published, $1.cve.score) }

        return ScanResult(
            scannedAt: Date(), lookbackDays: 90, severities: Severity.allCases, cvesChecked: cves.count,
            itemsChecked: items.count, findings: findings,
            warnings: ["Demo data from \(directory.path); Patch Now is disabled."] + resolver.warnings)
    }

    private static func load<T: Decodable>(_ type: T.Type, from url: URL) throws -> T {
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw NSError(
                domain: "D-Patch demo", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "Missing demo data file: \(url.path)"])
        }
        let data = try Data(contentsOf: url)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(type, from: data)
    }
}
