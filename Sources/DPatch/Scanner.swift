import Foundation

enum Scanner {
    static let completedNotification = Notification.Name("com.damonmatthews.dpatch.scanCompleted")

    /// Full scan: inventory, CVE download, matching, fix lookup. Saves and returns the result.
    /// With `--fixtures` or `$DPATCH_FIXTURES`, uses that demo data instead.
    static func run(progress: @escaping (String) -> Void) async throws -> ScanResult {
        let result: ScanResult
        if let directory = FixtureData.directory {
            result = try await FixtureData.makeResult(from: directory, progress: progress)
        } else {
            result = try await liveScan(progress: progress)
        }
        try Storage.save(result, to: Storage.resultsURL)
        DistributedNotificationCenter.default().postNotificationName(
            completedNotification, object: nil,
            userInfo: nil, deliverImmediately: true)
        return result
    }

    private static func liveScan(progress: @escaping (String) -> Void) async throws -> ScanResult {
        var warnings: [String] = []
        progress("Taking inventory of installed software…")
        let items = await Inventory.collect(warnings: &warnings)

        let lookback = min(max(Prefs.lookbackDays, 7), 365)
        let severities = Prefs.severities
        let cves = try await NVDClient(apiKey: Prefs.nvdAPIKey, severities: severities, progress: progress)
            .update(lookbackDays: lookback)

        progress("Matching \(cves.count) CVEs against \(items.count) installed items…")
        let matcher = Matcher(cves: cves)
        let resolver = FixResolver()
        var findings: [Finding] = []
        for item in items {
            let hits = matcher.hits(for: item)
            guard !hits.isEmpty, let installed = Version(item.version) else { continue }
            progress("Looking for fixes for \(item.name)…")
            for hit in hits {
                let fix = await resolver.fix(for: item, ranges: hit.ranges, references: hit.cve.references)
                if let f = finding(hit, item: item, installed: installed, fix: fix) { findings.append(f) }
            }
        }
        findings.sort { ($0.cve.published, $0.cve.score) > ($1.cve.published, $1.cve.score) }

        let checker = SourceChecker(enabled: Prefs.cveSources, progress: progress)
        let sources = await checker.records(for: Array(Set(findings.map(\.cve.id))).sorted())
        for i in findings.indices { findings[i].sources = sources[findings[i].cve.id] }

        // Listed at the top whether or not they fix a CVE (softwareupdate's list is loaded once per scan).
        progress("Checking for macOS updates…")
        let macOSUpdates = await resolver.macOSUpdates(installed: items.first { $0.kind == .macos }?.version)

        return ScanResult(
            scannedAt: Date(), lookbackDays: lookback, severities: severities, cvesChecked: cves.count,
            itemsChecked: items.count, findings: findings,
            warnings: warnings + resolver.warnings + checker.warnings, macOSUpdates: macOSUpdates)
    }

    /// A CVE that affects the installed version, listed whether or not an update fixes it yet.
    static func finding(_ hit: Matcher.Hit, item: InventoryItem, installed: Version, fix: Fix?) -> Finding? {
        guard
            let range = hit.ranges.filter({ $0.contains(installed) }).min(by: { Version.isLess($0.end, $1.end) })
        else { return nil }
        return Finding(
            cve: hit.cve, item: item, fixedIn: ProductRange.fixedInDescription(range, among: hit.ranges), fix: fix)
    }

    /// One line for the log and the notification: "3 fixable CVEs (1 critical); 5 more affect this Mac but have no fix yet."
    static func summary(_ r: ScanResult) -> String {
        let fixable = Set(r.findings.filter { $0.fix != nil }.map(\.cve.id))
        let crit = Set(r.findings.filter { $0.fix != nil && $0.cve.severity == .critical }.map(\.cve.id)).count
        let unfixed = Set(r.findings.map(\.cve.id)).subtracting(fixable).count
        var s = "\(fixable.count) fixable CVE\(fixable.count == 1 ? "" : "s") (\(crit) critical)"
        if unfixed > 0 { s += "; \(unfixed) more affect this Mac but have no fix yet" }
        return s
    }

    /// Entry point for `DPatch --scan` (used by the scheduled LaunchAgent).
    static func runHeadless() -> Int32 {
        var status: Int32 = 0
        let done = DispatchSemaphore(value: 0)
        Task.detached {
            do {
                let r = try await run { print($0) }
                print(
                    "Scan complete: \(summary(r)), across \(r.itemsChecked) items, \(r.cvesChecked) CVEs checked.")
                for warning in r.warnings { print("warning: \(warning)") }
                if Prefs.notifyAfterAutoscan, CommandLine.arguments.contains("--notify") {
                    notify(r.findings.isEmpty ? "No CVEs affect this Mac." : "\(summary(r)). Open D-Patch to review.")
                }
            } catch {
                print("Scan failed: \(error.localizedDescription)")
                status = 1
            }
            done.signal()
        }
        done.wait()
        return status
    }

    private static func notify(_ message: String) {
        let script = "display notification \"\(message)\" with title \"D-Patch\""
        _ = try? Process.run(URL(fileURLWithPath: "/usr/bin/osascript"), arguments: ["-e", script]).waitUntilExit()
    }
}
