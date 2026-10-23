import Foundation

enum Scanner {
    static let completedNotification = Notification.Name("com.damonmatthews.dpatch.scanCompleted")

    /// Full scan: inventory, CVE download, matching, fix lookup. Saves and returns the result.
    static func run(progress: @escaping (String) -> Void) async throws -> ScanResult {
        var warnings: [String] = []
        progress("Taking inventory of installed software…")
        let items = await Inventory.collect(warnings: &warnings)

        let lookback = min(max(Prefs.lookbackDays, 7), 365)
        let cves = try await NVDClient(apiKey: Prefs.nvdAPIKey, progress: progress).update(lookbackDays: lookback)

        progress("Matching \(cves.count) CVEs against \(items.count) installed items…")
        let matcher = Matcher(cves: cves)
        let resolver = FixResolver()
        var findings: [Finding] = []
        for item in items {
            let hits = matcher.hits(for: item)
            guard !hits.isEmpty else { continue }
            progress("Looking for fixes for \(item.name)…")
            for hit in hits {
                let installed = Version(item.version)!
                guard let range = hit.ranges.first(where: { $0.contains(installed) }),
                      let fix = await resolver.fix(for: item, ranges: hit.ranges) else { continue }
                findings.append(Finding(cve: hit.cve, item: item, fixedIn: range.fixedInDescription, fix: fix))
            }
        }
        findings.sort { ($0.cve.published, $0.cve.score) > ($1.cve.published, $1.cve.score) }

        let result = ScanResult(scannedAt: Date(), lookbackDays: lookback, cvesChecked: cves.count,
                                itemsChecked: items.count, findings: findings,
                                warnings: warnings + resolver.warnings)
        try Storage.save(result, to: Storage.resultsURL)
        DistributedNotificationCenter.default().postNotificationName(completedNotification, object: nil,
                                                                     userInfo: nil, deliverImmediately: true)
        return result
    }

    /// Entry point for `DPatch --scan` (used by the scheduled LaunchAgent).
    static func runHeadless() -> Int32 {
        var status: Int32 = 0
        let done = DispatchSemaphore(value: 0)
        Task.detached {
            do {
                let r = try await run { print($0) }
                let crit = Set(r.findings.filter { $0.cve.severity == .critical }.map(\.cve.id)).count
                let all = Set(r.findings.map(\.cve.id)).count
                print("Scan complete: \(all) fixable CVEs (\(crit) critical) across \(r.itemsChecked) items, \(r.cvesChecked) CVEs checked.")
                r.warnings.forEach { print("warning: \($0)") }
                if Prefs.notifyAfterAutoscan, CommandLine.arguments.contains("--notify") {
                    notify(all == 0 ? "No fixable critical/high CVEs found."
                                    : "\(all) fixable CVEs found (\(crit) critical). Open D-Patch to review.")
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
