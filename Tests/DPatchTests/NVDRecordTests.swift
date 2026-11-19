import Foundation
import Testing

@testable import DPatch

/// CVEs NVD hasn't analysed yet: no NVD score and no CPE configurations, only a CISA (ADP) score and
/// the vendor's affected versions. D-Patch must still read and match them; until 0.6.1 it never
/// downloaded them, so Apple's fixes in macOS 27.2.1 went unnoticed.
@Suite struct NVDRecordTests {
    /// NVD's record for CVE-2026-113961 (fixed in macOS 27.2.1), trimmed to the fields D-Patch reads.
    static let awaitingAnalysis = """
        {
          "id": "CVE-2026-113961",
          "published": "2026-11-09T22:18:25.917",
          "lastModified": "2026-11-12T22:18:21.267",
          "vulnStatus": "Awaiting Analysis",
          "descriptions": [{"lang": "en", "value": "An authorization issue was addressed with improved validation. This issue is fixed in macOS Golden Gate 27.2.1, macOS Sequoia 15.8.3, macOS Tahoe 26.7.3."}],
          "metrics": {
            "cvssMetricV31": [{
              "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
              "type": "Secondary",
              "cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}
            }]
          },
          "affected": [{
            "source": "product-security@apple.com",
            "affectedData": [
              {"vendor": "Apple", "product": "iOS and iPadOS", "versions": [
                {"version": "0", "lessThan": "26.7.3", "versionType": "custom", "status": "affected"},
                {"version": "0", "lessThan": "27.2.1", "versionType": "custom", "status": "affected"}]},
              {"vendor": "Apple", "product": "macOS", "versions": [
                {"version": "0", "lessThan": "15.8.3", "versionType": "custom", "status": "affected"},
                {"version": "0", "lessThan": "26.7.3", "versionType": "custom", "status": "affected"},
                {"version": "0", "lessThan": "27.2.1", "versionType": "custom", "status": "affected"}]}
            ]
          }]
        }
        """

    private func record() throws -> CVERecord {
        let nvd = try JSONDecoder().decode(NVDCVE.self, from: Data(Self.awaitingAnalysis.utf8))
        return try #require(CVERecord(nvd: nvd))
    }

    private func mac(_ version: String) -> InventoryItem {
        Fixtures.item(.macos, name: "macOS", version: version, aliases: ["macos", "macosx"], vendorHint: "apple")
    }

    @Test func keepsACVEScoredOnlyByCISA() throws {
        let r = try record()
        #expect(r.severity == .high)
        #expect(r.score == 7.5)
        #expect(r.ranges.contains { $0.product == "macOS" && $0.end == "27.2.1" && !$0.endInclusive })
    }

    @Test func flagsAMacThatNeeds27_2_1() throws {
        #expect(Matcher(cves: [try record()]).hits(for: mac("27.2")).map(\.cve.id) == ["CVE-2026-113961"])
    }

    @Test func doesNotFlagAMacOn27_2_1() throws {
        #expect(Matcher(cves: [try record()]).hits(for: mac("27.2.1")).isEmpty)
    }

    @Test func checksEachMacOSLineAgainstItsOwnFix() throws {
        // Older lines get their own fix (26.7.3, 15.8.3), so a fully updated one isn't flagged
        // just because it's below 27.2.1.
        let matcher = Matcher(cves: [try record()])
        #expect(matcher.hits(for: mac("26.7.3")).isEmpty)
        #expect(matcher.hits(for: mac("15.8.3")).isEmpty)
        #expect(!matcher.hits(for: mac("26.7.2")).isEmpty)
        #expect(!matcher.hits(for: mac("15.8.2")).isEmpty)
    }

    @Test func startsEachReleaseLineAtItsOwnVersion() {
        func open(_ end: String) -> ProductRange {
            ProductRange(
                nvd: false, vendor: "v", product: "p", start: nil, startInclusive: true, end: end, endInclusive: false)
        }
        let lines = CVERecord.releaseLines([open("27.2.1"), open("15.8.3"), open("26.7.3")])
            .sorted { Version.isLess($0.end, $1.end) }
        #expect(lines.map(\.start) == [nil, "26", "27"])
        #expect(
            CVERecord.releaseLines([open("1.2.5"), open("1.3.2")]).map(\.start).sorted { ($0 ?? "") < ($1 ?? "") } == [
                nil, "1.3",
            ])
        // A single range, or one with its own start, is unchanged.
        #expect(CVERecord.releaseLines([open("3.0")]).map(\.start) == [nil])
        var started = open("5.0")
        started.start = "4.0"
        #expect(
            CVERecord.releaseLines([started, open("3.0")]).map(\.start).sorted { ($0 ?? "") < ($1 ?? "") } == [
                nil, "4.0",
            ])
    }

    @Test func filtersBySeverityLocally() throws {
        let high = try record()
        var low = high
        low.id = "CVE-2026-0002"
        low.severity = .low
        #expect(NVDClient.select([high, low], severities: [.critical, .high]).map(\.id) == ["CVE-2026-113961"])
        #expect(NVDClient.select([high, low], severities: Severity.allCases).count == 2)
    }
}
