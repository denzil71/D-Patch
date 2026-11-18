import Foundation
import Testing

@testable import DPatch

@Suite struct CVESourcesTests {
    @Test func readsCISAsCatalogue() throws {
        let json = """
            {"catalogVersion": "2026.11.17", "vulnerabilities": [
              {"cveID": "CVE-2026-1111", "dateAdded": "2026-11-02", "knownRansomwareCampaignUse": "Known"},
              {"cveID": "CVE-2026-2222", "dateAdded": "2026-10-01", "knownRansomwareCampaignUse": "Unknown"}
            ]}
            """
        let kev = try #require(SourceChecker.parseKEV(Data(json.utf8)))
        #expect(kev.count == 2)
        let ransomware = try #require(kev["CVE-2026-1111"])
        #expect(ransomware.source == .kev)
        #expect(
            ransomware.note == "Known to be exploited in the wild (listed 2026-11-02); used in ransomware campaigns.")
        #expect(kev["CVE-2026-2222"]?.note == "Known to be exploited in the wild (listed 2026-10-01).")
        #expect(SourceChecker.parseKEV(Data("not json".utf8)) == nil)
    }

    @Test func readsOSVWithGitHubAdvisories() throws {
        let json = #"{"id": "CVE-2024-3094", "aliases": ["GHSA-rxwq-x6h5-x525", "BIT-xz-2024-3094"]}"#
        let record = try #require(SourceChecker.parseOSV(Data(json.utf8), cveID: "CVE-2024-3094"))
        #expect(record.source == .osv)
        #expect(record.ids == ["GHSA-rxwq-x6h5-x525"])
        #expect(record.url == "https://osv.dev/vulnerability/CVE-2024-3094")
        #expect(record.note == "Also in the GitHub Advisory Database.")
    }

    @Test func readsOSVWithoutAliases() throws {
        let record = try #require(SourceChecker.parseOSV(Data(#"{"id": "CVE-2026-1"}"#.utf8), cveID: "CVE-2026-1"))
        #expect(record.ids.isEmpty)
        #expect(record.note == nil)
    }

    @Test func readsTheExactEUVDMatch() throws {
        // EUVD's search matches loosely, so only an exact alias counts.
        let json = """
            {"items": [
              {"id": "EUVD-2024-1", "aliases": "CVE-2024-30940\\n"},
              {"id": "EUVD-2024-31700", "aliases": "CVE-2024-3094\\nGHSA-rxwq-x6h5-x525\\n"}
            ], "total": 2}
            """
        let record = try #require(SourceChecker.parseEUVD(Data(json.utf8), cveID: "CVE-2024-3094"))
        #expect(record.ids == ["EUVD-2024-31700"])
        #expect(record.url == "https://euvd.enisa.europa.eu/vulnerability/EUVD-2024-31700")
        #expect(SourceChecker.parseEUVD(Data(#"{"items": [], "total": 0}"#.utf8), cveID: "CVE-2024-3094") == nil)
    }

    @Test func findingsListNVDFirst() {
        let item = Fixtures.item(.formula, name: "xz", version: "5.6.0", aliases: ["xz"])
        var finding = Fixtures.finding("CVE-2024-3094", item: item, fix: Fixtures.fix(.brewFormula, "xz", to: "5.6.2"))
        #expect(finding.databases.map(\.source) == [.nvd])
        #expect(!finding.isKnownExploited)
        finding.sources = [
            SourceRecord(source: .euvd, url: "e"), SourceRecord(source: .kev, url: "k"),
            SourceChecker.nvdRecord("CVE-2024-3094"),
        ]
        #expect(finding.databases.map(\.source) == [.nvd, .kev, .euvd])
        #expect(finding.isKnownExploited)
    }

    @Test func scansMadeBeforeSourcesStillDecode() throws {
        // A finding saved by D-Patch 0.5 has no "sources" field.
        let item = Fixtures.item(.formula, name: "xz", version: "5.6.0", aliases: ["xz"])
        let finding = Fixtures.finding("CVE-2024-3094", item: item, fix: Fixtures.fix(.brewFormula, "xz", to: "5.6.2"))
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        var object = try #require(
            try JSONSerialization.jsonObject(with: encoder.encode(finding)) as? [String: Any])
        object["sources"] = nil
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded = try decoder.decode(Finding.self, from: JSONSerialization.data(withJSONObject: object))
        #expect(decoded.sources == nil)
        #expect(decoded.databases.map(\.source) == [.nvd])
    }
}
