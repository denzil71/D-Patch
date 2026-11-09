import Foundation
import Testing

@testable import DPatch

@Suite struct FixtureDataTests {
    @Test func matchesFixtureInventoryAndUsesTheExplicitFix() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let item = Fixtures.item(.formula, name: "curl", version: "8.4.0", aliases: ["curl"])
        let cve = Fixtures.cve(
            "CVE-2026-9001", ranges: [Fixtures.range(vendor: "curl", product: "curl", end: "8.6.0")])
        let fix = Fixtures.fix(.brewFormula, "curl", to: "8.6.0")

        try write([cve], to: directory.appendingPathComponent("cves.json"))
        try write([item], to: directory.appendingPathComponent("inventory.json"))
        try write(["\(cve.id)|\(item.key)": fix], to: directory.appendingPathComponent("fixes.json"))

        let result = try await FixtureData.makeResult(from: directory) { _ in }

        #expect(result.cvesChecked == 1)
        #expect(result.itemsChecked == 1)
        #expect(result.findings.count == 1)
        #expect(result.findings.first?.fix == fix)
        #expect(result.findings.first?.fixedIn == "8.6.0")
        #expect(result.warnings.first?.contains("Demo data") == true)
    }

    private func write<T: Encodable>(_ value: T, to url: URL) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        try encoder.encode(value).write(to: url)
    }
}
