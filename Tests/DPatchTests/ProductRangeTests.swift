import Testing

@testable import DPatch

@Suite struct ProductRangeTests {
    private func contains(_ range: ProductRange, _ version: String) throws -> Bool {
        range.contains(try #require(Version(version)))
    }

    @Test func upToAnExclusiveEnd() throws {
        let range = Fixtures.range(product: "curl", end: "8.5.0")
        #expect(try contains(range, "8.4.9"))
        #expect(try !contains(range, "8.5.0"))
    }

    @Test func upToAnInclusiveEnd() throws {
        let range = Fixtures.range(product: "curl", end: "8.5.0", endInclusive: true)
        #expect(try contains(range, "8.5.0"))
        #expect(try !contains(range, "8.5.1"))
    }

    @Test func fromAStart() throws {
        let inclusive = Fixtures.range(product: "curl", start: "8.0", end: "8.5.0")
        #expect(try contains(inclusive, "8.0"))
        #expect(try !contains(inclusive, "7.9"))
        let exclusive = Fixtures.range(product: "curl", start: "8.0", startInclusive: false, end: "8.5.0")
        #expect(try !contains(exclusive, "8.0"))
        #expect(try contains(exclusive, "8.0.1"))
    }

    @Test func describesTheFixedVersion() {
        #expect(Fixtures.range(product: "x", end: "2.0").fixedInDescription == "2.0")
        #expect(Fixtures.range(product: "x", end: "2.0", endInclusive: true).fixedInDescription == "after 2.0")
    }
}
