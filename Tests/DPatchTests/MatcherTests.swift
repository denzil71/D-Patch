import Testing

@testable import DPatch

@Suite struct MatcherTests {
    private let vlc = Fixtures.cve(
        "CVE-2026-0001", ranges: [Fixtures.range(vendor: "videolan", product: "vlc", end: "3.0.21")])

    @Test func matchesAnAffectedInstalledVersion() {
        let item = Fixtures.item(.app, name: "VLC", version: "3.0.20", aliases: ["vlc"], vendorHint: "videolan")
        #expect(Matcher(cves: [vlc]).hits(for: item).map(\.cve.id) == ["CVE-2026-0001"])
    }

    @Test func ignoresAFixedVersion() {
        let item = Fixtures.item(.app, name: "VLC", version: "3.0.21", aliases: ["vlc"], vendorHint: "videolan")
        #expect(Matcher(cves: [vlc]).hits(for: item).isEmpty)
    }

    @Test func shortAppNamesMustAgreeOnVendor() {
        // "vlc" is short, so an app from another vendor doesn't match a bare product name.
        let item = Fixtures.item(.app, name: "VLC", version: "3.0.20", aliases: ["vlc"], vendorHint: "someoneelse")
        #expect(Matcher(cves: [vlc]).hits(for: item).isEmpty)
    }

    @Test func matchesAProductNameThatExtendsTheAppName() {
        let cve = Fixtures.cve(
            "CVE-2026-0002",
            ranges: [Fixtures.range(vendor: "videolan", product: "vlc_media_player", end: "3.0.21")])
        let item = Fixtures.item(.app, name: "VLC", version: "3.0.20", aliases: ["vlc"], vendorHint: "videolan")
        #expect(Matcher(cves: [cve]).hits(for: item).map(\.cve.id) == ["CVE-2026-0002"])
    }

    @Test func prefersNVDRangesOverTheCNAs() {
        // The CNA's range covers the installed version, but NVD's analysed range says it's fixed.
        let cve = Fixtures.cve(
            "CVE-2026-0003",
            ranges: [
                Fixtures.range(vendor: "curl", product: "curl", end: "8.5.0", nvd: false),
                Fixtures.range(vendor: "curl", product: "curl", end: "8.4.0", nvd: true),
            ])
        let item = Fixtures.item(.formula, name: "curl", version: "8.4.5", aliases: ["curl"])
        #expect(Matcher(cves: [cve]).hits(for: item).isEmpty)
    }
}
