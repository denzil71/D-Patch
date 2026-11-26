import Foundation
import Testing

@testable import DPatch

/// CVEs D-Patch used to drop or hide: ones no one has scored yet, ones listing affected versions one
/// by one, and ones that affect this Mac but have no fix yet.
@Suite struct CoverageTests {
    /// CVE-2026-124851 as NVD served it on 26 Nov 2026: received, no score from anyone, but a version range.
    static let unscored = """
        {
          "id": "CVE-2026-124851",
          "published": "2026-11-24T18:15:22.150",
          "lastModified": "2026-11-24T18:15:22.150",
          "vulnStatus": "Received",
          "descriptions": [{"lang": "en", "value": "Zstandard through 1.5.7 mishandles a crafted frame."}],
          "metrics": {},
          "affected": [{"affectedData": [{"vendor": "Facebook", "product": "Zstandard", "versions": [
            {"version": "v1.5.1", "lessThanOrEqual": "v1.5.7", "versionType": "semver", "status": "affected"}]}]}]
        }
        """

    /// CVE-2026-134732, trimmed: the vendor lists each affected release and the first unaffected one.
    static let listed = """
        {
          "id": "CVE-2026-134732",
          "published": "2026-11-25T09:15:10.000",
          "lastModified": "2026-11-25T09:15:10.000",
          "vulnStatus": "Deferred",
          "metrics": {"cvssMetricV31": [{"type": "Secondary", "cvssData": {"baseScore": 5.3, "baseSeverity": "MEDIUM"}}]},
          "affected": [{"affectedData": [{"vendor": "Open Asset Import Library", "product": "Assimp", "versions": [
            {"version": "6.0.0", "status": "affected"}, {"version": "6.0.1", "status": "affected"},
            {"version": "6.0.2", "status": "affected"}, {"version": "6.0.3", "status": "affected"},
            {"version": "6.0.6", "status": "unaffected"},
            {"version": "4f2a9c1", "versionType": "git", "status": "affected"}]}]}]
        }
        """

    private func record(_ json: String) throws -> CVERecord {
        try #require(CVERecord(nvd: try JSONDecoder().decode(NVDCVE.self, from: Data(json.utf8))))
    }

    // MARK: Unscored CVEs

    @Test func keepsACVENoOneHasScored() throws {
        let r = try record(Self.unscored)
        #expect(r.severity == .unscored)
        #expect(r.score == 0)
        let zstd = Fixtures.item(.formula, name: "zstd", version: "1.5.7", aliases: ["zstandard", "zstd"])
        #expect(Matcher(cves: [r]).hits(for: zstd).map(\.cve.id) == ["CVE-2026-124851"])
    }

    @Test func listsUnscoredCVEsWhateverTheChosenLevels() throws {
        let unscored = try record(Self.unscored)
        let high = Fixtures.cve("CVE-H", severity: .high, ranges: [])
        #expect(NVDClient.select([unscored, high], severities: [.critical]).map(\.id) == ["CVE-2026-124851"])
    }

    @Test func settingsOfferOnlyScoredLevels() {
        #expect(!Severity.scored.contains(.unscored))
        #expect(Severity.unscored < .low)
    }

    // MARK: Affected versions listed one by one

    @Test func readsEachListedVersion() throws {
        let r = try record(Self.listed)
        let exact = r.ranges.filter(\.isExact).map(\.end).sorted(by: Version.isLess)
        // The commit hash can't be compared with a version, so it's left out.
        #expect(exact == ["6.0.0", "6.0.1", "6.0.2", "6.0.3"])
    }

    @Test func matchesOnlyTheListedVersions() throws {
        let matcher = Matcher(cves: [try record(Self.listed)])
        func assimp(_ v: String) -> InventoryItem {
            Fixtures.item(.formula, name: "assimp", version: v, aliases: ["assimp"])
        }
        #expect(matcher.hits(for: assimp("6.0.2")).count == 1)
        #expect(matcher.hits(for: assimp("6.0.6")).isEmpty)
        #expect(matcher.hits(for: assimp("5.4.3")).isEmpty)
    }

    @Test func readsANVDCPEForOneVersion() throws {
        let m = NVDCVE.CPEMatch(
            vulnerable: true, criteria: "cpe:2.3:a:assimp:assimp:6.0.3:*:*:*:*:*:*:*")
        let r = try #require(CVERecord.range(cpe: m))
        #expect(r.isExact && r.end == "6.0.3")
        // An update qualifier ("9.8:p1") can't be told apart in the installed version.
        let qualified = NVDCVE.CPEMatch(vulnerable: true, criteria: "cpe:2.3:a:openbsd:openssh:9.8:p1:*:*:*:*:*:*")
        #expect(CVERecord.range(cpe: qualified) == nil)
        let any = NVDCVE.CPEMatch(vulnerable: true, criteria: "cpe:2.3:a:assimp:assimp:*:*:*:*:*:*:*:*")
        #expect(CVERecord.range(cpe: any) == nil)
    }

    @Test func saysWhenNoFixedVersionIsNamed() throws {
        let r = try record(Self.listed)
        let item = Fixtures.item(.formula, name: "assimp", version: "6.0.1", aliases: ["assimp"])
        let hit = try #require(Matcher(cves: [r]).hits(for: item).first)
        let f = try #require(Scanner.finding(hit, item: item, installed: Version("6.0.1")!, fix: nil))
        #expect(f.fixedIn == "not stated (affected versions listed up to 6.0.3)")
    }

    // MARK: CVEs with no fix yet

    @Test func keepsAFindingWithNoFix() throws {
        let cve = Fixtures.cve("CVE-1", ranges: [Fixtures.range(product: "openssl", end: "4.1.1")])
        let item = Fixtures.item(.formula, name: "openssl@4", version: "4.1.0", aliases: ["openssl"])
        let hit = try #require(Matcher(cves: [cve]).hits(for: item).first)
        let f = try #require(Scanner.finding(hit, item: item, installed: Version("4.1.0")!, fix: nil))
        #expect(f.fix == nil)
        #expect(f.fixedIn == "4.1.1")
        #expect(FixKind(f.fix) == FixKind.none)
    }

    @Test func leavesUnfixedFindingsOutOfThePatchScript() {
        let curl = Fixtures.item(.formula, name: "curl", version: "8.4.0", aliases: ["curl"])
        let fixed = Fixtures.finding("CVE-1", item: curl, fix: Fixtures.fix(.brewFormula, "curl", to: "8.5.0"))
        var unfixed = fixed
        unfixed.fix = nil
        #expect(ScriptGenerator.fixes(for: [fixed, unfixed]).map(\.target) == ["curl"])
    }

    @Test func summarisesFixableAndUnfixedCVEs() {
        let curl = Fixtures.item(.formula, name: "curl", version: "8.4.0", aliases: ["curl"])
        let fixed = Fixtures.finding("CVE-1", item: curl, fix: Fixtures.fix(.brewFormula, "curl", to: "8.5.0"))
        var unfixed = Fixtures.finding("CVE-2", item: curl, fix: Fixtures.fix(.brewFormula, "curl", to: "8.5.0"))
        unfixed.fix = nil
        func result(_ f: [Finding]) -> ScanResult {
            ScanResult(
                scannedAt: Date(), lookbackDays: 90, cvesChecked: 2, itemsChecked: 1, findings: f, warnings: [])
        }
        #expect(Scanner.summary(result([fixed])) == "1 fixable CVE (0 critical)")
        #expect(
            Scanner.summary(result([fixed, unfixed]))
                == "1 fixable CVE (0 critical); 1 more affect this Mac but have no fix yet")
    }

    @Test func listsFixableBySeverityThenUnfixed() {
        let curl = Fixtures.item(.formula, name: "curl", version: "8.4.0", aliases: ["curl"])
        func finding(_ id: String, _ severity: Severity, score: Double, fixed: Bool) -> Finding {
            var f = Fixtures.finding(id, item: curl, fix: Fixtures.fix(.brewFormula, "curl", to: "8.5.0"))
            f.cve.severity = severity
            f.cve.score = score
            if !fixed { f.fix = nil }
            return f
        }
        let list = [
            finding("NOFIX-CRIT", .critical, score: 9.8, fixed: false),
            finding("LOW", .low, score: 2.0, fixed: true),
            finding("UNSCORED", .unscored, score: 0, fixed: true),
            finding("HIGH-7", .high, score: 7.0, fixed: true),
            finding("NOFIX-LOW", .low, score: 3.0, fixed: false),
            finding("CRIT", .critical, score: 9.1, fixed: true),
            finding("HIGH-8", .high, score: 8.2, fixed: true),
            finding("MED", .medium, score: 5.0, fixed: true),
        ]
        #expect(
            list.sorted(by: Finding.listOrder).map(\.cve.id) == [
                "CRIT", "HIGH-8", "HIGH-7", "MED", "LOW", "UNSCORED", "NOFIX-CRIT", "NOFIX-LOW",
            ])
    }

    // MARK: False matches that listing unfixed CVEs brought to light

    @Test func anAppNamedAfterAnotherProductIsNotThatProduct() {
        // 1Password for Safari's bundle ID ends in "safari"; Apple's Safari CVEs aren't about it.
        let cve = Fixtures.cve("CVE-S", ranges: [Fixtures.range(vendor: "apple", product: "safari", end: "27.2")])
        let item = Fixtures.item(
            .app, name: "1Password for Safari", version: "8.12.46", aliases: ["1passwordforsafari", "safari"],
            vendorHint: "1password")
        #expect(Matcher(cves: [cve]).hits(for: item).isEmpty)
    }

    @Test func aPluginNamedAfterAnAppIsNotTheApp() {
        let plugin = Fixtures.cve(
            "CVE-P", ranges: [Fixtures.range(vendor: "openclaw", product: "whatsapp", end: "2026.8.1", nvd: false)])
        let own = Fixtures.cve("CVE-W", ranges: [Fixtures.range(vendor: "whatsapp", product: "whatsapp", end: "27")])
        let item = Fixtures.item(
            .app, name: "WhatsApp", version: "26.47.12", aliases: ["whatsapp"], vendorHint: "whatsapp")
        #expect(Matcher(cves: [plugin, own]).hits(for: item).map(\.cve.id) == ["CVE-W"])
    }

    @Test func anAppsVendorCanBeItsOwnName() {
        // Discord's bundle ID vendor is "hnc"; NVD's vendor is "discord".
        let cve = Fixtures.cve("CVE-D", ranges: [Fixtures.range(vendor: "discord", product: "discord", end: "0.0.500")])
        let item = Fixtures.item(.app, name: "Discord", version: "0.0.421", aliases: ["discord"], vendorHint: "hnc")
        #expect(Matcher(cves: [cve]).hits(for: item).map(\.cve.id) == ["CVE-D"])
    }

    @Test func aProductStartingWithTheAppsNameIsNotTheApp() {
        // VS Code's alias "code" isn't Coder or CodeIgniter.
        let cve = Fixtures.cve("CVE-C", ranges: [Fixtures.range(vendor: "coder", product: "coder", end: "2.34.7")])
        let item = Fixtures.item(
            .app, name: "Code", version: "1.146.0", aliases: ["code", "vscode"], vendorHint: "microsoft")
        #expect(Matcher(cves: [cve]).hits(for: item).isEmpty)
    }

    @Test func homebrewsHomepageNamesTheFormulasVendor() {
        // CVE-2026-111497 lists Google's brotli (fixed in 1.2.1) and a Go port (fixed in 1.2.7).
        let cve = Fixtures.cve(
            "CVE-2026-111497",
            ranges: [
                Fixtures.range(vendor: "google", product: "brotli", start: "1.2.0", end: "1.2.1"),
                Fixtures.range(vendor: "andybalholm", product: "brotli", end: "1.2.7"),
            ])
        var brotli = Fixtures.item(.formula, name: "brotli", version: "1.2.1", aliases: ["brotli"])
        brotli.homepage = "https://github.com/google/brotli"
        #expect(Matcher(cves: [cve]).hits(for: brotli).isEmpty)
        brotli.version = "1.2.0"
        #expect(Matcher(cves: [cve]).hits(for: brotli).count == 1)
    }

    @Test func anotherPlatformsEditionIsNotTheMacApp() {
        let cve = Fixtures.cve(
            "CVE-A", ranges: [Fixtures.range(vendor: "VideoLAN", product: "VLC for Android", end: "3.7.2", nvd: false)])
        let item = Fixtures.item(.app, name: "VLC", version: "3.0.24", aliases: ["vlc"], vendorHint: "videolan")
        #expect(Matcher(cves: [cve]).hits(for: item).isEmpty)
    }

    @Test func aYearVersionedProductIsNotASemverOne() {
        let cve = Fixtures.cve("CVE-Y", ranges: [Fixtures.range(product: "jellyfin", end: "2026.3.15")])
        let item = Fixtures.item(.formula, name: "jellyfin", version: "12.4", aliases: ["jellyfin"])
        #expect(Matcher(cves: [cve]).hits(for: item).isEmpty)
        #expect(Version.isCalendar("2026.3.15") && !Version.isCalendar("12.4"))
    }

    @Test func aCommitIsNotAVersion() {
        #expect(Version.looksLikeCommit("9432ad1c4099511905353cebcececa3a1f7c3ff"))
        #expect(!Version.looksLikeCommit("20260115"))
        #expect(!Version.looksLikeCommit("1.2.3"))
        let v = NVDCVE.Affected.Data.V(
            version: "0", lessThan: "9432ad1c4099511905353cebcececa3a1f7c3ff", lessThanOrEqual: nil,
            status: "affected", versionType: nil)
        #expect(CVERecord.range(vendor: "elixir-protobuf", product: "protobuf", v) == nil)
    }

    // MARK: Homebrew's latest versions

    @Test func takesTheNewerOfTheLocalAndOnlineVersions() {
        #expect(FixResolver.newer("9.0.2", "9.1") == "9.1")
        #expect(FixResolver.newer("9.1", "9.0.2") == "9.1")
        #expect(FixResolver.newer(nil, "9.1") == "9.1")
        #expect(FixResolver.newer("9.0.2", nil) == "9.0.2")
        #expect(FixResolver.newer("9.0.2", "HEAD") == "9.0.2")
    }

    @Test func demoDataStaysOffline() async {
        // Offline, a stale local version is all there is: no fix, rather than a network request.
        let item = InventoryItem(
            kind: .formula, name: "ffmpeg", version: "9.0.2", aliases: ["ffmpeg"], latestVersion: "9.0.2")
        let fix = await FixResolver(online: false).fix(
            for: item, ranges: [Fixtures.range(product: "ffmpeg", end: "9.1")])
        #expect(fix == nil)
    }
}
