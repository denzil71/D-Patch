import Foundation

/// CVSS v3 severity, lowest first. `unscored` is a CVE no one (NVD, CISA or the vendor) has scored yet.
enum Severity: String, Codable, Comparable, CaseIterable {
    case unscored = "UNSCORED"
    case low = "LOW"
    case medium = "MEDIUM"
    case high = "HIGH"
    case critical = "CRITICAL"

    static let defaults: [Severity] = [.critical, .high]
    /// The levels that can be chosen in Settings; unscored CVEs are always included.
    static let scored: [Severity] = [.low, .medium, .high, .critical]

    static func < (a: Severity, b: Severity) -> Bool {
        allCases.firstIndex(of: a)! < allCases.firstIndex(of: b)!
    }

    var label: String { rawValue.capitalized }
}

/// One affected-version range for a product, as published by NVD (CPE) or the CNA.
/// Only ranges with an upper bound are kept; a single listed version is a range from and to itself.
struct ProductRange: Codable, Hashable {
    /// From NVD's analysed CPE data (true) or the CNA's affected list (false).
    var nvd: Bool
    var vendor: String
    var product: String
    var start: String?
    var startInclusive: Bool
    var end: String
    var endInclusive: Bool

    func contains(_ v: Version) -> Bool {
        if let s = start, let sv = Version(s) {
            if startInclusive ? v < sv : v <= sv { return false }
        }
        guard let ev = Version(end) else { return false }
        return endInclusive ? v <= ev : v < ev
    }

    /// One listed version ("affects 6.0.3") rather than a range.
    var isExact: Bool { start == end && startInclusive && endInclusive }

    var fixedInDescription: String { endInclusive ? "after \(end)" : end }

    /// "Fixed in" for the range that contains the installed version. Vendors that list affected
    /// versions one by one don't name a fixed one, so say which is the newest they list.
    static func fixedInDescription(_ range: ProductRange, among ranges: [ProductRange]) -> String {
        guard range.isExact else { return range.fixedInDescription }
        let newest = ranges.filter(\.isExact).map(\.end).max(by: Version.isLess) ?? range.end
        return "not stated (affected versions listed up to \(newest))"
    }
}

/// Compact form of an NVD CVE record, kept in the local cache.
struct CVERecord: Codable, Identifiable {
    var id: String
    var published: Date
    var lastModified: Date
    var severity: Severity
    var score: Double
    var vector: String
    var summary: String
    var references: [String]
    var ranges: [ProductRange]
}

enum ItemKind: String, Codable {
    case formula, cask, app, macos
}

/// Something installed on this Mac that a CVE can apply to.
struct InventoryItem: Codable, Hashable {
    var kind: ItemKind
    var name: String
    var version: String
    /// Normalized names this item may appear under in CVE product data.
    var aliases: [String]
    var vendorHint: String?
    var bundleID: String?
    var path: String?
    var caskToken: String?
    /// Newest version Homebrew offers, for formulae and brew-managed casks.
    var latestVersion: String?
    var isAppStore: Bool = false
    /// Homebrew's homepage for a formula or cask, which names its vendor ("github.com/google/brotli").
    var homepage: String?

    var key: String { "\(kind.rawValue):\(caskToken ?? bundleID ?? name)" }
}

enum FixMethod: String, Codable {
    case brewFormula, brewCask, brewCaskReplace, appStore, softwareUpdate
}

struct Fix: Codable, Hashable {
    var method: FixMethod
    /// Formula name, cask token, App Store ID or softwareupdate label.
    var target: String
    var toVersion: String
    var summary: String
    /// Apple's security notes for the update ("About the security content of macOS Tahoe 26.7").
    var notesURL: String?
    var notesTitle: String?

    static let appleSecurityReleases = "https://support.apple.com/en-us/100100"

    /// Where to read about an Apple update: its own notes, or Apple's index of security releases.
    var notesLink: (url: URL, title: String)? {
        guard method == .softwareUpdate else { return nil }
        if let u = notesURL.flatMap(URL.init(string:)) { return (u, notesTitle ?? "Apple security notes") }
        return URL(string: Self.appleSecurityReleases).map { ($0, "Apple security releases") }
    }
}

struct Finding: Codable, Identifiable {
    var cve: CVERecord
    var item: InventoryItem
    var fixedIn: String
    /// nil when no update that fixes it is available yet from Homebrew, the App Store or Apple.
    var fix: Fix?
    /// The databases this CVE appears in; nil for scans made before D-Patch recorded them (NVD only).
    var sources: [SourceRecord]?

    var id: String { "\(cve.id)|\(item.key)" }

    /// Databases listing this CVE, NVD first.
    var databases: [SourceRecord] { (sources ?? [SourceChecker.nvdRecord(cve.id)]).sorted { $0.source < $1.source } }

    /// CISA lists it as exploited in the wild.
    var isKnownExploited: Bool { sources?.contains { $0.source == .kev } ?? false }

    /// The only fix is a new major macOS version (26.x -> 27).
    var isMajorUpgrade: Bool {
        guard item.kind == .macos, let fix, fix.method == .softwareUpdate else { return false }
        let major = { (v: String) in v.split(separator: ".").first.map(String.init) }
        return major(fix.toVersion) != major(item.version)
    }
}

/// A macOS update that Apple Software Update offers, listed whether or not it fixes a CVE.
struct MacOSUpdate: Codable, Hashable, Identifiable {
    /// The softwareupdate label, e.g. "macOS Tahoe 26.8-25I12".
    var label: String
    var title: String
    var version: String
    /// A new major version (26.x → 27) rather than an update to the installed one.
    var isMajor: Bool

    var id: String { label }
}

struct ScanResult: Codable {
    var scannedAt: Date
    var lookbackDays: Int
    /// Levels this scan covered; nil for scans made before the preference existed (critical and high).
    var severities: [Severity]?
    var cvesChecked: Int
    var itemsChecked: Int
    var findings: [Finding]
    var warnings: [String]
    /// macOS updates available when the scan ran, smallest first; nil for scans made before this was recorded.
    var macOSUpdates: [MacOSUpdate]?
}
