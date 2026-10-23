import Foundation

/// CVSS v3 severity, lowest first.
enum Severity: String, Codable, Comparable, CaseIterable {
    case low = "LOW"
    case medium = "MEDIUM"
    case high = "HIGH"
    case critical = "CRITICAL"

    static let defaults: [Severity] = [.critical, .high]

    static func < (a: Severity, b: Severity) -> Bool {
        allCases.firstIndex(of: a)! < allCases.firstIndex(of: b)!
    }

    var label: String { rawValue.capitalized }
}

/// One affected-version range for a product, as published by NVD (CPE) or the CNA.
/// Only ranges with an upper bound are kept: without one there is no known fixed version.
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

    var fixedInDescription: String { endInclusive ? "after \(end)" : end }
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
    var fix: Fix

    var id: String { "\(cve.id)|\(item.key)" }

    /// The only fix is a new major macOS version (26.x -> 27).
    var isMajorUpgrade: Bool {
        guard item.kind == .macos, fix.method == .softwareUpdate else { return false }
        let major = { (v: String) in v.split(separator: ".").first.map(String.init) }
        return major(fix.toVersion) != major(item.version)
    }
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
}
