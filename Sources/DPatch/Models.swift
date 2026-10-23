import Foundation

enum Severity: String, Codable, Comparable {
    case high = "HIGH"
    case critical = "CRITICAL"

    static func < (a: Severity, b: Severity) -> Bool { a == .high && b == .critical }
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
}

struct Finding: Codable, Identifiable {
    var cve: CVERecord
    var item: InventoryItem
    var fixedIn: String
    var fix: Fix

    var id: String { "\(cve.id)|\(item.key)" }
}

struct ScanResult: Codable {
    var scannedAt: Date
    var lookbackDays: Int
    var cvesChecked: Int
    var itemsChecked: Int
    var findings: [Finding]
    var warnings: [String]
}
