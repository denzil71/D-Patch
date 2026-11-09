import Foundation

@testable import DPatch

/// Small builders so tests only spell out what they check.
enum Fixtures {
    static func range(
        vendor: String = "", product: String, start: String? = nil, startInclusive: Bool = true,
        end: String, endInclusive: Bool = false, nvd: Bool = true
    ) -> ProductRange {
        ProductRange(
            nvd: nvd, vendor: vendor, product: product, start: start, startInclusive: startInclusive,
            end: end, endInclusive: endInclusive)
    }

    static func cve(_ id: String, severity: Severity = .high, ranges: [ProductRange]) -> CVERecord {
        CVERecord(
            id: id, published: Date(timeIntervalSince1970: 0), lastModified: Date(timeIntervalSince1970: 0),
            severity: severity, score: 8.0, vector: "", summary: "", references: [], ranges: ranges)
    }

    static func item(
        _ kind: ItemKind, name: String, version: String, aliases: [String], vendorHint: String? = nil
    ) -> InventoryItem {
        InventoryItem(kind: kind, name: name, version: version, aliases: aliases, vendorHint: vendorHint)
    }

    static func fix(_ method: FixMethod, _ target: String, to version: String) -> Fix {
        Fix(method: method, target: target, toVersion: version, summary: "")
    }

    static func finding(_ cveID: String, item: InventoryItem, fix: Fix) -> Finding {
        Finding(cve: cve(cveID, ranges: []), item: item, fixedIn: fix.toVersion, fix: fix)
    }
}
