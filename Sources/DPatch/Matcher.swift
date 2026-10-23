import Foundation

/// Decides which CVE product ranges refer to which installed items.
struct Matcher {
    struct Hit {
        var cve: CVERecord
        var ranges: [ProductRange]
    }

    private struct Entry {
        var cve: Int
        var range: Int
        var vendor: String
    }

    private let cves: [CVERecord]
    private var byProduct: [String: [Entry]] = [:]        // normalized product
    private var byVendorProduct: [String: [Entry]] = [:]  // normalized vendor + product

    init(cves: [CVERecord]) {
        self.cves = cves
        for (ci, c) in cves.enumerated() {
            for (ri, r) in c.ranges.enumerated() {
                let v = normalizeName(r.vendor), p = normalizeName(r.product)
                guard !p.isEmpty else { continue }
                let e = Entry(cve: ci, range: ri, vendor: v)
                byProduct[p, default: []].append(e)
                byVendorProduct[v + p, default: []].append(e)
            }
        }
    }

    /// CVEs whose affected ranges name this item and include its installed version.
    func hits(for item: InventoryItem) -> [Hit] {
        guard let installed = Version(item.version) else { return [] }
        var found: [Int: Set<Int>] = [:]   // cve index -> range indexes

        func vendorFits(_ v: String) -> Bool {
            guard let h = item.vendorHint, !v.isEmpty else { return false }
            return v.contains(h) || h.contains(v)
        }
        for alias in item.aliases where !alias.isEmpty {
            for e in byVendorProduct[alias] ?? [] { found[e.cve, default: []].insert(e.range) }
            // Bare product names: very short ones are too ambiguous; for apps with a known vendor,
            // short names must also agree on vendor ("Numbers" by Apple, not by someone else).
            guard alias.count >= 3 else { continue }
            for e in byProduct[alias] ?? [] {
                let strict = item.kind == .app || item.kind == .macos
                if !strict || alias.count >= 6 || vendorFits(e.vendor) || item.vendorHint == nil {
                    found[e.cve, default: []].insert(e.range)
                }
            }
        }
        // Apps whose CPE name extends the app name with the same vendor: "VLC" -> videolan:vlc_media_player.
        if item.kind == .app, item.vendorHint != nil {
            for alias in item.aliases where alias.count >= 3 {
                for (product, entries) in byProduct where product.count > alias.count && product.hasPrefix(alias) {
                    for e in entries where vendorFits(e.vendor) { found[e.cve, default: []].insert(e.range) }
                }
            }
        }

        return found.compactMap { ci, ris in
            let ranges = ris.map { cves[ci].ranges[$0] }
            guard ranges.contains(where: { $0.contains(installed) }) else { return nil }
            return Hit(cve: cves[ci], ranges: ranges)
        }
    }
}
