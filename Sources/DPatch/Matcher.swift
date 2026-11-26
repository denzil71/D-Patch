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

    /// Extensions of an app's name that mean another platform's edition ("VLC for Android").
    static let otherPlatforms = ["android", "iphone", "ipad", "windows", "linux", "tvos", "watchos", "forios"]

    private let cves: [CVERecord]
    private var byProduct: [String: [Entry]] = [:]  // normalized product
    private var byVendorProduct: [String: [Entry]] = [:]  // normalized vendor + product

    init(cves: [CVERecord]) {
        self.cves = cves
        for (ci, c) in cves.enumerated() {
            for (ri, r) in c.ranges.enumerated() {
                let v = normalizeName(r.vendor)
                let p = normalizeName(r.product)
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
        var found: [Int: Set<Int>] = [:]  // cve index -> range indexes

        // The CVE's vendor is the one in this app's bundle ID.
        func vendorFits(_ v: String) -> Bool {
            guard let h = item.vendorHint, !v.isEmpty else { return false }
            return v.contains(h) || h.contains(v)
        }
        // Or it's the app's own name ("discord" for Discord, whose bundle ID says "hnc"), not a plugin
        // or another company.
        func vendorIsItself(_ v: String) -> Bool { vendorFits(v) || item.aliases.contains(v) }
        for alias in item.aliases where !alias.isEmpty {
            for e in byVendorProduct[alias] ?? [] { found[e.cve, default: []].insert(e.range) }
            // Bare product names: very short ones are too ambiguous. Apps must also agree on vendor:
            // "safari" in 1Password for Safari's bundle ID isn't Apple's Safari, and a "discord"
            // plugin isn't Discord.
            guard alias.count >= 3 else { continue }
            for e in byProduct[alias] ?? [] {
                let strict = item.kind == .app || item.kind == .macos
                if !strict || vendorIsItself(e.vendor) {
                    found[e.cve, default: []].insert(e.range)
                }
            }
        }
        // Apps whose CPE name extends the app name with the same vendor: "VLC" -> videolan:vlc_media_player,
        // but not another platform's edition (videolan:vlc_for_android).
        if item.kind == .app, item.vendorHint != nil {
            for alias in item.aliases where alias.count >= 3 {
                for (product, entries) in byProduct where product.count > alias.count && product.hasPrefix(alias) {
                    let rest = product.dropFirst(alias.count)
                    guard !Self.otherPlatforms.contains(where: { rest.contains($0) }) else { continue }
                    for e in entries where vendorFits(e.vendor) { found[e.cve, default: []].insert(e.range) }
                }
            }
        }

        return found.compactMap { ci, ris in
            // A product versioned by year (2026.3.15) is a different one from an installed 12.4.
            var ranges = ris.map { cves[ci].ranges[$0] }
                .filter { !Version.isCalendar($0.end) || Version.isCalendar(item.version) }
            // When some of the CVE's vendors appear in Homebrew's homepage, theirs is the product
            // installed: google:brotli for github.com/google/brotli, not the Go port andybalholm:brotli.
            if let home = item.homepage.map(normalizeName) {
                let own = ranges.filter { r in
                    let v = normalizeName(r.vendor)
                    return v.count >= 3 && home.contains(v)
                }
                if !own.isEmpty { ranges = own }
            }
            // NVD's analysed ranges win; the CNA's often mix release lines (e.g. "< 27" for a fix also in 26.7).
            if ranges.contains(where: \.nvd) { ranges = ranges.filter(\.nvd) }
            guard ranges.contains(where: { $0.contains(installed) }) else { return nil }
            return Hit(cve: cves[ci], ranges: ranges)
        }
    }
}
