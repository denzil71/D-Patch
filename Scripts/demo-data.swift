#!/usr/bin/env swift
import Foundation

// Writes a repeatable set of dummy CVEs and installed software for D-Patch's demo mode.
// Usage: swift Scripts/demo-data.swift <output-directory>
// swiftlint:disable line_length function_parameter_count

// These shapes mirror the Codable types in Sources/DPatch/Models.swift. Keep them in sync.

enum Severity: String, Codable, CaseIterable {
    case low = "LOW"
    case medium = "MEDIUM"
    case high = "HIGH"
    case critical = "CRITICAL"
}

struct ProductRange: Codable {
    var nvd: Bool
    var vendor: String
    var product: String
    var start: String?
    var startInclusive: Bool
    var end: String
    var endInclusive: Bool
}

struct CVERecord: Codable {
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

struct InventoryItem: Codable {
    var kind: ItemKind
    var name: String
    var version: String
    var aliases: [String]
    var vendorHint: String?
    var bundleID: String?
    var path: String?
    var caskToken: String?
    var latestVersion: String?
    var isAppStore: Bool = false

    var key: String { "\(kind.rawValue):\(caskToken ?? bundleID ?? name)" }
}

enum FixMethod: String, Codable {
    case brewFormula, brewCask, brewCaskReplace, appStore, softwareUpdate
}

struct Fix: Codable {
    var method: FixMethod
    var target: String
    var toVersion: String
    var summary: String
    var notesURL: String?
    var notesTitle: String?
}

// MARK: - Builders

let output = URL(
    fileURLWithPath: CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "build/demo/fixtures")
try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)

let now = Date()
let calendar = Calendar.current

func day(_ ago: Int, hour: Int = 10) -> Date {
    let date = calendar.date(byAdding: .day, value: -ago, to: now)!
    return calendar.date(bySettingHour: hour, minute: 0, second: 0, of: date)!
}

func formula(_ name: String, _ version: String, latest: String, aliases: [String]) -> InventoryItem {
    InventoryItem(
        kind: .formula, name: name, version: version, aliases: aliases, vendorHint: nil, bundleID: nil,
        path: nil, caskToken: nil, latestVersion: latest)
}

func cask(_ token: String, _ version: String, latest: String, aliases: [String], vendor: String) -> InventoryItem {
    InventoryItem(
        kind: .cask, name: token, version: version, aliases: aliases, vendorHint: vendor, bundleID: nil,
        path: nil, caskToken: token, latestVersion: latest)
}

func app(
    _ name: String, _ version: String, bundleID: String, path: String, aliases: [String], vendor: String,
    isAppStore: Bool = false
) -> InventoryItem {
    InventoryItem(
        kind: .app, name: name, version: version, aliases: aliases, vendorHint: vendor, bundleID: bundleID,
        path: path, caskToken: nil, latestVersion: nil, isAppStore: isAppStore)
}

func range(
    vendor: String, product: String, start: String? = nil, end: String, nvd: Bool = true
) -> ProductRange {
    ProductRange(
        nvd: nvd, vendor: vendor, product: product, start: start, startInclusive: true, end: end,
        endInclusive: false)
}

func cve(
    _ id: String, _ severity: Severity, _ score: Double, _ vector: String, _ summary: String,
    published: Date, ranges: [ProductRange], references: [String] = []
) -> CVERecord {
    CVERecord(
        id: id, published: published, lastModified: published, severity: severity, score: score, vector: vector,
        summary: summary, references: references, ranges: ranges)
}

func fix(
    _ method: FixMethod, _ target: String, _ toVersion: String, _ summary: String, notesURL: String? = nil,
    notesTitle: String? = nil
) -> Fix {
    Fix(
        method: method, target: target, toVersion: toVersion, summary: summary, notesURL: notesURL,
        notesTitle: notesTitle)
}

let criticalVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
let highVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
let mediumVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"
let lowVector = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"

// MARK: - Installed software

let curl = formula("curl", "8.4.0", latest: "8.6.0", aliases: ["curl", "libcurl"])
let openssl = formula("openssl@3", "3.3.1", latest: "3.3.2", aliases: ["openssl", "opensslopenssl"])
let node = formula("node", "22.4.0", latest: "22.5.1", aliases: ["node", "nodejs", "nodejsnodejs"])
let jq = formula("jq", "1.7.0", latest: "1.7.1", aliases: ["jq", "jqlangjq"])
let ffmpeg = formula("ffmpeg", "7.0.1", latest: "7.0.2", aliases: ["ffmpeg", "ffmpegffmpeg"])

let vlc = cask("vlc", "3.0.20", latest: "3.0.21", aliases: ["vlc"], vendor: "videolan")
let firefox = cask("firefox", "128.0", latest: "129.0", aliases: ["firefox", "mozillafirefox"], vendor: "mozilla")

let slack = app(
    "Slack", "4.39.0", bundleID: "com.tinyspeck.slackmacgap", path: "/Applications/Slack.app",
    aliases: ["slack", "slackmacgap"], vendor: "tinyspeck")
let zoom = app(
    "zoom.us", "6.1.0", bundleID: "us.zoom.xos", path: "/Applications/zoom.us.app",
    aliases: ["zoom", "zoom.us", "zoomxos"], vendor: "zoom")
let numbers = app(
    "Numbers", "14.0", bundleID: "com.apple.Numbers", path: "/Applications/Numbers.app",
    aliases: ["numbers", "iworknumbers"], vendor: "apple", isAppStore: true)
let keynote = app(
    "Keynote", "14.0", bundleID: "com.apple.Keynote", path: "/Applications/Keynote.app",
    aliases: ["keynote", "iworkkeynote"], vendor: "apple", isAppStore: true)
let safari = app(
    "Safari", "18.0", bundleID: "com.apple.Safari", path: "/Applications/Safari.app",
    aliases: ["safari", "applesafari"], vendor: "apple")
let macOS = InventoryItem(
    kind: .macos, name: "macOS", version: "26.5", aliases: ["macos", "macosx"], vendorHint: "apple",
    bundleID: "com.apple.macos", path: nil, caskToken: nil, latestVersion: nil)

let items = [
    curl, openssl, node, jq, ffmpeg, vlc, firefox, slack, zoom, numbers, keynote, safari, macOS,
]

// MARK: - CVEs and the fixes they should show

var cves: [CVERecord] = []
var fixes: [String: Fix] = [:]

func add(_ record: CVERecord, _ item: InventoryItem, _ itemFix: Fix) {
    cves.append(record)
    fixes["\(record.id)|\(item.key)"] = itemFix
}

add(
    cve(
        "CVE-2026-50001", .critical, 9.8, criticalVector,
        "A heap buffer overflow in curl's HTTP/2 handling lets a malicious server execute arbitrary code when a request is redirected.",
        published: day(0, hour: 9),
        ranges: [range(vendor: "haxx", product: "curl", start: "8.0.0", end: "8.6.0")],
        references: ["https://curl.se/docs/CVE-2026-50001.html"]),
    curl,
    fix(
        .brewFormula, "curl", "8.6.0", "Homebrew: upgrade formula curl 8.4.0 → 8.6.0"))

add(
    cve(
        "CVE-2026-50002", .high, 8.8, highVector,
        "Firefox could be tricked into loading a malicious extension from a crafted page, leading to code execution in the browser process.",
        published: day(0, hour: 13),
        ranges: [range(vendor: "mozilla", product: "firefox", start: "120.0", end: "129.0")],
        references: ["https://www.mozilla.org/en-US/security/advisories/mfsa2026-42/"]),
    firefox,
    fix(.brewCask, "firefox", "129.0", "Homebrew: upgrade cask firefox 128.0 → 129.0"))

add(
    cve(
        "CVE-2026-50003", .medium, 6.5, mediumVector,
        "jq mishandles deeply nested input, which can crash the process or expose memory contents in error messages.",
        published: day(0, hour: 16),
        ranges: [range(vendor: "jqlang", product: "jq", start: "1.6", end: "1.7.1")]),
    jq,
    fix(.brewFormula, "jq", "1.7.1", "Homebrew: upgrade formula jq 1.7.0 → 1.7.1"))

add(
    cve(
        "CVE-2026-50004", .critical, 9.1, criticalVector,
        "Node.js permits a specially crafted HTTP request to corrupt memory in the built-in HTTP parser, allowing remote code execution.",
        published: day(1),
        ranges: [range(vendor: "nodejs", product: "nodejs", start: "18.0.0", end: "22.5.1")],
        references: ["https://nodejs.org/en/blog/vulnerability/november-2026-security-releases"]),
    node,
    fix(.brewFormula, "node", "22.5.1", "Homebrew: upgrade formula node 22.4.0 → 22.5.1"))

add(
    cve(
        "CVE-2026-50005", .high, 8.6, highVector,
        "A memory corruption issue in the macOS kernel could allow a local attacker to execute code with kernel privileges.",
        published: day(1, hour: 12),
        ranges: [range(vendor: "apple", product: "macos", start: "26.0", end: "27.0")],
        references: ["https://support.apple.com/en-us/126000"]),
    macOS,
    fix(
        .softwareUpdate, "macOS 27.0-26A100", "27.0",
        "Apple Software Update: install “macOS 27” (26.5 → 27.0) — major macOS upgrade",
        notesURL: "https://support.apple.com/en-us/126000",
        notesTitle: "Apple: security content of macOS 27"))

add(
    cve(
        "CVE-2026-50006", .low, 3.7, lowVector,
        "OpenSSL's command-line tools can read an uninitialised buffer when parsing a malformed certificate, exposing a few bytes of process memory.",
        published: day(1, hour: 15),
        ranges: [range(vendor: "openssl", product: "openssl", start: "3.0.0", end: "3.3.2")]),
    openssl,
    fix(.brewFormula, "openssl@3", "3.3.2", "Homebrew: upgrade formula openssl@3 3.3.1 → 3.3.2"))

add(
    cve(
        "CVE-2026-50007", .high, 8.1, highVector,
        "Slack's custom URL handler fails to validate a path, allowing another app to overwrite files in the user's home folder.",
        published: day(3),
        ranges: [range(vendor: "tinyspeck", product: "slack", start: "4.0.0", end: "4.40.0")]),
    slack,
    fix(
        .brewCaskReplace, "slack", "4.40.0",
        "Homebrew: install cask slack over the existing app, 4.39.0 → 4.40.0"))

add(
    cve(
        "CVE-2026-50008", .medium, 6.1, mediumVector,
        "Numbers opens a document from an untrusted source without warning, which can leak the contents of other open spreadsheets.",
        published: day(3, hour: 11),
        ranges: [range(vendor: "apple", product: "numbers", start: "13.0", end: "14.1")]),
    numbers,
    fix(.appStore, "409203825", "14.1", "Mac App Store: update Numbers 14.0 → 14.1"))

add(
    cve(
        "CVE-2026-50009", .high, 7.8, highVector,
        "An out-of-bounds read in a macOS system service can be triggered by a malicious app and may disclose sensitive memory.",
        published: day(3, hour: 14),
        ranges: [range(vendor: "apple", product: "macos", start: "26.0", end: "26.6")],
        references: ["https://support.apple.com/en-us/125999"]),
    macOS,
    fix(
        .softwareUpdate, "macOS Tahoe 26.6-25G1", "26.6",
        "Apple Software Update: install “macOS Tahoe 26.6” (26.5 → 26.6)",
        notesURL: "https://support.apple.com/en-us/125999",
        notesTitle: "Apple: security content of macOS Tahoe 26.6"))

add(
    cve(
        "CVE-2026-50010", .critical, 9.8, criticalVector,
        "VLC's subtitle parser trusts a length field in an SRT file, leading to a heap overflow when the file is opened.",
        published: day(7),
        ranges: [range(vendor: "videolan", product: "vlc", start: "3.0.0", end: "3.0.21")],
        references: ["https://www.videolan.org/security/sb-vlc3021.html"]),
    vlc,
    fix(.brewCask, "vlc", "3.0.21", "Homebrew: upgrade cask vlc 3.0.20 → 3.0.21"))

add(
    cve(
        "CVE-2026-50011", .high, 8.8, highVector,
        "Safari's web inspector allows a malicious page to read local files when the inspector is open.",
        published: day(7, hour: 12),
        ranges: [range(vendor: "apple", product: "safari", start: "17.0", end: "18.1")],
        references: ["https://support.apple.com/en-us/125998"]),
    safari,
    fix(
        .softwareUpdate, "Safari 18.1-18B100", "18.1",
        "Apple Software Update: install “Safari 18.1” (18.0 → 18.1)",
        notesURL: "https://support.apple.com/en-us/125998",
        notesTitle: "Apple: security content of Safari 18.1"))

add(
    cve(
        "CVE-2026-50012", .medium, 6.8, mediumVector,
        "Zoom's screen-sharing helper accepts a connection from any local process, letting another user on the Mac watch the shared screen.",
        published: day(7, hour: 16),
        ranges: [range(vendor: "zoom", product: "zoom", start: "5.0.0", end: "6.2.0")]),
    zoom,
    fix(.appStore, "123456789", "6.2.0", "Mac App Store: update zoom.us 6.1.0 → 6.2.0"))

add(
    cve(
        "CVE-2026-50013", .high, 8.2, highVector,
        "FFmpeg's Matroska demuxer can write past the end of a buffer when reading a crafted file, potentially executing code.",
        published: day(14),
        ranges: [range(vendor: "ffmpeg", product: "ffmpeg", start: "6.0", end: "7.0.2")]),
    ffmpeg,
    fix(.brewFormula, "ffmpeg", "7.0.2", "Homebrew: upgrade formula ffmpeg 7.0.1 → 7.0.2"))

add(
    cve(
        "CVE-2026-50014", .medium, 5.5, mediumVector,
        "Keynote follows a link in an imported presentation without asking, which can be used to open a malicious website.",
        published: day(14, hour: 11),
        ranges: [range(vendor: "apple", product: "keynote", start: "13.0", end: "14.1")]),
    keynote,
    fix(.appStore, "409183694", "14.1", "Mac App Store: update Keynote 14.0 → 14.1"))

add(
    cve(
        "CVE-2026-50015", .high, 7.5, highVector,
        "A second flaw in Slack's URL handler lets a crafted link start a call without confirmation and share the microphone.",
        published: day(14, hour: 15),
        ranges: [range(vendor: "tinyspeck", product: "slack", start: "4.0.0", end: "4.40.0")]),
    slack,
    fix(
        .brewCaskReplace, "slack", "4.40.0",
        "Homebrew: install cask slack over the existing app, 4.39.0 → 4.40.0"))

add(
    cve(
        "CVE-2026-50016", .critical, 9.0, criticalVector,
        "curl's cookie parser can be confused by a domain containing a trailing dot, sending cookies to the wrong host.",
        published: day(30),
        ranges: [range(vendor: "haxx", product: "curl", start: "8.3.0", end: "8.6.0")]),
    curl,
    fix(.brewFormula, "curl", "8.6.0", "Homebrew: upgrade formula curl 8.4.0 → 8.6.0"))

add(
    cve(
        "CVE-2026-50017", .high, 8.0, highVector,
        "Node.js's permission model does not block a crafted `require` path, allowing a sandboxed script to load arbitrary native modules.",
        published: day(60),
        ranges: [range(vendor: "nodejs", product: "nodejs", start: "20.0.0", end: "22.5.1")]),
    node,
    fix(.brewFormula, "node", "22.5.1", "Homebrew: upgrade formula node 22.4.0 → 22.5.1"))

add(
    cve(
        "CVE-2026-50018", .low, 2.5, lowVector,
        "jq prints part of an environment variable in a verbose error message when a filter fails on malformed input.",
        published: day(89),
        ranges: [range(vendor: "jqlang", product: "jq", start: "1.6", end: "1.7.1")]),
    jq,
    fix(.brewFormula, "jq", "1.7.1", "Homebrew: upgrade formula jq 1.7.0 → 1.7.1"))

// MARK: - Write

let encoder = JSONEncoder()
encoder.dateEncodingStrategy = .iso8601
encoder.outputFormatting = [.prettyPrinted, .sortedKeys]

func write<T: Encodable>(_ value: T, to name: String) throws {
    try encoder.encode(value).write(to: output.appendingPathComponent(name), options: .atomic)
}

try write(cves, to: "cves.json")
try write(items, to: "inventory.json")
try write(fixes, to: "fixes.json")

let severities = Dictionary(grouping: cves, by: \.severity).mapValues(\.count)
let counts = Severity.allCases.map { "\(severities[$0] ?? 0) \($0.rawValue.lowercased())" }.joined(separator: ", ")
print("Wrote demo data to \(output.path)")
print("  \(cves.count) CVEs (\(counts)), \(items.count) installed items, \(fixes.count) fixes")
