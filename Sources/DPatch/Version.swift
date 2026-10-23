import Foundation

/// Loose, comparable software version: "1.2.3", "9.8p1", "4.95.0,242831", "3.5.1_1", "v2.0-rc1".
struct Version: Comparable, CustomStringConvertible {
    enum Part: Equatable {
        case num(Int)
        case str(String)
    }

    let parts: [Part]
    let description: String

    init?(_ raw: String) {
        var s = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if s.hasPrefix("v") { s.removeFirst() }
        // Cask "version,build" and Homebrew revision "_N" are not part of the upstream version.
        if let comma = s.firstIndex(of: ",") { s = String(s[..<comma]) }
        if let r = s.range(of: #"_\d+$"#, options: .regularExpression) { s.removeSubrange(r) }

        var parts: [Part] = []
        var current = ""
        var currentIsDigit = false
        func flush() {
            guard !current.isEmpty else { return }
            if currentIsDigit, let n = Int(current.prefix(18)) { parts.append(.num(n)) }
            else { parts.append(.str(current)) }
            current = ""
        }
        for ch in s {
            if ch.isASCII && ch.isNumber {
                if !currentIsDigit { flush() }
                currentIsDigit = true
                current.append(ch)
            } else if ch.isASCII && ch.isLetter {
                if currentIsDigit { flush() }
                currentIsDigit = false
                current.append(ch)
            } else {
                flush()
            }
        }
        flush()
        guard case .num = parts.first else { return nil }
        self.parts = parts
        self.description = raw
    }

    static func == (a: Version, b: Version) -> Bool { compare(a, b) == 0 }
    static func < (a: Version, b: Version) -> Bool { compare(a, b) < 0 }

    private static func compare(_ a: Version, _ b: Version) -> Int {
        let n = max(a.parts.count, b.parts.count)
        for i in 0..<n {
            let x = i < a.parts.count ? a.parts[i] : .num(0)
            let y = i < b.parts.count ? b.parts[i] : .num(0)
            switch (x, y) {
            case let (.num(p), .num(q)): if p != q { return p < q ? -1 : 1 }
            case let (.str(p), .str(q)): if p != q { return p < q ? -1 : 1 }
            // A letter part marks a pre-release ("1.0rc1" < "1.0") or patch suffix; numbers win.
            case (.num, .str): return 1
            case (.str, .num): return -1
            }
        }
        return 0
    }

    /// First version-looking token in free text, e.g. "1.18.0 or later" -> "1.18.0".
    static func firstToken(in text: String) -> String? {
        guard let r = text.range(of: #"\d[0-9A-Za-z.\-_]*"#, options: .regularExpression) else { return nil }
        return String(text[r]).trimmingCharacters(in: CharacterSet(charactersIn: ".-_"))
    }
}

/// Lowercase alphanumerics only, so "Visual Studio Code", "visual_studio_code" and "visual-studio-code" agree.
func normalizeName(_ s: String) -> String {
    String(s.lowercased().unicodeScalars.filter { CharacterSet.alphanumerics.contains($0) && $0.isASCII })
}
