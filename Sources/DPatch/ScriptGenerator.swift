import Foundation

/// Builds a bash script that installs the fixes for the selected findings.
enum ScriptGenerator {
    static func script(for findings: [Finding], date: Date = Date()) -> String {
        let df = DateFormatter()
        df.dateFormat = "yyyy-MM-dd HH:mm"
        let os = Inventory.macOSItem().version
        let host = Host.current().localizedName ?? ProcessInfo.processInfo.hostName

        var lines = [
            "#!/usr/bin/env bash",
            "# D-Patch remediation script",
            "# Generated \(df.string(from: date)) on \(host) (macOS \(os))",
            "#",
            "# Addresses:",
        ]
        for f in findings.sorted(by: { $0.cve.id < $1.cve.id }) {
            let line = "#   \(f.cve.id)  \(f.cve.severity.rawValue) \(f.cve.score)  \(f.item.name) \(f.item.version), fixed in \(f.fixedIn)"
            lines.append(line.components(separatedBy: .newlines).joined(separator: " "))
        }

        // One action per fix target, even when it closes several CVEs.
        var fixes: [Fix] = []
        for f in findings where !fixes.contains(where: { $0.method == f.fix.method && $0.target == f.fix.target }) {
            fixes.append(f.fix)
        }
        let order: [FixMethod] = [.brewFormula, .brewCask, .brewCaskReplace, .appStore, .softwareUpdate]
        fixes.sort { (order.firstIndex(of: $0.method)!, $0.target) < (order.firstIndex(of: $1.method)!, $1.target) }
        let needsBrew = fixes.contains { [.brewFormula, .brewCask, .brewCaskReplace, .appStore].contains($0.method) }

        lines += [
            "",
            "set -uo pipefail",
            "",
            "failures=()",
            "run() {",
            "  echo",
            "  echo \"==> $*\"",
            "  if ! \"$@\"; then",
            "    failures+=(\"$*\")",
            "    echo \"!! failed: $*\"",
            "  fi",
            "}",
            "",
            "echo \"D-Patch will apply \(fixes.count) update(s):\"",
        ]
        for fix in fixes { lines.append("echo \"  - \(escapeDQ(fix.summary))\"") }
        lines += [
            "if [[ \"${1:-}\" != \"-y\" ]]; then",
            "  read -r -p \"Continue? [y/N] \" answer",
            "  [[ \"$answer\" =~ ^[Yy]$ ]] || { echo \"Cancelled.\"; exit 0; }",
            "fi",
        ]

        if needsBrew {
            lines += [
                "",
                "BREW=\"$(command -v brew || true)\"",
                "for p in /opt/homebrew/bin/brew /usr/local/bin/brew; do [[ -z \"$BREW\" && -x \"$p\" ]] && BREW=\"$p\"; done",
                "if [[ -z \"$BREW\" ]]; then echo \"Homebrew is required but was not found.\"; exit 1; fi",
                "run \"$BREW\" update",
            ]
        }

        var section: FixMethod?
        for fix in fixes {
            if fix.method != section {
                section = fix.method
                lines.append("")
                switch fix.method {
                case .brewFormula: lines.append("# Homebrew formulae")
                case .brewCask: lines.append("# Homebrew casks")
                case .brewCaskReplace:
                    lines.append("# Apps installed outside Homebrew: replace them with the current Homebrew cask")
                case .appStore:
                    lines += ["# Mac App Store apps (requires being signed in to the App Store)",
                              "command -v mas >/dev/null 2>&1 || run \"$BREW\" install mas",
                              "MAS=\"$(command -v mas || echo \"$(dirname \"$BREW\")/mas\")\""]
                case .softwareUpdate:
                    lines.append("# Apple software updates (needs an administrator password)")
                }
            }
            let t = shellQuote(fix.target)
            switch fix.method {
            case .brewFormula: lines.append("run \"$BREW\" upgrade --formula \(t)")
            case .brewCask: lines.append("run \"$BREW\" upgrade --cask --greedy \(t)")
            case .brewCaskReplace: lines.append("run \"$BREW\" install --cask --force \(t)")
            case .appStore: lines.append("run \"$MAS\" upgrade \(t)")
            case .softwareUpdate: lines.append("run sudo /usr/sbin/softwareupdate --install \(t)")
            }
        }

        lines += [
            "",
            "echo",
            "if (( ${#failures[@]} )); then",
            "  echo \"Finished with ${#failures[@]} failure(s):\"",
            "  printf '  %s\\n' \"${failures[@]}\"",
            "  exit 1",
            "fi",
            "echo \"All updates applied.\"",
        ]
        if fixes.contains(where: { $0.method == .softwareUpdate }) {
            lines.append("echo \"Apple updates may need a restart to take effect.\"")
        }
        return lines.joined(separator: "\n") + "\n"
    }

    static func shellQuote(_ s: String) -> String { "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'" }

    private static func escapeDQ(_ s: String) -> String {
        s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "$", with: "\\$").replacingOccurrences(of: "`", with: "\\`")
    }
}
