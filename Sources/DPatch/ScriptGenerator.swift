import Foundation

/// Builds a bash script that installs the fixes for the selected findings.
enum ScriptGenerator {
    /// `confirm`: ask before changing anything (the app asks itself before it runs a script).
    /// `rescan`: path of the D-Patch executable to rescan with afterwards, so the app's list refreshes.
    static func script(for findings: [Finding], confirm: Bool = true, rescan: String? = nil,
                       date: Date = Date()) -> String {
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

        let fixes = self.fixes(for: findings)
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
        if confirm {
            lines += [
                "if [[ \"${1:-}\" != \"-y\" ]]; then",
                "  read -r -p \"Continue? [y/N] \" answer",
                "  [[ \"$answer\" =~ ^[Yy]$ ]] || { echo \"Cancelled.\"; exit 0; }",
                "fi",
            ]
        }

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
            lines.append("run " + command(for: fix, brew: "\"$BREW\"", mas: "\"$MAS\""))
        }

        if let exe = rescan {
            lines += ["", "echo", "echo \"==> Rescanning so D-Patch shows what is still open…\"",
                      "\(shellQuote(exe)) --scan | tail -1"]
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

    /// One action per fix target, even when it closes several CVEs, in the order the script runs them.
    static func fixes(for findings: [Finding]) -> [Fix] {
        var fixes: [Fix] = []
        for f in findings where !fixes.contains(where: { $0.method == f.fix.method && $0.target == f.fix.target }) {
            fixes.append(f.fix)
        }
        // A newer macOS update includes the fixes of an older one; install only the newest.
        let macOS = fixes.filter { $0.method == .softwareUpdate && $0.target.hasPrefix("macOS") }
        if let newest = macOS.max(by: { Version.isLess($0.toVersion, $1.toVersion) }) {
            fixes.removeAll { $0.method == .softwareUpdate && $0.target.hasPrefix("macOS") && $0.target != newest.target }
        }
        let order: [FixMethod] = [.brewFormula, .brewCask, .brewCaskReplace, .appStore, .softwareUpdate]
        fixes.sort { (order.firstIndex(of: $0.method)!, $0.target) < (order.firstIndex(of: $1.method)!, $1.target) }
        return fixes
    }

    /// What `script(for:confirm:rescan:)` does, step by step, in plain English (Markdown).
    static func steps(for findings: [Finding], rescan: Bool) -> [String] {
        let fixes = self.fixes(for: findings)
        func name(_ fix: Fix) -> String {
            findings.first { $0.fix.method == fix.method && $0.fix.target == fix.target }?.item.name ?? fix.target
        }
        var steps: [String] = []
        if fixes.contains(where: { $0.method != .softwareUpdate }) {
            steps.append("Find Homebrew and refresh its list of available versions (`brew update`).")
        }
        if fixes.contains(where: { $0.method == .appStore }) {
            steps.append("Install the `mas` command-line tool with Homebrew, if it isn't already installed.")
        }
        for fix in fixes {
            let to = FixResolver.plain(fix.toVersion)
            switch fix.method {
            case .brewFormula:
                steps.append("Upgrade **\(fix.target)** to \(to) with Homebrew.")
            case .brewCask:
                steps.append("Upgrade the **\(name(fix))** app to \(to) with Homebrew.")
            case .brewCaskReplace:
                steps.append("Replace **\(name(fix))**, which was installed outside Homebrew, with Homebrew's copy (\(to)). Homebrew keeps it updated from then on.")
            case .appStore:
                steps.append("Update **\(name(fix))** to \(to) from the Mac App Store.")
            case .softwareUpdate:
                let notes = fix.notesLink.map { " [Read Apple's notes](\($0.url.absoluteString))" } ?? ""
                steps.append("Install **\(name(fix)) \(to)** with Apple Software Update. It asks for your administrator password, and the Mac may need to restart.\(notes)")
            }
        }
        if rescan {
            steps.append("Rescan this Mac so D-Patch's list shows what is still open.")
        }
        steps.append("Carry on if a step fails, and list any failures at the end.")
        return steps
    }

    /// The shell command that applies one fix, as run by the script and shown in the app.
    static func command(for fix: Fix, brew: String = "brew", mas: String = "mas") -> String {
        let t = shellQuote(fix.target)
        switch fix.method {
        case .brewFormula: return "\(brew) upgrade --formula \(t)"
        case .brewCask: return "\(brew) upgrade --cask --greedy \(t)"
        case .brewCaskReplace: return "\(brew) install --cask --force \(t)"
        case .appStore: return "\(mas) upgrade \(t)"
        case .softwareUpdate: return "sudo /usr/sbin/softwareupdate --install \(t)"
        }
    }

    static func shellQuote(_ s: String) -> String { "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'" }

    private static func escapeDQ(_ s: String) -> String {
        s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "$", with: "\\$").replacingOccurrences(of: "`", with: "\\`")
    }
}
