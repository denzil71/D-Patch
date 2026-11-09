import Testing

@testable import DPatch

@Suite struct ScriptGeneratorTests {
    @Test func quotesForTheShell() {
        #expect(ScriptGenerator.shellQuote("plain") == "'plain'")
        #expect(ScriptGenerator.shellQuote("it's") == #"'it'\''s'"#)
    }

    @Test func buildsTheCommandForEachFix() {
        typealias F = Fixtures
        #expect(
            ScriptGenerator.command(for: F.fix(.brewFormula, "curl", to: "8.5.0")) == "brew upgrade --formula 'curl'")
        #expect(
            ScriptGenerator.command(for: F.fix(.brewCask, "firefox", to: "130"))
                == "brew upgrade --cask --greedy 'firefox'")
        #expect(
            ScriptGenerator.command(for: F.fix(.brewCaskReplace, "vlc", to: "3.0.21"))
                == "brew install --cask --force 'vlc'")
        #expect(ScriptGenerator.command(for: F.fix(.appStore, "409183694", to: "14")) == "mas upgrade '409183694'")
        #expect(
            ScriptGenerator.command(for: F.fix(.softwareUpdate, "macOS 26.7-25H1", to: "26.7"))
                == "sudo /usr/sbin/softwareupdate --install 'macOS 26.7-25H1'")
    }

    @Test func oneFixPerTargetInRunOrder() {
        let curl = Fixtures.item(.formula, name: "curl", version: "8.4.0", aliases: ["curl"])
        let mac = Fixtures.item(.macos, name: "macOS", version: "26.5", aliases: ["macos"])
        let findings = [
            Fixtures.finding("CVE-1", item: mac, fix: Fixtures.fix(.softwareUpdate, "macOS 26.6-25G1", to: "26.6")),
            Fixtures.finding("CVE-2", item: curl, fix: Fixtures.fix(.brewFormula, "curl", to: "8.5.0")),
            // Same fix as CVE-2: listed once.
            Fixtures.finding("CVE-3", item: curl, fix: Fixtures.fix(.brewFormula, "curl", to: "8.5.0")),
            // A newer macOS update includes the older one's fixes, so only the newest is kept.
            Fixtures.finding("CVE-4", item: mac, fix: Fixtures.fix(.softwareUpdate, "macOS 26.7-25H1", to: "26.7")),
        ]
        let fixes = ScriptGenerator.fixes(for: findings)
        #expect(fixes.map(\.target) == ["curl", "macOS 26.7-25H1"])
    }

    @Test func spotsMajorMacOSUpgrades() {
        let mac = Fixtures.item(.macos, name: "macOS", version: "26.5", aliases: ["macos"])
        let minor = Fixtures.finding("CVE-1", item: mac, fix: Fixtures.fix(.softwareUpdate, "macOS 26.7", to: "26.7"))
        let major = Fixtures.finding("CVE-2", item: mac, fix: Fixtures.fix(.softwareUpdate, "macOS 27.1", to: "27.1"))
        #expect(!minor.isMajorUpgrade)
        #expect(major.isMajorUpgrade)
    }
}
