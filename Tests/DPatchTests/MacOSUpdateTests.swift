import Testing

@testable import DPatch

@Suite struct MacOSUpdateTests {
    private let list: [(label: String, title: String, version: String)] = [
        ("macOS 27.0-26A100", "macOS 27.0", "27.0"),
        ("Safari26.2-26.2", "Safari", "26.2"),
        ("macOS Tahoe 26.6-25G42", "macOS Tahoe 26.6", "26.6"),
        ("macOS Tahoe 26.5-25F71", "macOS Tahoe 26.5", "26.5"),
    ]

    @Test func listsNewerMacOSUpdatesSmallestFirst() {
        let updates = FixResolver.macOSUpdates(from: list, installed: "26.5")
        #expect(updates.map(\.version) == ["26.6", "27.0"])
        #expect(updates.map(\.label) == ["macOS Tahoe 26.6-25G42", "macOS 27.0-26A100"])
    }

    @Test func marksMajorUpgrades() {
        let updates = FixResolver.macOSUpdates(from: list, installed: "26.5")
        #expect(updates.map(\.isMajor) == [false, true])
    }

    @Test func leavesOutOtherAppleUpdatesAndTheInstalledVersion() {
        let updates = FixResolver.macOSUpdates(from: list, installed: "26.6")
        #expect(updates.map(\.version) == ["27.0"])
    }

    @Test func nothingToInstallIsEmpty() {
        #expect(FixResolver.macOSUpdates(from: [], installed: "26.5").isEmpty)
        #expect(FixResolver.macOSUpdates(from: list, installed: "27.0").isEmpty)
    }

    @Test func withoutAnInstalledVersionListsAllAsMinor() {
        let updates = FixResolver.macOSUpdates(from: list, installed: nil)
        #expect(updates.count == 3)
        #expect(updates.allSatisfy { !$0.isMajor })
    }
}
