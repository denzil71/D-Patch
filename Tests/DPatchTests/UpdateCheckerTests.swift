import Foundation
import Testing

@testable import DPatch

@Suite struct UpdateCheckerTests {
    private func outcome(_ tag: String, current: String, skipped: String? = nil, userInitiated: Bool = false)
        -> UpdateChecker.Outcome
    {
        UpdateChecker.outcome(latestTag: tag, current: current, skipped: skipped, userInitiated: userInitiated)
    }

    @Test func offersANewerRelease() {
        #expect(outcome("v0.4.5", current: "0.4.4") == .offer(version: "0.4.5"))
        #expect(outcome("v0.10.0", current: "0.9.3") == .offer(version: "0.10.0"))
        #expect(outcome("1.0.0", current: "0.99.99") == .offer(version: "1.0.0"))
    }

    @Test func sameOrOlderIsUpToDate() {
        #expect(outcome("v0.4.4", current: "0.4.4") == .upToDate)
        #expect(outcome("v0.4", current: "0.4.0") == .upToDate)
        #expect(outcome("v0.4.3", current: "0.4.4") == .upToDate)
    }

    @Test func unreadableVersionsAreUpToDate() {
        #expect(outcome("nightly", current: "0.4.4") == .upToDate)
        #expect(outcome("v0.4.5", current: "") == .upToDate)
    }

    @Test func automaticChecksRespectASkippedVersion() {
        #expect(outcome("v0.4.5", current: "0.4.4", skipped: "0.4.5") == .skipped(version: "0.4.5"))
        // A newer release than the skipped one is offered again.
        #expect(outcome("v0.4.6", current: "0.4.4", skipped: "0.4.5") == .offer(version: "0.4.6"))
    }

    @Test func checkingByHandIgnoresASkippedVersion() {
        #expect(outcome("v0.4.5", current: "0.4.4", skipped: "0.4.5", userInitiated: true) == .offer(version: "0.4.5"))
    }

    @Test func readsGitHubsLatestReleaseJSON() throws {
        let json =
            #"{"tag_name": "v0.4.4", "html_url": "https://github.com/denzil71/D-Patch/releases/tag/v0.4.4", "name": "D-Patch 0.4.4"}"#
        let release = try JSONDecoder().decode(UpdateChecker.Release.self, from: Data(json.utf8))
        #expect(release.tagName == "v0.4.4")
        #expect(release.htmlURL.absoluteString.hasSuffix("/releases/tag/v0.4.4"))
    }
}
