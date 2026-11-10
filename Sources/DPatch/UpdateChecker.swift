import AppKit

/// Checks GitHub for a newer D-Patch release and offers a link to it. Nothing is downloaded or installed.
@MainActor
final class UpdateChecker: ObservableObject {
    static let shared = UpdateChecker()

    static let latestReleaseAPI = URL(string: "https://api.github.com/repos/denzil71/D-Patch/releases/latest")!
    static let releasesPage = URL(string: "https://github.com/denzil71/D-Patch/releases")!
    /// Automatic checks run at most this often.
    static let interval: TimeInterval = 24 * 60 * 60

    @Published private(set) var isChecking = false
    /// What the last check found, for Settings.
    @Published private(set) var status: String?
    /// A notice for the main window to show; cleared when it's dismissed.
    @Published var notice: Notice?

    /// Shown as a SwiftUI alert on the main window. (An NSAlert run modally from here never
    /// appeared alongside the SwiftUI window, leaving the app stuck in an invisible modal session.)
    struct Notice: Identifiable {
        let id = UUID()
        let title: String
        let message: String
        /// Set when a newer release is on offer: its version and release page.
        var update: (version: String, page: URL)?
    }

    private var timer: Timer?

    /// This build's version; nil for a build without an Info.plist (e.g. `swift run`).
    static var currentVersion: String? {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String
    }

    /// What a check should do with the latest release it found.
    enum Outcome: Equatable {
        case upToDate
        /// A newer release, which an automatic check skips when the user chose Skip This Version.
        case offer(version: String)
        case skipped(version: String)
    }

    /// Compares the latest release's tag ("v1.2.3") with the running version.
    nonisolated static func outcome(
        latestTag: String, current: String, skipped: String?, userInitiated: Bool
    ) -> Outcome {
        let latest = version(fromTag: latestTag)
        guard let new = Version(latest), let old = Version(current), new > old else { return .upToDate }
        if !userInitiated, skipped == latest { return .skipped(version: latest) }
        return .offer(version: latest)
    }

    /// "v0.4.4" → "0.4.4".
    nonisolated static func version(fromTag tag: String) -> String {
        tag.hasPrefix("v") || tag.hasPrefix("V") ? String(tag.dropFirst()) : tag
    }

    /// Checks shortly after launch, then whenever a day has passed since the last check (while enabled).
    func start() {
        guard Self.currentVersion != nil else { return }
        DispatchQueue.main.asyncAfter(deadline: .now() + 10) { [weak self] in self?.checkIfDue() }
        timer = Timer.scheduledTimer(withTimeInterval: 60 * 60, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.checkIfDue() }
        }
    }

    private func checkIfDue() {
        guard Prefs.checkForUpdates else { return }
        guard Date().timeIntervalSince(Prefs.lastUpdateCheck ?? .distantPast) >= Self.interval else { return }
        Task { await check(userInitiated: false) }
    }

    struct Release: Decodable {
        let tagName: String
        let htmlURL: URL
        enum CodingKeys: String, CodingKey {
            case tagName = "tag_name"
            case htmlURL = "html_url"
        }
    }

    /// `userInitiated` checks also report "up to date" and errors, and ignore a skipped version.
    func check(userInitiated: Bool) async {
        guard !isChecking else { return }
        guard let current = Self.currentVersion else {
            status = "This build has no version number, so it can't be compared with releases."
            if userInitiated { notice = Notice(title: "Can't Check for Updates", message: status ?? "") }
            return
        }
        isChecking = true
        defer { isChecking = false }
        var request = URLRequest(url: Self.latestReleaseAPI, timeoutInterval: 20)
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        let release: Release
        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw URLError(.badServerResponse) }
            release = try JSONDecoder().decode(Release.self, from: data)
        } catch {
            status = "Couldn't check for updates."
            NSLog("D-Patch: update check failed: \(error)")
            if userInitiated {
                notice = Notice(
                    title: "Couldn't Check for Updates",
                    message: "D-Patch couldn't reach GitHub. Check your internet connection and try again.")
            }
            return
        }
        Prefs.lastUpdateCheck = Date()

        let outcome = Self.outcome(
            latestTag: release.tagName, current: current, skipped: Prefs.skippedUpdateVersion,
            userInitiated: userInitiated)
        NSLog("D-Patch: update check: latest \(release.tagName), running \(current): \(outcome)")
        switch outcome {
        case .upToDate:
            status = "D-Patch \(current) is the latest version."
            if userInitiated { notice = Notice(title: "You're Up to Date", message: status ?? "") }
        case .skipped(let version):
            status = "D-Patch \(version) is available (skipped)."
        case .offer(let version):
            status = "D-Patch \(version) is available."
            notice = Notice(
                title: "D-Patch \(version) Is Available",
                message: "You have \(current). The release page has what's new and the download.",
                update: (version, release.htmlURL))
        }
    }

    func skip(_ version: String) {
        Prefs.skippedUpdateVersion = version
        status = "D-Patch \(version) is available (skipped)."
    }
}
