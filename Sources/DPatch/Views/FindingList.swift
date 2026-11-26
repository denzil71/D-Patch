import AppKit
import SwiftUI

struct FindingList: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        let visible = model.visible
        Group {
            if model.result == nil {
                ContentUnavailableView {
                    Label("No scan yet", systemImage: "shield.lefthalf.filled")
                } description: {
                    Text(
                        "D-Patch checks the software on this Mac against known CVEs, at the severity levels chosen in Settings, and lists the ones that affect it, with a fix where one is available."
                    )
                } actions: {
                    Button("Scan Now") { model.scan() }.disabled(model.isScanning)
                }
            } else {
                VStack(spacing: 0) {
                    FilterBar()
                    Divider()
                    if !model.macOSUpdates.isEmpty {
                        MacOSUpdatesBanner(updates: model.macOSUpdates)
                        Divider()
                    }
                    if visible.isEmpty {
                        emptyState
                            .frame(maxWidth: .infinity, maxHeight: .infinity)
                    } else {
                        // Not a List: on macOS its rows keep their first height, so an expanded row has no room.
                        ScrollView {
                            LazyVStack(alignment: .leading, spacing: 0, pinnedViews: [.sectionHeaders]) {
                                Section {
                                    ForEach(visible) { f in
                                        FindingRow(finding: f)
                                            .padding(.horizontal, 16)
                                        Divider().padding(.leading, 16)
                                    }
                                } header: {
                                    ListHeader(visible: visible)
                                        .padding(.horizontal, 16)
                                        .background(.bar)
                                }
                            }
                        }
                        .background(Color(nsColor: .textBackgroundColor))
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
            }
        }
        .navigationTitle(title)
    }

    @ViewBuilder private var emptyState: some View {
        if !model.shown.isEmpty, !model.search.isEmpty {
            ContentUnavailableView(
                "No matches", systemImage: "magnifyingglass",
                description: Text("No CVEs match “\(model.search)”."))
        } else if !model.shown.isEmpty, model.filtersActive {
            ContentUnavailableView {
                Label("No CVEs match the filters", systemImage: "line.3.horizontal.decrease.circle")
            } actions: {
                Button("Clear Filters") { model.clearFilters() }
            }
        } else if model.hiddenUnfixedCount > 0 {
            let n = model.hiddenUnfixedCount
            ContentUnavailableView(
                "Nothing to patch", systemImage: "checkmark.shield",
                description: Text(
                    "No fixable CVEs affect this Mac. \(n) CVE\(n == 1 ? "" : "s") with no fix yet \(n == 1 ? "is" : "are") hidden (Settings › General)."
                ))
        } else {
            ContentUnavailableView(
                "Nothing to patch", systemImage: "checkmark.shield",
                description: Text("No CVEs at the chosen severity levels affect this Mac."))
        }
    }

    private var title: String {
        if case .day(let d)? = model.filter {
            return d.formatted(date: .complete, time: .omitted)
        }
        return "All CVEs"
    }
}

/// macOS updates Apple Software Update offers, pinned above the CVE list (also when it's empty),
/// since they're worth installing whether or not a CVE names them.
private struct MacOSUpdatesBanner: View {
    let updates: [MacOSUpdate]
    static let softwareUpdateSettings = URL(
        string: "x-apple.systempreferences:com.apple.Software-Update-Settings.extension")!

    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            Image(systemName: "apple.logo")
                .font(.title2)
                .foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 3) {
                ForEach(updates) { update in
                    HStack(spacing: 8) {
                        Text("\(update.title) is available").fontWeight(.medium)
                        if update.isMajor {
                            Text("Major upgrade")
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(.secondary)
                                .padding(.horizontal, 6)
                                .padding(.vertical, 1)
                                .overlay(Capsule().stroke(Color.secondary.opacity(0.5)))
                        }
                    }
                    .help(update.label)
                }
            }
            Spacer()
            Button("Open Software Update") { NSWorkspace.shared.open(Self.softwareUpdateSettings) }
                .help("Install macOS updates in System Settings › General › Software Update")
        }
        .font(.callout)
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .background(Color.accentColor.opacity(0.08))
    }
}

private struct ListHeader: View {
    @EnvironmentObject var model: AppModel
    var visible: [Finding]

    var body: some View {
        let fixable = visible.filter { $0.fix != nil }
        let allOn = !fixable.isEmpty && fixable.allSatisfy { model.checked.contains($0.id) }
        HStack {
            Toggle(isOn: Binding(get: { allOn }, set: { model.setAllVisible($0) })) {
                Text(
                    "\(visible.count) CVE\(visible.count == 1 ? "" : "s"), \(fixable.count == visible.count ? "all" : "\(fixable.count)") fixable"
                )
            }
            .toggleStyle(.checkbox)
            .disabled(fixable.isEmpty)
            .help("Tick every CVE shown that has a fix")
            if model.hiddenUnfixedCount > 0 {
                Text("· \(model.hiddenUnfixedCount) with no fix hidden")
                    .foregroundStyle(.secondary)
                    .help("Show them with Settings › General › Show CVEs with no fix yet")
            }
            Spacer()
            if !model.checked.isEmpty {
                let hidden = model.hiddenCheckedCount
                Text("\(model.checked.count) ticked" + (hidden > 0 ? " (\(hidden) not shown)" : ""))
                    .help(
                        hidden > 0
                            ? "Some ticked CVEs are hidden by the filters or the selected date; Patch Selected still includes them."
                            : "")
                Button("Clear") { model.checked.removeAll() }.buttonStyle(.link)
            }
        }
        .font(.callout)
        .padding(.vertical, 6)
    }
}

struct FindingRow: View {
    @EnvironmentObject var model: AppModel
    let finding: Finding

    var body: some View {
        let cve = finding.cve
        let expanded = model.expanded.contains(finding.id)
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                Toggle(
                    "", isOn: Binding(get: { model.checked.contains(finding.id) }, set: { _ in model.toggle(finding) })
                )
                .toggleStyle(.checkbox)
                .labelsHidden()
                .disabled(finding.fix == nil)
                .help(finding.fix == nil ? "No update fixes this yet" : "")
                Button {
                    withAnimation(.easeInOut(duration: 0.22)) { model.toggleExpanded(finding) }
                } label: {
                    HStack(alignment: .firstTextBaseline, spacing: 10) {
                        Image(systemName: "chevron.right")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.secondary)
                            .rotationEffect(.degrees(expanded ? 90 : 0))
                            .frame(width: 10)
                        SeverityTag(severity: cve.severity, score: cve.score)
                        Text(cve.id).font(.body.monospaced().weight(.medium))
                        SourceBadges(records: finding.databases)
                        Text("\(finding.item.name) \(finding.item.version)")
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                        Spacer(minLength: 8)
                        if let fix = finding.fix {
                            Text("→ \(FixResolver.plain(fix.toVersion))")
                                .font(.callout.monospacedDigit())
                                .foregroundStyle(.green)
                        } else {
                            Text("No fix yet")
                                .font(.callout)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .help(expanded ? "Hide details" : "Show overview and fix")
            }
            if expanded {
                FindingDetail(finding: finding)
                    .padding(.leading, 30)
                    .padding(.top, 10)
                    .padding(.bottom, 6)
                    // Fade only: a move transition made the text slide out from under the info row.
                    .transition(.opacity)
            }
        }
        .padding(.vertical, 6)
    }
}
struct SeverityTag: View {
    var severity: Severity
    var score: Double

    var body: some View {
        Text(severity == .unscored ? severity.rawValue : "\(severity.rawValue) \(String(format: "%.1f", score))")
            .font(.caption.weight(.bold).monospacedDigit())
            .foregroundStyle(severity.color)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(severity.color.opacity(0.12), in: RoundedRectangle(cornerRadius: 4))
            .frame(width: 104, alignment: .leading)
    }
}

struct FindingDetail: View {
    let finding: Finding

    var body: some View {
        let cve = finding.cve
        VStack(alignment: .leading, spacing: 14) {
            DetailSection(title: "Overview", systemImage: "info.circle") {
                Text(cve.summary.isEmpty ? "No description published." : cve.summary)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 12, verticalSpacing: 4) {
                    row(
                        "Severity",
                        cve.severity == .unscored
                            ? "Not scored yet by NVD, CISA or the vendor"
                            : "\(cve.severity.rawValue.capitalized) — CVSS \(String(format: "%.1f", cve.score))")
                    if !cve.vector.isEmpty { row("Vector", cve.vector) }
                    row("Published", cve.published.formatted(date: .long, time: .shortened))
                    row(
                        "Affects",
                        "\(finding.item.name) \(finding.item.version)" + (finding.item.path.map { " — \($0)" } ?? ""))
                    row("Fixed in", finding.fixedIn)
                }
                .font(.callout)
            }

            DetailSection(title: "How to fix", systemImage: "wrench.and.screwdriver") {
                if let fix = finding.fix {
                    fixDetail(fix)
                } else {
                    Text("No update fixes this yet").fontWeight(.medium)
                    Text(noFixNote)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

            DetailSection(title: "Databases", systemImage: "square.stack.3d.up") {
                VStack(alignment: .leading, spacing: 5) {
                    ForEach(finding.databases, id: \.self) { record in
                        DatabaseLine(cveID: cve.id, record: record)
                    }
                }
                .font(.callout)
            }

            DetailSection(title: "References", systemImage: "link") {
                VStack(alignment: .leading, spacing: 3) {
                    ForEach(Array(cve.references.enumerated()), id: \.offset) { _, ref in
                        if let url = URL(string: ref) {
                            Link(ref, destination: url).lineLimit(1).truncationMode(.middle)
                        }
                    }
                }
                .font(.callout)
            }
        }
    }

    @ViewBuilder private func fixDetail(_ fix: Fix) -> some View {
        let command = ScriptGenerator.command(for: fix)
        Text(fix.summary).fontWeight(.medium)
        if let notes = fix.notesLink {
            Link(notes.title, destination: notes.url)
                .font(.callout)
                .help(notes.url.absoluteString)
        }
        HStack(alignment: .top, spacing: 8) {
            Text(command)
                .font(.system(.callout, design: .monospaced))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
            Button {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(command, forType: .string)
            } label: {
                Image(systemName: "doc.on.doc")
            }
            .buttonStyle(.borderless)
            .help("Copy command")
        }
        .padding(8)
        .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 5))
        .overlay(RoundedRectangle(cornerRadius: 5).stroke(.separator))
        Text(LocalizedStringKey(note(fix)))
            .font(.callout)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
    }

    /// Why there's nothing to install, and what is known about a fix.
    private var noFixNote: String {
        let source: String
        switch finding.item.kind {
        case .formula, .cask: source = "Homebrew doesn't offer a version"
        case .macos: source = "Apple Software Update doesn't offer a version"
        case .app:
            source =
                finding.item.caskToken != nil
                ? "Homebrew doesn't offer a version"
                : finding.item.isAppStore
                    ? "The Mac App Store doesn't offer a version"
                    : "Neither Homebrew nor the Mac App Store offers a version"
        }
        let fixed =
            finding.fixedIn.hasPrefix("not stated")
            ? "The vendor hasn't said which version fixes it."
            : "Fixed in: \(finding.fixedIn)."
        return
            "\(source) outside the affected range yet. \(fixed) Check the references for a workaround or a vendor download, and scan again later."
    }

    private func note(_ fix: Fix) -> String {
        switch fix.method {
        case .brewFormula:
            return
                "Upgrades the Homebrew formula to \(fix.toVersion). Run `brew update` first so Homebrew knows about the latest version."
        case .brewCask:
            return
                "Upgrades the Homebrew-managed app to \(FixResolver.plain(fix.toVersion)). Quit the app first."
        case .brewCaskReplace:
            return
                "This app was installed outside Homebrew. The command installs the Homebrew cask (\(FixResolver.plain(fix.toVersion))) over it, after which Homebrew manages its updates. Quit the app first."
        case .appStore:
            return
                "Updates the app from the Mac App Store using the `mas` tool (`brew install mas`); you must be signed in to the App Store. You can also update it in App Store › Updates."
        case .softwareUpdate:
            return
                "Installs the Apple update. It needs an administrator password and may restart the Mac. You can also install it from System Settings › General › Software Update."
        }
    }

    private func row(_ label: String, _ value: String) -> some View {
        GridRow {
            Text(label).foregroundStyle(.secondary)
            Text(value).textSelection(.enabled)
        }
    }
}

/// Small labels after the CVE ID naming each database that lists it; KEV stands out because it
/// means the CVE is being exploited.
struct SourceBadges: View {
    let records: [SourceRecord]

    var body: some View {
        HStack(spacing: 3) {
            ForEach(records, id: \.self) { record in
                let exploited = record.source == .kev
                Text(record.source.name)
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(exploited ? Color.red : Color.secondary)
                    .padding(.horizontal, 4)
                    .padding(.vertical, 1)
                    .background(
                        exploited ? Color.red.opacity(0.12) : Color.secondary.opacity(0.1),
                        in: RoundedRectangle(cornerRadius: 3)
                    )
                    .help(record.note.map { "\(record.source.fullName): \($0)" } ?? record.source.fullName)
            }
        }
        .fixedSize()
    }
}

/// One database's entry in a finding's details: a link to it, its own IDs and any note.
private struct DatabaseLine: View {
    let cveID: String
    let record: SourceRecord

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 6) {
                if let url = URL(string: record.url) {
                    Link(record.source.fullName, destination: url).help(record.url)
                } else {
                    Text(record.source.fullName)
                }
                ForEach(record.ids, id: \.self) { id in
                    if let url = Self.link(for: id) {
                        Link(id, destination: url).font(.callout.monospaced())
                    } else {
                        Text(id).font(.callout.monospaced()).foregroundStyle(.secondary)
                    }
                }
            }
            if let note = record.note {
                Text(note)
                    .foregroundStyle(record.source == .kev ? Color.red : Color.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    /// GitHub Advisory IDs link to GitHub; EUVD IDs to ENISA.
    static func link(for id: String) -> URL? {
        if id.hasPrefix("GHSA-") { return URL(string: "https://github.com/advisories/\(id)") }
        if id.hasPrefix("EUVD-") { return URL(string: "https://euvd.enisa.europa.eu/vulnerability/\(id)") }
        return nil
    }
}

private struct DetailSection<Content: View>: View {
    let title: String
    let systemImage: String
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label(title, systemImage: systemImage)
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(.secondary)
            content
        }
    }
}

extension Severity {
    var color: Color {
        switch self {
        case .critical: return .red
        case .high: return .orange
        case .medium: return .yellow
        case .low: return .gray
        case .unscored: return .purple
        }
    }
}

/// Severity chips, fix-source menu and major-upgrade toggle above the CVE list.
private struct FilterBar: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        HStack(spacing: 14) {
            HStack(spacing: 6) {
                ForEach(model.severitiesFound, id: \.self) { level in
                    SeverityChip(level: level, on: isShown(level)) { toggle(level) }
                }
            }

            HStack(spacing: 6) {
                Text("Fix")
                Menu {
                    Toggle("All fixes", isOn: isFixedBy(nil))
                    Divider()
                    ForEach(FixKind.allCases.filter { $0 != FixKind.none || model.showUnfixed }) { kind in
                        Toggle(kind.rawValue, isOn: isFixedBy(kind))
                    }
                } label: {
                    Text(model.fixFilter?.rawValue ?? "All fixes")
                }
                .fixedSize()
                .help("Filter by fix source")
            }

            Toggle("Hide major macOS upgrades", isOn: $model.hideMajorUpgrades)
                .toggleStyle(.checkbox)
                .disabled(!model.findings.contains(where: \.isMajorUpgrade))
                .help("Hide CVEs whose only fix is a new major version of macOS")

            Spacer()
            if model.filtersActive {
                Button("Clear Filters") { model.clearFilters() }.buttonStyle(.link)
            }
        }
        .font(.callout)
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        .background(.bar)
    }

    private func isShown(_ s: Severity) -> Bool { model.severityFilter.isEmpty || model.severityFilter.contains(s) }

    /// Checkmark state for the fix-source menu.
    private func isFixedBy(_ kind: FixKind?) -> Binding<Bool> {
        Binding(
            get: { model.fixFilter == kind },
            set: { if $0 { model.fixFilter = kind } }
        )
    }

    /// Chips start all on; clicking hides or shows a level, and the last shown level can't be hidden.
    private func toggle(_ s: Severity) {
        var shown = model.severityFilter.isEmpty ? Set(model.severitiesFound) : model.severityFilter
        if shown.contains(s) { shown.remove(s) } else { shown.insert(s) }
        guard !shown.isEmpty else { return }
        model.severityFilter = shown == Set(model.severitiesFound) ? [] : shown
    }
}

private struct SeverityChip: View {
    let level: Severity
    let on: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 5) {
                Circle().fill(on ? level.color : Color.secondary.opacity(0.4)).frame(width: 7, height: 7)
                Text(level.label)
            }
            .padding(.horizontal, 9)
            .padding(.vertical, 3)
            .foregroundStyle(on ? Color.primary : Color.secondary)
            .background(on ? level.color.opacity(0.18) : Color.clear, in: Capsule())
            .overlay(Capsule().stroke(on ? level.color.opacity(0.6) : Color.secondary.opacity(0.35)))
        }
        .buttonStyle(.plain)
        // Keep each chip on one line when the window is narrow.
        .fixedSize()
        .help(on ? "Hide \(level.label.lowercased()) CVEs" : "Show \(level.label.lowercased()) CVEs")
    }
}
