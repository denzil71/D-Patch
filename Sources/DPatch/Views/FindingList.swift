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
                    Text("D-Patch checks the software on this Mac against critical and high CVEs and lists the ones with an available fix.")
                } actions: {
                    Button("Scan Now") { model.scan() }.disabled(model.isScanning)
                }
            } else if visible.isEmpty {
                ContentUnavailableView(model.search.isEmpty ? "Nothing to patch" : "No matches",
                                       systemImage: model.search.isEmpty ? "checkmark.shield" : "magnifyingglass",
                                       description: Text(model.search.isEmpty
                                                         ? "No fixable critical or high CVEs affect this Mac."
                                                         : "No CVEs match “\(model.search)”."))
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
        .navigationTitle(title)
    }

    private var title: String {
        if case .day(let d)? = model.filter {
            return d.formatted(date: .complete, time: .omitted)
        }
        return "All CVEs"
    }
}

private struct ListHeader: View {
    @EnvironmentObject var model: AppModel
    var visible: [Finding]

    var body: some View {
        let allOn = visible.allSatisfy { model.checked.contains($0.id) }
        HStack {
            Toggle(isOn: Binding(get: { allOn }, set: { model.setAllVisible($0) })) {
                Text("\(visible.count) fixable CVE\(visible.count == 1 ? "" : "s")")
            }
            .toggleStyle(.checkbox)
            Spacer()
            if !model.checked.isEmpty {
                Text("\(model.checked.count) ticked")
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
                Toggle("", isOn: Binding(get: { model.checked.contains(finding.id) }, set: { _ in model.toggle(finding) }))
                    .toggleStyle(.checkbox)
                    .labelsHidden()
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
                        Text("\(finding.item.name) \(finding.item.version)")
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                        Spacer(minLength: 8)
                        Text("→ \(FixResolver.plain(finding.fix.toVersion))")
                            .font(.callout.monospacedDigit())
                            .foregroundStyle(.green)
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
                    .transition(.opacity.combined(with: .move(edge: .top)))
            }
        }
        .padding(.vertical, 6)
    }
}
struct SeverityTag: View {
    var severity: Severity
    var score: Double

    var body: some View {
        Text("\(severity == .critical ? "CRITICAL" : "HIGH") \(score, specifier: "%.1f")")
            .font(.caption.weight(.bold).monospacedDigit())
            .foregroundStyle(severity == .critical ? Color.red : Color.orange)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background((severity == .critical ? Color.red : Color.orange).opacity(0.12), in: RoundedRectangle(cornerRadius: 4))
            .frame(width: 104, alignment: .leading)
    }
}

struct FindingDetail: View {
    let finding: Finding

    var body: some View {
        let cve = finding.cve
        let command = ScriptGenerator.command(for: finding.fix)
        VStack(alignment: .leading, spacing: 14) {
            DetailSection(title: "Overview", systemImage: "info.circle") {
                Text(cve.summary.isEmpty ? "No description published." : cve.summary)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 12, verticalSpacing: 4) {
                    row("Severity", "\(cve.severity.rawValue.capitalized) — CVSS \(String(format: "%.1f", cve.score))")
                    if !cve.vector.isEmpty { row("Vector", cve.vector) }
                    row("Published", cve.published.formatted(date: .long, time: .shortened))
                    row("Affects", "\(finding.item.name) \(finding.item.version)" + (finding.item.path.map { " — \($0)" } ?? ""))
                    row("Fixed in", finding.fixedIn)
                }
                .font(.callout)
            }

            DetailSection(title: "How to fix", systemImage: "wrench.and.screwdriver") {
                Text(finding.fix.summary).fontWeight(.medium)
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
                Text(LocalizedStringKey(note))
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            DetailSection(title: "References", systemImage: "link") {
                VStack(alignment: .leading, spacing: 3) {
                    Link("NVD — \(cve.id)", destination: URL(string: "https://nvd.nist.gov/vuln/detail/\(cve.id)")!)
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

    private var note: String {
        switch finding.fix.method {
        case .brewFormula:
            return "Upgrades the Homebrew formula to \(finding.fix.toVersion). Run `brew update` first so Homebrew knows about the latest version."
        case .brewCask:
            return "Upgrades the Homebrew-managed app to \(FixResolver.plain(finding.fix.toVersion)). Quit the app first."
        case .brewCaskReplace:
            return "This app was installed outside Homebrew. The command installs the Homebrew cask (\(FixResolver.plain(finding.fix.toVersion))) over it, after which Homebrew manages its updates. Quit the app first."
        case .appStore:
            return "Updates the app from the Mac App Store using the `mas` tool (`brew install mas`); you must be signed in to the App Store. You can also update it in App Store › Updates."
        case .softwareUpdate:
            return "Installs the Apple update. It needs an administrator password and may restart the Mac. You can also install it from System Settings › General › Software Update."
        }
    }

    private func row(_ label: String, _ value: String) -> some View {
        GridRow {
            Text(label).foregroundStyle(.secondary)
            Text(value).textSelection(.enabled)
        }
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
