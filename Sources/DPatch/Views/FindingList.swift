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
                List {
                    Section {
                        ForEach(visible) { FindingRow(finding: $0) }
                    } header: {
                        ListHeader(visible: visible)
                    }
                }
                .listStyle(.inset)
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
        .padding(.vertical, 4)
    }
}

struct FindingRow: View {
    @EnvironmentObject var model: AppModel
    let finding: Finding
    @State private var expanded = false

    var body: some View {
        let cve = finding.cve
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Toggle("", isOn: Binding(get: { model.checked.contains(finding.id) }, set: { _ in model.toggle(finding) }))
                .toggleStyle(.checkbox)
                .labelsHidden()
            DisclosureGroup(isExpanded: $expanded) {
                FindingDetail(finding: finding)
                    .padding(.top, 6)
                    .padding(.bottom, 4)
            } label: {
                HStack(alignment: .firstTextBaseline, spacing: 10) {
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
                .onTapGesture { withAnimation { expanded.toggle() } }
            }
        }
        .padding(.vertical, 2)
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
        VStack(alignment: .leading, spacing: 10) {
            Text(cve.summary)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)

            Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 12, verticalSpacing: 4) {
                row("Published", cve.published.formatted(date: .long, time: .shortened))
                row("Installed", "\(finding.item.name) \(finding.item.version)" + (finding.item.path.map { " — \($0)" } ?? ""))
                row("Fixed in", finding.fixedIn)
                GridRow {
                    Text("Fix").foregroundStyle(.secondary)
                    Text(finding.fix.summary).fontWeight(.medium).foregroundStyle(.green)
                }
                if !cve.vector.isEmpty { row("CVSS", cve.vector) }
            }
            .font(.callout)

            HStack(spacing: 14) {
                Link("NVD entry", destination: URL(string: "https://nvd.nist.gov/vuln/detail/\(cve.id)")!)
                ForEach(Array(cve.references.prefix(4).enumerated()), id: \.offset) { _, ref in
                    if let url = URL(string: ref) {
                        Link(url.host() ?? ref, destination: url).lineLimit(1)
                    }
                }
            }
            .font(.callout)
        }
    }

    private func row(_ label: String, _ value: String) -> some View {
        GridRow {
            Text(label).foregroundStyle(.secondary)
            Text(value).textSelection(.enabled)
        }
    }
}
