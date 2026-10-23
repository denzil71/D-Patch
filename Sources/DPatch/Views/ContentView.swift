import SwiftUI

struct ContentView: View {
    @EnvironmentObject var model: AppModel
    @State private var patch: PatchRequest?

    var body: some View {
        NavigationSplitView {
            DateSidebar()
                .navigationSplitViewColumnWidth(min: 200, ideal: 230, max: 320)
        } detail: {
            FindingList()
                .searchable(text: $model.search, placement: .toolbar, prompt: "CVE, app or keyword")
        }
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                Button {
                    model.scan()
                } label: {
                    Label("Scan", systemImage: "arrow.clockwise")
                }
                .disabled(model.isScanning)
                .help("Scan this Mac against the CVE database (⌘R)")

                Button {
                    patch = PatchRequest(findings: model.checkedFindings)
                } label: {
                    Label(model.checked.isEmpty ? "Patch Selected" : "Patch Selected (\(model.checked.count))",
                          systemImage: "bandage")
                        .labelStyle(.titleAndIcon)
                }
                .buttonStyle(.borderedProminent)
                .disabled(model.checked.isEmpty)
                .help("Download and install the fixes for the ticked CVEs")
            }
        }
        .safeAreaInset(edge: .bottom) { StatusBar() }
        .sheet(item: $patch) { PatchSheet(request: $0) { model.checked.removeAll() } }
        .alert("Scan failed", isPresented: Binding(get: { model.errorMessage != nil },
                                                   set: { if !$0 { model.errorMessage = nil } })) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(model.errorMessage ?? "")
        }
    }
}

struct DateSidebar: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        List(selection: $model.filter) {
            Section {
                HStack {
                    Label("All dates", systemImage: "calendar")
                    Spacer()
                    CountBadges(counts: model.days.reduce(into: [:]) { total, d in
                        total.merge(d.counts, uniquingKeysWith: +)
                    })
                }
                .tag(DayFilter.all)
            }
            Section("Published") {
                ForEach(model.days) { d in
                    HStack {
                        Text(d.day, format: .dateTime.weekday(.abbreviated).day().month(.abbreviated).year())
                        Spacer()
                        CountBadges(counts: d.counts)
                    }
                    .tag(DayFilter.day(d.day))
                }
            }
        }
        .listStyle(.sidebar)
    }
}

struct CountBadges: View {
    var counts: [Severity: Int]

    var body: some View {
        HStack(spacing: 4) {
            ForEach(Severity.allCases.reversed(), id: \.self) { s in
                if let n = counts[s], n > 0 {
                    Badge(text: "\(n)", color: s.color).help("\(n) \(s.label.lowercased())")
                }
            }
        }
    }
}

struct Badge: View {
    var text: String
    var color: Color

    var body: some View {
        Text(text)
            .font(.caption.weight(.semibold).monospacedDigit())
            .foregroundStyle(.white)
            .padding(.horizontal, 6)
            .padding(.vertical, 1)
            .background(color, in: Capsule())
    }
}

struct StatusBar: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        HStack(spacing: 8) {
            if model.isScanning {
                ProgressView().controlSize(.small)
                Text(model.status).lineLimit(1).truncationMode(.middle)
            } else if let r = model.result {
                Text("Last scan \(r.scannedAt.formatted(date: .abbreviated, time: .shortened)) · \(r.itemsChecked) installed items · \(r.cvesChecked) \((r.severities ?? Severity.defaults).map { $0.label.lowercased() }.joined(separator: "/")) CVEs from the last \(r.lookbackDays) days")
                    .lineLimit(1)
                if !r.warnings.isEmpty {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.yellow)
                        .help(r.warnings.joined(separator: "\n"))
                }
            } else {
                Text("Not scanned yet")
            }
            Spacer()
        }
        .font(.callout)
        .foregroundStyle(.secondary)
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
        .background(.bar)
    }
}
