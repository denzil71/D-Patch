import SwiftUI

struct ContentView: View {
    @EnvironmentObject var model: AppModel
    @State private var script: GeneratedScript?

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
                    script = GeneratedScript(text: ScriptGenerator.script(for: model.checkedFindings))
                } label: {
                    Label(model.checked.isEmpty ? "Generate" : "Generate (\(model.checked.count))",
                          systemImage: "terminal")
                        .labelStyle(.titleAndIcon)
                }
                .buttonStyle(.borderedProminent)
                .disabled(model.checked.isEmpty)
                .help("Create a bash script that installs the fixes for the ticked CVEs")
            }
        }
        .safeAreaInset(edge: .bottom) { StatusBar() }
        .sheet(item: $script) { ScriptSheet(script: $0) }
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
                    CountBadges(critical: model.days.map(\.critical).reduce(0, +),
                                high: model.days.map(\.high).reduce(0, +))
                }
                .tag(DayFilter.all)
            }
            Section("Published") {
                ForEach(model.days) { d in
                    HStack {
                        Text(d.day, format: .dateTime.weekday(.abbreviated).day().month(.abbreviated).year())
                        Spacer()
                        CountBadges(critical: d.critical, high: d.high)
                    }
                    .tag(DayFilter.day(d.day))
                }
            }
        }
        .listStyle(.sidebar)
    }
}

struct CountBadges: View {
    var critical: Int
    var high: Int

    var body: some View {
        HStack(spacing: 4) {
            if critical > 0 { Badge(text: "\(critical)", color: .red).help("\(critical) critical") }
            if high > 0 { Badge(text: "\(high)", color: .orange).help("\(high) high") }
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
                Text("Last scan \(r.scannedAt.formatted(date: .abbreviated, time: .shortened)) · \(r.itemsChecked) installed items · \(r.cvesChecked) critical/high CVEs from the last \(r.lookbackDays) days")
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
