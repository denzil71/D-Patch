import AppKit
import SwiftUI
import UniformTypeIdentifiers

struct PatchRequest: Identifiable {
    let id = UUID()
    let findings: [Finding]
}

/// Confirms the ticked fixes, then runs them in Terminal (or saves them as a script).
struct PatchSheet: View {
    let request: PatchRequest
    var onLaunched: () -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var showScript: Bool
    @State private var launched: URL?
    @State private var savedTo: URL?

    init(request: PatchRequest, showScript: Bool = false, onLaunched: @escaping () -> Void = {}) {
        self.request = request
        self.onLaunched = onLaunched
        _showScript = State(initialValue: showScript)
    }

    private var fixes: [Fix] { ScriptGenerator.fixes(for: request.findings) }
    private var cveCount: Int { Set(request.findings.map(\.cve.id)).count }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Patch selected CVEs").font(.title2.weight(.semibold))

            if let url = launched {
                Label("Patching in Terminal", systemImage: "terminal").font(.headline)
                Text("Follow the progress in the Terminal window. When it finishes, D-Patch rescans and this list updates by itself.\n\nScript: \(url.path)")
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                Text("\(fixes.count) update\(fixes.count == 1 ? "" : "s") will close \(cveCount) CVE\(cveCount == 1 ? "" : "s"):")
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(fixes, id: \.self) { fix in
                        Label(fix.summary, systemImage: icon(fix.method))
                        if let notes = fix.notesLink {
                            Link("Read \(notes.title.replacingOccurrences(of: "Apple: ", with: "Apple's notes: "))",
                                 destination: notes.url)
                                .font(.callout)
                                .padding(.leading, 28)
                                .help(notes.url.absoluteString)
                        }
                    }
                }
                .padding(.leading, 4)

                ForEach(notes, id: \.self) { note in
                    Label(note, systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }

                DisclosureGroup("Script", isExpanded: $showScript) {
                    ScriptSteps(steps: ScriptGenerator.steps(for: request.findings, rescan: true))
                        .padding(.vertical, 8)
                    ScrollView {
                        Text(ScriptGenerator.script(for: request.findings, confirm: false, rescan: Bundle.main.executablePath))
                            .font(.system(.callout, design: .monospaced))
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(10)
                    }
                    .frame(height: 260)
                    .background(Color(nsColor: .textBackgroundColor))
                    .clipShape(RoundedRectangle(cornerRadius: 6))
                    .overlay(RoundedRectangle(cornerRadius: 6).stroke(.separator))
                }

                if let url = savedTo {
                    Label("Saved to \(url.path)", systemImage: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                        .textSelection(.enabled)
                }
            }

            Spacer(minLength: 0)
            HStack {
                if launched == nil {
                    Button("Save Script…") { save() }
                }
                Spacer()
                if launched == nil {
                    Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                    Button("Patch Now") { patch() }
                        .keyboardShortcut(.defaultAction)
                        .disabled(fixes.isEmpty)
                } else {
                    Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
                }
            }
        }
        .padding(20)
        .frame(width: 680)
        .frame(minHeight: 300)
    }

    private var notes: [String] {
        var n: [String] = []
        if fixes.contains(where: { [.brewCask, .brewCaskReplace].contains($0.method) }) {
            n.append("Quit the apps being updated first.")
        }
        if fixes.contains(where: { $0.method == .softwareUpdate }) {
            n.append("Apple updates ask for your administrator password in Terminal and may need a restart.")
        }
        if fixes.contains(where: { $0.method == .softwareUpdate && $0.summary.contains("major macOS upgrade") }) {
            n.append("This includes a major macOS upgrade. Untick those CVEs to stay on your current macOS version.")
        }
        if fixes.contains(where: { $0.method == .appStore }) {
            n.append("App Store updates need you to be signed in to the App Store.")
        }
        return n
    }

    private func icon(_ m: FixMethod) -> String {
        switch m {
        case .brewFormula, .brewCask, .brewCaskReplace: return "mug"
        case .appStore: return "bag"
        case .softwareUpdate: return "apple.logo"
        }
    }

    /// Writes the script as a .command file, which macOS opens and runs in the user's terminal app.
    private func patch() {
        let dir = Storage.base.appendingPathComponent("runs")
        let df = DateFormatter()
        df.dateFormat = "yyyyMMdd-HHmmss"
        let url = dir.appendingPathComponent("d-patch-\(df.string(from: Date())).command")
        do {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            let text = ScriptGenerator.script(for: request.findings, confirm: false, rescan: Bundle.main.executablePath)
            try text.write(to: url, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
        } catch {
            NSAlert(error: error).runModal()
            return
        }
        guard NSWorkspace.shared.open(url) else {
            NSAlert(error: NSError(domain: "D-Patch", code: 1, userInfo: [NSLocalizedDescriptionKey:
                "Could not open Terminal. Run the script yourself: bash \(ScriptGenerator.shellQuote(url.path))"])).runModal()
            return
        }
        launched = url
        onLaunched()
    }

    private func save() {
        let panel = NSSavePanel()
        let df = DateFormatter()
        df.dateFormat = "yyyyMMdd-HHmm"
        panel.nameFieldStringValue = "d-patch-\(df.string(from: Date())).sh"
        panel.directoryURL = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first
        panel.allowedContentTypes = [UTType(filenameExtension: "sh") ?? .shellScript]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try ScriptGenerator.script(for: request.findings).write(to: url, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
            savedTo = url
        } catch {
            NSAlert(error: error).runModal()
        }
    }
}

/// Plain-English summary of what the script does: a sentence for one step, a numbered list for more.
private struct ScriptSteps: View {
    let steps: [String]

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            if steps.count == 1 {
                Text("When it runs, this script will \(lowercasedFirst(steps[0]))")
            } else {
                Text("When it runs, this script will:")
                ForEach(Array(steps.enumerated()), id: \.offset) { i, step in
                    HStack(alignment: .firstTextBaseline, spacing: 6) {
                        Text("\(i + 1).").monospacedDigit().foregroundStyle(.secondary)
                            .frame(width: 20, alignment: .trailing)
                        Text(LocalizedStringKey(step))
                    }
                }
            }
        }
        .fixedSize(horizontal: false, vertical: true)
    }

    private func lowercasedFirst(_ s: String) -> LocalizedStringKey {
        LocalizedStringKey(s.prefix(1).lowercased() + s.dropFirst())
    }
}
