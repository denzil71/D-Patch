import AppKit
import SwiftUI
import UniformTypeIdentifiers

struct GeneratedScript: Identifiable {
    let id = UUID()
    let text: String
}

struct ScriptSheet: View {
    let script: GeneratedScript
    @Environment(\.dismiss) private var dismiss
    @State private var savedTo: URL?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Patch script").font(.title2.weight(.semibold))
            Text("Review the script, then save it and run it in Terminal. It asks for confirmation before changing anything; Apple updates ask for your administrator password.")
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            ScrollView {
                Text(script.text)
                    .font(.system(.callout, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(10)
            }
            .background(Color(nsColor: .textBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 6))
            .overlay(RoundedRectangle(cornerRadius: 6).stroke(.separator))

            if let url = savedTo {
                HStack {
                    Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                    Text("Saved to \(url.path). Run it with: bash \(ScriptGenerator.shellQuote(url.path))")
                        .textSelection(.enabled)
                    Button("Show in Finder") { NSWorkspace.shared.activateFileViewerSelecting([url]) }
                        .buttonStyle(.link)
                }
                .font(.callout)
            }

            HStack {
                Button("Copy") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(script.text, forType: .string)
                }
                Spacer()
                Button("Close") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Save…") { save() }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(minWidth: 720, idealWidth: 780, minHeight: 520, idealHeight: 600)
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
            try script.text.write(to: url, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
            savedTo = url
        } catch {
            NSAlert(error: error).runModal()
        }
    }
}
