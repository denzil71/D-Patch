import AppKit
import HighlightSwift
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
    @Environment(\.colorScheme) private var colorScheme
    @State private var showScript: Bool
    @State private var launched: URL?
    @State private var savedTo: URL?
    /// The script with its bash colours, highlighted as soon as the sheet opens so the Script
    /// section never appears plain first and then fades the colours in.
    @State private var scriptText: AttributedString?

    init(request: PatchRequest, showScript: Bool = false, onLaunched: @escaping () -> Void = {}) {
        self.request = request
        self.onLaunched = onLaunched
        _showScript = State(initialValue: showScript)
    }

    private var fixes: [Fix] { ScriptGenerator.fixes(for: request.findings) }
    private var cveCount: Int { Set(request.findings.map(\.cve.id)).count }
    private var displayScript: String {
        ScriptGenerator.script(for: request.findings, confirm: false, rescan: Bundle.main.executablePath)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Patch selected CVEs").font(.title2.weight(.semibold))

            if let url = launched {
                Label("Patching in Terminal", systemImage: "terminal").font(.headline)
                Text(
                    "Follow the progress in the Terminal window. When it finishes, D-Patch rescans and this list updates by itself.\n\nScript: \(url.path)"
                )
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
            } else {
                Text(
                    "\(fixes.count) update\(fixes.count == 1 ? "" : "s") will close \(cveCount) CVE\(cveCount == 1 ? "" : "s"):"
                )
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(fixes, id: \.self) { fix in
                        Label(fix.summary, systemImage: icon(fix.method))
                        if let notes = fix.notesLink {
                            Link(
                                "Read \(notes.title.replacingOccurrences(of: "Apple: ", with: "Apple's notes: "))",
                                destination: notes.url
                            )
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

                // A custom disclosure rather than DisclosureGroup: the group gives its content an
                // unbounded height, so the script's ScrollView could not fill the sheet.
                Button {
                    withAnimation(.easeInOut(duration: 0.2)) { showScript.toggle() }
                } label: {
                    HStack(spacing: 6) {
                        Image(systemName: "chevron.right")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.secondary)
                            .rotationEffect(.degrees(showScript ? 90 : 0))
                        Text("Script")
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .help(showScript ? "Hide the script" : "Show the script")

                if showScript {
                    VStack(alignment: .leading, spacing: 8) {
                        ScriptSteps(steps: ScriptGenerator.steps(for: request.findings, rescan: true))
                        ScrollView {
                            Text(scriptText ?? AttributedString(displayScript))
                                .font(.system(.callout, design: .monospaced))
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .padding(10)
                        }
                        .frame(maxHeight: .infinity)
                        .background(Color(nsColor: .textBackgroundColor))
                        .clipShape(RoundedRectangle(cornerRadius: 6))
                        .overlay(RoundedRectangle(cornerRadius: 6).stroke(.separator))
                    }
                }

                if let url = savedTo {
                    Label("Saved to \(url.path)", systemImage: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                        .textSelection(.enabled)
                }
            }

            // When the script is open its ScrollView takes the spare height instead.
            if !showScript || launched != nil {
                Spacer(minLength: 0)
            }
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
        .frame(width: sheetWidth, height: sheetHeight)
        .background(NoInitialFocus())
        .task(id: "\(colorScheme == .dark)-\(displayScript)") {
            scriptText = await ScriptHighlighter.attributed(script: displayScript, dark: colorScheme == .dark)
        }
    }

    /// Use most of the screen: the script is the main thing to read in this sheet.
    private var sheetWidth: CGFloat {
        let available = NSScreen.main?.visibleFrame.width ?? 1200
        return min(1000, max(700, available - 100))
    }

    /// Three quarters of the parent window, so the script needs as little scrolling as possible.
    /// The sheet is tall even while the script is closed: macOS does not resize an already
    /// presented sheet when its content grows, so changing this when Script is toggled would clip
    /// the expanded content.
    private var sheetHeight: CGFloat {
        let parent = NSApp.windows
            .filter { !$0.isSheet && $0.isVisible }
            .max { $0.frame.height < $1.frame.height }
        let parentHeight = parent?.frame.height ?? (NSScreen.main?.visibleFrame.height ?? 900)
        let screenMax = ((parent?.screen ?? NSScreen.main)?.visibleFrame.height ?? parentHeight) - 40
        return min(max(parentHeight * 0.75, 520), screenMax)
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
            NSAlert(
                error: NSError(
                    domain: "D-Patch", code: 1,
                    userInfo: [
                        NSLocalizedDescriptionKey:
                            "Could not open Terminal. Run the script yourself: bash \(ScriptGenerator.shellQuote(url.path))"
                    ])
            ).runModal()
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

/// Clears the sheet's initial keyboard focus. SwiftUI focuses the first focusable control when a
/// sheet opens, which draws a focus ring on a button the user did not choose.
private struct NoInitialFocus: NSViewRepresentable {
    func makeNSView(context _: Context) -> NoInitialFocusView { NoInitialFocusView() }
    func updateNSView(_: NoInitialFocusView, context _: Context) {}
}

private final class NoInitialFocusView: NSView {
    private var observer: NSObjectProtocol?

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        if let observer {
            NotificationCenter.default.removeObserver(observer)
            self.observer = nil
        }
        guard let window else { return }
        window.initialFirstResponder = nil
        clearFocus()
        observer = NotificationCenter.default.addObserver(
            forName: NSWindow.didBecomeKeyNotification,
            object: window,
            queue: .main
        ) { [weak self] _ in
            self?.clearFocus()
        }
    }

    override func hitTest(_: NSPoint) -> NSView? { nil }

    private func clearFocus() {
        DispatchQueue.main.async { [weak self] in
            self?.window?.makeFirstResponder(nil)
        }
    }

    deinit {
        if let observer { NotificationCenter.default.removeObserver(observer) }
    }
}

/// Highlights the patch script in bash colours for the current appearance. HighlightSwift's own
/// `CodeText` view highlights only after it appears, so expanding the Script section first showed
/// plain text and then faded the colours in; the sheet highlights up front instead and the
/// section renders coloured on its first frame.
private enum ScriptHighlighter {
    private static let highlight = Highlight()

    static func attributed(script: String, dark: Bool) async -> AttributedString? {
        try? await highlight.attributedText(
            script, language: .bash,
            colors: dark ? .dark(.xcode) : .light(.xcode))
    }
}
