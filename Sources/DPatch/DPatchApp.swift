import AppKit
import SwiftUI

@main
enum Main {
    static func main() {
        if CommandLine.arguments.contains("--scan") {
            exit(Scanner.runHeadless())
        }
        #if DEBUG
        if let i = CommandLine.arguments.firstIndex(of: "--snapshot"), i + 1 < CommandLine.arguments.count {
            MainActor.assumeIsolated { Snapshot.render(to: CommandLine.arguments[i + 1]) }
            exit(0)
        }
        #endif
        if CommandLine.arguments.contains("--script") {
            // Script for every finding of the last scan, e.g. `DPatch --script > patch.sh`.
            guard let r = Storage.load(ScanResult.self, from: Storage.resultsURL) else {
                FileHandle.standardError.write(Data("No scan results yet; run with --scan first.\n".utf8))
                exit(1)
            }
            let unattended = CommandLine.arguments.contains("--no-confirm")
            print(ScriptGenerator.script(for: r.findings, confirm: !unattended,
                                         rescan: unattended ? Bundle.main.executablePath : nil), terminator: "")
            exit(0)
        }
        DPatchApp.main()
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
        // Keep the scheduled scan pointing at this copy of the app if it was moved.
        if Scheduler.needsRepair { try? Scheduler.apply() }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}

struct DPatchApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate
    @StateObject private var model = AppModel()

    var body: some Scene {
        Window("D-Patch", id: "main") {
            ContentView()
                .environmentObject(model)
                .frame(minWidth: 900, minHeight: 560)
        }
        .commands {
            CommandGroup(after: .newItem) {
                Button("Scan Now") { model.scan() }
                    .keyboardShortcut("r")
                    .disabled(model.isScanning)
            }
        }

        Settings {
            SettingsView()
        }
    }
}
