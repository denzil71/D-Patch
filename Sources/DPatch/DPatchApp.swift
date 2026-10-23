import AppKit
import SwiftUI

@main
enum Main {
    static func main() {
        if CommandLine.arguments.contains("--scan") {
            exit(Scanner.runHeadless())
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
