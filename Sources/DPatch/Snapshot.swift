#if DEBUG
import AppKit
import SwiftUI

/// Debug builds only: `DPatch --snapshot out.png [--expand N]` renders the main window offscreen
/// from the saved results, with the Nth finding (default 0) expanded, to check layout without a screen.
/// `--patch-sheet` renders the Patch sheet for every finding instead.
enum Snapshot {
    @MainActor
    static func render(to path: String) {
        _ = NSApplication.shared
        let model = AppModel()
        let args = CommandLine.arguments
        let index = args.firstIndex(of: "--expand").flatMap { Int(args[safe: $0 + 1] ?? "") } ?? 0
        if let f = model.visible[safe: index] { model.expanded.insert(f.id) }

        let size = NSSize(width: 1100, height: 760)
        let root: AnyView = args.contains("--patch-sheet")
            ? AnyView(PatchSheet(request: PatchRequest(findings: model.findings)).frame(width: 680, height: 560)
                .background(Color(nsColor: .windowBackgroundColor)))
            : AnyView(ContentView().environmentObject(model).frame(width: size.width, height: size.height))
        let host = NSHostingView(rootView: root)
        let window = NSWindow(contentRect: NSRect(origin: .zero, size: size), styleMask: [.titled], backing: .buffered, defer: false)
        window.contentView = host
        host.layoutSubtreeIfNeeded()
        RunLoop.main.run(until: Date().addingTimeInterval(1.0))
        host.layoutSubtreeIfNeeded()

        guard let rep = host.bitmapImageRepForCachingDisplay(in: host.bounds) else { return }
        host.cacheDisplay(in: host.bounds, to: rep)
        try? rep.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: path))
        print("Wrote \(path)")
    }
}

private extension Array {
    subscript(safe i: Int) -> Element? { indices.contains(i) ? self[i] : nil }
}
#endif
