import Foundation
import Testing

@testable import DPatch

@Suite struct ScriptHighlighterTests {
    /// Makes an empty directory and all intermediate directories.
    private func make(_ path: URL) throws {
        try FileManager.default.createDirectory(at: path, withIntermediateDirectories: true)
    }

    /// Writes an empty highlight.min.js into `bundle`, in either the nested (Contents/Resources)
    /// or flat layout.
    private func addHighlightJS(_ bundle: URL, nested: Bool) throws {
        let path =
            nested
            ? bundle.appendingPathComponent("Contents/Resources/highlight.min.js")
            : bundle.appendingPathComponent("highlight.min.js")
        try make(path.deletingLastPathComponent())
        FileManager.default.createFile(atPath: path.path, contents: Data())
    }

    @Test func findsTheResourceInANestedBundle() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        try addHighlightJS(directory.appendingPathComponent("HighlightSwift_HighlightSwift.bundle"), nested: true)

        #expect(ScriptHighlighter.highlightJSReachable(in: [directory]))
    }

    @Test func findsTheResourceInAFlatBundle() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        try addHighlightJS(directory.appendingPathComponent("HighlightSwift_HighlightSwift.bundle"), nested: false)

        #expect(ScriptHighlighter.highlightJSReachable(in: [directory]))
    }

    @Test func searchesEveryDirectory() throws {
        let empty = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer {
            try? FileManager.default.removeItem(at: empty)
            try? FileManager.default.removeItem(at: directory)
        }
        try make(empty)
        try addHighlightJS(directory.appendingPathComponent("HighlightSwift_HighlightSwift.bundle"), nested: true)

        #expect(ScriptHighlighter.highlightJSReachable(in: [empty, directory]))
    }

    @Test func rejectsBundlesWithoutTheResource() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        try make(directory.appendingPathComponent("HighlightSwift_HighlightSwift.bundle"))

        #expect(!ScriptHighlighter.highlightJSReachable(in: [directory]))
    }

    @Test func rejectsMissingAndUnreadableDirectories() throws {
        let missing = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        #expect(!ScriptHighlighter.highlightJSReachable(in: [missing]))
    }
}
