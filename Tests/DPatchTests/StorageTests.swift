import Foundation
import Testing

@testable import DPatch

@Suite struct StorageTests {
    private let standard = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        .appendingPathComponent("D-Patch")

    @Test func usesTheStandardFolderByDefault() {
        #expect(Storage.baseURL(arguments: ["DPatch"], environment: [:]) == standard)
    }

    @Test func homeArgumentWinsOverTheEnvironment() {
        let url = Storage.baseURL(arguments: ["DPatch", "--home", "/tmp/a"], environment: ["DPATCH_HOME": "/tmp/b"])
        #expect(url.path == "/tmp/a")
        #expect(Storage.baseURL(arguments: ["DPatch"], environment: ["DPATCH_HOME": "/tmp/b"]).path == "/tmp/b")
    }

    @Test func demoDataWithoutAHomeKeepsRealResultsSafe() {
        let fromArgument = Storage.baseURL(arguments: ["DPatch", "--fixtures", "/tmp/fx"], environment: [:])
        let fromEnvironment = Storage.baseURL(arguments: ["DPatch"], environment: ["DPATCH_FIXTURES": "/tmp/fx"])
        #expect(fromArgument == standard.appendingPathComponent("Demo"))
        #expect(fromEnvironment == standard.appendingPathComponent("Demo"))
    }

    @Test func demoDataWithAHomeUsesThatHome() {
        let url = Storage.baseURL(arguments: ["DPatch", "--fixtures", "/tmp/fx", "--home", "/tmp/h"], environment: [:])
        #expect(url.path == "/tmp/h")
    }
}
