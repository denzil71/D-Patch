import Foundation

enum Shell {
    struct Output {
        var status: Int32
        var stdout: Data
        var stderr: String
        var text: String { String(decoding: stdout, as: UTF8.self) }
    }

    /// Runs a program and waits for it, killing it after `timeout` seconds.
    static func run(_ path: String, _ args: [String], timeout: TimeInterval = 300) async throws -> Output {
        try await withCheckedThrowingContinuation { cont in
            DispatchQueue.global().async {
                let p = Process()
                p.executableURL = URL(fileURLWithPath: path)
                p.arguments = args
                var env = ProcessInfo.processInfo.environment
                env["PATH"] = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
                env["HOMEBREW_NO_AUTO_UPDATE"] = "1"
                env["HOMEBREW_NO_ENV_HINTS"] = "1"
                p.environment = env
                let out = Pipe(), err = Pipe()
                p.standardOutput = out
                p.standardError = err
                do { try p.run() } catch { cont.resume(throwing: error); return }

                let timer = DispatchWorkItem { if p.isRunning { p.terminate() } }
                DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: timer)
                // Read before waiting so a large output cannot fill the pipe and block the child.
                var outData = Data(), errData = Data()
                let group = DispatchGroup()
                group.enter()
                DispatchQueue.global().async { outData = out.fileHandleForReading.readDataToEndOfFile(); group.leave() }
                errData = err.fileHandleForReading.readDataToEndOfFile()
                group.wait()
                p.waitUntilExit()
                timer.cancel()
                cont.resume(returning: Output(status: p.terminationStatus, stdout: outData,
                                              stderr: String(decoding: errData, as: UTF8.self)))
            }
        }
    }

    static var brewPath: String? {
        ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"].first { FileManager.default.isExecutableFile(atPath: $0) }
    }
}
