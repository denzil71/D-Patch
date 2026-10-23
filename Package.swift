// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "DPatch",
    platforms: [.macOS(.v14)],
    targets: [
        .executableTarget(name: "DPatch", path: "Sources/DPatch")
    ]
)
