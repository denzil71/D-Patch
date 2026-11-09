// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "DPatch",
    platforms: [.macOS(.v14)],
    dependencies: [
        .package(url: "https://github.com/appstefan/HighlightSwift.git", from: "1.1.0")
    ],
    targets: [
        .executableTarget(name: "DPatch", dependencies: ["HighlightSwift"], path: "Sources/DPatch"),
        .testTarget(name: "DPatchTests", dependencies: ["DPatch"], path: "Tests/DPatchTests"),
    ]
)
