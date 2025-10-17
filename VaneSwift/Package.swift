// swift-tools-version:5.5
// The swift-tools-version declares the minimum version of Swift required to build this package.
// Swift Package: VaneSwift

import PackageDescription

let package = Package(
    name: "VaneSwift",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15),
    ],
    products: [
        .library(
            name: "VaneSwift",
            targets: ["VaneSwift"]
        )
    ],
    dependencies: [],
    targets: [
        .binaryTarget(name: "RustFramework", path: "./RustFramework.xcframework"),
        .target(
            name: "VaneSwift",
            dependencies: [
                .target(name: "RustFramework")
            ],
            linkerSettings: [
                .linkedFramework("SystemConfiguration")
            ]
        ),
        .testTarget(name: "VaneSwiftTests", dependencies: ["VaneSwift"]),
    ]
)
