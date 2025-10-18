// swift-tools-version:5.5
// The swift-tools-version declares the minimum version of Swift required to build this package.
// Swift Package: VaneSwift

import Foundation
import PackageDescription

let includeAlamofire = ProcessInfo.processInfo.environment["INCLUDE_ALAMOFIRE"] == "1"

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
    dependencies: includeAlamofire
        ? [
            .package(url: "https://github.com/Alamofire/Alamofire.git", from: "5.8.0")
        ] : [],
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
        .testTarget(
            name: "VaneSwiftTests",
            dependencies: includeAlamofire
                ? [
                    "VaneSwift",
                    .product(name: "Alamofire", package: "Alamofire"),
                ]
                : [
                    "VaneSwift"
                ]
        ),
    ]
)
