// swift-tools-version: 5.7
import PackageDescription

let package = Package(
    name: "Elecrypto",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15)
    ],
    products: [
        .library(
            name: "Elecrypto",
            targets: ["Elecrypto"]),
    ],
    targets: [
        .target(
            name: "Elecrypto",
            dependencies: [],
            linkerSettings: [
                .linkedLibrary("elecrypto_core")
            ]
        ),
        .testTarget(
            name: "ElecryptoTests",
            dependencies: ["Elecrypto"]),
    ]
)
