// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "Digoxin",
    platforms: [.macOS(.v26)],
    products: [
        .library(name: "Digoxin", targets: ["Digoxin"]),
    ],
    targets: [
        .target(
            name: "Digoxin",
            swiftSettings: [
                .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
                .enableUpcomingFeature("InferIsolatedConformances"),
            ],
        ),
        .testTarget(
            name: "DigoxinTests",
            dependencies: ["Digoxin"],
            swiftSettings: [
                .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
            ],
        ),
    ],
    swiftLanguageModes: [.v6],
)
