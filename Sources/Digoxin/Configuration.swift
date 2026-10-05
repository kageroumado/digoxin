import Foundation
import os

extension Digoxin {
    /// How an app connects to the service.
    public struct Configuration: Sendable {
        /// The app's slug on the server, such as `refrax`.
        public var app: String
        /// The service root; requests go to `<baseURL>/v1/<app>/…`.
        public var baseURL: URL
        /// The app's own Application Support folder; Digoxin keeps its state
        /// in a `Digoxin` folder inside it.
        public var storageDirectory: URL
        /// The app's allowlisted heartbeat properties, read when a heartbeat
        /// is made.
        public var propertiesProvider: @Sendable () async -> [String: TelemetryValue]
        /// The app's allowlisted crash context fields, read when a crash
        /// report is queued.
        public var crashContextProvider: @Sendable () async -> [String: TelemetryValue]
        /// Rewrites applied to crash report files before the built-in ones.
        public var extraScrubRules: [ScrubRule]
        /// Where the client's lines go.
        public var log: @Sendable (String) -> Void

        public init(
            app: String,
            baseURL: URL,
            storageDirectory: URL,
            propertiesProvider: @escaping @Sendable () async -> [String: TelemetryValue] = { [:] },
            crashContextProvider: @escaping @Sendable () async -> [String: TelemetryValue] = { [:] },
            extraScrubRules: [ScrubRule] = [],
            log: @escaping @Sendable (String) -> Void = Configuration.defaultLog,
        ) {
            self.app = app
            self.baseURL = baseURL
            self.storageDirectory = storageDirectory
            self.propertiesProvider = propertiesProvider
            self.crashContextProvider = crashContextProvider
            self.extraScrubRules = extraScrubRules
            self.log = log
        }

        private static let logger = Logger(subsystem: "glass.kagerou.digoxin", category: "client")

        public static let defaultLog: @Sendable (String) -> Void = { line in
            logger.info("\(line, privacy: .public)")
        }

        /// The folder Digoxin owns inside ``storageDirectory``.
        var root: URL {
            storageDirectory.appendingPathComponent("Digoxin", isDirectory: true)
        }

        func endpoint(_ path: String) -> URL {
            baseURL.appendingPathComponent("v1").appendingPathComponent(app).appendingPathComponent(path)
        }
    }
}
