import Foundation

/// What the client keeps between launches, in `<storage>/Digoxin/state.json`.
/// It exists only while the tier is on.
struct LocalState: Codable, Equatable {
    var tier: ConsentTier = .off
    /// The install id the server registered, `nil` before registration.
    var registered: String?
    /// The server's word on the evidence: `attested`, `device`,
    /// `reregistered` or `unverified`.
    var trust: String?
    /// The last sequence number used; every signed request takes the next.
    var seq: Int = 0
    /// The local day of the last heartbeat made, `yyyy-MM-dd`.
    var lastHeartbeatDay: String?
    /// The local days the app was used in the last week, `yyyy-MM-dd`.
    var activeDays: [String] = []
    /// The app version seen last, and the one before it.
    var lastVersion: String?
    var previousVersion: String?
    var lastSent: Date?
    var lastError: String?
    /// Sends that failed in a row, and when the next may go. Kept on disk so
    /// a relaunch waits out the same backoff rather than starting it over.
    var failures: Int?
    var nextTry: Date?
}

/// A heartbeat as sent: the basic info, the local day it counts, how many
/// of the last seven days the app was used, and the app's properties.
struct Heartbeat: Codable, Equatable {
    var info: BasicInfo
    var day: String
    var activeDays7: Int
    var properties: [String: TelemetryValue]

    private enum CodingKeys: String, CodingKey {
        case day, activeDays7, properties
    }

    init(info: BasicInfo, day: String, activeDays7: Int, properties: [String: TelemetryValue]) {
        self.info = info
        self.day = day
        self.activeDays7 = activeDays7
        self.properties = properties
    }

    init(from decoder: any Decoder) throws {
        info = try BasicInfo(from: decoder)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        day = try container.decode(String.self, forKey: .day)
        activeDays7 = try container.decode(Int.self, forKey: .activeDays7)
        properties = try container.decode([String: TelemetryValue].self, forKey: .properties)
    }

    func encode(to encoder: any Encoder) throws {
        try info.encode(to: encoder)
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(day, forKey: .day)
        try container.encode(activeDays7, forKey: .activeDays7)
        try container.encode(properties, forKey: .properties)
    }
}

struct QueuedHeartbeat: Codable, Equatable {
    var queued: Date
    var heartbeat: Heartbeat
}

/// A crash report's context: the basic info, how the app was installed and
/// launched, and the app's own fields.
struct CrashContext: Codable, Equatable {
    var info: BasicInfo
    var installLocation: String
    var previousVersion: String?
    var consecutiveLaunchCrashes: Int?
    var secondsSinceLaunch: Double?
    var fields: [String: TelemetryValue]

    private enum CodingKeys: String, CodingKey {
        case installLocation, previousVersion, consecutiveLaunchCrashes, secondsSinceLaunch, fields
    }

    init(
        info: BasicInfo, installLocation: String, previousVersion: String?,
        consecutiveLaunchCrashes: Int?, secondsSinceLaunch: Double?, fields: [String: TelemetryValue],
    ) {
        self.info = info
        self.installLocation = installLocation
        self.previousVersion = previousVersion
        self.consecutiveLaunchCrashes = consecutiveLaunchCrashes
        self.secondsSinceLaunch = secondsSinceLaunch
        self.fields = fields
    }

    init(from decoder: any Decoder) throws {
        info = try BasicInfo(from: decoder)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        installLocation = try container.decode(String.self, forKey: .installLocation)
        previousVersion = try container.decodeIfPresent(String.self, forKey: .previousVersion)
        consecutiveLaunchCrashes = try container.decodeIfPresent(Int.self, forKey: .consecutiveLaunchCrashes)
        secondsSinceLaunch = try container.decodeIfPresent(Double.self, forKey: .secondsSinceLaunch)
        fields = try container.decode([String: TelemetryValue].self, forKey: .fields)
    }

    func encode(to encoder: any Encoder) throws {
        try info.encode(to: encoder)
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(installLocation, forKey: .installLocation)
        try container.encodeIfPresent(previousVersion, forKey: .previousVersion)
        try container.encodeIfPresent(consecutiveLaunchCrashes, forKey: .consecutiveLaunchCrashes)
        try container.encodeIfPresent(secondsSinceLaunch, forKey: .secondsSinceLaunch)
        try container.encode(fields, forKey: .fields)
    }
}

/// The signed wrapper of every request after registration.
struct Envelope: Encodable {
    static let version = 1

    var v = Envelope.version
    var seq: Int
    var sent: String
    var install: String
    var heartbeats: [Heartbeat]?
    var context: CrashContext?
}

/// A signed delete made when the person turned telemetry off, kept until
/// the server confirms it. It holds no key: the key was destroyed when the
/// request was signed, so it is the only way left to delete that install,
/// and every install retired this way keeps its own until it resolves.
struct PendingDeletion: Codable, Equatable {
    var install: String
    var body: Data
    var signature: Data
    var created: Date
    var failures: Int = 0
}

/// The files under `<storage>/Digoxin/`.
struct LocalStore {
    let root: URL

    var identityURL: URL { root.appendingPathComponent("identity.key") }
    var stateURL: URL { root.appendingPathComponent("state.json") }
    var heartbeatsURL: URL { root.appendingPathComponent("heartbeats.json") }
    var crashesURL: URL { root.appendingPathComponent("crashes", isDirectory: true) }
    var pendingDeletionsURL: URL { root.appendingPathComponent("pending-deletions", isDirectory: true) }

    func pendingDeletionURL(install: String) -> URL {
        pendingDeletionsURL.appendingPathComponent("\(install).json")
    }

    static let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }()

    static let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }()

    func read<T: Decodable>(_ type: T.Type, from url: URL) -> T? {
        (try? Data(contentsOf: url)).flatMap { try? Self.decoder.decode(type, from: $0) }
    }

    func write(_ value: some Encodable, to url: URL) {
        guard let data = try? Self.encoder.encode(value) else { return }
        try? writePrivately(data, to: url)
    }

    func remove(_ url: URL) {
        try? FileManager.default.removeItem(at: url)
    }

    /// The queued crash reports, oldest first: one folder each, holding
    /// `context.json` and the scrubbed files under `files/`.
    func crashReports() -> [URL] {
        let folders = (try? FileManager.default.contentsOfDirectory(
            at: crashesURL, includingPropertiesForKeys: [.creationDateKey], options: [.skipsHiddenFiles],
        )) ?? []
        return folders.sorted { creation($0) < creation($1) }
    }

    func creation(_ url: URL) -> Date {
        (try? url.resourceValues(forKeys: [.creationDateKey]).creationDate) ?? .distantPast
    }

    /// The installs whose delete the server has yet to confirm.
    func pendingDeletions() -> [PendingDeletion] {
        let files = (try? FileManager.default.contentsOfDirectory(
            at: pendingDeletionsURL, includingPropertiesForKeys: nil, options: [.skipsHiddenFiles],
        )) ?? []
        return files.compactMap { read(PendingDeletion.self, from: $0) }.sorted { $0.created < $1.created }
    }

    /// Removes everything but the pending deletions, adding `pending` to
    /// them; removes the folder itself when nothing is pending.
    func wipe(adding pending: PendingDeletion?) {
        let items = (try? FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: nil)) ?? []
        for item in items where item.standardizedFileURL != pendingDeletionsURL.standardizedFileURL {
            remove(item)
        }
        if let pending { write(pending, to: pendingDeletionURL(install: pending.install)) }
        if pendingDeletions().isEmpty { remove(root) }
    }
}
