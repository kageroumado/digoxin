import Foundation

/// What the person agreed to send. Every app offers the same three tiers.
public enum ConsentTier: String, Codable, Sendable, CaseIterable {
    /// Nothing is sent and nothing is kept on disk; choosing it after another
    /// tier deletes the install on the server.
    case off
    /// One signed heartbeat per day the app is used, carrying ``BasicInfo``,
    /// the count of active days in the last week, and the app's allowlisted
    /// properties.
    case counting
    /// ``counting``, plus scrubbed crash reports.
    case crashReports
}

/// A property or context value an app sends. The server keeps a key only
/// when the app's allowlist names it with this value's type.
public enum TelemetryValue: Sendable, Hashable {
    case bool(Bool)
    case int(Int)
    case double(Double)
    case string(String)
}

extension TelemetryValue: Codable {
    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let value = try? container.decode(Bool.self) {
            self = .bool(value)
        } else if let value = try? container.decode(Int.self) {
            self = .int(value)
        } else if let value = try? container.decode(Double.self) {
            self = .double(value)
        } else {
            self = try .string(container.decode(String.self))
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case let .bool(value): try container.encode(value)
        case let .int(value): try container.encode(value)
        case let .double(value): try container.encode(value)
        case let .string(value): try container.encode(value)
        }
    }
}

extension TelemetryValue: ExpressibleByBooleanLiteral, ExpressibleByIntegerLiteral,
    ExpressibleByFloatLiteral, ExpressibleByStringLiteral
{
    public init(booleanLiteral value: Bool) { self = .bool(value) }
    public init(integerLiteral value: Int) { self = .int(value) }
    public init(floatLiteral value: Double) { self = .double(value) }
    public init(stringLiteral value: String) { self = .string(value) }
}

/// Where a client stands, for an app's settings to show.
public enum DigoxinStatus: Sendable, Equatable {
    /// The tier is ``ConsentTier/off`` and nothing is pending.
    case off
    /// The tier is off and the server has not yet confirmed the deletion of
    /// this install; the signed request is retried until it does.
    case deletionPending
    /// This Mac has no Secure Enclave, so no identity exists and nothing is sent.
    case secureEnclaveUnavailable
    /// On, and nothing has been sent yet.
    case waiting
    /// On and registered; `trust` is the server's tier for the evidence:
    /// `attested`, `device`, `reregistered` or `unverified`.
    case registered(trust: String)
    /// On, and the last send failed for `reason`; it is retried with backoff.
    case failing(reason: String)
}
