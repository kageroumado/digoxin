import Darwin
import Foundation
import SystemConfiguration

/// An app's own rewrite, applied to crash report files before the built-in ones.
public struct ScrubRule: Sendable {
    enum Kind: Sendable {
        case literal(String, String)
        case pattern(String, String)
        case field(String)
    }

    let kind: Kind

    /// Replaces every occurrence of `literal`.
    public static func replacing(_ literal: String, with replacement: String) -> ScrubRule {
        ScrubRule(kind: .literal(literal, replacement))
    }

    /// Replaces every match of the ICU regular expression `pattern` with
    /// `template` (`$1` names a capture group).
    public static func pattern(_ pattern: String, with template: String) -> ScrubRule {
        ScrubRule(kind: .pattern(pattern, template))
    }

    /// Clears the string value of `key` wherever it appears in a JSON file
    /// such as an `.ips` report.
    public static func clearingField(_ key: String) -> ScrubRule {
        ScrubRule(kind: .field(key))
    }
}

/// Takes the person and the machine out of a crash report.
///
/// A macOS crash report (`.ips`) is two JSON documents, a header line and
/// a body, and it names the account in every path under the home folder,
/// the Mac by several ids that are stable across reports, and whatever a
/// thread's registers pointed at. The scrubber rewrites the text of every
/// JSON string and leaves everything else byte for byte, so the numbers
/// that symbolication needs (addresses, image UUIDs and offsets) are the
/// ones the system wrote, and the file stays the JSON it was:
///
/// - paths under a home folder become `~`, other volumes `/Volumes/<volume>`,
///   per-user temporary folders `/var/folders/<tmp>`;
/// - the account's short and full name become `<user>`, the Mac's host,
///   computer and Bonjour names `<host>`, e-mail addresses `<email>`;
/// - URLs keep their scheme and host; their user info, path and query go;
/// - `crashReporterKey`, `sleepWakeUUID`, `bootSessionUUID` and
///   `deviceIdentifierForVendor` become the zero UUID, and a UUID inside a
///   longer string (a simulator's device id in `coalitionName`, an
///   App Translocation folder) becomes the zero UUID too.
///
/// A file that is not JSON (an exception log) gets the same text rewrites,
/// with the `CrashReporter Key:`-style lines of the legacy text format
/// emptied.
public struct CrashReportScrubber: Sendable {
    /// What names this Mac and its account.
    public struct Machine: Sendable, Equatable {
        public var home: String
        public var userName: String
        public var fullName: String
        public var hostNames: [String]

        public init(home: String, userName: String, fullName: String, hostNames: [String]) {
            self.home = home
            self.userName = userName
            self.fullName = fullName
            // Longest first, so a name that contains another is replaced whole.
            self.hostNames = Set(hostNames.filter { $0.count > 2 && $0 != "localhost" })
                .sorted { ($0.count, $0) > ($1.count, $1) }
        }

        /// This Mac. The home folder is the account's real one, outside any
        /// sandbox container; the names are local reads, never a DNS lookup.
        public static var current: Machine {
            var kernelName = [CChar](repeating: 0, count: Int(MAXHOSTNAMELEN) + 1)
            let kernel = gethostname(&kernelName, kernelName.count - 1) == 0
                ? kernelName.withUnsafeBufferPointer { String(cString: $0.baseAddress!) } : nil
            let home = getpwuid(getuid()).flatMap { String(validatingCString: $0.pointee.pw_dir) } ?? NSHomeDirectory()
            return Machine(
                home: home, userName: NSUserName(), fullName: NSFullUserName(),
                hostNames: [
                    kernel,
                    SCDynamicStoreCopyComputerName(nil, nil) as String?,
                    SCDynamicStoreCopyLocalHostName(nil) as String?,
                ].compactMap(\.self),
            )
        }
    }

    static let zeroUUID = "00000000-0000-0000-0000-000000000000"
    static let clearedFields: Set<String> = [
        "crashReporterKey", "sleepWakeUUID", "bootSessionUUID", "deviceIdentifierForVendor",
    ]

    let machine: Machine
    let rules: [ScrubRule]
    let fields: Set<String>

    public init(machine: Machine = .current, extraRules: [ScrubRule] = []) {
        self.machine = machine
        rules = extraRules
        var fields = Self.clearedFields
        for rule in extraRules {
            if case let .field(key) = rule.kind { fields.insert(key) }
        }
        self.fields = fields
    }

    /// The file's contents, scrubbed.
    public func scrubFile(at url: URL) throws -> Data {
        try scrub(Data(contentsOf: url))
    }

    /// `data` scrubbed: as JSON (one document or several, as `.ips` files
    /// are) when it starts with `{` or `[`, as text otherwise.
    public func scrub(_ data: Data) -> Data {
        let start = data.first { ![0x20, 0x09, 0x0A, 0x0D].contains($0) }
        if start == UInt8(ascii: "{") || start == UInt8(ascii: "[") {
            return scrubJSON(data)
        }
        return Data(scrubText(String(decoding: data, as: UTF8.self)).utf8)
    }

    /// `text` scrubbed as a plain log.
    public func scrub(_ text: String) -> String {
        String(decoding: scrub(Data(text.utf8)), as: UTF8.self)
    }

    // MARK: - JSON

    /// Copies the bytes through, rewriting the content of string literals.
    /// A value whose key is a cleared field becomes the zero UUID.
    func scrubJSON(_ data: Data) -> Data {
        let bytes = [UInt8](data)
        var output = [UInt8]()
        output.reserveCapacity(bytes.count)
        var index = 0
        var lastKey: String?
        var afterColon = false
        while index < bytes.count {
            let byte = bytes[index]
            guard byte == UInt8(ascii: "\"") else {
                if byte == UInt8(ascii: ":") {
                    afterColon = true
                } else if !isJSONSpace(byte) {
                    afterColon = false
                }
                output.append(byte)
                index += 1
                continue
            }
            let end = literalEnd(bytes, from: index)
            let raw = bytes[index ..< end]
            index = end
            var next = index
            while next < bytes.count, isJSONSpace(bytes[next]) { next += 1 }
            let isKey = next < bytes.count && bytes[next] == UInt8(ascii: ":")
            guard let decoded = decodeLiteral(raw) else {
                output.append(contentsOf: raw)
                continue
            }
            if isKey {
                lastKey = decoded
                output.append(contentsOf: raw)
                continue
            }
            var value = decoded
            if afterColon, let key = lastKey, fields.contains(key) {
                value = Self.isUUID(decoded) || decoded.isEmpty ? Self.zeroUUID : "<removed>"
            } else if !Self.isUUID(decoded) {
                value = scrubText(decoded, embeddedUUIDs: true)
            }
            afterColon = false
            if value == decoded {
                output.append(contentsOf: raw)
            } else {
                output.append(contentsOf: encodeLiteral(value))
            }
        }
        return Data(output)
    }

    private func isJSONSpace(_ byte: UInt8) -> Bool {
        byte == 0x20 || byte == 0x09 || byte == 0x0A || byte == 0x0D
    }

    /// The index just past the string literal opening at `start`, or the
    /// end of the input for one left open.
    private func literalEnd(_ bytes: [UInt8], from start: Int) -> Int {
        var index = start + 1
        while index < bytes.count {
            switch bytes[index] {
            case UInt8(ascii: "\\"): index += 2
            case UInt8(ascii: "\""): return index + 1
            default: index += 1
            }
        }
        return bytes.count
    }

    /// A literal's text, quotes included in `raw`; `nil` when malformed.
    private func decodeLiteral(_ raw: ArraySlice<UInt8>) -> String? {
        guard raw.count >= 2, raw.last == UInt8(ascii: "\"") else { return nil }
        let body = raw.dropFirst().dropLast()
        guard body.contains(UInt8(ascii: "\\")) else {
            return String(validating: body, as: UTF8.self)
        }
        return (try? JSONDecoder().decode(String.self, from: Data(raw)))
    }

    /// `value` as a JSON literal, escaping `/` the way the system's reports do.
    private func encodeLiteral(_ value: String) -> [UInt8] {
        var out: [UInt8] = [UInt8(ascii: "\"")]
        for scalar in value.unicodeScalars {
            switch scalar {
            case "\"": out += Array("\\\"".utf8)
            case "\\": out += Array("\\\\".utf8)
            case "/": out += Array("\\/".utf8)
            case "\n": out += Array("\\n".utf8)
            case "\r": out += Array("\\r".utf8)
            case "\t": out += Array("\\t".utf8)
            case _ where scalar.value < 0x20:
                out += Array(String(format: "\\u%04x", scalar.value).utf8)
            default:
                out += Array(String(scalar).utf8)
            }
        }
        out.append(UInt8(ascii: "\""))
        return out
    }

    // MARK: - Text

    static func isUUID(_ text: String) -> Bool {
        text.count == 36 && text.wholeMatch(of: uuidPattern) != nil
    }

    // `nonisolated(unsafe)`: a `Regex` built from a literal holds no state,
    // and matching never mutates it.
    private nonisolated(unsafe) static let uuidPattern =
        /[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}/
    private nonisolated(unsafe) static let url =
        /([A-Za-z][A-Za-z0-9+.\-]{1,15}):\/\/([^\s\/?#"'<>]*)[^\s"'<>]*/
    /// `/Users/<someone>`; `/Users/Shared` names no one and is left alone.
    private nonisolated(unsafe) static let macHome =
        /\/Users\/(?!Shared(?:\/|$))[^\/\s"':;,\)\]]+/
    private nonisolated(unsafe) static let volume = /\/Volumes\/(?!VOLUME\/)[^\/"\n]+/
    private nonisolated(unsafe) static let tempFolder = /\/var\/folders\/[^\/\s"]+\/[^\/\s"]+/
    private nonisolated(unsafe) static let email = /[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/
    private nonisolated(unsafe) static let legacyIDLine =
        /(?m)^(Anonymous UUID|Sleep\/Wake UUID|CrashReporter Key|Boot Session UUID):[ \t]*\S+/

    /// `text` with the built-in rewrites and the app's rules applied.
    /// `embeddedUUIDs` also zeroes UUIDs that are part of a longer string.
    func scrubText(_ text: String, embeddedUUIDs: Bool = false) -> String {
        var result = applyingRules(to: text)
        if result.contains("://") {
            result = result.replacing(Self.url) { match in
                let scheme = match.output.1
                if scheme.lowercased() == "file" { return String(match.output.0) }
                var host = match.output.2
                if let at = host.lastIndex(of: "@") {
                    host = host[host.index(after: at)...]
                }
                if !host.hasPrefix("["), let colon = host.firstIndex(of: ":") {
                    host = host[..<colon]
                }
                return "\(scheme)://\(host)"
            }
        }
        if result.contains("/") {
            if machine.home.count > 1 {
                result = result.replacingOccurrences(of: machine.home, with: "~")
            }
            result = result.replacing(Self.macHome) { _ in "~" }
            result = result.replacing(Self.volume) { _ in "/Volumes/<volume>" }
            result = result.replacing(Self.tempFolder) { _ in "/var/folders/<tmp>" }
        }
        if result.contains("@") {
            result = result.replacing(Self.email) { _ in "<email>" }
        }
        if machine.fullName.count > 2 {
            result = result.replacingOccurrences(of: machine.fullName, with: "<user>")
        }
        for name in machine.hostNames {
            result = result.replacingOccurrences(of: name, with: "<host>", options: .caseInsensitive)
        }
        result = removingAccountName(from: result)
        if embeddedUUIDs {
            if result.contains("-") {
                result = result.replacing(Self.uuidPattern) { _ in Self.zeroUUID }
            }
        } else if result.contains(":") {
            result = result.replacing(Self.legacyIDLine) { match in "\(match.output.1): <removed>" }
        }
        return result
    }

    private func applyingRules(to text: String) -> String {
        var result = text
        for rule in rules {
            switch rule.kind {
            case let .literal(literal, replacement) where !literal.isEmpty:
                result = result.replacingOccurrences(of: literal, with: replacement)
            case let .pattern(pattern, template):
                guard let regex = try? NSRegularExpression(pattern: pattern) else { continue }
                result = regex.stringByReplacingMatches(
                    in: result, range: NSRange(result.startIndex ..< result.endIndex, in: result), withTemplate: template,
                )
            case .literal, .field:
                continue
            }
        }
        return result
    }

    /// The account's short name standing on its own, once every path that
    /// contains it has already become `~`.
    private func removingAccountName(from text: String) -> String {
        let name = machine.userName
        guard name.count > 2, text.range(of: name, options: .caseInsensitive) != nil else { return text }
        let pattern = "\\b\(NSRegularExpression.escapedPattern(for: name))\\b"
        guard let regex = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else { return text }
        return regex.stringByReplacingMatches(
            in: text, range: NSRange(text.startIndex ..< text.endIndex, in: text), withTemplate: "<user>",
        )
    }
}
