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
/// Anything else (a plain log, an exception log, a report cut off mid-file)
/// is scrubbed as text: the same rewrites over the whole file, `\/` read as
/// `/`, the cleared fields' values replaced wherever `"key" : "value"`
/// appears, and the `CrashReporter Key:`-style lines of the legacy text
/// format emptied.
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

    /// `data` scrubbed: as JSON when the whole of it parses, as one document
    /// or as an `.ips` file's header line and body; as text otherwise.
    ///
    /// UTF-16 and UTF-32 are read as UTF-8 first: their NUL bytes stand
    /// between the letters of every name, where no rewrite would match, and
    /// `JSONSerialization` parses those encodings too.
    public func scrub(_ data: Data) -> Data {
        let data = Self.utf8(data)
        if Self.isJSON(data) {
            return scrubJSON(data)
        }
        return Data(scrubLog(String(decoding: data, as: UTF8.self)).utf8)
    }

    /// `text` scrubbed the same way.
    public func scrub(_ text: String) -> String {
        String(decoding: scrub(Data(text.utf8)), as: UTF8.self)
    }

    // MARK: - Encoding

    /// `data` as UTF-8: decoded from UTF-16 or UTF-32 when its byte order
    /// mark or the NULs among its first four bytes say it is one, and with
    /// every NUL byte dropped otherwise, which UTF-8 text never holds.
    static func utf8(_ data: Data) -> Data {
        guard data.contains(0) else { return data }
        if let encoding = wideEncoding(of: data), var text = wideText(data, as: encoding) {
            text = text.replacingOccurrences(of: "\0", with: "")
            if text.first == "\u{FEFF}" { text.removeFirst() }
            return Data(text.utf8)
        }
        return data.filter { $0 != 0 }
    }

    /// `data` decoded as `encoding`, a malformed unit as U+FFFD and a cut
    /// last unit dropped. `nil` when a unit holds two printable ASCII bytes:
    /// that is ASCII read as wide text (binary, or UTF-8 after a wide start),
    /// and decoding it would turn two letters at a time into one character
    /// that no rewrite matches and that encodes back to the same bytes.
    private static func wideText(_ data: Data, as encoding: String.Encoding) -> String? {
        let bytes = [UInt8](data)
        let width = encoding == .utf32LittleEndian || encoding == .utf32BigEndian ? 4 : 2
        let bigEndian = encoding == .utf16BigEndian || encoding == .utf32BigEndian
        var values: [UInt32] = []
        values.reserveCapacity(bytes.count / width)
        for start in stride(from: 0, through: bytes.count - width, by: width) {
            let unit = bytes[start ..< start + width]
            if unit.count(where: isPrintableASCII) >= 2 { return nil }
            let ordered = bigEndian ? Array(unit) : unit.reversed()
            values.append(ordered.reduce(0) { $0 << 8 | UInt32($1) })
        }
        if width == 2 {
            return String(decoding: values.map { UInt16($0) }, as: UTF16.self)
        }
        var scalars = String.UnicodeScalarView()
        scalars.append(contentsOf: values.map { Unicode.Scalar($0) ?? "\u{FFFD}" })
        return String(scalars)
    }

    private static func isPrintableASCII(_ byte: UInt8) -> Bool {
        (0x20 ... 0x7E).contains(byte) || byte == 0x09 || byte == 0x0A || byte == 0x0D
    }

    private static func wideEncoding(of data: Data) -> String.Encoding? {
        let head = Array(data.prefix(4)) + [UInt8](repeating: 1, count: max(0, 4 - data.count))
        switch (head[0], head[1], head[2], head[3]) {
        case (0xFF, 0xFE, 0, 0), (_, 0, 0, 0) where head[0] != 0: return .utf32LittleEndian
        case (0, 0, 0xFE, 0xFF), (0, 0, 0, _) where head[3] != 0: return .utf32BigEndian
        case (0xFF, 0xFE, _, _), (_, 0, _, _) where head[0] != 0: return .utf16LittleEndian
        case (0xFE, 0xFF, _, _), (0, _, _, _) where head[1] != 0: return .utf16BigEndian
        default: return nil
        }
    }

    // MARK: - JSON

    /// Whether `data` is one JSON document, or two with the first on its
    /// own line.
    static func isJSON(_ data: Data) -> Bool {
        let start = data.first { ![0x20, 0x09, 0x0A, 0x0D].contains($0) }
        guard start == UInt8(ascii: "{") || start == UInt8(ascii: "[") else { return false }
        if parses(data[...]) { return true }
        guard let newline = data.firstIndex(of: 0x0A) else { return false }
        return parses(data[..<newline]) && parses(data[data.index(after: newline)...])
    }

    private static func parses(_ data: Data.SubSequence) -> Bool {
        (try? JSONSerialization.jsonObject(with: Data(data))) != nil
    }

    /// Copies the bytes through, rewriting the content of string literals,
    /// keys and values alike. A value whose key is a cleared field becomes
    /// the zero UUID.
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
            // Only JSON the parser accepted reaches here, so a literal that
            // will not decode is a disagreement between the two: fail closed.
            guard let decoded = decodeLiteral(raw) else {
                output.append(contentsOf: encodeLiteral("<removed>"))
                afterColon = false
                continue
            }
            var value = decoded
            if isKey {
                lastKey = decoded
                if !Self.isUUID(decoded) {
                    value = scrubText(decoded, embeddedUUIDs: true)
                }
            } else if afterColon, let key = lastKey, fields.contains(key) {
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

    /// A file that is not JSON, scrubbed as text. A JSON report cut short
    /// lands here too, so its escaped slashes are read as slashes and its
    /// cleared fields are found by their keys.
    func scrubLog(_ text: String) -> String {
        scrubText(clearingFields(in: text.replacingOccurrences(of: "\\/", with: "/")))
    }

    /// `text` with the value of every `"field" : "value"` of a cleared field
    /// replaced, an unterminated last value included.
    private func clearingFields(in text: String) -> String {
        guard text.contains("\""), fields.contains(where: { text.contains($0) }) else { return text }
        let keys = fields.map(NSRegularExpression.escapedPattern(for:)).joined(separator: "|")
        guard let regex = try? NSRegularExpression(pattern: #""(?:\#(keys))"\s*:\s*"((?:[^"\\]|\\.)*)"?"#) else {
            return text
        }
        var result = text
        let matches = regex.matches(in: text, range: NSRange(text.startIndex ..< text.endIndex, in: text))
        for match in matches.reversed() {
            guard let range = Range(match.range(at: 1), in: result) else { continue }
            let value = String(result[range])
            result.replaceSubrange(range, with: Self.isUUID(value) || value.isEmpty ? Self.zeroUUID : "<removed>")
        }
        return result
    }

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
