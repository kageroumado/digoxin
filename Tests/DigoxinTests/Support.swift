import CryptoKit
import Foundation
import Synchronization
@testable import Digoxin

/// Software P-256 keys standing in for the Secure Enclave.
struct SoftwareKey: InstallKey {
    let key: P256.Signing.PrivateKey

    var publicKeyDER: Data { key.publicKey.derRepresentation }

    func sign(_ body: Data) throws -> Data {
        try key.signature(for: body).derRepresentation
    }
}

struct SoftwareKeyStore: InstallKeyStore {
    var isAvailable = true

    func load(from url: URL) -> (any InstallKey)? {
        guard let raw = try? Data(contentsOf: url),
              let key = try? P256.Signing.PrivateKey(rawRepresentation: raw) else { return nil }
        return SoftwareKey(key: key)
    }

    func create(at url: URL) throws -> any InstallKey {
        let key = P256.Signing.PrivateKey()
        try writePrivately(key.rawRepresentation, to: url)
        return SoftwareKey(key: key)
    }
}

struct NoAttestor: Attestor {
    func evidence(for key: any InstallKey, challenge: Data, log: @Sendable (String) -> Void) async -> Evidence {
        Evidence()
    }
}

/// A request the fake server took, with its body as sent.
struct Recorded: Sendable {
    var method: String
    var path: String
    var headers: [String: String]
    var body: Data

    var json: [String: Any]? {
        try? JSONSerialization.jsonObject(with: body) as? [String: Any]
    }

    /// A multipart body's envelope part.
    var envelope: [String: Any]? {
        parts.first { $0.name == "envelope" }.flatMap { try? JSONSerialization.jsonObject(with: $0.data) as? [String: Any] }
    }

    /// A multipart body's parts, by name and file name.
    var parts: [(name: String, filename: String?, data: Data)] {
        guard let type = headers["Content-Type"], let boundary = type.components(separatedBy: "boundary=").last else { return [] }
        let text = String(decoding: body, as: UTF8.self)
        return text.components(separatedBy: "--\(boundary)").compactMap { chunk in
            guard let split = chunk.range(of: "\r\n\r\n") else { return nil }
            let head = chunk[..<split.lowerBound]
            guard let name = head.firstMatch(of: /name="([^"]+)"/)?.output.1 else { return nil }
            let filename = head.firstMatch(of: /filename="([^"]+)"/).map { String($0.output.1) }
            var content = String(chunk[split.upperBound...])
            // "\r\n" is one Character.
            if content.hasSuffix("\r\n") { content.removeLast() }
            return (String(name), filename, Data(content.utf8))
        }
    }
}

/// The Digoxin service as far as the client can tell: it checks the install
/// header, every signature and the sequence numbers the way the Go service
/// does, and records what it took.
final class FakeServer: Sendable {
    struct Install {
        var key: P256.Signing.PublicKey
        var lastSeq: Int
    }

    struct State {
        var installs: [String: Install] = [:]
        var requests: [Recorded] = []
        /// Statuses to answer the next requests with, in order.
        var scripted: [Int] = []
        var offline = false
        var trust = "unverified"
    }

    let state = Mutex(State())
    let host = "digoxin-\(UUID().uuidString.lowercased()).test"

    var baseURL: URL { URL(string: "https://\(host)/api")! }

    init() {
        MockURLProtocol.servers.withLock { $0[host] = self }
    }

    var requests: [Recorded] { state.withLock { $0.requests } }

    func requests(_ method: String, _ suffix: String) -> [Recorded] {
        requests.filter { $0.method == method && $0.path.hasSuffix(suffix) }
    }

    func setOffline(_ offline: Bool) { state.withLock { $0.offline = offline } }
    func script(_ statuses: Int...) { state.withLock { $0.scripted += statuses } }
    func forget() { state.withLock { $0.installs = [:] } }
    var installs: [String] { state.withLock { Array($0.installs.keys) } }

    func handle(_ request: URLRequest, body: Data) -> (status: Int, body: Data)? {
        state.withLock { state in
            if state.offline { return nil }
            let recorded = Recorded(
                method: request.httpMethod ?? "GET", path: request.url?.path ?? "",
                headers: request.allHTTPHeaderFields ?? [:], body: body,
            )
            state.requests.append(recorded)
            if !state.scripted.isEmpty {
                let status = state.scripted.removeFirst()
                return (status, Data(#"{"error":"scripted"}"#.utf8))
            }
            return Self.answer(recorded, state: &state)
        }
    }

    private static func json(_ status: Int, _ object: [String: Any]) -> (Int, Data) {
        (status, (try? JSONSerialization.data(withJSONObject: object)) ?? Data())
    }

    private static func answer(_ r: Recorded, state: inout State) -> (Int, Data) {
        let id = r.headers["Digoxin-Install"] ?? ""
        let signature = r.headers["Digoxin-Signature"].flatMap { Data(base64Encoded: $0) }
            .flatMap { try? P256.Signing.ECDSASignature(derRepresentation: $0) }
        if r.method == "GET", r.path.hasSuffix("/challenge") {
            return json(200, ["challenge": Data((0 ..< 56).map { _ in UInt8.random(in: 0 ... 255) }).base64EncodedString()])
        }
        if r.method == "POST", r.path.hasSuffix("/installs") {
            guard let fields = r.json, let der = (fields["public_key"] as? String).flatMap({ Data(base64Encoded: $0) }),
                  let key = try? P256.Signing.PublicKey(derRepresentation: der),
                  makeInstallID(publicKeyDER: der) == id, let signature, key.isValidSignature(signature, for: r.body)
            else { return json(401, ["error": "signature does not verify"]) }
            if state.installs[id] == nil { state.installs[id] = Install(key: key, lastSeq: 0) }
            return json(201, ["install": id, "trust": state.trust])
        }
        guard let install = state.installs[id] else {
            return json(401, ["error": "signature does not verify"])
        }
        guard let signature, install.key.isValidSignature(signature, for: r.body) else {
            return json(401, ["error": "signature does not verify"])
        }
        let envelope = r.method == "POST" && r.path.hasSuffix("/crash-reports") ? r.envelope : r.json
        guard let envelope, envelope["install"] as? String == id, let seq = envelope["seq"] as? Int else {
            return json(400, ["error": "envelope"])
        }
        guard seq > install.lastSeq else { return json(409, ["error": "seq already used"]) }
        state.installs[id]?.lastSeq = seq
        switch r.method {
        case "DELETE":
            state.installs[id] = nil
            return (204, Data())
        case _ where r.path.hasSuffix("/heartbeats"):
            return json(202, ["accepted": (envelope["heartbeats"] as? [Any])?.count ?? 0, "rejected": []])
        default:
            return json(201, ["id": "0123"])
        }
    }
}

/// Routes requests to the ``FakeServer`` registered for their host, so
/// tests running in parallel each talk to their own.
final class MockURLProtocol: URLProtocol {
    static let servers = Mutex<[String: FakeServer]>([:])

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let server = request.url?.host.flatMap { host in Self.servers.withLock { $0[host] } }
        guard let server, let answer = server.handle(request, body: Self.body(of: request)) else {
            client?.urlProtocol(self, didFailWithError: URLError(.notConnectedToInternet))
            return
        }
        let response = HTTPURLResponse(url: request.url!, statusCode: answer.status, httpVersion: "HTTP/1.1", headerFields: nil)!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: answer.body)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}

    /// URLSession hands a protocol the body as a stream.
    static func body(of request: URLRequest) -> Data {
        if let body = request.httpBody { return body }
        guard let stream = request.httpBodyStream else { return Data() }
        stream.open()
        defer { stream.close() }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 16384)
        while stream.hasBytesAvailable {
            let read = stream.read(&buffer, maxLength: buffer.count)
            if read <= 0 { break }
            data.append(buffer, count: read)
        }
        return data
    }
}

/// A clock the test moves by hand.
final class TestClock: Sendable {
    let date: Mutex<Date>

    init(_ date: Date) { self.date = Mutex(date) }

    var now: Date { date.withLock { $0 } }
    func advance(days: Int) { date.withLock { $0 = $0.addingTimeInterval(TimeInterval(days * 86400)) } }
    func advance(seconds: TimeInterval) { date.withLock { $0 = $0.addingTimeInterval(seconds) } }
}

let fixedInfo = BasicInfo(
    appVersion: "0.34", appBuild: "41", os: "27.0", arch: "arm64", chipFamily: "M3", memoryClassGB: 36, language: "fr",
)

/// A temporary folder that is moved to the Trash when the test ends.
func temporaryFolder() -> URL {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent("digoxin-tests-\(UUID().uuidString)")
    try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    return url
}

func makeClient(
    server: FakeServer, storage: URL, clock: TestClock, keyStore: any InstallKeyStore = SoftwareKeyStore(),
    properties: [String: TelemetryValue] = ["chromiumInstalled": true],
) -> Digoxin {
    let sessionConfiguration = URLSessionConfiguration.ephemeral
    sessionConfiguration.protocolClasses = [MockURLProtocol.self]
    var calendar = Calendar(identifier: .gregorian)
    calendar.timeZone = TimeZone(identifier: "Europe/Paris")!
    let configuration = Digoxin.Configuration(
        app: "refrax", baseURL: server.baseURL, storageDirectory: storage,
        propertiesProvider: { properties }, crashContextProvider: { ["engines": "webkit-621"] }, log: { _ in },
    )
    return Digoxin(
        configuration: configuration, keyStore: keyStore, attestor: NoAttestor(),
        sessionConfiguration: sessionConfiguration, now: { clock.now }, calendar: calendar,
        info: { fixedInfo }, bundlePath: "/Applications/Refrax.app",
    )
}
