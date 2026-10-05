import Foundation

/// Anonymous, attested usage counting and crash reports, at the tier the
/// person chose.
///
/// An actor because it owns state that every call reads and writes (the
/// sequence number each signed request takes, the queues, the retry timer)
/// and is called from wherever the app happens to be. Its work is file I/O,
/// Secure Enclave signing and network, none of which belongs on the main
/// actor; an app on `@MainActor` calls it with `await` and never blocks.
///
/// ```swift
/// let telemetry = Digoxin(configuration: .init(app: "refrax", baseURL: url, storageDirectory: support))
/// await telemetry.setTier(.counting)   // from the app's settings
/// await telemetry.recordUse()          // when the app is used
/// ```
public actor Digoxin {
    let configuration: Configuration
    let keyStore: any InstallKeyStore
    let attestor: any Attestor
    let session: URLSession
    let now: @Sendable () -> Date
    var calendar: Calendar
    let info: @Sendable () -> BasicInfo
    let bundlePath: String
    let store: LocalStore

    var state: LocalState
    private var retry: Task<Void, Never>?
    private var isFlushing = false
    /// The service answered that it is not there; nothing is sent again
    /// until the app next launches.
    private var serviceAbsent = false
    /// The last failure's class, so a run of the same failure is logged once.
    private var lastFailure: FailureClass?
    /// Bumped when the tier turns off, so a send in flight does not write
    /// back state the person just deleted.
    private var generation = 0

    static let heartbeatBatch = 8
    static let queueLife: TimeInterval = 7 * 24 * 3600
    static let maxCrashFiles = 4
    static let maxCrashBytes = 2 << 20
    /// Waits between failed sends: a minute, then longer, up to six hours.
    static let backoff: [Duration] = [.seconds(60), .seconds(300), .seconds(1800), .seconds(7200), .seconds(21600)]
    /// The wait after the server refused to register another install from
    /// this address today: its cap is per day.
    static let registrationCapWait: Duration = .seconds(24 * 3600)
    /// The server's word on a 429 that is its per-minute write limit.
    static let perMinuteLimit = "too many requests"

    public init(configuration: Configuration) {
        self.init(
            configuration: configuration, keyStore: SecureEnclaveKeyStore(), attestor: AppleAttestor(),
            sessionConfiguration: .ephemeral,
        )
    }

    init(
        configuration: Configuration,
        keyStore: any InstallKeyStore,
        attestor: any Attestor,
        sessionConfiguration: URLSessionConfiguration,
        now: @escaping @Sendable () -> Date = { Date() },
        calendar: Calendar = .current,
        info: @escaping @Sendable () -> BasicInfo = { BasicInfo.current() },
        bundlePath: String = Bundle.main.bundlePath,
    ) {
        self.configuration = configuration
        self.keyStore = keyStore
        self.attestor = attestor
        session = URLSession(configuration: sessionConfiguration)
        self.now = now
        self.calendar = calendar
        self.info = info
        self.bundlePath = bundlePath
        store = LocalStore(root: configuration.root)
        state = store.read(LocalState.self, from: store.stateURL) ?? LocalState()
    }

    // MARK: - Public API

    /// The tier the person chose; ``ConsentTier/off`` until they choose another.
    public var tier: ConsentTier {
        state.tier
    }

    /// Where this client stands, for the app's settings to show.
    public var status: DigoxinStatus {
        if state.tier == .off {
            return FileManager.default.fileExists(atPath: store.pendingDeletionURL.path) ? .deletionPending : .off
        }
        if !keyStore.isAvailable { return .secureEnclaveUnavailable }
        if let error = state.lastError { return .failing(reason: error) }
        if state.registered != nil, let trust = state.trust { return .registered(trust: trust) }
        return .waiting
    }

    /// Applies the person's choice. Turning on creates the install key;
    /// turning off signs a delete for the server, destroys the key and
    /// everything queued at once, and sends the delete (retried until the
    /// server confirms it when the Mac is offline).
    public func setTier(_ newTier: ConsentTier) async {
        let old = state.tier
        guard newTier != old else { return }
        if newTier == .off {
            await turnOff()
            return
        }
        state.tier = newTier
        if newTier == .counting {
            store.remove(store.crashesURL)
        }
        if old == .off {
            if keyStore.isAvailable {
                _ = try? loadOrCreateKey()
            } else {
                log("this Mac has no Secure Enclave; nothing will be sent")
            }
        }
        persist()
        log("tier is \(newTier.rawValue)")
    }

    /// Notes that the app is being used. The first call on a local day
    /// queues that day's heartbeat and sends it; later calls that day only
    /// count the day as active.
    public func recordUse() async {
        guard state.tier != .off else {
            await flush()
            return
        }
        guard keyStore.isAvailable else { return }
        noteVersion()
        let today = dayKey(now())
        let weekStart = dayKey(calendar.date(byAdding: .day, value: -6, to: now()) ?? now())
        state.activeDays = Set(state.activeDays + [today]).filter { $0 >= weekStart }.sorted()
        if state.lastHeartbeatDay != today {
            let generation = generation
            let properties = await configuration.propertiesProvider()
            guard generation == self.generation, state.tier != .off, state.lastHeartbeatDay != today else { return }
            let heartbeat = Heartbeat(info: info(), day: today, activeDays7: state.activeDays.count, properties: properties)
            var queue = heartbeatQueue()
            queue.append(QueuedHeartbeat(queued: now(), heartbeat: heartbeat))
            store.write(queue, to: store.heartbeatsURL)
            state.lastHeartbeatDay = today
        }
        persist()
        await flush()
    }

    /// Queues a crash report and sends it: each file is scrubbed with
    /// ``CrashReportScrubber`` before it is written to the queue, so nothing
    /// unscrubbed is kept or sent. Does nothing unless the tier is
    /// ``ConsentTier/crashReports``.
    ///
    /// `context` holds the app's allowlisted fields; two keys are read as
    /// the report's own: `consecutiveLaunchCrashes` (an int) and
    /// `secondsSinceLaunch` (a number), which is otherwise read from the
    /// first `.ips` file.
    public func submitCrashReport(files: [URL], context: [String: TelemetryValue] = [:]) async {
        guard state.tier == .crashReports, keyStore.isAvailable else { return }
        noteVersion()
        let generation = generation
        let provided = await configuration.crashContextProvider()
        guard generation == self.generation, state.tier == .crashReports else { return }

        let scrubber = CrashReportScrubber(extraRules: configuration.extraScrubRules)
        var kept: [(name: String, data: Data)] = []
        var total = 0
        var names: Set<String> = []
        for url in files.prefix(Self.maxCrashFiles) {
            guard let data = try? scrubber.scrubFile(at: url), !data.isEmpty, total + data.count <= Self.maxCrashBytes else {
                log("crash report file \(url.lastPathComponent) is unreadable or over the size limit; left out")
                continue
            }
            var name = Self.fileName(url.lastPathComponent)
            while names.contains(name) { name = "1-" + name }
            names.insert(name)
            kept.append((name, data))
            total += data.count
        }
        guard !kept.isEmpty else { return }

        var fields = provided.merging(context) { _, given in given }
        let launchCrashes: Int? = if case let .int(n) = fields.removeValue(forKey: "consecutiveLaunchCrashes") { n } else { nil }
        var sinceLaunch: Double? = switch fields.removeValue(forKey: "secondsSinceLaunch") {
        case let .double(seconds): seconds
        case let .int(seconds): Double(seconds)
        default: nil
        }
        if sinceLaunch == nil, let ips = kept.first(where: { $0.name.hasSuffix(".ips") }) {
            sinceLaunch = Self.secondsSinceLaunch(ips: ips.data)
        }
        let crash = CrashContext(
            info: info(), installLocation: Self.installLocation(bundlePath: bundlePath),
            previousVersion: state.previousVersion, consecutiveLaunchCrashes: launchCrashes,
            secondsSinceLaunch: sinceLaunch, fields: fields,
        )
        let folder = store.crashesURL.appendingPathComponent(UUID().uuidString, isDirectory: true)
        do {
            for (name, data) in kept {
                try writePrivately(data, to: folder.appendingPathComponent("files").appendingPathComponent(name))
            }
            store.write(crash, to: folder.appendingPathComponent("context.json"))
        } catch {
            store.remove(folder)
            log("could not queue a crash report: \(error.localizedDescription)")
            return
        }
        persist()
        await flush()
    }

    /// Sends what is queued: a pending delete first, then heartbeats, then
    /// crash reports, registering first when the server does not know this
    /// install yet.
    public func flush() async {
        guard !isFlushing else { return }
        isFlushing = true
        defer { isFlushing = false }
        await sendPendingDeletion()
        guard state.tier != .off, !serviceAbsent, keyStore.isAvailable else { return }
        // A backoff that outlived the last launch is waited out.
        if let next = state.nextTry, next > now() {
            if retry == nil { scheduleRetry(in: .seconds(next.timeIntervalSince(now()))) }
            return
        }
        let generation = generation
        do {
            try await drainHeartbeats(generation: generation)
            if state.tier == .crashReports {
                try await drainCrashReports(generation: generation)
            }
            lastFailure = nil
        } catch is Superseded {
            return
        } catch {
            noteFailure(error)
        }
    }

    // MARK: - Local state

    func persist() {
        guard state.tier != .off else { return }
        store.write(state, to: store.stateURL)
    }

    func log(_ line: String) {
        configuration.log("digoxin \(configuration.app): \(line)")
    }

    func dayKey(_ date: Date) -> String {
        let parts = calendar.dateComponents([.year, .month, .day], from: date)
        return String(format: "%04d-%02d-%02d", parts.year ?? 0, parts.month ?? 0, parts.day ?? 0)
    }

    private func noteVersion() {
        let current = info().appVersion
        if let last = state.lastVersion, last != current {
            state.previousVersion = last
        }
        state.lastVersion = current
    }

    func heartbeatQueue() -> [QueuedHeartbeat] {
        store.read([QueuedHeartbeat].self, from: store.heartbeatsURL) ?? []
    }

    static func installLocation(bundlePath: String) -> String {
        if bundlePath.contains("/AppTranslocation/") { return "translocated" }
        if bundlePath.contains("/Applications/") { return "applications" }
        return "other"
    }

    /// A name the server takes: letters, digits, `.`, `_` and `-`,
    /// starting with a letter or digit, at most 128 characters.
    static func fileName(_ name: String) -> String {
        var cleaned = String(name.unicodeScalars.map { scalar -> Character in
            scalar.isASCII && (CharacterSet.alphanumerics.contains(scalar) || "._-".unicodeScalars.contains(scalar))
                ? Character(scalar) : "-"
        })
        while let first = cleaned.first, !(first.isASCII && (first.isLetter || first.isNumber)) {
            cleaned.removeFirst()
        }
        if cleaned.isEmpty { cleaned = "report" }
        return String(cleaned.prefix(128))
    }

    /// The seconds from `procLaunch` to `captureTime` in an `.ips` body.
    static func secondsSinceLaunch(ips: Data) -> Double? {
        let text = String(decoding: ips, as: UTF8.self)
        guard let newline = text.firstIndex(of: "\n"),
              let body = try? JSONSerialization.jsonObject(with: Data(text[text.index(after: newline)...].utf8)) as? [String: Any],
              let launch = (body["procLaunch"] as? String).flatMap(ipsDate),
              let capture = (body["captureTime"] as? String).flatMap(ipsDate),
              capture >= launch
        else { return nil }
        return capture.timeIntervalSince(launch)
    }

    /// `2026-10-05 00:10:46.5678 +0200`, the fraction of any length.
    static func ipsDate(_ text: String) -> Date? {
        guard let match = text.wholeMatch(of: /(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(\.\d+)? ([+-]\d{4})/) else { return nil }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss Z"
        guard let whole = formatter.date(from: "\(match.output.1) \(match.output.3)") else { return nil }
        return whole.addingTimeInterval(match.output.2.flatMap { Double("0" + $0) } ?? 0)
    }

    // MARK: - Turning off

    private func turnOff() async {
        retry?.cancel()
        retry = nil
        generation += 1
        var pending: PendingDeletion?
        if let key = keyStore.load(from: store.identityURL) {
            // Unregistered keys get the delete too: a registration whose answer
            // was lost left an install the server knows and this Mac does not.
            do {
                let body = try envelope(install: key.installID)
                pending = try PendingDeletion(install: key.installID, body: body, signature: key.sign(body), created: now())
            } catch {
                log("could not sign the delete: \(error.localizedDescription)")
            }
        }
        store.wipe(keeping: pending)
        state = LocalState()
        lastFailure = nil
        serviceAbsent = false
        log(pending == nil ? "tier is off; nothing was registered" : "tier is off; local identity destroyed, deleting the install")
        await sendPendingDeletion()
    }

    private func sendPendingDeletion() async {
        guard var pending = store.read(PendingDeletion.self, from: store.pendingDeletionURL) else { return }
        var request = URLRequest(url: configuration.endpoint("installs").appendingPathComponent(pending.install))
        request.httpMethod = "DELETE"
        request.httpBody = pending.body
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(pending.install, forHTTPHeaderField: Self.installHeader)
        request.setValue(pending.signature.base64EncodedString(), forHTTPHeaderField: Self.signatureHeader)
        do {
            _ = try await exchange(request)
            log("the server deleted install \(pending.install)")
            finishDeletion()
        } catch let Failure.refused(status, reason) where (400 ..< 500).contains(status) && status != 429 {
            log("the server refused the delete (\(status))\(reason.map { ": \($0)" } ?? ""); dropping it")
            finishDeletion()
        } catch {
            pending.failures += 1
            store.write(pending, to: store.pendingDeletionURL)
            let wait = Self.wait(afterFailures: pending.failures - 1)
            log("the delete is not sent yet (\(error)); next try in \(wait)")
            scheduleRetry(in: wait)
        }
    }

    private func finishDeletion() {
        store.remove(store.pendingDeletionURL)
        if state.tier == .off { store.remove(store.root) }
    }

    // MARK: - Sending

    /// The tier turned off while a send was in flight.
    struct Superseded: Error {}

    private func drainHeartbeats(generation: Int) async throws {
        let cutoff = now().addingTimeInterval(-Self.queueLife)
        var queue = heartbeatQueue().filter { $0.queued > cutoff }
        while !queue.isEmpty {
            let batch = Array(queue.prefix(Self.heartbeatBatch))
            let key = try await registeredKey(generation: generation)
            let body = try envelope(install: key.installID, heartbeats: batch.map(\.heartbeat))
            let reply = try await request("POST", "heartbeats", body: body, contentType: "application/json", key: key)
            guard generation == self.generation else { throw Superseded() }
            let rejected = Self.rejections(in: reply)
            if !rejected.isEmpty {
                log("the server refused \(rejected.count) of \(batch.count) heartbeats: \(rejected.joined(separator: "; "))")
            }
            queue = heartbeatQueue().filter { item in !batch.contains(item) && item.queued > cutoff }
            store.write(queue, to: store.heartbeatsURL)
            noteSent()
        }
    }

    private func drainCrashReports(generation: Int) async throws {
        let cutoff = now().addingTimeInterval(-Self.queueLife)
        for folder in store.crashReports() {
            guard store.creation(folder) > cutoff,
                  let context = store.read(CrashContext.self, from: folder.appendingPathComponent("context.json"))
            else {
                store.remove(folder)
                continue
            }
            let key = try await registeredKey(generation: generation)
            let files = (try? FileManager.default.contentsOfDirectory(
                at: folder.appendingPathComponent("files"), includingPropertiesForKeys: nil,
            )) ?? []
            let envelope = try envelope(install: key.installID, context: context)
            let (body, contentType) = try Self.multipart(envelope: envelope, files: files)
            do {
                _ = try await request("POST", "crash-reports", body: body, contentType: contentType, key: key)
                log("sent a crash report with \(files.count) files")
            } catch let Failure.refused(status, reason)
                where [400, 403, 413].contains(status) || (status == 429 && reason != Self.perMinuteLimit)
            {
                log("the server refused a crash report (\(status))\(reason.map { ": \($0)" } ?? ""); dropped")
            }
            guard generation == self.generation else { throw Superseded() }
            store.remove(folder)
            noteSent()
        }
    }

    private func noteSent() {
        state.lastSent = now()
        state.lastError = nil
        state.failures = nil
        state.nextTry = nil
        persist()
    }

    /// The multipart body of a crash report: the envelope, then each file.
    static func multipart(envelope: Data, files: [URL]) throws -> (Data, String) {
        let boundary = "digoxin-" + UUID().uuidString
        var body = Data()
        func part(_ disposition: String, type: String, _ content: Data) {
            body.append(Data("--\(boundary)\r\nContent-Disposition: form-data; \(disposition)\r\nContent-Type: \(type)\r\n\r\n".utf8))
            body.append(content)
            body.append(Data("\r\n".utf8))
        }
        part("name=\"envelope\"", type: "application/json", envelope)
        for file in files.sorted(by: { $0.lastPathComponent < $1.lastPathComponent }) {
            try part("name=\"file\"; filename=\"\(file.lastPathComponent)\"", type: "application/octet-stream", Data(contentsOf: file))
        }
        body.append(Data("--\(boundary)--\r\n".utf8))
        return (body, "multipart/form-data; boundary=\(boundary)")
    }

    /// The refusal reasons of a batch, from the server's `202 {accepted, rejected[]}`.
    static func rejections(in reply: Data) -> [String] {
        guard let object = try? JSONSerialization.jsonObject(with: reply) as? [String: Any],
              let rejected = object["rejected"] as? [[String: Any]]
        else { return [] }
        return rejected.map { $0["why"] as? String ?? "no reason given" }
    }

    /// The signed envelope, taking the next sequence number.
    func envelope(install: String, heartbeats: [Heartbeat]? = nil, context: CrashContext? = nil) throws -> Data {
        state.seq += 1
        persist()
        let value = Envelope(
            seq: state.seq, sent: ISO8601DateFormatter().string(from: now()), install: install,
            heartbeats: heartbeats, context: context,
        )
        return try LocalStore.encoder.encode(value)
    }

    // MARK: - Registration

    func loadOrCreateKey() throws -> any InstallKey {
        if let key = keyStore.load(from: store.identityURL) { return key }
        let key = try keyStore.create(at: store.identityURL)
        state.registered = nil
        state.trust = nil
        persist()
        log("created install key \(key.installID)")
        return key
    }

    private func registeredKey(generation: Int) async throws -> any InstallKey {
        guard keyStore.isAvailable else { throw Failure.noSecureEnclave }
        let key = try loadOrCreateKey()
        guard state.registered != key.installID else { return key }
        try await register(key)
        guard generation == self.generation else { throw Superseded() }
        return key
    }

    private struct Challenge: Decodable {
        var challenge: String
    }

    private struct Registered: Decodable {
        var install: String
        var trust: String
    }

    private struct Registration: Encodable {
        struct AppAttest: Encodable {
            var key_id: String
            var attestation: String
        }

        var public_key: String
        var challenge: String
        var version: String
        var app_attest: AppAttest?
        var device_check: String?
    }

    private func register(_ key: any InstallKey) async throws {
        let challengeData = try await exchange(URLRequest(url: configuration.endpoint("challenge")))
        guard let challenge = try? JSONDecoder().decode(Challenge.self, from: challengeData),
              let challengeBytes = Data(base64Encoded: challenge.challenge)
        else { throw Failure.refused(status: 200, reason: "no challenge") }
        let evidence = await attestor.evidence(for: key, challenge: challengeBytes) { [configuration] line in
            configuration.log(line)
        }
        log("registering with \(evidence.tier) evidence")
        var registration = Registration(
            public_key: key.publicKeyDER.base64EncodedString(), challenge: challenge.challenge,
            version: info().appVersion, device_check: evidence.deviceToken?.base64EncodedString(),
        )
        if let keyID = evidence.appAttestKeyID, let attestation = evidence.attestation {
            registration.app_attest = .init(key_id: keyID, attestation: attestation.base64EncodedString())
        }
        let body = try LocalStore.encoder.encode(registration)
        let answer: Data
        do {
            answer = try await request("POST", "installs", body: body, contentType: "application/json", key: key)
        } catch let Failure.refused(status: 429, reason: reason) where reason != Self.perMinuteLimit {
            throw Failure.registrationCapped(reason: reason)
        }
        guard let registered = try? JSONDecoder().decode(Registered.self, from: answer),
              registered.install == key.installID
        else { throw Failure.refused(status: 201, reason: "registration answered another install") }
        state.registered = registered.install
        state.trust = registered.trust
        persist()
        log("registered as \(registered.install) (\(registered.trust))")
    }

    // MARK: - Requests

    static let installHeader = "Digoxin-Install"
    static let signatureHeader = "Digoxin-Signature"

    enum Failure: Error, Equatable {
        case noSecureEnclave
        case unreachable(String)
        case refused(status: Int, reason: String?)
        /// Registration answered 429: this address registered its daily
        /// allowance of new installs.
        case registrationCapped(reason: String?)
    }

    /// How a send failed, as far as what to do next is concerned.
    enum FailureClass: Equatable {
        /// Nothing answers these paths: the service is not deployed (404,
        /// 410, 501). Asking again in this launch would get the same answer.
        case serviceAbsent
        case unreachable
        case serverError
        case refused
        case noSecureEnclave
        case registrationCapped
    }

    static func failureClass(of error: any Error) -> FailureClass {
        switch error as? Failure {
        case .noSecureEnclave: .noSecureEnclave
        case .unreachable: .unreachable
        case .registrationCapped: .registrationCapped
        case let .refused(status, _) where [404, 410, 501].contains(status): .serviceAbsent
        case let .refused(status, _) where status >= 500: .serverError
        case .refused, nil: .refused
        }
    }

    /// The wait after `failures` sends in a row failed, the first at zero.
    static func wait(afterFailures failures: Int) -> Duration {
        backoff[min(max(failures, 0), backoff.count - 1)]
    }

    private func request(_ method: String, _ path: String, body: Data, contentType: String, key: any InstallKey) async throws -> Data {
        var request = URLRequest(url: configuration.endpoint(path))
        request.httpMethod = method
        request.httpBody = body
        request.setValue(contentType, forHTTPHeaderField: "Content-Type")
        request.setValue(key.installID, forHTTPHeaderField: Self.installHeader)
        try request.setValue(key.sign(body).base64EncodedString(), forHTTPHeaderField: Self.signatureHeader)
        return try await exchange(request)
    }

    private func exchange(_ request: URLRequest) async throws -> Data {
        var request = request
        request.timeoutInterval = 30
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            throw Failure.unreachable(error.localizedDescription)
        }
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard (200 ..< 300).contains(status) else {
            let reason = (try? JSONSerialization.jsonObject(with: data) as? [String: Any])?["error"] as? String
            throw Failure.refused(status: status, reason: reason)
        }
        return data
    }

    private func noteFailure(_ error: any Error) {
        let description = switch error as? Failure {
        case .noSecureEnclave: "this Mac has no Secure Enclave"
        case let .unreachable(reason): "unreachable: \(reason)"
        case let .refused(status, reason): "refused (\(status))\(reason.map { ": \($0)" } ?? "")"
        case let .registrationCapped(reason): "registration refused (429)\(reason.map { ": \($0)" } ?? "")"
        case nil: error.localizedDescription
        }
        state.lastError = description
        // A server that forgot this install (a deleted database, retention)
        // answers 401: register again on the next try.
        if case let .refused(status, _) = error as? Failure, status == 401 {
            state.registered = nil
        }
        let failure = Self.failureClass(of: error)
        defer { lastFailure = failure }
        switch failure {
        case .noSecureEnclave:
            persist()
        case .serviceAbsent:
            serviceAbsent = true
            retry?.cancel()
            retry = nil
            state.failures = nil
            state.nextTry = nil
            persist()
            log("the service is not available (\(description)); the queue waits for the next launch")
        case .registrationCapped:
            state.nextTry = now().addingTimeInterval(TimeInterval(Self.registrationCapWait.components.seconds))
            persist()
            if failure != lastFailure { log("this address registered its new installs for today; retrying tomorrow") }
            scheduleRetry(in: Self.registrationCapWait)
        default:
            let failures = state.failures ?? 0
            let wait = Self.wait(afterFailures: failures)
            state.failures = failures + 1
            state.nextTry = now().addingTimeInterval(TimeInterval(wait.components.seconds))
            persist()
            if failure != lastFailure {
                log("send failed, \(description); next try in \(wait), and more failures like it are not logged")
            }
            scheduleRetry(in: wait)
        }
    }

    private func scheduleRetry(in wait: Duration) {
        retry?.cancel()
        retry = Task(name: "Digoxin retry for \(configuration.app)") {
            try? await Task.sleep(for: wait)
            guard !Task.isCancelled else { return }
            self.retry = nil
            await self.flush()
        }
    }
}
