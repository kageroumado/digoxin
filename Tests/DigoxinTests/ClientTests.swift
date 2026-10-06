import CryptoKit
import Foundation
import Testing
@testable import Digoxin

/// 2026-10-05 10:00 in Paris.
let morning = Date(timeIntervalSince1970: 1_791_187_200)

@Suite struct ClientTests {
    let server = FakeServer()
    let storage = temporaryFolder()
    let clock = TestClock(morning)

    var root: URL { storage.appendingPathComponent("Digoxin") }

    func client(keyStore: any InstallKeyStore = SoftwareKeyStore()) -> Digoxin {
        makeClient(server: server, storage: storage, clock: clock, keyStore: keyStore)
    }

    @Test func offSendsNothingAndKeepsNothing() async throws {
        let digoxin = client()
        #expect(await digoxin.tier == .off)
        await digoxin.recordUse()
        await digoxin.submitCrashReport(files: [writeIPS()])
        await digoxin.flush()
        #expect(server.requests.isEmpty)
        #expect(!FileManager.default.fileExists(atPath: root.path))
        #expect(await digoxin.status == .off)
    }

    @Test func countingSendsOneSignedHeartbeatPerDayOfUse() async throws {
        let digoxin = client()
        await digoxin.setTier(.counting)
        await digoxin.recordUse()
        await digoxin.recordUse()
        #expect(server.requests("POST", "/installs").count == 1)
        let first = try #require(server.requests("POST", "/heartbeats").first?.json)
        let beat = try #require((first["heartbeats"] as? [[String: Any]])?.first)
        #expect(beat["day"] as? String == "2026-10-05")
        #expect(beat["activeDays7"] as? Int == 1)
        #expect(beat["chipFamily"] as? String == "M3")
        #expect(beat["memoryClassGB"] as? Int == 36)
        #expect((beat["properties"] as? [String: Any])?["chromiumInstalled"] as? Bool == true)
        #expect(Set(beat.keys) == ["appVersion", "appBuild", "os", "arch", "chipFamily", "memoryClassGB", "language", "day", "activeDays7", "properties"])
        #expect(server.requests("POST", "/heartbeats").count == 1)

        clock.advance(days: 2)
        await digoxin.recordUse()
        let heartbeats = server.requests("POST", "/heartbeats")
        #expect(heartbeats.count == 2)
        let second = try #require((heartbeats[1].json?["heartbeats"] as? [[String: Any]])?.first)
        #expect(second["day"] as? String == "2026-10-07")
        #expect(second["activeDays7"] as? Int == 2)
        #expect((heartbeats[1].json?["seq"] as? Int ?? 0) > (first["seq"] as? Int ?? 0))
        #expect(await digoxin.status == .registered(trust: "unverified"))
        let path = try #require(heartbeats.first?.path)
        #expect(path == "/api/v1/refrax/heartbeats")
    }

    @Test func activeDaysCountOnlyTheLastWeek() async throws {
        let digoxin = client()
        await digoxin.setTier(.counting)
        for _ in 0 ..< 9 {
            await digoxin.recordUse()
            clock.advance(days: 1)
        }
        let last = try #require(server.requests("POST", "/heartbeats").last?.json?["heartbeats"] as? [[String: Any]])
        #expect(last.first?["activeDays7"] as? Int == 7)
    }

    @Test func offlineHeartbeatsWaitAndGoTogether() async throws {
        let digoxin = client()
        await digoxin.setTier(.counting)
        server.setOffline(true)
        await digoxin.recordUse()
        guard case .failing = await digoxin.status else {
            Issue.record("an unreachable server is not a failure")
            return
        }
        clock.advance(days: 1)
        await digoxin.recordUse() // queued; the send fails again
        server.setOffline(false)
        #expect(server.requests.isEmpty)
        clock.advance(seconds: 3600)
        await digoxin.flush()
        let batches = server.requests("POST", "/heartbeats")
        #expect(batches.count == 1)
        #expect((batches.first?.json?["heartbeats"] as? [Any])?.count == 2)
        #expect(await digoxin.status == .registered(trust: "unverified"))
    }

    @Test func aServerThatForgotTheInstallGetsItAgain() async throws {
        let digoxin = client()
        await digoxin.setTier(.counting)
        await digoxin.recordUse()
        server.forget()
        clock.advance(days: 1)
        await digoxin.recordUse() // 401, then a fresh registration on the next try
        clock.advance(seconds: 120)
        await digoxin.flush()
        #expect(server.requests("POST", "/installs").count == 2)
        #expect(server.requests("POST", "/heartbeats").count == 3)
    }

    @Test func noSecureEnclaveMeansNoIdentityAndNothingSent() async throws {
        let digoxin = client(keyStore: SoftwareKeyStore(isAvailable: false))
        await digoxin.setTier(.crashReports)
        await digoxin.recordUse()
        await digoxin.submitCrashReport(files: [writeIPS()])
        #expect(await digoxin.status == .secureEnclaveUnavailable)
        #expect(server.requests.isEmpty)
        #expect(!FileManager.default.fileExists(atPath: root.appendingPathComponent("identity.key").path))
    }

    @Test func crashReportsAreScrubbedBeforeTheyLeave() async throws {
        let digoxin = client()
        await digoxin.setTier(.counting)
        await digoxin.submitCrashReport(files: [writeIPS()])
        #expect(server.requests("POST", "/crash-reports").isEmpty, "counting sends no crash reports")

        await digoxin.setTier(.crashReports)
        let home = CrashReportScrubber.Machine.current.home
        await digoxin.submitCrashReport(
            files: [writeIPS(home: home), writeText("exception.log", "thrown at \(home)/Code/x.swift")],
            context: ["consecutiveLaunchCrashes": 2, "openTabs": 9],
        )
        let report = try #require(server.requests("POST", "/crash-reports").first)
        let envelope = try #require(report.envelope)
        let context = try #require(envelope["context"] as? [String: Any])
        #expect(context["installLocation"] as? String == "applications")
        #expect(context["consecutiveLaunchCrashes"] as? Int == 2)
        #expect(abs((context["secondsSinceLaunch"] as? Double ?? 0) - 81.5) < 0.001)
        #expect(context["fields"] as? [String: AnyHashable] == ["engines": "webkit-621", "openTabs": 9])
        let files = report.parts.filter { $0.name == "file" }
        #expect(files.map(\.filename) == ["Refrax-2026-10-05-001046.ips", "exception.log"])
        for file in files {
            let text = String(decoding: file.data, as: UTF8.self)
            #expect(!text.contains(home), "\(file.filename ?? "")")
            #expect(text.contains("~/") || text.contains("~\\/"))
        }
        let queued = (try? FileManager.default.contentsOfDirectory(atPath: root.appendingPathComponent("crashes").path)) ?? []
        #expect(queued.isEmpty, "a sent report leaves the queue")
    }

    @Test func turningOffDeletesTheInstallEverywhere() async throws {
        let digoxin = client()
        await digoxin.setTier(.crashReports)
        await digoxin.recordUse()
        #expect(server.installs.count == 1)
        await digoxin.setTier(.off)
        let delete = try #require(server.requests("DELETE", "").first)
        #expect(delete.path == "/api/v1/refrax/installs/\(server.requests("POST", "/installs")[0].headers["Digoxin-Install"] ?? "")")
        #expect(server.installs.isEmpty)
        #expect(!FileManager.default.fileExists(atPath: root.path))
        #expect(await digoxin.status == .off)
    }

    @Test func turningOffOfflineDestroysTheKeyAtOnceAndDeletesLater() async throws {
        let digoxin = client()
        await digoxin.setTier(.counting)
        await digoxin.recordUse()
        server.setOffline(true)
        await digoxin.setTier(.off)
        #expect(await digoxin.status == .deletionPending)
        let left = try FileManager.default.contentsOfDirectory(atPath: root.path)
        #expect(left == ["pending-deletions"], "only the signed delete is kept, never the key")
        #expect(try FileManager.default.contentsOfDirectory(atPath: root.appendingPathComponent("pending-deletions").path).count == 1)

        clock.advance(days: 5)
        server.setOffline(false)
        await digoxin.recordUse() // off: counts nothing, but finishes the delete
        #expect(server.requests("DELETE", "").count == 1)
        #expect(server.installs.isEmpty)
        #expect(server.requests("POST", "/heartbeats").count == 1)
        #expect(!FileManager.default.fileExists(atPath: root.path))
        #expect(await digoxin.status == .off)
    }

    /// A server that forgot the install answers the delete 401, as it
    /// answers any request it cannot verify; the client then has nothing
    /// left to delete.
    @Test func aDeleteTheServerCannotPlaceIsDone() async throws {
        let digoxin = client()
        await digoxin.setTier(.counting)
        await digoxin.recordUse()
        server.forget()
        await digoxin.setTier(.off)
        #expect(server.requests("DELETE", "").count == 1)
        #expect(await digoxin.status == .off)
        #expect(!FileManager.default.fileExists(atPath: root.path))
    }

    /// Each install retired offline keeps its own delete: its key is gone,
    /// so a delete overwritten would leave it on the server for good.
    @Test func everyInstallTurnedOffOfflineIsDeleted() async throws {
        let digoxin = client()
        await digoxin.setTier(.counting)
        await digoxin.recordUse()
        let first = try #require(server.installs.first)
        server.setOffline(true)
        await digoxin.setTier(.off)
        await digoxin.setTier(.counting)
        await digoxin.recordUse()
        await digoxin.setTier(.off)
        #expect(try FileManager.default.contentsOfDirectory(atPath: root.appendingPathComponent("pending-deletions").path).count == 2)

        server.setOffline(false)
        await digoxin.flush()
        #expect(!server.installs.contains(first))
        #expect(server.installs.isEmpty)
        #expect(server.requests("DELETE", "").count == 2)
        #expect(!FileManager.default.fileExists(atPath: root.path))
        #expect(await digoxin.status == .off)
    }

    /// Turned off while the attestation is made, the registration stops
    /// there: its key is already destroyed and its delete sent.
    @Test func turningOffDuringAttestationRegistersNothing() async throws {
        let attestor = PausedAttestor()
        let digoxin = makeClient(server: server, storage: storage, clock: clock, attestor: attestor)
        await digoxin.setTier(.counting)
        let using = Task { await digoxin.recordUse() }
        await attestor.waitUntilEntered()
        await digoxin.setTier(.off)
        await attestor.resume()
        await using.value
        #expect(server.requests("POST", "/installs").isEmpty)
        #expect(server.installs.isEmpty)
        #expect(await digoxin.status == .off)
        #expect(!FileManager.default.fileExists(atPath: root.path))
    }

    /// Turned off while the registration is on its way, the delete waits for
    /// it: sent first, it would find nothing, and the registration would land
    /// after it.
    @Test func turningOffDuringRegistrationDeletesAfterIt() async throws {
        let hold = server.holdRegistrations()
        let digoxin = client()
        await digoxin.setTier(.counting)
        let using = Task { await digoxin.recordUse() }
        await hold.arrival()
        let turningOff = Task { await digoxin.setTier(.off) }
        try await Task.sleep(for: .milliseconds(100))
        hold.release.signal()
        await turningOff.value
        await using.value
        #expect(server.requests.map(\.method).filter { $0 != "GET" } == ["POST", "DELETE"], "the registration, then its delete")
        #expect(server.installs.isEmpty)
        #expect(server.requests("POST", "/heartbeats").isEmpty)
        #expect(await digoxin.status == .off)
    }

    /// The server reads every day as a Gregorian date, whatever calendar
    /// the person reads dates in.
    @Test(arguments: [Calendar.Identifier.buddhist, .japanese, .persian])
    func daysAreGregorian(in identifier: Calendar.Identifier) async {
        var calendar = Calendar(identifier: identifier)
        calendar.timeZone = TimeZone(identifier: "Europe/Paris")!
        let digoxin = makeClient(server: server, storage: storage, clock: clock, calendar: calendar)
        #expect(await digoxin.dayKey(morning) == "2026-10-05")
    }

    @Test func stateSurvivesARelaunch() async throws {
        let first = client()
        await first.setTier(.counting)
        await first.recordUse()
        let relaunched = client()
        #expect(await relaunched.tier == .counting)
        await relaunched.recordUse()
        #expect(server.requests("POST", "/heartbeats").count == 1, "the day was already counted")
        clock.advance(days: 1)
        await relaunched.recordUse()
        #expect(server.requests("POST", "/installs").count == 1)
        #expect(server.requests("POST", "/heartbeats").count == 2)
    }

    @Test func aMissingServiceIsAskedAgainOnlyNextLaunch() async throws {
        let digoxin = client()
        await digoxin.setTier(.counting)
        server.script(404)
        await digoxin.recordUse()
        let asked = server.requests.count
        clock.advance(days: 1)
        await digoxin.recordUse()
        #expect(server.requests.count == asked)
    }

    // MARK: - Fixtures

    func writeIPS(home: String = "/Users/alice") -> URL {
        let text = ipsFixture.replacingOccurrences(of: "\\/Users\\/alice", with: home.replacingOccurrences(of: "/", with: "\\/"))
        return writeText("Refrax-2026-10-05-001046.ips", text)
    }

    func writeText(_ name: String, _ text: String) -> URL {
        let url = storage.appendingPathComponent("input").appendingPathComponent(name)
        try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? Data(text.utf8).write(to: url)
        return url
    }
}

@Suite struct BasicInfoTests {
    @Test func chipFamilies() {
        #expect(BasicInfo.chipFamily(brand: "Apple M3 Pro") == "M3")
        #expect(BasicInfo.chipFamily(brand: "Apple M1") == "M1")
        #expect(BasicInfo.chipFamily(brand: "Apple M10 Ultra") == "M10")
        #expect(BasicInfo.chipFamily(brand: "Intel(R) Core(TM) i9-9980HK CPU @ 2.40GHz") == "Intel")
        #expect(BasicInfo.chipFamily(brand: "VirtualApple @ 2.50GHz processor") == "unknown")
    }

    @Test func memoryClasses() {
        let gb: UInt64 = 1 << 30
        #expect(BasicInfo.memoryClass(bytes: 8 * gb) == 8)
        #expect(BasicInfo.memoryClass(bytes: 18 * gb) == 16)
        #expect(BasicInfo.memoryClass(bytes: 36 * gb) == 36)
        #expect(BasicInfo.memoryClass(bytes: 192 * gb) == 128)
        #expect(BasicInfo.memoryClass(bytes: 4 * gb) == 8)
    }

    @Test func languages() {
        #expect(BasicInfo.language(preferred: ["fr-FR", "en"]) == "fr")
        #expect(BasicInfo.language(preferred: ["zh-Hans-CN"]) == "zh")
        #expect(BasicInfo.language(preferred: []) == "xx")
    }

    @Test func thisMacsInfoIsInRange() {
        let info = BasicInfo.current()
        #expect(info.os.wholeMatch(of: /\d{2}\.\d{1,2}/) != nil)
        #expect(BasicInfo.memoryClasses.contains(info.memoryClassGB))
        #expect(info.chipFamily.wholeMatch(of: /M\d+|Intel|unknown/) != nil)
        #expect(info.language.count == 2)
    }

    @Test func installLocationsAndFileNames() {
        #expect(Digoxin.installLocation(bundlePath: "/Applications/Refrax.app") == "applications")
        #expect(Digoxin.installLocation(bundlePath: "/Users/alice/Applications/Refrax.app") == "applications")
        #expect(Digoxin.installLocation(bundlePath: "/private/var/folders/x/T/AppTranslocation/ABC/d/Refrax.app") == "translocated")
        #expect(Digoxin.installLocation(bundlePath: "/Users/alice/Downloads/Refrax.app") == "other")
        #expect(Digoxin.fileName("Refrax 2026-10-05.ips") == "Refrax-2026-10-05.ips")
        #expect(Digoxin.fileName("../.hidden") == "hidden")
        #expect(Digoxin.fileName("日本.log") == "log")
    }

    @Test func ipsLaunchTimes() throws {
        let seconds = try #require(Digoxin.secondsSinceLaunch(ips: Data(ipsFixture.utf8)))
        #expect(abs(seconds - 81.5) < 0.0001)
    }

    @Test func attestationsCoverTheDeviceToken() {
        // The Go service's TestClientDataHashBindsKeyChallengeAndToken.
        let key = Data("key".utf8), challenge = Data("challenge".utf8)
        let expected = Data(SHA256.hash(data: key + challenge + Data(SHA256.hash(data: Data("token".utf8)))))
        #expect(clientDataHash(publicKeyDER: key, challenge: challenge, deviceToken: Data("token".utf8)) == expected)
        let empty = Data(SHA256.hash(data: key + challenge + Data(SHA256.hash(data: Data()))))
        #expect(clientDataHash(publicKeyDER: key, challenge: challenge, deviceToken: nil) == empty)
    }

    @Test func installIDsMatchTheServer() {
        // The Go service's vector: base32(sha256(bytes(range(91)))).lower()[:26].
        #expect(makeInstallID(publicKeyDER: Data((0 ..< 91).map(UInt8.init))) == "ldjjiwnscmfc4fisklkarok6nw")
        #expect(Base32.encode(Data("foobar".utf8)) == "mzxw6ytboi")
    }
}
