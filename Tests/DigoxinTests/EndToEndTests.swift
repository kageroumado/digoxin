import Foundation
import Testing
@testable import Digoxin

/// The whole path against a running Go service: the public initializer,
/// this Mac's Secure Enclave, Apple's attestation services (which decline
/// in a test process, so the install registers `unverified`), and the
/// service's admin API to see what arrived. Runs when `DIGOXIN_E2E_URL` and
/// `DIGOXIN_E2E_ADMIN` name a service started with an app called `e2e`;
/// `Scripts/e2e.sh` does that.
@Suite(.enabled(if: ProcessInfo.processInfo.environment["DIGOXIN_E2E_URL"] != nil), .serialized)
struct EndToEndTests {
    let baseURL = URL(string: ProcessInfo.processInfo.environment["DIGOXIN_E2E_URL"] ?? "http://127.0.0.1:1")!
    let admin = URL(string: ProcessInfo.processInfo.environment["DIGOXIN_E2E_ADMIN"] ?? "http://127.0.0.1:1")!

    func adminJSON(_ path: String) async throws -> (Int, Any?) {
        let (data, response) = try await URLSession.shared.data(from: admin.appendingPathComponent(path))
        return ((response as? HTTPURLResponse)?.statusCode ?? 0, try? JSONSerialization.jsonObject(with: data))
    }

    func show(_ label: String, _ value: Any?) {
        let text = value.flatMap { JSONSerialization.isValidJSONObject($0) ? $0 : nil }
            .flatMap { try? JSONSerialization.data(withJSONObject: $0, options: [.sortedKeys]) }
            .map { String(decoding: $0, as: UTF8.self) } ?? "\(value ?? "nil")"
        print("e2e \(label): \(text)")
    }

    @Test func registerCountCrashThenDelete() async throws {
        let storage = temporaryFolder()
        let digoxin = Digoxin(configuration: .init(
            app: "e2e", baseURL: baseURL, storageDirectory: storage,
            propertiesProvider: { ["chromiumInstalled": true, "notAllowlisted": "dropped"] },
            crashContextProvider: { ["engines": "webkit-621"] },
            log: { print("client: \($0)") },
        ))
        await digoxin.setTier(.crashReports)
        await digoxin.recordUse()
        let status = await digoxin.status
        show("status after first use", "\(status)")
        guard case let .registered(trust) = status else {
            Issue.record("not registered: \(status)")
            return
        }
        #expect(trust == "unverified")
        let install = try #require(await digoxin.state.registered)

        let home = CrashReportScrubber.Machine.current.home
        let ips = storage.appendingPathComponent("e2e-2026-10-05-001046.ips")
        try Data(ipsFixture.replacingOccurrences(of: "\\/Users\\/alice", with: home.replacingOccurrences(of: "/", with: "\\/")).utf8)
            .write(to: ips)
        await digoxin.submitCrashReport(files: [ips], context: ["consecutiveLaunchCrashes": 1])

        let (_, stats) = try await adminJSON("admin/e2e/stats")
        show("stats", stats)
        let actives = (stats as? [String: Any])?["actives"] as? [String: [String: Int]]
        #expect(actives?["dau"]?["unverified"] == 1)
        #expect(((stats as? [String: Any])?["properties"] as? [String: Any])?["notAllowlisted"] == nil)

        let (_, crashes) = try await adminJSON("admin/e2e/crashes")
        show("crashes", crashes)
        let report = try #require((crashes as? [[String: Any]])?.first)
        let id = try #require(report["id"] as? String)
        let (data, _) = try await URLSession.shared.data(
            from: admin.appendingPathComponent("admin/e2e/crashes/\(id)/files/e2e-2026-10-05-001046.ips"),
        )
        let stored = String(decoding: data, as: UTF8.self)
        print("e2e stored .ips, first 300 bytes of the body: \(stored.dropFirst(stored.firstIndex(of: "\n").map { stored.distance(from: stored.startIndex, to: $0) } ?? 0).prefix(300))")
        #expect(!stored.contains(home))
        #expect(!stored.contains("9CE69F15"))

        let (before, _) = try await adminJSON("admin/e2e/installs/\(install)")
        await digoxin.setTier(.off)
        let (after, _) = try await adminJSON("admin/e2e/installs/\(install)")
        let (_, crashesAfter) = try await adminJSON("admin/e2e/crashes")
        show("install \(install) before off / after off", "\(before) / \(after)")
        show("crashes after off", crashesAfter)
        #expect(before == 200 && after == 404)
        #expect((crashesAfter as? [Any])?.isEmpty == true)
        #expect(await digoxin.status == .off)
        #expect(!FileManager.default.fileExists(atPath: storage.appendingPathComponent("Digoxin").path))
    }
}
