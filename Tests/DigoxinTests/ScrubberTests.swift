import Foundation
import Testing
@testable import Digoxin

/// A made-up Mac, so the fixtures name nobody real.
let alice = CrashReportScrubber.Machine(
    home: "/Users/alice", userName: "alice", fullName: "Alice Liddell",
    hostNames: ["Alices-MacBook-Pro", "Alice’s MacBook Pro", "localhost", "ab"],
)

/// An `.ips` report shaped like the system's: a header line, then a body
/// with every field the scrubber rewrites, and the numbers it must keep.
let ipsFixture = #"""
{"app_name":"Refrax","timestamp":"2026-10-05 00:10:46.00 +0200","app_version":"0.34","slice_uuid":"eda0c22e-8ca4-3b60-ab95-2406d492017d","build_version":"41","platform":1,"bundleID":"website.refrax.browser","share_with_app_devs":0,"is_first_party":0,"bug_type":"309","os_version":"macOS 27.0.1 (26A434)","roots_installed":0,"name":"Refrax","incident_id":"39FBD650-8675-4ADD-8CEB-248F38A93CBE"}
{
  "uptime" : 1000,
  "procRole" : "Foreground",
  "userID" : 501,
  "modelCode" : "Mac13,1",
  "captureTime" : "2026-10-05 00:10:46.5678 +0200",
  "procLaunch" : "2026-10-05 00:09:25.0678 +0200",
  "incident" : "39FBD650-8675-4ADD-8CEB-248F38A93CBE",
  "procPath" : "\/Users\/alice\/Applications\/Refrax.app\/Contents\/MacOS\/Refrax",
  "coalitionName" : "com.apple.CoreSimulator.SimDevice.3DD4FD53-FEB9-4B96-943E-C5EE18CA10C3",
  "crashReporterKey" : "9CE69F15-4FAD-16A7-5D92-0CF44D76A81A",
  "bootSessionUUID" : "1D2B6F0A-5C3E-4C1B-9E55-7A0D3F1E2B44",
  "sleepWakeUUID" : "AF0E9B7C-1234-4D5E-8F90-ABCDEF012345",
  "storeInfo" : {"deviceIdentifierForVendor":"9CA13F44-2AF4-5F02-AC7B-AE59409ABE86","thirdParty":true},
  "sharedCache" : {"base":6815612928,"size":7410368512,"uuid":"c284a291-b68b-3d0d-a1a0-3f866f87efdc"},
  "threads" : [{"triggered":true,"id":9356851,"threadState":{"x":[{"value":18446744072367376383},{"value":4401531776,"objc-selector":"loadURL:"},{"value":521000432128,"description":" \"https:\/\/alice:hunter2@example.com:8443\/inbox?token=abc#top\""}]},"queue":"com.apple.main-thread","name":"Alice Liddell’s worker \"main\""}],
  "usedImages" : [{"source":"P","arch":"arm64e","base":4343250944,"size":622592,"uuid":"230a6330-9cd9-31ab-9b1c-3025ddf7482f","path":"\/Users\/alice\/Library\/Frameworks\/Engine.framework\/Engine","name":"Engine"},{"source":"P","arch":"arm64e","base":4339220480,"size":16384,"uuid":"9f4808a7-e620-371e-b8ac-090cbc8473b2","path":"\/private\/var\/folders\/x7\/q2kxk_3d1k5b8m\/T\/AppTranslocation\/6B3E2D94-8D3A-4C1A-9C77-0F5E8B1A2C3D\/d\/Refrax.app\/Contents\/MacOS\/Refrax","name":"Refrax"}],
  "vmRegionInfo" : "0x0 is not in any region.  REGION TYPE  START - END  [ VSIZE] PRT\/MAX SHRMOD  REGION DETAIL\n  mapped file  1000-2000 [ 4K] r--\/r-- SM=COW  \/Volumes\/Alice Photos\/Library.photoslibrary\/db",
  "asi" : {"Refrax":["Signed in as alice@example.org on Alices-MacBook-Pro.local, file:\/\/\/Users\/alice\/Downloads\/a.pdf"]},
  "bug_type" : "309"
}
"""#

/// The two JSON documents of an `.ips` file.
func ipsDocuments(_ data: Data) throws -> (header: [String: Any], body: [String: Any]) {
    let text = String(decoding: data, as: UTF8.self)
    let newline = try #require(text.firstIndex(of: "\n"))
    let header = try JSONSerialization.jsonObject(with: Data(text[..<newline].utf8)) as? [String: Any]
    let body = try JSONSerialization.jsonObject(with: Data(text[text.index(after: newline)...].utf8)) as? [String: Any]
    return try (#require(header), #require(body))
}

@Suite struct ScrubberTests {
    let scrubber = CrashReportScrubber(machine: alice)

    @Test func ipsStaysValidJSONAndKeepsWhatSymbolicates() throws {
        let scrubbed = scrubber.scrub(Data(ipsFixture.utf8))
        let (header, body) = try ipsDocuments(scrubbed)
        #expect(header["slice_uuid"] as? String == "eda0c22e-8ca4-3b60-ab95-2406d492017d")
        #expect(header["incident_id"] as? String == "39FBD650-8675-4ADD-8CEB-248F38A93CBE")
        let images = try #require(body["usedImages"] as? [[String: Any]])
        #expect(images.map { $0["uuid"] as? String } == ["230a6330-9cd9-31ab-9b1c-3025ddf7482f", "9f4808a7-e620-371e-b8ac-090cbc8473b2"])
        #expect(images.map { $0["base"] as? Int } == [4_343_250_944, 4_339_220_480])
        #expect((body["sharedCache"] as? [String: Any])?["uuid"] as? String == "c284a291-b68b-3d0d-a1a0-3f866f87efdc")
        // A register value past Int64 survives byte for byte: the scrubber
        // never re-serializes a number.
        #expect(String(decoding: scrubbed, as: UTF8.self).contains("{\"value\":18446744072367376383}"))
    }

    @Test func ipsLosesTheMachineAndThePerson() throws {
        let scrubbed = scrubber.scrub(Data(ipsFixture.utf8))
        let text = String(decoding: scrubbed, as: UTF8.self)
        let (_, body) = try ipsDocuments(scrubbed)
        let zero = CrashReportScrubber.zeroUUID
        #expect(body["crashReporterKey"] as? String == zero)
        #expect(body["bootSessionUUID"] as? String == zero)
        #expect(body["sleepWakeUUID"] as? String == zero)
        #expect((body["storeInfo"] as? [String: Any])?["deviceIdentifierForVendor"] as? String == zero)
        #expect(body["coalitionName"] as? String == "com.apple.CoreSimulator.SimDevice.\(zero)")
        #expect(body["procPath"] as? String == "~/Applications/Refrax.app/Contents/MacOS/Refrax")
        let images = try #require(body["usedImages"] as? [[String: Any]])
        #expect(images[0]["path"] as? String == "~/Library/Frameworks/Engine.framework/Engine")
        #expect(images[1]["path"] as? String == "/private/var/folders/<tmp>/T/AppTranslocation/\(zero)/d/Refrax.app/Contents/MacOS/Refrax")
        #expect((body["vmRegionInfo"] as? String)?.hasSuffix("/Volumes/<volume>/Library.photoslibrary/db") == true)
        let asi = try #require((body["asi"] as? [String: [String]])?["Refrax"]?.first)
        #expect(asi == "Signed in as <email> on <host>.local, file://~/Downloads/a.pdf")
        #expect(text.contains(#"" \"https:\/\/example.com\"""#))
        for leak in ["alice", "Alice", "hunter2", "inbox", "token=abc", "8443", "Photos", "9CE69F15", "1D2B6F0A", "AF0E9B7C", "9CA13F44", "3DD4FD53", "x7\\/q2kxk"] {
            #expect(!text.contains(leak), "\(leak) is still in the report")
        }
    }

    @Test func escapedStringsComeBackEscaped() throws {
        let json = #"{"a":"quote \" and é and \/Users\/alice\/x","b":"tab\there \/Users\/alice"}"#
        let scrubbed = scrubber.scrub(Data(json.utf8))
        let object = try #require(try JSONSerialization.jsonObject(with: scrubbed) as? [String: String])
        #expect(object["a"] == "quote \" and é and ~/x")
        #expect(object["b"] == "tab\there ~")
    }

    @Test func untouchedFilesAreByteIdentical() {
        let json = #"{"value":18446744072367376383,"path":"\/System\/Library\/Frameworks\/AppKit.framework\/AppKit"}"#
        #expect(scrubber.scrub(Data(json.utf8)) == Data(json.utf8))
    }

    @Test func textLogsGetTheSameRewritesAndLoseLegacyIDs() {
        let log = """
        Process:               Refrax [4242]
        Path:                  /Users/alice/Applications/Refrax.app/Contents/MacOS/Refrax
        Anonymous UUID:        0C4B5B3E-1111-2222-3333-444455556666
        Sleep/Wake UUID:       AF0E9B7C-1234-4D5E-8F90-ABCDEF012345
        CrashReporter Key:     9CE69F15-4FAD-16A7-5D92-0CF44D76A81A
        Binary Images: 0x100000000 - 0x100ffffff Refrax <230a6330-9cd9-31ab-9b1c-3025ddf7482f> /Users/alice/x
        User alice opened https://example.com/docs?ref=alice on Alices-MacBook-Pro
        """
        let scrubbed = scrubber.scrub(log)
        #expect(scrubbed.contains("Path:                  ~/Applications/Refrax.app"))
        #expect(scrubbed.contains("Anonymous UUID: <removed>"))
        #expect(scrubbed.contains("Sleep/Wake UUID: <removed>"))
        #expect(scrubbed.contains("CrashReporter Key: <removed>"))
        #expect(scrubbed.contains("<230a6330-9cd9-31ab-9b1c-3025ddf7482f>"), "image UUIDs symbolicate the report")
        #expect(scrubbed.contains("User <user> opened https://example.com on <host>"))
        #expect(!scrubbed.lowercased().contains("alice"))
    }

    /// A log line can open with a bracket and still be no JSON at all.
    @Test func bracketedLogsAreScrubbedAsText() {
        let log = "[2026-10-05 12:00:00] Alices-MacBook-Pro failed opening /Users/alice/private.txt; alice@example.com; https://example.com/private?token=SECRET"
        #expect(scrubber.scrub(log) == "[2026-10-05 12:00:00] <host> failed opening ~/private.txt; <email>; https://example.com")
    }

    /// A report cut off mid-file is no JSON: scrubbed as text, it still loses
    /// its paths, its ids and the string left open at the cut.
    @Test func truncatedReportsLoseTheMachineToo() {
        let cut = ipsFixture.range(of: "\"asi\"")!.lowerBound
        let truncated = String(ipsFixture[..<cut]) + #""asi" : {"Refrax":["Signed in as alice@example.org, file:\/\/\/Users\/alice"#
        let text = scrubber.scrub(truncated)
        #expect(text.contains(#""crashReporterKey" : "\#(CrashReportScrubber.zeroUUID)""#))
        #expect(text.contains("\"procPath\" : \"~/Applications/Refrax.app/Contents/MacOS/Refrax\""))
        #expect(text.contains("230a6330-9cd9-31ab-9b1c-3025ddf7482f"), "image UUIDs symbolicate the report")
        for leak in ["alice", "Alice", "hunter2", "token=abc", "9CE69F15", "1D2B6F0A", "AF0E9B7C", "9CA13F44"] {
            #expect(!text.contains(leak), "\(leak) is still in the report")
        }
    }

    /// `JSONSerialization` reads UTF-16 and UTF-32 as well, where a NUL
    /// stands between the letters of every ASCII name.
    @Test(arguments: [String.Encoding.utf16LittleEndian, .utf16BigEndian, .utf32LittleEndian, .utf32BigEndian])
    func wideEncodingsAreScrubbedToo(_ encoding: String.Encoding) throws {
        let inputs = [
            #"{"p":"\/Users\/alice\/x alice@example.com","h":"Alice’s MacBook Pro"}"#,
            "[x] /Users/alice/y alice@example.com on Alice’s MacBook Pro",
            "\u{FEFF}[x] Alice Liddell on Alice’s MacBook Pro",
        ]
        for input in inputs {
            let scrubbed = scrubber.scrub(try #require(input.data(using: encoding)))
            #expect(!scrubbed.contains(0))
            let text = String(decoding: scrubbed, as: UTF8.self)
            #expect(!text.lowercased().contains("alice") && !text.contains("MacBook"), "\(text)")
        }
    }

    /// Binary whose second byte is NUL is no UTF-16: read as UTF-16 its
    /// ASCII would become CJK, out of every rewrite's reach.
    @Test func binaryWithNULsKeepsItsASCIIScrubbable() {
        var data = Data([0x7F, 0x00, 0xC3, 0x9A, 0xE1, 0x80, 0xF0])
        data += Data("/Users/alice/secret.txt".utf8) + Data([0x00, 0x8A, 0x91])
        let text = String(decoding: scrubber.scrub(data), as: UTF8.self)
        #expect(text.contains("~/secret.txt"))
        #expect(!text.contains("alice"))
    }

    /// UTF-16 for a while and UTF-8 after: read whole as UTF-16, the UTF-8
    /// half would become CJK that hides its ASCII, two letters a character.
    @Test(arguments: [String.Encoding.utf16LittleEndian, .utf16BigEndian, .utf32LittleEndian, .utf32BigEndian])
    func mixedEncodingsHideNothing(_ encoding: String.Encoding) throws {
        let data = try #require("[x] started on Alice’s MacBook Pro\n".data(using: encoding))
            + Data("[y] /Users/alice/secret.txt alice@example.com\n".utf8)
        let scrubbed = scrubber.scrub(data)
        let text = String(decoding: scrubbed, as: UTF8.self)
        #expect(text.contains("~/secret.txt <email>"), "\(text)")
        for reading in [String.Encoding.utf16LittleEndian, .utf16BigEndian] {
            let reread = text.data(using: reading).map { String(decoding: $0, as: UTF8.self) } ?? ""
            #expect(!reread.contains("alice"), "the UTF-8 half survives as \(reading)")
        }
    }

    /// One malformed unit or a cut last byte loses that character, never
    /// the decoding of the rest.
    @Test func damagedWideTextIsStillDecoded() throws {
        let data = try #require("Alice’s MacBook Pro ".data(using: .utf16LittleEndian))
            + Data([0x00, 0xD8]) + #require(" Alice Liddell".data(using: .utf16LittleEndian)) + Data([0x41])
        let text = String(decoding: scrubber.scrub(data), as: UTF8.self)
        #expect(text == "<host> \u{FFFD} <user>")
    }

    /// Keys are text too: an app's JSON can key a dictionary by path,
    /// address or host, while a report's own keys stay as they are.
    @Test func keysAreScrubbedLikeValues() throws {
        let json = #"{"\/Users\/alice\/doc.txt":3,"alice@example.com":{"Alices-MacBook-Pro":true},"usedImages":[]}"#
        let object = try #require(try JSONSerialization.jsonObject(with: scrubber.scrub(Data(json.utf8))) as? [String: Any])
        #expect(Set(object.keys) == ["~/doc.txt", "<email>", "usedImages"])
        #expect((object["<email>"] as? [String: Bool])?.keys.first == "<host>")
    }

    @Test func appRulesRunToo() throws {
        let rules: [ScrubRule] = [
            .replacing("Profile 7", with: "<profile>"),
            .pattern("tab-[0-9]+", with: "tab-#"),
            .clearingField("windowTitle"),
        ]
        let scrubber = CrashReportScrubber(machine: alice, extraRules: rules)
        let json = #"{"windowTitle":"Bank of Alice — Statement","note":"Profile 7 crashed in tab-1234"}"#
        let object = try #require(try JSONSerialization.jsonObject(with: scrubber.scrub(Data(json.utf8))) as? [String: String])
        #expect(object["windowTitle"] == "<removed>")
        #expect(object["note"] == "<profile> crashed in tab-#")
    }

    /// Every report on this Mac, scrubbed as this Mac: still two JSON
    /// documents, the same images, and no account name left. Reads
    /// ~/Library/Logs/DiagnosticReports and writes nothing.
    @Test(.enabled(if: !realReports.isEmpty)) func realReportsOnThisMac() throws {
        let scrubber = CrashReportScrubber()
        let name = NSUserName()
        for url in realReports {
            let original = try Data(contentsOf: url)
            guard let before = try? ipsDocuments(original) else { continue }
            let scrubbed = scrubber.scrub(original)
            let after = try ipsDocuments(scrubbed)
            let uuids = { (body: [String: Any]) in (body["usedImages"] as? [[String: Any]])?.compactMap { $0["uuid"] as? String } }
            #expect(uuids(before.body) == uuids(after.body), "\(url.lastPathComponent)")
            #expect(after.body["crashReporterKey"] as? String == CrashReportScrubber.zeroUUID)
            if name.count > 2 {
                #expect(String(decoding: scrubbed, as: UTF8.self).range(of: "/Users/\(name)") == nil, "\(url.lastPathComponent)")
            }
        }
    }
}

let realReports: [URL] = {
    let folder = URL(fileURLWithPath: CrashReportScrubber.Machine.current.home)
        .appendingPathComponent("Library/Logs/DiagnosticReports")
    let files = (try? FileManager.default.contentsOfDirectory(at: folder, includingPropertiesForKeys: nil)) ?? []
    return Array(files.filter { $0.pathExtension == "ips" }.prefix(40))
}()
