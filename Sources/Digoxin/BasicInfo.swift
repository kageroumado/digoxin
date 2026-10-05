import Darwin
import Foundation

/// What every heartbeat and crash report says about the app and the Mac,
/// each field coarse enough that many Macs share it.
public struct BasicInfo: Codable, Sendable, Equatable {
    /// `CFBundleShortVersionString`.
    public var appVersion: String
    /// `CFBundleVersion`.
    public var appBuild: String
    /// The macOS version as major.minor, such as `26.4`.
    public var os: String
    /// The process's architecture: `arm64`, or `x86_64` (Intel or Rosetta).
    public var arch: String
    /// `M1` … `M5` for Apple silicon, `Intel`, or `unknown`.
    public var chipFamily: String
    /// The installed memory rounded down to a common size: 8, 16, 24, 32,
    /// 36, 48, 64, 96 or 128 (which stands for 128 and more).
    public var memoryClassGB: Int
    /// The first preferred language's two-letter code, or `xx` for one
    /// that has none.
    public var language: String

    /// The memory sizes Macs ship with, ascending.
    static let memoryClasses = [8, 16, 24, 32, 36, 48, 64, 96, 128]

    /// The running app's info.
    public static func current(bundle: Bundle = .main) -> BasicInfo {
        let version = ProcessInfo.processInfo.operatingSystemVersion
        return BasicInfo(
            appVersion: bundle.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0",
            appBuild: bundle.infoDictionary?["CFBundleVersion"] as? String ?? "0",
            os: "\(version.majorVersion).\(version.minorVersion)",
            arch: processArch,
            chipFamily: chipFamily(brand: sysctlString("machdep.cpu.brand_string") ?? ""),
            memoryClassGB: memoryClass(bytes: ProcessInfo.processInfo.physicalMemory),
            language: language(preferred: Locale.preferredLanguages),
        )
    }

    static var processArch: String {
        #if arch(arm64)
            "arm64"
        #else
            "x86_64"
        #endif
    }

    /// `Apple M3 Pro` → `M3`; any Intel brand → `Intel`; anything else,
    /// including Rosetta's `VirtualApple`, → `unknown`.
    static func chipFamily(brand: String) -> String {
        if brand.contains("Intel") { return "Intel" }
        guard let match = brand.firstMatch(of: /Apple (M[1-9][0-9]?)\b/) else { return "unknown" }
        return String(match.output.1)
    }

    /// The largest common size at or below the installed memory, at least 8.
    static func memoryClass(bytes: UInt64) -> Int {
        let gigabytes = Int((Double(bytes) / Double(1 << 30)).rounded())
        return memoryClasses.last { $0 <= gigabytes } ?? memoryClasses[0]
    }

    static func language(preferred: [String]) -> String {
        guard let first = preferred.first,
              let code = Locale.Language(identifier: first).languageCode?.identifier(.alpha2),
              code.count == 2
        else { return "xx" }
        return code.lowercased()
    }

    static func sysctlString(_ name: String) -> String? {
        var size = 0
        guard sysctlbyname(name, nil, &size, nil, 0) == 0, size > 0 else { return nil }
        var buffer = [CChar](repeating: 0, count: size)
        guard sysctlbyname(name, &buffer, &size, nil, 0) == 0 else { return nil }
        return String(decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }
}
