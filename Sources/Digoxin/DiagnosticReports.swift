import Foundation

/// The crash reports macOS writes for a process.
public enum DiagnosticReports {
    /// The `.ips` reports macOS wrote for `processName` after `date`, oldest
    /// first. They live in `~/Library/Logs/DiagnosticReports`, which an app
    /// in the App Sandbox cannot read.
    public static func reports(forProcess processName: String, after date: Date) -> [URL] {
        let folder = URL(fileURLWithPath: CrashReportScrubber.Machine.current.home)
            .appendingPathComponent("Library/Logs/DiagnosticReports", isDirectory: true)
        let files = (try? FileManager.default.contentsOfDirectory(
            at: folder, includingPropertiesForKeys: [.creationDateKey], options: [.skipsHiddenFiles],
        )) ?? []
        let created = { (url: URL) in (try? url.resourceValues(forKeys: [.creationDateKey]).creationDate) ?? .distantPast }
        return files
            .filter { $0.pathExtension == "ips" && $0.lastPathComponent.hasPrefix(processName + "-") && created($0) > date }
            .sorted { created($0) < created($1) }
    }
}
