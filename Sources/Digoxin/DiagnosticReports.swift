import Foundation

/// The crash reports macOS writes for a process.
public enum DiagnosticReports {
    /// Where macOS writes crash reports: the account's folder for the
    /// processes it runs, and the system folder for processes running as
    /// root, such as a privileged helper or a launch daemon. The system
    /// folder is readable by administrators; for anyone else it reads as
    /// empty. An app in the App Sandbox can read neither.
    public static var folders: [URL] {
        [
            URL(fileURLWithPath: CrashReportScrubber.Machine.current.home)
                .appendingPathComponent("Library/Logs/DiagnosticReports", isDirectory: true),
            URL(fileURLWithPath: "/Library/Logs/DiagnosticReports", isDirectory: true),
        ]
    }

    /// The `.ips` reports macOS wrote for `processName` after `date` in
    /// ``folders``, oldest first.
    public static func reports(forProcess processName: String, after date: Date) -> [URL] {
        reports(forProcess: processName, after: date, in: folders)
    }

    static func reports(forProcess processName: String, after date: Date, in folders: [URL]) -> [URL] {
        let created = { (url: URL) in (try? url.resourceValues(forKeys: [.creationDateKey]).creationDate) ?? .distantPast }
        return folders
            .flatMap { folder in
                (try? FileManager.default.contentsOfDirectory(
                    at: folder, includingPropertiesForKeys: [.creationDateKey], options: [.skipsHiddenFiles],
                )) ?? []
            }
            .filter { $0.pathExtension == "ips" && $0.lastPathComponent.hasPrefix(processName + "-") && created($0) > date }
            .sorted { created($0) < created($1) }
    }
}
