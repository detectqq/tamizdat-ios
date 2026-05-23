import Foundation

/// Shared file-logger for the VK TURN credential flow
/// (`CaptchaWebViewManager`, `VKCredsClient`, `TURNCredsRefresher`,
/// `ManualCaptchaSheet`). Writes timestamped lines to the same App
/// Group file the extension uses (`extension-log.txt`) so the in-app
/// `LogView` shows our events alongside the bridge / NE stream.
///
/// Without this the captcha/refresh code wrote only to `os.Logger`,
/// which is visible in macOS Console but not from the on-device UI.
/// Operators had no way to tell whether refresh ran at all, let alone
/// where it failed.
///
/// Format mirrors `ParsedLogLine.from`:
///   `HH:mm:ss.SSS <level>: <tag>: <message>`
/// where `<level>` is one of `info`, `warn`, `error`, `crit`.
enum TURNLog {
    static let appGroupID = "group.com.anarki.samizdat-test"
    static let fileName = "extension-log.txt"

    private static let timeFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss.SSS"
        f.locale = Locale(identifier: "en_US_POSIX")
        return f
    }()

    /// Ensure `extension-log.txt` exists in the App Group container,
    /// then return a non-blocking FileHandle opened for writing in
    /// O_APPEND mode. The handle is recreated on every write — opening
    /// a new fd per line is cheap (microseconds) and avoids stale-fd
    /// issues if iOS reclaims the container while we hold it.
    private static func handle() -> FileHandle? {
        let fm = FileManager.default
        guard let container = fm.containerURL(
            forSecurityApplicationGroupIdentifier: appGroupID
        ) else {
            return nil
        }
        let url = container.appendingPathComponent(fileName)
        if !fm.fileExists(atPath: url.path) {
            fm.createFile(atPath: url.path, contents: nil, attributes: nil)
        }
        guard let h = try? FileHandle(forWritingTo: url) else {
            return nil
        }
        // Seek to end for append behaviour without O_APPEND on the fd.
        _ = try? h.seekToEnd()
        return h
    }

    static func info(_ tag: String, _ message: String) {
        write(level: "info", tag: tag, message: message)
    }

    static func warn(_ tag: String, _ message: String) {
        write(level: "warn", tag: tag, message: message)
    }

    static func error(_ tag: String, _ message: String) {
        write(level: "error", tag: tag, message: message)
    }

    static func crit(_ tag: String, _ message: String) {
        write(level: "crit", tag: tag, message: message)
    }

    private static func write(level: String, tag: String, message: String) {
        let line = "\(timeFormatter.string(from: Date())) \(level): \(tag): \(message)\n"
        guard let h = handle() else { return }
        defer { try? h.close() }
        _ = try? h.write(contentsOf: Data(line.utf8))
        try? h.synchronize()
    }
}
