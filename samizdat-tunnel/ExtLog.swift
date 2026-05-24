import Foundation
import Darwin

/// Synchronous, fsync-per-write logger for the Network Extension.
///
/// WHY this exists separately from `TURNLog` / `appendExtLog`: those
/// rely on `FileHandle.write` / `synchronize`, which Foundation
/// buffers internally. When the extension calls into gomobile
/// `SocksstubStartVKTurnUpstream` (a blocking call that can sleep up
/// to 15 seconds while VK Allocate handshakes), any log line the
/// caller emits after the block never lands on disk before the
/// extension is reaped by iOS or its log file handle goes stale.
///
/// `ExtLog` opens a fresh file descriptor on every line, writes the
/// bytes via `Darwin.write`, calls `fsync`, then closes the fd. No
/// FileHandle, no buffering, no shared state. The cost is a few
/// microseconds per line — acceptable since we only call it on
/// boundary events, not the hot data path.
///
/// File location: App Group container, filename matches the existing
/// `extension-log.txt` that `appendExtLog` writes to and that the
/// in-app `LogView` reads. Both writers append to the same file —
/// `O_APPEND` ensures atomic positioning under the kernel even when
/// two writers race.
enum ExtLog {

    /// App Group identifier — MUST stay in sync with the entitlements
    /// of both targets and with `PacketTunnelProvider.appGroupID`.
    private static let appGroupID = "group.com.anarki.samizdat-test"

    /// Log filename inside the App Group container. Same file the
    /// existing `appendExtLog` (FileHandle-buffered) writes to — the
    /// in-app `LogView` reads it and tails for the live stream.
    private static let logFileName = "extension-log.txt"

    /// Cached path inside the App Group container so we don't pay the
    /// `containerURL(forSecurityApplicationGroupIdentifier:)` lookup
    /// on every line. Resolved lazily on first write.
    private static let cachedPath: String? = {
        guard let url = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: appGroupID
        ) else {
            return nil
        }
        return url.appendingPathComponent(logFileName).path
    }()

    private static let timeFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss.SSS"
        f.locale = Locale(identifier: "en_US_POSIX")
        return f
    }()

    static func info(_ text: String) {
        write(level: "info", text: text)
    }

    static func warn(_ text: String) {
        write(level: "warn", text: text)
    }

    static func error(_ text: String) {
        write(level: "error", text: text)
    }

    /// Internal entry point. Builds the formatted line, then calls the
    /// raw POSIX `open` / `write` / `fsync` / `close` sequence directly
    /// — bypassing every Swift-level buffer.
    ///
    /// Failure modes are intentionally silent: if the container is not
    /// resolvable, or the open / write fails, we just drop the line.
    /// Logging must never propagate errors back to callers.
    private static func write(level: String, text: String) {
        guard let path = cachedPath else { return }
        let stamp = timeFormatter.string(from: Date())
        let line = "\(stamp) \(level): \(text)\n"
        let bytes = Array(line.utf8)
        let fd = path.withCString { cpath -> Int32 in
            // O_WRONLY | O_APPEND | O_CREAT: append-only, create if
            // missing, 0644 perms (rw for owner, r for group/others).
            // O_APPEND makes the kernel position write at end-of-file
            // atomically so we can race against `appendExtLog` (which
            // uses FileHandle with seekToEnd) without losing bytes.
            Darwin.open(cpath, O_WRONLY | O_APPEND | O_CREAT, 0o644)
        }
        guard fd >= 0 else { return }
        defer { Darwin.close(fd) }
        let n = bytes.withUnsafeBufferPointer { buf -> Int in
            guard let base = buf.baseAddress else { return -1 }
            return Darwin.write(fd, base, buf.count)
        }
        guard n > 0 else { return }
        _ = Darwin.fsync(fd)
    }
}
