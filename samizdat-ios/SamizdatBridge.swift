import Foundation
import Combine
import NetworkExtension
import SamizdatClient // gomobile-generated framework

/// SamizdatBridge wraps the gomobile-generated `SamizdatClient` framework so
/// the rest of the SwiftUI code talks to a friendly Swift API instead of the
/// raw `Samizdat…()` C-bridge functions.
///
/// State is published; ContentView observes it and re-renders.
///
/// Architecture (post-Phase-1 rework):
///
///  - **Status** comes from `NEVPNStatusDidChange` notifications (push), with
///    a 5-second safety re-poll. We no longer hammer the system at 4 Hz, which
///    used to mean ~16 XPC roundtrips per second to `nesessionmanager` (each
///    `loadAllFromPreferences` is a real XPC call) and was the most plausible
///    reason iOS was reaping the extension at 35-60 s as "high non-tunnel
///    work".
///
///  - **Logs** are read directly from the App Group log file the extension
///    writes to (`extension-log.txt`). The bridge tails it via a 1 Hz file-
///    size poll on the app side, completely decoupled from the extension's
///    XPC. This also means the file survives extension death — its last
///    lines are the "last words" trail iOS denied us elsewhere.
@MainActor
final class SamizdatBridge: ObservableObject {

    enum State: String {
        case disconnected, connecting, connected, error
    }

    @Published private(set) var state: State = .disconnected
    @Published private(set) var lastError: String = ""
    @Published private(set) var socksAddr: String = ""
    @Published private(set) var logs: [String] = []

    /// Synthetic events the Bridge wants to surface in the unified log
    /// (state transitions, file-stale warnings). Capped FIFO.
    private var bridgeEvents: [String] = []
    private let bridgeEventsCap = 200
    private var previousNEStatus: String = "init"

    /// Lines accumulated from the App Group log file. Capped FIFO.
    private var fileLogLines: [String] = []
    private let fileLogLinesCap = 1000

    private var statusObserver: NSObjectProtocol?
    private var safetyPollTask: Task<Void, Never>?

    private let logFileURL: URL?
    private var logFileOffset: UInt64 = 0
    private var lastFileGrowth = Date.distantPast
    private var didLogFileStale = false
    private var logFileTimer: DispatchSourceTimer?

    static let appGroupID = "group.com.anarki.samizdat-test"
    private static let logFileName = "extension-log.txt"

    init() {
        let containerURL = FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: SamizdatBridge.appGroupID)
        self.logFileURL = containerURL?.appendingPathComponent(SamizdatBridge.logFileName)

        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: nil,
            queue: nil
        ) { [weak self] _ in
            Task { @MainActor in await self?.refreshStatus() }
        }

        // Safety re-poll: NEVPNStatusDidChange fires reliably for our own
        // start/stop, but in rare cases (e.g. iOS reaping the extension
        // between us seeing .connected and the system flipping to
        // .disconnected) we want a slow ground-truth check. 5 s is cheap
        // because connectionStatus() now uses the cached manager.
        safetyPollTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 5_000_000_000)
                await self?.refreshStatus()
            }
        }

        Task { @MainActor in await refreshStatus() }
        startLogFileWatcher()
    }

    deinit {
        if let observer = statusObserver {
            NotificationCenter.default.removeObserver(observer)
        }
        safetyPollTask?.cancel()
        logFileTimer?.cancel()
    }

    // MARK: – Public API

    /// Validate a config blob without connecting. Returns nil on success,
    /// or a human-readable error message.
    static func validate(_ blob: String) -> String? {
        let err = SamizdatParseConfigError(blob)
        return err.isEmpty ? nil : err
    }

    /// Starts the system VPN configuration backed by PacketTunnelProvider.
    func connect(_ blob: String) async throws {
        state = .connecting
        lastError = ""
        try await VPNProfileStore.shared.startTunnel(configBlob: blob)
        // Note: previously truncated the log file here. Path 3 keeps it
        // because the main-app SocksStub also writes there from app launch
        // (well before connect()). Truncation would erase that history.
        // The extension truncates the file itself on its startTunnel
        // entry, so per-extension-session boundaries still exist.
        await refreshStatus()
    }

    func disconnect() {
        VPNProfileStore.shared.stopTunnel()
        state = .disconnected
    }

    func clearLogs() {
        bridgeEvents.removeAll(keepingCapacity: true)
        fileLogLines.removeAll(keepingCapacity: true)
        truncateLogFile()
        logFileOffset = 0
        rebuildUnifiedLogs()
    }

    var version: String {
        SamizdatVersion()
    }

    /// Push freshly-acquired VK TURN credentials into the in-process Go
    /// runner so its next worker-group rotation tick uses them for
    /// TURN Allocate, instead of the snapshot it took from
    /// `Config.PreloadedCreds` when the tunnel started.
    ///
    /// Returns the gomobile error string ("" on success, "not running"
    /// when no VK TURN runner is alive in this process). Stateless —
    /// safe to call from `TURNCredsRefresher` after every successful
    /// refresh whether or not the user has the tunnel up.
    ///
    /// NOTE: the VK TURN runner lives in the EXTENSION process, not the
    /// main app. A call from the main app reaches the main app's own
    /// runner and usually returns "not running". `TURNCredsRefresher`
    /// therefore also sends a `refreshVKTurnCreds` provider message so
    /// the extension re-reads the App Group mirror and updates the live
    /// Go runner in the correct process.
    ///
    /// TODO(gomobile-rebuild): `SocksstubUpdateVKTurnCreds` is a new
    /// export; the SamizdatClient.xcframework currently checked into
    /// the repo predates it. After regenerating bindings the linker
    /// will find the symbol and this call will start returning
    /// meaningful values. See commit message for the regen command.
    @discardableResult
    static func updateVKTurnCreds(_ credsJSON: String) -> String {
        SocksstubUpdateVKTurnCreds(credsJSON)
    }

    // MARK: – Status

    private func refreshStatus() async {
        let raw = await VPNProfileStore.shared.connectionStatus()
        let rawName = neStatusName(raw)
        let newState: State
        switch raw {
        case .invalid, .disconnected:
            newState = .disconnected
        case .connecting, .reasserting:
            newState = .connecting
        case .connected:
            newState = .connected
        case .disconnecting:
            newState = .disconnected
        @unknown default:
            newState = .error
        }

        if rawName != previousNEStatus {
            appendBridgeEvent("status \(previousNEStatus) → \(rawName)")
            previousNEStatus = rawName
            if raw == .connected || raw == .connecting {
                didLogFileStale = false
                lastFileGrowth = Date()
            }
        }

        let err = SamizdatLastError()
        if state != newState { state = newState }
        if lastError != err { lastError = err }
        if !socksAddr.isEmpty { socksAddr = "" }
        rebuildUnifiedLogs()
    }

    // MARK: – Log file watcher

    private func startLogFileWatcher() {
        guard let _ = logFileURL else { return }
        // 1 Hz file-size poll on a background queue. Reads only when the
        // file has grown. No XPC, no roundtrip to the extension.
        let timer = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
        timer.schedule(deadline: .now() + .seconds(1), repeating: .seconds(1))
        timer.setEventHandler { [weak self] in
            Task { @MainActor in self?.readNewLogLines() }
        }
        timer.resume()
        logFileTimer = timer
    }

    private func readNewLogLines() {
        guard let url = logFileURL else { return }
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: url.path),
              let size = attrs[.size] as? UInt64 else {
            // File may not exist yet (extension hasn't started) — silent.
            return
        }
        if size < logFileOffset {
            // File was truncated externally (e.g. our clearLogs).
            logFileOffset = 0
        }
        if size == logFileOffset {
            checkFileStaleness()
            return
        }

        guard let handle = try? FileHandle(forReadingFrom: url) else { return }
        defer { try? handle.close() }
        do {
            try handle.seek(toOffset: logFileOffset)
            let data = handle.availableData
            logFileOffset += UInt64(data.count)
            lastFileGrowth = Date()
            didLogFileStale = false

            if let text = String(data: data, encoding: .utf8), !text.isEmpty {
                let trimmed = text.hasSuffix("\n") ? String(text.dropLast()) : text
                let parts = trimmed.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
                fileLogLines.append(contentsOf: parts)
                if fileLogLines.count > fileLogLinesCap {
                    fileLogLines.removeFirst(fileLogLines.count - fileLogLinesCap)
                }
                rebuildUnifiedLogs()
            }
        } catch {
            // Best-effort.
        }
    }

    /// Swift heartbeat fires every 2 s; Go heartbeat every 5 s. If neither
    /// has appended in 4 s while status is .connected, the extension is
    /// in trouble — surface that immediately so it lands in the file
    /// before the kill-flush window.
    private func checkFileStaleness() {
        guard state == .connected else { return }
        guard !didLogFileStale else { return }
        let elapsed = Date().timeIntervalSince(lastFileGrowth)
        if elapsed > 4 {
            didLogFileStale = true
            appendBridgeEvent("log file stale \(Int(elapsed))s — extension suspended/throttled/dead")
        }
    }

    private func truncateLogFile() {
        guard let url = logFileURL else { return }
        try? Data().write(to: url, options: .atomic)
    }

    // MARK: – Helpers

    private func rebuildUnifiedLogs() {
        // Bridge events appear inline at the end so the user sees the
        // status transitions and stale-file warnings in chronological
        // order with the file content.
        let combined = fileLogLines + bridgeEvents
        if logs != combined { logs = combined }
    }

    private func appendBridgeEvent(_ message: String) {
        let stamp = SamizdatBridge.timeFormatter.string(from: Date())
        bridgeEvents.append("\(stamp) bridge: \(message)")
        if bridgeEvents.count > bridgeEventsCap {
            bridgeEvents.removeFirst(bridgeEvents.count - bridgeEventsCap)
        }
    }

    private func neStatusName(_ s: NEVPNStatus) -> String {
        switch s {
        case .invalid:       return "invalid"
        case .disconnected:  return "disconnected"
        case .connecting:    return "connecting"
        case .connected:     return "connected"
        case .reasserting:   return "reasserting"
        case .disconnecting: return "disconnecting"
        @unknown default:    return "unknown(\(s.rawValue))"
        }
    }

    private static let timeFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss.SSS"
        f.locale = Locale(identifier: "en_US_POSIX")
        return f
    }()
}
