import Foundation
import Combine
import SamizdatClient // gomobile-generated framework

/// SamizdatBridge wraps the gomobile-generated `SamizdatClient` framework so
/// the rest of the SwiftUI code talks to a friendly Swift API instead of the
/// raw `Samizdat…()` C-bridge functions.
///
/// State is published; ContentView observes it and re-renders.
@MainActor
final class SamizdatBridge: ObservableObject {

    enum State: String {
        case disconnected, connecting, connected, error
    }

    @Published private(set) var state: State = .disconnected
    @Published private(set) var lastError: String = ""
    @Published private(set) var socksAddr: String = ""
    @Published private(set) var logs: [String] = []

    private var pollTask: Task<Void, Never>?

    init() {
        startPolling()
    }

    deinit {
        pollTask?.cancel()
    }

    // MARK: – Public API

    /// Validate a config blob without connecting. Returns nil on success,
    /// or a human-readable error message.
    static func validate(_ blob: String) -> String? {
        let err = SamizdatParseConfigError(blob)
        return err.isEmpty ? nil : err
    }

    /// Connect using a samizdat:// URL. Throws on parse error; network
    /// errors surface via `state == .error` + `lastError`.
    func connect(_ blob: String) throws {
        var nsErr: NSError?
        SamizdatConnect(blob, &nsErr)
        if let nsErr {
            throw nsErr
        }
        // Poll loop will pick up the new state immediately on next tick.
    }

    func disconnect() {
        SamizdatDisconnect()
    }

    func clearLogs() {
        SamizdatClearLogs()
        logs = []
    }

    var version: String {
        SamizdatVersion()
    }

    // MARK: – Polling

    private func startPolling() {
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.refresh()
                try? await Task.sleep(nanoseconds: 250_000_000) // 4 Hz
            }
        }
    }

    private func refresh() async {
        let raw = SamizdatStatus()
        let newState = State(rawValue: raw) ?? .disconnected
        let err = SamizdatLastError()
        let socks = SamizdatSocksAddr()
        let dump = SamizdatLogs(0)
        let lines = dump.isEmpty ? [] : dump.components(separatedBy: "\n")

        if state != newState { state = newState }
        if lastError != err { lastError = err }
        if socksAddr != socks { socksAddr = socks }
        if logs != lines { logs = lines }
    }
}
