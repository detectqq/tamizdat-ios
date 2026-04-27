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
    private var lastExtensionLogPoll = Date.distantPast
    private var extensionLogDump = ""

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

    /// Starts the system VPN configuration backed by PacketTunnelProvider.
    func connect(_ blob: String) async throws {
        state = .connecting
        lastError = ""
        try await VPNProfileStore.shared.startTunnel(configBlob: blob)
        await refresh()
    }

    func disconnect() {
        VPNProfileStore.shared.stopTunnel()
        state = .disconnected
    }

    func clearLogs() {
        SamizdatClearLogs()
        extensionLogDump = ""
        Task {
            await VPNProfileStore.shared.clearExtensionLogs()
        }
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
        let newState: State
        switch await VPNProfileStore.shared.connectionStatus() {
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
        var err = SamizdatLastError()
        let socks = ""
        var dump = SamizdatLogs(0)

        if Date().timeIntervalSince(lastExtensionLogPoll) >= 1 {
            lastExtensionLogPoll = Date()
            if let extensionDump = await VPNProfileStore.shared.extensionLogs(), !extensionDump.isEmpty {
                extensionLogDump = extensionDump
                if err.isEmpty,
                   let lastErrorLine = extensionDump.components(separatedBy: "\n").last(where: { $0.contains(" error:") }) {
                    err = lastErrorLine
                }
            }
        }

        dump = [dump, extensionLogDump].filter { !$0.isEmpty }.joined(separator: "\n")
        let lines = dump.isEmpty ? [] : dump.components(separatedBy: "\n")

        if state != newState { state = newState }
        if lastError != err { lastError = err }
        if socksAddr != socks { socksAddr = socks }
        if logs != lines { logs = lines }
    }
}
