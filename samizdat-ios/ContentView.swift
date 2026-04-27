import SwiftUI

struct ContentView: View {
    @StateObject private var bridge = SamizdatBridge()
    @State private var showConfig = false
    @State private var showLogs = false
    @State private var hasConfig = ConfigStore.shared.load() != nil

    var body: some View {
        VStack(spacing: 28) {
            // ── Status ─────────────────────────────────────────────────────
            VStack(spacing: 12) {
                Image(systemName: stateIcon)
                    .font(.system(size: 88))
                    .foregroundStyle(stateColor)
                    .symbolEffect(.pulse, isActive: bridge.state == .connecting)

                Text(stateTitle)
                    .font(.title)
                    .bold()

                if !bridge.lastError.isEmpty && bridge.state == .error {
                    Text(bridge.lastError)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)
                }
                if !bridge.socksAddr.isEmpty && bridge.state == .connected {
                    Text("SOCKS5: \(bridge.socksAddr)")
                        .font(.footnote.monospaced())
                        .foregroundStyle(.secondary)
                }
            }

            Spacer()

            // ── Connect/Disconnect ─────────────────────────────────────────
            Button(action: toggleConnection) {
                Text(buttonTitle)
                    .font(.title2.weight(.semibold))
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 16)
            }
            .buttonStyle(.borderedProminent)
            .tint(buttonTint)
            .disabled(bridge.state == .connecting || !hasConfig)

            if !hasConfig {
                Text("Paste a samizdat:// config first")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            // ── Sub-buttons ────────────────────────────────────────────────
            HStack(spacing: 12) {
                Button {
                    showConfig = true
                } label: {
                    Label("Config", systemImage: "key.fill")
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                }
                .buttonStyle(.bordered)

                Button {
                    showLogs = true
                } label: {
                    Label("Logs", systemImage: "doc.text.fill")
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                }
                .buttonStyle(.bordered)
            }

            Text("v\(bridge.version)")
                .font(.caption2)
                .foregroundStyle(.tertiary)
        }
        .padding(24)
        .sheet(isPresented: $showConfig) {
            ConfigPasteView { saved in
                hasConfig = saved
            }
        }
        .sheet(isPresented: $showLogs) {
            LogView(bridge: bridge)
        }
    }

    // MARK: – derived

    private var stateIcon: String {
        switch bridge.state {
        case .disconnected: "shield.slash"
        case .connecting:   "shield.lefthalf.filled"
        case .connected:    "shield.lefthalf.filled.badge.checkmark"
        case .error:        "exclamationmark.shield.fill"
        }
    }

    private var stateColor: Color {
        switch bridge.state {
        case .disconnected: .secondary
        case .connecting:   .yellow
        case .connected:    .green
        case .error:        .red
        }
    }

    private var stateTitle: String {
        switch bridge.state {
        case .disconnected: "Disconnected"
        case .connecting:   "Connecting…"
        case .connected:    "Connected"
        case .error:        "Error"
        }
    }

    private var buttonTitle: String {
        switch bridge.state {
        case .connected:  "Disconnect"
        case .connecting: "Connecting…"
        default:          "Connect"
        }
    }

    private var buttonTint: Color {
        bridge.state == .connected ? .red : .blue
    }

    private func toggleConnection() {
        if bridge.state == .connected {
            bridge.disconnect()
            return
        }
        guard let blob = ConfigStore.shared.load() else { return }
        do {
            try bridge.connect(blob)
        } catch {
            // bridge state is already .error via Go side; nothing else to do.
        }
    }
}

#Preview {
    ContentView()
}
