import SwiftUI
import Foundation
import SamizdatClient
import UserNotifications

/// IPA-D22: redesigned Settings sheet — grouped inset cards over the
/// theme background gradient. Sections (top → bottom):
///   1. Notifications  (Whitelist alerts toggle)
///   2. Configuration  (Endpoints → push to EndpointsView)
///   3. Ping probe     (URL code-block + Save / Reset)
///   4. Appearance     (Cream / Dark segmented control)
///   5. Diagnostics    (View logs + About)
///
/// Pool variant section deleted in D22 (V1 hardcoded in Go). Telegram
/// uploader stays reachable but as a row in Diagnostics rather than
/// its own section — it's a debug aid, not a primary config knob.
struct SettingsView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(\.themeTokens) private var theme

    /// Called whenever the user changes endpoints. The parent uses this
    /// to refresh `hasConfig` and `hasBackupConfigured`.
    var onConfigChanged: (Bool) -> Void = { _ in }

    /// Theme picker is rendered here but the *root* view (App.swift /
    /// ContentView) reads `ThemePreferences.current` to compute the
    /// environment value. To make the picker change propagate live, we
    /// post a Notification on change; the root listens and re-renders.
    @State private var selectedTheme: AppTheme = ThemePreferences.current

    @State private var notificationsEnabled: Bool = NotificationPreferences.enabled
    @State private var permissionStatus: UNAuthorizationStatus = .notDetermined
    @State private var permissionDeniedAlert: Bool = false

    @State private var pingURL: String = PingURLPreferences.url
    @State private var pingURLDraft: String = PingURLPreferences.url
    @State private var fragPoCTransportEnabled: Bool = FragPoCTransportStore.enabled
    @State private var fragPoCUDPEnabled: Bool = FragPoCUDPStore.enabled
    @State private var fragPoCConfigDraft: String = FragPoCConfigStore.configBlob
    @State private var fragPoCConfigError: String?
    @State private var fragPoCPortMode: FragPoCPortMode = FragPoCPortConfigStore.mode
    @State private var fragPoCPortsDraft: String = FragPoCPortConfigStore.activePorts
        .map(String.init).joined(separator: ", ")
    @State private var smokeResults: [SmokePortResult] = []
    @State private var smokeRunning = false
    @State private var smokeTask: Task<Void, Never>?
    // D47: single-port payload size test (live step-by-step)
    @State private var payloadProgress = PayloadProgress()
    @State private var payloadRunning = false
    @State private var payloadTask: Task<Void, Never>?
    // D47: sequential max connections test (fill port → next port)
    @State private var maxConnsProgress = MaxConnsProgress()
    @State private var maxConnsRunning = false
    @State private var maxConnsTask: Task<Void, Never>?

    // IPA-D23: whitelist-detection probe targets.
    @State private var testHostDraft: String = WhitelistProbePreferences.testHost
    @State private var whitelistHostDraft: String = WhitelistProbePreferences.whitelistHost
    // D45: expanded whitelist tunables.
    @State private var wlSuccessesDraft: Int = WhitelistProbePreferences.successesNeeded
    @State private var wlIntervalDraft: Int = WhitelistProbePreferences.probeInterval

    @State private var showEndpoints = false
    @State private var showLogs = false
    @State private var showTelegram = false

    var body: some View {
        ZStack {
            ThemeBackground(theme: theme)

            VStack(spacing: 0) {
                // ── Header ───────────────────────────────────────
                HStack {
                    Chip(label: "Done") { dismiss() }
                    Spacer()
                    Text("Settings")
                        .font(.geist(.semibold, size: 16))
                        .foregroundStyle(theme.text)
                    Spacer()
                    Color.clear.frame(width: 56, height: 1)
                }
                .padding(.horizontal, 20)
                .padding(.top, 8)
                .padding(.bottom, 6)

                // ── Large title ──────────────────────────────────
                Text("Settings")
                    .font(.geist(.bold, size: 32))
                    .tracking(-0.96)
                    .foregroundStyle(theme.text)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 20)
                    .padding(.bottom, 14)

                ScrollView {
                    VStack(spacing: 0) {
                        // ── Notifications ────────────────────────
                        SectionLabel(text: "Notifications")
                        notificationsCard
                            .padding(.horizontal, 16)

                        // ── Configuration ────────────────────────
                        SectionLabel(text: "Configuration")
                            .padding(.top, 22)
                        configurationCard
                            .padding(.horizontal, 16)

                        // ── Ping probe ───────────────────────────
                        SectionLabel(text: "Ping probe")
                            .padding(.top, 22)
                        pingProbeCard
                            .padding(.horizontal, 16)

                        // ── Whitelist detection ──────────────────
                        SectionLabel(text: "Whitelist detection")
                            .padding(.top, 22)
                        whitelistProbeCard
                            .padding(.horizontal, 16)

                        // ── Appearance ───────────────────────────
                        SectionLabel(text: "Appearance")
                            .padding(.top, 22)
                        appearanceCard
                            .padding(.horizontal, 16)

                        // ── Transport ────────────────────────────
                        SectionLabel(text: "Transport")
                            .padding(.top, 22)
                        transportCard
                            .padding(.horizontal, 16)

                        // FragPoC sub-settings — only visible when
                        // the FragPoC toggle above is ON.
                        if fragPoCTransportEnabled {
                            fragPoCUDPCard
                                .padding(.horizontal, 16)
                                .padding(.top, 10)
                            fragPoCServerCard
                                .padding(.horizontal, 16)
                                .padding(.top, 10)
                            fragPoCPortCard
                                .padding(.horizontal, 16)
                                .padding(.top, 10)
                            fragPoCSmokeTestCard
                                .padding(.horizontal, 16)
                                .padding(.top, 10)
                            fragPoCPayloadTestCard
                                .padding(.horizontal, 16)
                                .padding(.top, 10)
                            fragPoCMaxConnsTestCard
                                .padding(.horizontal, 16)
                                .padding(.top, 10)
                        }

                        // ── Diagnostics ──────────────────────────
                        SectionLabel(text: "Diagnostics")
                            .padding(.top, 22)
                        diagnosticsCard
                            .padding(.horizontal, 16)

                        // ── About ────────────────────────────────
                        SectionLabel(text: "About")
                            .padding(.top, 22)
                        aboutCard
                            .padding(.horizontal, 16)

                        Color.clear.frame(height: 28)
                    }
                }
            }
        }
        .preferredColorScheme(theme.isDark ? .dark : .light)
        .task {
            permissionStatus = await NotificationPreferences.currentSystemAuthorization()
        }
        .alert("Notifications were not granted", isPresented: $permissionDeniedAlert) {
            Button("Open iOS Settings") { openSystemSettings() }
            Button("Cancel", role: .cancel) { }
        } message: {
            Text("Enable notifications for Tamizdat in iOS Settings to receive whitelist-detection alerts.")
        }
        .sheet(isPresented: $showEndpoints) {
            EndpointsView { saved in
                onConfigChanged(saved)
            }
            .environment(\.themeTokens, theme)
        }
        .sheet(isPresented: $showTelegram) {
            TelegramSettingsView()
        }
    }

    // MARK: – Section cards

    private var notificationsCard: some View {
        CardContainer(padding: 0) {
            DesignRow(
                icon: IconCard(systemName: "bell.badge", bg: theme.blueDim, fg: theme.blue),
                title: "Whitelist alerts",
                sub: "Local push when auto-detector flips between Main and Whitelist.",
                isLast: permissionStatus != .denied || !notificationsEnabled
            ) {
                Toggle("", isOn: $notificationsEnabled)
                    .labelsHidden()
                    .tint(theme.mint)
                    .onChange(of: notificationsEnabled) { _, newValue in
                        if newValue {
                            Task { await handleEnableNotifications() }
                        } else {
                            NotificationPreferences.enabled = false
                        }
                    }
            }
            if permissionStatus == .denied && notificationsEnabled {
                DesignRow(
                    icon: IconCard(systemName: "exclamationmark.triangle.fill",
                                   bg: theme.amberDim, fg: theme.amber),
                    title: "Notifications are blocked",
                    sub: "Tap to open iOS Settings and re-enable.",
                    isLast: true
                ) {
                    Image(systemName: "chevron.right")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(theme.textMuted)
                }
                .contentShape(Rectangle())
                .onTapGesture { openSystemSettings() }
            }
        }
    }

    private var configurationCard: some View {
        CardContainer(padding: 0) {
            DesignRow(
                icon: IconCard(systemName: "key.fill", bg: theme.mintDim, fg: theme.mint),
                title: "Proxies",
                sub: configSubtitle,
                isLast: true
            ) {
                Image(systemName: "chevron.right")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(theme.textMuted)
            }
            .contentShape(Rectangle())
            .onTapGesture { showEndpoints = true }
        }
    }

    private var pingProbeCard: some View {
        CardContainer(padding: 16) {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 12) {
                    IconCard(systemName: "waveform.path.ecg",
                             bg: theme.mintDim, fg: theme.mint)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Probe URL")
                            .font(.geist(.medium, size: 16))
                            .foregroundStyle(theme.text)
                        Text("HEAD every 10s through the tunnel")
                            .font(.geistMono(.regular, size: 11))
                            .foregroundStyle(theme.textDim)
                    }
                    Spacer()
                }

                // Inline TextField for editing
                TextField("https://example.com/probe", text: $pingURLDraft)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled(true)
                    .keyboardType(.URL)
                    .font(.geistMono(.regular, size: 12.5))
                    .foregroundStyle(theme.text)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 11)
                    .background(theme.chip)
                    .clipShape(RoundedRectangle(cornerRadius: 14))
                    .onSubmit { saveURL() }

                HStack(spacing: 8) {
                    Button(action: saveURL) {
                        Text("Save")
                            .font(.geist(.semibold, size: 13))
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 10)
                            .background(theme.mint)
                            .foregroundStyle(theme.mintInk)
                            .clipShape(RoundedRectangle(cornerRadius: 10))
                    }
                    .buttonStyle(.plain)
                    Button(action: resetURL) {
                        Text("Reset to default")
                            .font(.geist(.semibold, size: 13))
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 10)
                            .background(theme.chip)
                            .foregroundStyle(theme.text)
                            .clipShape(RoundedRectangle(cornerRadius: 10))
                    }
                    .buttonStyle(.plain)
                }
            }
        }
    }

    private var whitelistProbeCard: some View {
        CardContainer(padding: 16) {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 12) {
                    IconCard(systemName: "shield.lefthalf.filled",
                             bg: theme.amberDim, fg: theme.amber)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Probe targets")
                            .font(.geist(.medium, size: 16))
                            .foregroundStyle(theme.text)
                        Text("ICMP ping every 3 s outside the tunnel")
                            .font(.geistMono(.regular, size: 11))
                            .foregroundStyle(theme.textDim)
                    }
                    Spacer()
                }

                Text("Test host")
                    .font(.geist(.medium, size: 12))
                    .foregroundStyle(theme.textMuted)
                TextField("8.8.8.8", text: $testHostDraft)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled(true)
                    .keyboardType(.URL)
                    .font(.geistMono(.regular, size: 12.5))
                    .foregroundStyle(theme.text)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 11)
                    .background(theme.chip)
                    .clipShape(RoundedRectangle(cornerRadius: 14))
                    .onSubmit { saveWhitelistProbes() }

                Text("Whitelist host")
                    .font(.geist(.medium, size: 12))
                    .foregroundStyle(theme.textMuted)
                TextField("77.88.8.8", text: $whitelistHostDraft)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled(true)
                    .keyboardType(.URL)
                    .font(.geistMono(.regular, size: 12.5))
                    .foregroundStyle(theme.text)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 11)
                    .background(theme.chip)
                    .clipShape(RoundedRectangle(cornerRadius: 14))
                    .onSubmit { saveWhitelistProbes() }

                // D45: successes needed before switching back to primary
                Text("Successes before failback")
                    .font(.geist(.medium, size: 12))
                    .foregroundStyle(theme.textMuted)
                Stepper(value: $wlSuccessesDraft, in: 1...10) {
                    Text("\(wlSuccessesDraft)")
                        .font(.geistMono(.regular, size: 14))
                        .foregroundStyle(theme.text)
                }
                .tint(theme.mint)

                // D45: probe interval (seconds)
                Text("Probe interval (seconds)")
                    .font(.geist(.medium, size: 12))
                    .foregroundStyle(theme.textMuted)
                Stepper(value: $wlIntervalDraft, in: 1...30) {
                    Text("\(wlIntervalDraft) s")
                        .font(.geistMono(.regular, size: 14))
                        .foregroundStyle(theme.text)
                }
                .tint(theme.mint)

                HStack(spacing: 8) {
                    Button(action: saveWhitelistProbes) {
                        Text("Save")
                            .font(.geist(.semibold, size: 13))
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 10)
                            .background(theme.mint)
                            .foregroundStyle(theme.mintInk)
                            .clipShape(RoundedRectangle(cornerRadius: 10))
                    }
                    .buttonStyle(.plain)
                    Button(action: resetWhitelistProbes) {
                        Text("Reset")
                            .font(.geist(.semibold, size: 13))
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 10)
                            .background(theme.chip)
                            .foregroundStyle(theme.text)
                            .clipShape(RoundedRectangle(cornerRadius: 10))
                    }
                    .buttonStyle(.plain)
                }

                Text("Apply requires reconnect to refresh routing.")
                    .font(.geist(.regular, size: 11))
                    .foregroundStyle(theme.textDim)
            }
        }
    }

    private var appearanceCard: some View {
        CardContainer(padding: 16) {
            HStack(spacing: 12) {
                IconCard(systemName: "paintpalette.fill",
                         bg: theme.chip, fg: theme.text)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Theme")
                        .font(.geist(.medium, size: 16))
                        .foregroundStyle(theme.text)
                    Text("Cream is the default. Dark suits OLED.")
                        .font(.geist(.regular, size: 12.5))
                        .foregroundStyle(theme.textDim)
                }
                Spacer()
                // Custom segmented control matching the chip design
                HStack(spacing: 2) {
                    themeSegment(.cream)
                    themeSegment(.dark)
                }
                .padding(3)
                .background(theme.chip)
                .clipShape(RoundedRectangle(cornerRadius: 12))
            }
        }
    }

    private func themeSegment(_ option: AppTheme) -> some View {
        let active = selectedTheme == option
        return Button {
            selectedTheme = option
            ThemePreferences.current = option
            // Propagate to root immediately
            NotificationCenter.default.post(name: .tamizdatThemeChanged, object: nil)
        } label: {
            Text(option.label)
                .font(.geist(.semibold, size: 13))
                .padding(.horizontal, 12)
                .padding(.vertical, 6)
                .background(active ? theme.chipActive : Color.clear)
                .foregroundStyle(active ? theme.chipActiveText : theme.textDim)
                .clipShape(RoundedRectangle(cornerRadius: 10))
        }
        .buttonStyle(.plain)
    }

    private var transportCard: some View {
        CardContainer(padding: 0) {
            DesignRow(
                icon: IconCard(systemName: "antenna.radiowaves.left.and.right",
                               bg: theme.blueDim, fg: theme.blue),
                title: "FragPoC transport (test)",
                sub: "Routes through a FragPoC endpoint. Applies on next reconnect.",
                isLast: true
            ) {
                Toggle("FragPoC transport (test)", isOn: $fragPoCTransportEnabled)
                    .labelsHidden()
                    .tint(theme.mint)
                    .onChange(of: fragPoCTransportEnabled) { _, newValue in
                        FragPoCTransportStore.enabled = newValue
                    }
            }
        }
    }

    /// FragPoC UDP forwarding toggle. When off, UDP flows (DNS, QUIC)
    /// are dropped — DNS falls back to the system resolver, QUIC
    /// downgrades to HTTP/2 through the TCP tunnel. Takes effect
    /// immediately without reconnect.
    private var fragPoCUDPCard: some View {
        CardContainer(padding: 0) {
            DesignRow(
                icon: IconCard(systemName: "arrow.up.arrow.down.circle",
                               bg: theme.blueDim, fg: theme.blue),
                title: "UDP forwarding",
                sub: "Forward DNS and QUIC through FragPoC. Off = TCP only, less tokens used.",
                isLast: true
            ) {
                Toggle("UDP forwarding", isOn: $fragPoCUDPEnabled)
                    .labelsHidden()
                    .tint(theme.mint)
                    .onChange(of: fragPoCUDPEnabled) { _, newValue in
                        FragPoCUDPStore.enabled = newValue
                        SocksstubSetFragPoCUDP(newValue)
                    }
            }
        }
    }


    /// Separate FragPoC endpoint URI. Empty keeps the legacy built-in sync2
    /// test server; a custom URI lets us point iOS at ai-archive.ru:443 or any
    /// future FragPoC load-balanced edge without abusing the tamizdat:// H2 URL.
    private var fragPoCServerCard: some View {
        CardContainer(padding: 16) {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 12) {
                    IconCard(systemName: "server.rack",
                             bg: theme.blueDim, fg: theme.blue)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("FragPoC server")
                            .font(.geist(.medium, size: 16))
                            .foregroundStyle(theme.text)
                        Text(FragPoCConfigStore.summaryLabel(for: fragPoCConfigDraft))
                            .font(.geistMono(.regular, size: 11))
                            .foregroundStyle(theme.textDim)
                    }
                    Spacer()
                }

                TextField("fragpoc://<shortid>@ai-archive.ru:443?secure=1&ports=443", text: $fragPoCConfigDraft, axis: .vertical)
                    .lineLimit(2...5)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled(true)
                    .keyboardType(.URL)
                    .font(.geistMono(.regular, size: 12.5))
                    .foregroundStyle(theme.text)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 11)
                    .background(theme.chip)
                    .clipShape(RoundedRectangle(cornerRadius: 14))

                if let fragPoCConfigError {
                    Text(fragPoCConfigError)
                        .font(.geist(.regular, size: 11))
                        .foregroundStyle(theme.red)
                }

                HStack(spacing: 8) {
                    Button(action: saveFragPoCConfig) {
                        Text("Save")
                            .font(.geist(.semibold, size: 13))
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 10)
                            .background(theme.mint)
                            .foregroundStyle(theme.mintInk)
                            .clipShape(RoundedRectangle(cornerRadius: 10))
                    }
                    .buttonStyle(.plain)
                    Button(action: resetFragPoCConfig) {
                        Text("Legacy")
                            .font(.geist(.semibold, size: 13))
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 10)
                            .background(theme.chip)
                            .foregroundStyle(theme.text)
                            .clipShape(RoundedRectangle(cornerRadius: 10))
                    }
                    .buttonStyle(.plain)
                }

                Text("Leave empty for the built-in legacy endpoint. Put ports=443,80 in the URI when the edge only exposes public 80/443.")
                    .font(.geist(.regular, size: 11))
                    .foregroundStyle(theme.textDim)
            }
        }
    }

    /// IPA-D38: FragPoC port-mode picker — One port / 80+443 / Multi-port,
    /// each with an editable port list. Element 0 of the list is the base
    /// server port; the rest form the dynamic dial pool the FragPoC client
    /// rotates across. Only effective while the FragPoC transport is on.
    private var fragPoCPortCard: some View {
        CardContainer(padding: 16) {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 12) {
                    IconCard(systemName: "network",
                             bg: theme.blueDim, fg: theme.blue)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Port mode")
                            .font(.geist(.medium, size: 16))
                            .foregroundStyle(theme.text)
                        Text("Legacy/test port pool; custom URI ports= overrides this")
                            .font(.geistMono(.regular, size: 11))
                            .foregroundStyle(theme.textDim)
                    }
                    Spacer()
                }

                // 3-way segmented control
                HStack(spacing: 2) {
                    fragPoCPortSegment(.single)
                    fragPoCPortSegment(.dual)
                    fragPoCPortSegment(.multi)
                }
                .padding(3)
                .background(theme.chip)
                .clipShape(RoundedRectangle(cornerRadius: 12))

                Text(fragPoCPortMode.hint)
                    .font(.geist(.regular, size: 11))
                    .foregroundStyle(theme.textDim)

                Text("Ports — comma-separated, first is the base port")
                    .font(.geist(.medium, size: 12))
                    .foregroundStyle(theme.textMuted)
                TextField("443, 80", text: $fragPoCPortsDraft, axis: .vertical)
                    .lineLimit(2...6)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled(true)
                    .keyboardType(.numbersAndPunctuation)
                    .font(.geistMono(.regular, size: 12.5))
                    .foregroundStyle(theme.text)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 11)
                    .background(theme.chip)
                    .clipShape(RoundedRectangle(cornerRadius: 14))

                HStack(spacing: 8) {
                    Button(action: saveFragPoCPorts) {
                        Text("Save")
                            .font(.geist(.semibold, size: 13))
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 10)
                            .background(theme.mint)
                            .foregroundStyle(theme.mintInk)
                            .clipShape(RoundedRectangle(cornerRadius: 10))
                    }
                    .buttonStyle(.plain)
                    Button(action: resetFragPoCPorts) {
                        Text("Reset")
                            .font(.geist(.semibold, size: 13))
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 10)
                            .background(theme.chip)
                            .foregroundStyle(theme.text)
                            .clipShape(RoundedRectangle(cornerRadius: 10))
                    }
                    .buttonStyle(.plain)
                }

                Text("Legacy/test pool. Custom fragpoc:// without ports= uses only the URI port.")
                    .font(.geist(.regular, size: 11))
                    .foregroundStyle(theme.textDim)
            }
        }
    }

    private func fragPoCPortSegment(_ mode: FragPoCPortMode) -> some View {
        let active = fragPoCPortMode == mode
        return Button {
            selectFragPoCPortMode(mode)
        } label: {
            Text(mode.label)
                .font(.geist(.semibold, size: 12))
                .frame(maxWidth: .infinity)
                .padding(.vertical, 7)
                .background(active ? theme.chipActive : Color.clear)
                .foregroundStyle(active ? theme.chipActiveText : theme.textDim)
                .clipShape(RoundedRectangle(cornerRadius: 10))
        }
        .buttonStyle(.plain)
    }

    /// Smoke-test status for a single port.
    private enum SmokeStatus: String {
        case pending  // yellow — probe launched but not finished
        case ok       // green  — port reachable, FragPoC answered
        case fail     // red    — blocked / unreachable / timeout
    }

    /// One port's smoke-test result. Starts as `.pending` (yellow lamp),
    /// updated to `.ok` or `.fail` as its probe completes.
    private struct SmokePortResult: Identifiable {
        let port: Int
        var status: SmokeStatus
        var ms: Int
        var err: String?
        var id: Int { port }
    }

    /// JSON shape returned by SocksstubProbeOnePort.
    private struct SmokePortJSON: Codable {
        let port: Int
        let ok: Bool
        let ms: Int
        let err: String?
    }

    /// IPA-D40: multi-port smoke test — probes each port of the active
    /// FragPoC mode with one OpOpenSecure round-trip and shows a green/red
    /// lamp per port. Probing runs outside the tunnel, so it must be run
    /// with the VPN disconnected to measure the raw carrier path.
    private var fragPoCSmokeTestCard: some View {
        CardContainer(padding: 16) {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 12) {
                    IconCard(systemName: "dot.radiowaves.left.and.right",
                             bg: theme.mintDim, fg: theme.mint)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Port smoke test")
                            .font(.geist(.medium, size: 16))
                            .foregroundStyle(theme.text)
                        Text("Probes each port of the active mode")
                            .font(.geistMono(.regular, size: 11))
                            .foregroundStyle(theme.textDim)
                    }
                    Spacer()
                }

                Button {
                    if smokeRunning {
                        smokeTask?.cancel()
                    } else {
                        smokeTask = Task { await runSmokeTest() }
                    }
                } label: {
                    HStack(spacing: 8) {
                        if smokeRunning {
                            Image(systemName: "stop.fill")
                            Text("Stop")
                        } else {
                            Text("Run test")
                        }
                    }
                    .font(.geist(.semibold, size: 13))
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 10)
                    .background(smokeRunning ? theme.red : theme.mint)
                    .foregroundStyle(smokeRunning ? .white : theme.mintInk)
                    .clipShape(RoundedRectangle(cornerRadius: 10))
                }
                .buttonStyle(.plain)

                if !smokeResults.isEmpty {
                    // Summary line — only counts settled (non-pending) results.
                    let settled = smokeResults.filter { $0.status != .pending }
                    if !settled.isEmpty {
                        HStack(spacing: 6) {
                            Text("\(settled.filter { $0.status == .ok }.count) reachable")
                                .foregroundStyle(Color.green)
                            Text("·")
                                .foregroundStyle(theme.textDim)
                            Text("\(settled.filter { $0.status == .fail }.count) blocked")
                                .foregroundStyle(Color.red)
                            if smokeRunning {
                                Text("·")
                                    .foregroundStyle(theme.textDim)
                                Text("\(smokeResults.filter { $0.status == .pending }.count) pending")
                                    .foregroundStyle(Color.yellow)
                            }
                            Spacer()
                        }
                        .font(.geist(.semibold, size: 12))
                    }
                    VStack(spacing: 6) {
                        ForEach(smokeResults) { result in
                            HStack(spacing: 10) {
                                Circle()
                                    .fill(smokeColor(result.status))
                                    .frame(width: 9, height: 9)
                                Text(String(result.port))
                                    .font(.geistMono(.regular, size: 13))
                                    .foregroundStyle(theme.text)
                                Spacer()
                                if result.status == .pending {
                                    ProgressView()
                                        .controlSize(.mini)
                                } else {
                                    Text("\(result.ms) ms")
                                        .font(.geistMono(.regular, size: 11))
                                        .foregroundStyle(theme.textDim)
                                }
                            }
                        }
                    }
                }

                Text("Run with the VPN disconnected to test the raw network. Green = port reachable and FragPoC answered; red = blocked, unreachable, or no server on that port.")
                    .font(.geist(.regular, size: 11))
                    .foregroundStyle(theme.textDim)
            }
        }
    }

    private var diagnosticsCard: some View {
        CardContainer(padding: 0) {
            DesignRow(
                icon: IconCard(systemName: "doc.text",
                               bg: theme.chip, fg: theme.textDim),
                title: "View logs",
                sub: "Live stream + filters",
                isLast: false
            ) {
                Image(systemName: "chevron.right")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(theme.textMuted)
            }
            .contentShape(Rectangle())
            .onTapGesture { showLogs = true }

            DesignRow(
                icon: IconCard(systemName: "paperplane.fill",
                               bg: theme.chip, fg: theme.textDim),
                title: "Telegram log uploader",
                sub: "Bot token + chat id for debugging",
                isLast: true
            ) {
                Image(systemName: "chevron.right")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(theme.textMuted)
            }
            .contentShape(Rectangle())
            .onTapGesture { showTelegram = true }
        }
        .sheet(isPresented: $showLogs) {
            // Pull bridge from environment-free reach — Logs reads from
            // App Group log file directly, no shared SamizdatBridge needed.
            LogView()
                .environment(\.themeTokens, theme)
        }
    }

    private var aboutCard: some View {
        CardContainer(padding: 0) {
            DesignRow(
                icon: IconCard(systemName: "info.circle",
                               bg: theme.chip, fg: theme.textDim),
                title: "Version",
                sub: versionLabel,
                isLast: false
            ) {
                EmptyView()
            }
            DesignRow(
                icon: IconCard(systemName: "arrow.up.right.square",
                               bg: theme.chip, fg: theme.textDim),
                title: "Project on GitHub",
                sub: "github.com/detectqq/tamizdat",
                isLast: true
            ) {
                Image(systemName: "chevron.right")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(theme.textMuted)
            }
            .contentShape(Rectangle())
            .onTapGesture {
                if let url = URL(string: "https://github.com/detectqq/tamizdat") {
                    UIApplication.shared.open(url)
                }
            }
        }
    }

    // MARK: – Helpers

    private var versionLabel: String {
        let info = Bundle.main.infoDictionary
        let marketing = info?["CFBundleShortVersionString"] as? String ?? "?"
        let build = info?["CFBundleVersion"] as? String ?? "?"
        return "\(marketing) (\(build)) · IPA-D57"
    }

    private var configSubtitle: String {
        let blob = ConfigStore.shared.load() ?? ""
        if blob.isEmpty { return "Not configured" }
        let split = SamizdatURLCodec.split(blob)
        let mainConfigured = !split.primary.isEmpty
        let backupConfigured = (split.backup != nil)
        switch (mainConfigured, backupConfigured) {
        case (true, true):   return "Main + Whitelist · 2 configured"
        case (true, false):  return "Main only"
        case (false, true):  return "Whitelist only (Main missing)"
        case (false, false): return "Not configured"
        }
    }

    private func saveURL() {
        let trimmed = pingURLDraft.trimmingCharacters(in: .whitespacesAndNewlines)
        PingURLPreferences.url = trimmed
        pingURL = PingURLPreferences.url
        pingURLDraft = pingURL
        Task { await VPNProfileStore.shared.refreshPingURL() }
    }

    private func resetURL() {
        PingURLPreferences.resetToDefault()
        pingURL = PingURLPreferences.url
        pingURLDraft = pingURL
        Task { await VPNProfileStore.shared.refreshPingURL() }
    }


    private func saveFragPoCConfig() {
        let trimmed = fragPoCConfigDraft.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmed.isEmpty {
            guard let components = URLComponents(string: trimmed),
                  components.scheme == "fragpoc",
                  components.host?.isEmpty == false else {
                fragPoCConfigError = "Use fragpoc://<shortid>@host:port?secure=1"
                return
            }
        }
        fragPoCConfigError = nil
        FragPoCConfigStore.configBlob = trimmed
        // Keep the main-app Go runtime in sync too. The Settings smoke/
        // payload/connection tests run in the app process, not in the Network
        // Extension, so the provider-message refresh below is not enough.
        SocksstubSetFragPoCConfig(trimmed)
        fragPoCConfigDraft = trimmed
        Task { await VPNProfileStore.shared.refreshSamizdatClient() }
    }

    private func resetFragPoCConfig() {
        fragPoCConfigDraft = ""
        fragPoCConfigError = nil
        FragPoCConfigStore.configBlob = ""
        SocksstubSetFragPoCConfig("")
        Task { await VPNProfileStore.shared.refreshSamizdatClient() }
    }

    private func syncFragPoCConfigToAppRuntime() {
        SocksstubSetFragPoCConfig(FragPoCConfigStore.configBlob)
        SocksstubSetFragPoCPorts(FragPoCPortConfigStore.effectiveActivePortsCSV)
    }

    /// Switches the FragPoC port mode. Commits any unsaved edits to the
    /// outgoing mode first, then reloads the draft from the new mode's
    /// stored list so each mode keeps its own ports.
    private func selectFragPoCPortMode(_ mode: FragPoCPortMode) {
        guard mode != fragPoCPortMode else { return }
        saveFragPoCPorts()
        fragPoCPortMode = mode
        FragPoCPortConfigStore.mode = mode
        fragPoCPortsDraft = FragPoCPortConfigStore.ports(for: mode)
            .map(String.init).joined(separator: ", ")
    }

    /// Parses the draft and persists it as the current mode's port list.
    /// Empty/all-invalid input is left untouched (keeps the previous list).
    private func saveFragPoCPorts() {
        let parsed = FragPoCPortConfigStore.parsePorts(fragPoCPortsDraft)
        guard !parsed.isEmpty else { return }
        FragPoCPortConfigStore.setPorts(parsed, for: fragPoCPortMode)
        fragPoCPortsDraft = parsed.map(String.init).joined(separator: ", ")
    }

    /// Restores the current mode's port list to its built-in default.
    private func resetFragPoCPorts() {
        let defaults = FragPoCPortConfigStore.defaultPorts(for: fragPoCPortMode)
        FragPoCPortConfigStore.setPorts(defaults, for: fragPoCPortMode)
        fragPoCPortsDraft = defaults.map(String.init).joined(separator: ", ")
    }

    /// D44: Progressive smoke test — all ports appear as yellow lamps immediately,
    /// each turning green or red as its probe completes. Probes run concurrently
    /// via TaskGroup; each finished probe updates its entry on the main actor so
    /// the UI refreshes in real time.
    private func runSmokeTest() async {
        guard !smokeRunning else { return }
        smokeRunning = true
        syncFragPoCConfigToAppRuntime()

        // Parse the effective endpoint port list and seed every port as pending
        // (yellow). Custom fragpoc:// URIs override the legacy lab port mode.
        let ports = FragPoCPortConfigStore.effectiveActivePorts
        smokeResults = ports.map { SmokePortResult(port: $0, status: .pending, ms: 0) }

        // Launch all probes concurrently. Each probe calls the per-port Go
        // function and posts its result back to the main actor individually.
        await withTaskGroup(of: (Int, SmokePortJSON?).self) { group in
            for (idx, port) in ports.enumerated() {
                group.addTask {
                    let json = SocksstubProbeOnePort(port)
                    let decoded = try? JSONDecoder().decode(
                        SmokePortJSON.self, from: Data(json.utf8))
                    return (idx, decoded)
                }
            }
            for await (idx, decoded) in group {
                if Task.isCancelled { break }
                guard idx < smokeResults.count else { continue }
                if let d = decoded {
                    smokeResults[idx].status = d.ok ? .ok : .fail
                    smokeResults[idx].ms = d.ms
                    smokeResults[idx].err = d.err
                } else {
                    smokeResults[idx].status = .fail
                    smokeResults[idx].err = "decode error"
                }
            }
        }
        smokeRunning = false
        smokeTask = nil
    }

    /// Maps smoke status to a lamp color.
    private func smokeColor(_ status: SmokeStatus) -> Color {
        switch status {
        case .pending: return .yellow
        case .ok:      return .green
        case .fail:    return .red
        }
    }

    // MARK: – D47: Single-port payload size test

    /// Progress state for the single-port payload test. The test picks
    /// the first active port and probes sizes 10→1500 B step 10, showing
    /// live progress on that one port.
    private struct PayloadProgress {
        var port: Int = 0
        var currentSize: Int = 0   // size currently being tested
        var maxOKSize: Int = 0     // largest size that got AckOK
        var step: Int = 0          // 1-based step counter
        var totalSteps: Int = 150  // 1500 / 10
        var done: Bool = false
        var err: String?
    }

    /// JSON shape returned by SocksstubProbePayloadStep.
    private struct PayloadStepJSON: Codable {
        let port: Int
        let size: Int
        let ok: Bool
        let err: String?
    }

    private var fragPoCPayloadTestCard: some View {
        CardContainer(padding: 16) {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 12) {
                    IconCard(systemName: "arrow.up.arrow.down",
                             bg: theme.blueDim, fg: theme.blue)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Max payload test")
                            .font(.geist(.medium, size: 16))
                            .foregroundStyle(theme.text)
                        Text("Probes one port: 10→1500 B, step 10")
                            .font(.geistMono(.regular, size: 11))
                            .foregroundStyle(theme.textDim)
                    }
                    Spacer()
                }

                Button {
                    if payloadRunning {
                        payloadTask?.cancel()
                    } else {
                        payloadTask = Task { await runPayloadTest() }
                    }
                } label: {
                    HStack(spacing: 8) {
                        if payloadRunning {
                            Image(systemName: "stop.fill")
                            Text("Stop  :\(payloadProgress.port)  \(payloadProgress.currentSize) B")
                        } else {
                            Text("Run test")
                        }
                    }
                    .font(.geist(.semibold, size: 13))
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 10)
                    .background(payloadRunning ? theme.red : theme.blue)
                    .foregroundStyle(.white)
                    .clipShape(RoundedRectangle(cornerRadius: 10))
                }
                .buttonStyle(.plain)

                if payloadRunning || payloadProgress.done {
                    VStack(alignment: .leading, spacing: 8) {
                        // Port + step counter
                        HStack {
                            Text("Port \(payloadProgress.port)")
                                .font(.geist(.semibold, size: 13))
                                .foregroundStyle(theme.text)
                            Spacer()
                            Text("step \(payloadProgress.step)/\(payloadProgress.totalSteps)")
                                .font(.geistMono(.regular, size: 11))
                                .foregroundStyle(theme.textDim)
                        }

                        // Progress bar
                        GeometryReader { geo in
                            ZStack(alignment: .leading) {
                                RoundedRectangle(cornerRadius: 4)
                                    .fill(theme.chip)
                                    .frame(height: 6)
                                RoundedRectangle(cornerRadius: 4)
                                    .fill(payloadProgress.done && payloadProgress.maxOKSize == 0
                                          ? theme.red : theme.blue)
                                    .frame(width: geo.size.width * CGFloat(payloadProgress.step)
                                           / CGFloat(max(payloadProgress.totalSteps, 1)),
                                           height: 6)
                                    .animation(.easeInOut(duration: 0.1), value: payloadProgress.step)
                            }
                        }
                        .frame(height: 6)

                        // Big result number
                        HStack(alignment: .firstTextBaseline, spacing: 4) {
                            Text("\(payloadProgress.maxOKSize)")
                                .font(.geistMono(.bold, size: 28))
                                .foregroundStyle(theme.blue)
                                .contentTransition(.numericText())
                                .animation(.easeInOut(duration: 0.1), value: payloadProgress.maxOKSize)
                            Text("B max")
                                .font(.geist(.medium, size: 14))
                                .foregroundStyle(theme.textDim)
                        }

                        if let err = payloadProgress.err {
                            Text(err)
                                .font(.geistMono(.regular, size: 10))
                                .foregroundStyle(theme.red)
                                .lineLimit(2)
                        }
                    }
                }

                Text("Tests the first active port. Sends increasingly larger payloads via OpOpenSecure. Run with VPN off.")
                    .font(.geist(.regular, size: 11))
                    .foregroundStyle(theme.textDim)
            }
        }
    }

    /// D47: Single-port payload test — sequential steps on MainActor,
    /// each Go call detached. UI updates after every single step.
    private func runPayloadTest() async {
        guard !payloadRunning else { return }
        payloadRunning = true
        syncFragPoCConfigToAppRuntime()
        let port = FragPoCPortConfigStore.effectiveActivePorts.first ?? 443
        payloadProgress = PayloadProgress(port: port)

        for size in stride(from: 10, through: 1500, by: 10) {
            if Task.isCancelled { break }
            let json = await Task.detached(priority: .userInitiated) {
                SocksstubProbePayloadStep(port, size)
            }.value
            if Task.isCancelled { break }
            let decoded = try? JSONDecoder().decode(
                PayloadStepJSON.self, from: Data(json.utf8))
            let ok = decoded?.ok ?? false

            payloadProgress.currentSize = size
            payloadProgress.step += 1
            if ok {
                payloadProgress.maxOKSize = size
            } else {
                payloadProgress.err = decoded?.err
                payloadProgress.done = true
                break
            }
        }
        if !payloadProgress.done { payloadProgress.done = true }
        payloadRunning = false
        payloadTask = nil
    }

    // MARK: – D47: Sequential max connections test

    /// Per-port progress for the max-connections test.
    private struct MaxConnsPortRow: Identifiable {
        let port: Int
        var count: Int = 0
        var testing: Bool = false
        var done: Bool = false
        var err: String?
        var id: Int { port }
    }

    /// Aggregate progress for the max-connections test.
    private struct MaxConnsProgress {
        var total: Int = 0
        var ports: [MaxConnsPortRow] = []
        var done: Bool = false
    }

    /// JSON shape returned by SocksstubMaxConnsOpenOne.
    private struct MaxConnsStepJSON: Codable {
        let total: Int
        let port: Int
        let ok: Bool
        let portCount: Int
        let perPort: [String: Int]
        let err: String?
    }

    private var fragPoCMaxConnsTestCard: some View {
        CardContainer(padding: 16) {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 12) {
                    IconCard(systemName: "point.3.connected.trianglepath.dotted",
                             bg: theme.amberDim, fg: theme.amber)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Max connections test")
                            .font(.geist(.medium, size: 16))
                            .foregroundStyle(theme.text)
                        Text("Fills each port, then moves to the next")
                            .font(.geistMono(.regular, size: 11))
                            .foregroundStyle(theme.textDim)
                    }
                    Spacer()
                }

                Button {
                    if maxConnsRunning {
                        maxConnsTask?.cancel()
                    } else {
                        maxConnsTask = Task { await runMaxConnsTest() }
                    }
                } label: {
                    HStack(spacing: 8) {
                        if maxConnsRunning {
                            Image(systemName: "stop.fill")
                            Text("Stop  \(maxConnsProgress.total) conns")
                        } else {
                            Text("Run test")
                        }
                    }
                    .font(.geist(.semibold, size: 13))
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 10)
                    .background(maxConnsRunning ? theme.red : theme.amber)
                    .foregroundStyle(maxConnsRunning ? .white : .black)
                    .clipShape(RoundedRectangle(cornerRadius: 10))
                }
                .buttonStyle(.plain)

                if maxConnsProgress.total > 0 || maxConnsProgress.done {
                    VStack(alignment: .leading, spacing: 8) {
                        // Big total counter
                        HStack(alignment: .firstTextBaseline, spacing: 4) {
                            Text("\(maxConnsProgress.total)")
                                .font(.geistMono(.bold, size: 28))
                                .foregroundStyle(theme.amber)
                                .contentTransition(.numericText())
                                .animation(.easeInOut(duration: 0.1), value: maxConnsProgress.total)
                            Text("total")
                                .font(.geist(.medium, size: 14))
                                .foregroundStyle(theme.textDim)
                        }

                        // Per-port rows
                        ForEach(maxConnsProgress.ports) { row in
                            HStack(spacing: 10) {
                                Circle()
                                    .fill(maxConnsLampColor(row))
                                    .frame(width: 9, height: 9)
                                Text(":\(row.port)")
                                    .font(.geistMono(.regular, size: 13))
                                    .foregroundStyle(theme.text)
                                Spacer()
                                if row.testing {
                                    HStack(spacing: 4) {
                                        Text("\(row.count)")
                                            .font(.geistMono(.bold, size: 13))
                                            .foregroundStyle(theme.amber)
                                            .contentTransition(.numericText())
                                        ProgressView().controlSize(.mini)
                                    }
                                } else if row.done {
                                    Text("\(row.count)")
                                        .font(.geistMono(.bold, size: 13))
                                        .foregroundStyle(row.count > 0 ? theme.mint : theme.red)
                                } else {
                                    Text("—")
                                        .font(.geistMono(.regular, size: 11))
                                        .foregroundStyle(theme.textDim)
                                }
                            }
                        }
                    }
                }

                Text("Fills one port completely, then moves to the next. All connections stay open. Run with VPN off.")
                    .font(.geist(.regular, size: 11))
                    .foregroundStyle(theme.textDim)
            }
        }
    }

    private func maxConnsLampColor(_ row: MaxConnsPortRow) -> Color {
        if row.testing { return .yellow }
        if row.done && row.count > 0 { return .green }
        if row.done { return .red }
        return Color.gray.opacity(0.4)
    }

    /// D47: Sequential max-connections test — fills port 1 completely,
    /// then port 2, etc. All connections stay open across ports. UI
    /// updates after every single connection opened.
    /// Max connections per single port before moving to the next.
    private let maxConnsPerPort = 120

    private func runMaxConnsTest() async {
        guard !maxConnsRunning else { return }
        maxConnsRunning = true
        syncFragPoCConfigToAppRuntime()

        let activePorts = FragPoCPortConfigStore.effectiveActivePorts
        let csv = FragPoCPortConfigStore.effectiveActivePortsCSV
        maxConnsProgress = MaxConnsProgress(
            ports: activePorts.map { MaxConnsPortRow(port: $0) }
        )

        // Initialize Go-side session
        _ = await Task.detached { SocksstubStartMaxConnsSession(csv) }.value

        // Fill each port sequentially (up to 120 per port)
        for (idx, port) in activePorts.enumerated() {
            if Task.isCancelled { break }
            maxConnsProgress.ports[idx].testing = true

            while maxConnsProgress.ports[idx].count < maxConnsPerPort {
                if Task.isCancelled { break }
                let json = await Task.detached(priority: .userInitiated) {
                    SocksstubMaxConnsOpenOne(port)
                }.value
                if Task.isCancelled { break }

                guard let decoded = try? JSONDecoder().decode(
                    MaxConnsStepJSON.self, from: Data(json.utf8)) else {
                    maxConnsProgress.ports[idx].err = "decode error"
                    break
                }

                maxConnsProgress.total = decoded.total

                if decoded.ok {
                    maxConnsProgress.ports[idx].count = decoded.portCount
                } else {
                    // This port is full — record and move to the next
                    maxConnsProgress.ports[idx].err = decoded.err
                    break
                }
            }

            maxConnsProgress.ports[idx].testing = false
            maxConnsProgress.ports[idx].done = true
        }

        maxConnsProgress.done = true

        // Cleanup — close all held connections
        _ = await Task.detached { SocksstubMaxConnsClose() }.value
        maxConnsRunning = false
        maxConnsTask = nil
    }

    // MARK: – Whitelist probes

    private func saveWhitelistProbes() {
        WhitelistProbePreferences.testHost = testHostDraft
        WhitelistProbePreferences.whitelistHost = whitelistHostDraft
        WhitelistProbePreferences.successesNeeded = wlSuccessesDraft
        WhitelistProbePreferences.probeInterval = wlIntervalDraft
        // Re-sync drafts so blank-saves snap back to the resolved default.
        testHostDraft = WhitelistProbePreferences.testHost
        whitelistHostDraft = WhitelistProbePreferences.whitelistHost
        wlSuccessesDraft = WhitelistProbePreferences.successesNeeded
        wlIntervalDraft = WhitelistProbePreferences.probeInterval
        Task { await VPNProfileStore.shared.refreshWhitelistProbes() }
    }

    private func resetWhitelistProbes() {
        WhitelistProbePreferences.reset()
        testHostDraft = WhitelistProbePreferences.testHost
        whitelistHostDraft = WhitelistProbePreferences.whitelistHost
        wlSuccessesDraft = WhitelistProbePreferences.successesNeeded
        wlIntervalDraft = WhitelistProbePreferences.probeInterval
        Task { await VPNProfileStore.shared.refreshWhitelistProbes() }
    }

    private func handleEnableNotifications() async {
        let granted = await NotificationPreferences.requestPermission()
        permissionStatus = await NotificationPreferences.currentSystemAuthorization()
        if granted {
            NotificationPreferences.enabled = true
        } else {
            NotificationPreferences.enabled = false
            notificationsEnabled = false
            permissionDeniedAlert = true
        }
    }

    private func openSystemSettings() {
        guard let url = URL(string: UIApplication.openSettingsURLString) else { return }
        UIApplication.shared.open(url)
    }
}

/// Notification name used to flip the theme live without dismissing the
/// Settings sheet. App.swift / ContentView listens and re-reads
/// `ThemePreferences.current` to update the environment.
extension Notification.Name {
    static let tamizdatThemeChanged = Notification.Name("tamizdat.themeChanged")
}
