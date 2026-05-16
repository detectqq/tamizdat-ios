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
    @State private var fragPoCPortMode: FragPoCPortMode = FragPoCPortConfigStore.mode
    @State private var fragPoCPortsDraft: String = FragPoCPortConfigStore.activePorts
        .map(String.init).joined(separator: ", ")
    @State private var smokeResults: [SmokePortResult] = []
    @State private var smokeRunning = false

    // IPA-D23: whitelist-detection probe targets.
    @State private var testHostDraft: String = WhitelistProbePreferences.testHost
    @State private var whitelistHostDraft: String = WhitelistProbePreferences.whitelistHost

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
                        fragPoCPortCard
                            .padding(.horizontal, 16)
                            .padding(.top, 10)
                        fragPoCSmokeTestCard
                            .padding(.horizontal, 16)
                            .padding(.top, 10)

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
                sub: "Routes through the FragPoC test server. Applies on next reconnect.",
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
                        Text("How FragPoC spreads dials across server ports")
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

                Text("Applies on next reconnect.")
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

    /// One port's smoke-test result, decoded from the JSON that
    /// SocksstubRunFragPoCSmokeTest returns.
    private struct SmokePortResult: Codable, Identifiable {
        let port: Int
        let ok: Bool
        let ms: Int
        let err: String?
        var id: Int { port }
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
                    Task { await runSmokeTest() }
                } label: {
                    HStack(spacing: 8) {
                        if smokeRunning {
                            ProgressView().controlSize(.small)
                            Text("Probing…")
                        } else {
                            Text("Run test")
                        }
                    }
                    .font(.geist(.semibold, size: 13))
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 10)
                    .background(theme.mint)
                    .foregroundStyle(theme.mintInk)
                    .clipShape(RoundedRectangle(cornerRadius: 10))
                }
                .buttonStyle(.plain)
                .disabled(smokeRunning)

                if !smokeResults.isEmpty {
                    VStack(spacing: 6) {
                        ForEach(smokeResults) { result in
                            HStack(spacing: 10) {
                                Circle()
                                    .fill(result.ok ? Color.green : Color.red)
                                    .frame(width: 9, height: 9)
                                Text(String(result.port))
                                    .font(.geistMono(.regular, size: 13))
                                    .foregroundStyle(theme.text)
                                Spacer()
                                Text("\(result.ms) ms")
                                    .font(.geistMono(.regular, size: 11))
                                    .foregroundStyle(theme.textDim)
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
        return "\(marketing) (\(build)) · IPA-D24"
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

    /// Runs the multi-port smoke test off the main thread, then publishes the
    /// per-port results. Probes the active mode's port list; the Go side
    /// probes all ports in parallel, each bounded by a ~6 s timeout.
    private func runSmokeTest() async {
        guard !smokeRunning else { return }
        smokeRunning = true
        smokeResults = []
        let csv = FragPoCPortConfigStore.activePortsCSV
        let json = await Task.detached(priority: .userInitiated) {
            SocksstubRunFragPoCSmokeTest(csv)
        }.value
        smokeResults = (try? JSONDecoder().decode(
            [SmokePortResult].self, from: Data(json.utf8))) ?? []
        smokeRunning = false
    }

    private func saveWhitelistProbes() {
        WhitelistProbePreferences.testHost = testHostDraft
        WhitelistProbePreferences.whitelistHost = whitelistHostDraft
        // Re-sync drafts so blank-saves snap back to the resolved default.
        testHostDraft = WhitelistProbePreferences.testHost
        whitelistHostDraft = WhitelistProbePreferences.whitelistHost
        Task { await VPNProfileStore.shared.refreshWhitelistProbes() }
    }

    private func resetWhitelistProbes() {
        WhitelistProbePreferences.reset()
        testHostDraft = WhitelistProbePreferences.testHost
        whitelistHostDraft = WhitelistProbePreferences.whitelistHost
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
