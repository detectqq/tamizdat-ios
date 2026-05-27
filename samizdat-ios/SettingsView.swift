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

    // VK TURN call-hash field. The hash is the slug after `/join/` in a
    // VK call invite URL (e.g. `https://vk.ru/call/join/<HASH>`). The
    // user creates a group call in VK, copies the invite link, pastes
    // either the full URL or just the hash into this field. The hash is
    // persisted in App Group UserDefaults so the NE can also see it.
    @State private var vkCallHashDraft: String = VKCredsPreferences.primaryCallHash
    @State private var vkDerivedPeerAddr: String = VKCredsPreferences.peerAddr
    @State private var vkDerivedPasswordConfigured: Bool = !VKCredsPreferences.connectPassword.isEmpty
    @State private var vkCallHashFeedback: String = ""

    /// Debounce token for the auto-persist refresh trigger. The three
    /// VK TURN fields fire `onChange` on every keystroke; we
    /// schedule a forceRefresh 1 s after the last edit, cancelling
    /// any pending one. Tap "Clear" to bail out cleanly.
    @State private var vkRefreshDebounceTask: Task<Void, Never>?

    // IPA-D23: whitelist-detection probe targets.
    @State private var testHostDraft: String = WhitelistProbePreferences.testHost
    @State private var whitelistHostDraft: String = WhitelistProbePreferences.whitelistHost
    // D45: expanded whitelist tunables.
    @State private var wlSuccessesDraft: Int = WhitelistProbePreferences.successesNeeded
    @State private var wlIntervalDraft: Int = WhitelistProbePreferences.probeInterval

    // Phase 2G: what does the whitelist endpoint actually do?
    // Either dial the backup tamizdat URI (legacy), or route through
    // VK TURN. The backup URI is preserved in either case so the
    // operator can flip back without re-pasting it.
    @State private var whitelistMode: WhitelistMode = WhitelistMode.current

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

                        // ── VK TURN ──────────────────────────────
                        SectionLabel(text: "VK TURN")
                            .padding(.top, 22)
                        vkTurnCard
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
            syncVKDerivedH2Config()
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
                syncVKDerivedH2Config()
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

    // VK TURN card: lets the operator paste a VK call-invite hash. The
    // hash is required by VKCredsClient / TURNCredsRefresher to begin
    // the 5-step VK API flow; if it is empty, refresh silently no-ops.
    //
    // To obtain a hash: open VK in a browser or app, create a group call,
    // copy the invitation link (https://vk.ru/call/join/<HASH>) and paste
    // either the full URL or just the slug here.
    //
    // Donor caveat (amurcanov/proxy-turn-vk-android README): when leaving
    // the call, choose "just leave" — not "end for everyone" — otherwise
    // the hash dies and refresh starts failing with VKCredsError.deadHash.
    private var vkTurnCard: some View {
        CardContainer(padding: 16) {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 12) {
                    IconCard(systemName: "phone.connection",
                             bg: theme.mintDim, fg: theme.mint)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Call invite hash")
                            .font(.geist(.medium, size: 16))
                            .foregroundStyle(theme.text)
                        Text("VK → group → call → invite link → slug after /join/")
                            .font(.geistMono(.regular, size: 11))
                            .foregroundStyle(theme.textDim)
                    }
                    Spacer()
                }

                TextField("https://vk.ru/call/join/...", text: $vkCallHashDraft)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled(true)
                    .keyboardType(.URL)
                    .font(.geistMono(.regular, size: 12.5))
                    .foregroundStyle(theme.text)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 11)
                    .background(theme.chip)
                    .clipShape(RoundedRectangle(cornerRadius: 14))
                    .onSubmit { persistAndMaybeRefresh() }
                    .onChange(of: vkCallHashDraft) { _, _ in persistAndMaybeRefresh() }

                Text("Сервер (из H2 URI)")
                    .font(.geist(.medium, size: 12))
                    .foregroundStyle(theme.textMuted)
                Text(vkDerivedPeerAddr.isEmpty ? "Нет Whitelist/Main H2 URI" : vkDerivedPeerAddr)
                    .font(.geistMono(.regular, size: 12.5))
                    .foregroundStyle(vkDerivedPeerAddr.isEmpty ? theme.textDim : theme.text)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 11)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(theme.chip)
                    .clipShape(RoundedRectangle(cornerRadius: 14))

                Text("Пароль подключения")
                    .font(.geist(.medium, size: 12))
                    .foregroundStyle(theme.textMuted)
                Text(vkDerivedPasswordConfigured ? "shortid из Whitelist/Main H2 URI" : "Нет shortid в Whitelist/Main H2 URI")
                    .font(.geistMono(.regular, size: 12.5))
                    .foregroundStyle(vkDerivedPasswordConfigured ? theme.text : theme.textDim)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 11)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(theme.chip)
                    .clipShape(RoundedRectangle(cornerRadius: 14))

                // VK TURN peer/password are derived from the H2
                // tamizdat:// URI: server = URI authority, password =
                // shortid. Prefer Whitelist/H2, fallback to Main.
                // Persistence happens on every hash change; a debounced
                // forceRefresh fires 1 s after the last edit when hash +
                // derived H2 tuple are available. The Whitelist-mode
                // picker (H2 / TURN) in the Whitelist detection card is
                // the single source of truth for whether VK TURN is engaged.
                Text("Hash сохраняется автоматически. Сервер берётся из H2 tamizdat:// URI, пароль = shortid из этого URI. VK TURN включается, когда «Whitelist mode = TURN» в разделе Whitelist detection.")
                    .font(.geistMono(.regular, size: 10))
                    .foregroundStyle(theme.textDim)
                    .padding(.top, 4)

                if !vkCallHashFeedback.isEmpty {
                    Text(vkCallHashFeedback)
                        .font(.geistMono(.regular, size: 11))
                        .foregroundStyle(theme.textDim)
                }

                Button(action: clearVKHash) {
                    Text("Clear")
                        .font(.geist(.semibold, size: 13))
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                        .background(theme.chip)
                        .foregroundStyle(theme.text)
                        .clipShape(RoundedRectangle(cornerRadius: 10))
                }
                .buttonStyle(.plain)
                // Emergency reset for the "stuck refresh" state. If a
                // previous refresh wedged (network hang, WKWebView never
                // completing) `isRefreshing` stays true forever and every
                // subsequent forceRefresh just skips. This button cancels
                // the in-flight Task and flips the flag back.
                Button(action: resetRefreshState) {
                    Text("Reset refresh state")
                        .font(.geist(.semibold, size: 13))
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                        .background(theme.amberDim)
                        .foregroundStyle(theme.amber)
                        .clipShape(RoundedRectangle(cornerRadius: 10))
                }
                .buttonStyle(.plain)
            }
        }
    }

    /// Strip wrapping whitespace and (if present) the `/call/join/`
    /// prefix so the user can paste either a full invite URL or a bare
    /// hash. Trailing query / fragment is dropped as well.
    private static func normalizeVKHash(_ raw: String) -> String {
        var s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if let range = s.range(of: "/call/join/") {
            s = String(s[range.upperBound...])
        }
        if let q = s.firstIndex(where: { $0 == "?" || $0 == "#" }) {
            s = String(s[..<q])
        }
        return s.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
    }

    private func syncVKDerivedH2Config() -> SamizdatURLCodec.H2PeerConfig? {
        let blob = ConfigStore.shared.load() ?? ""
        let derived = SamizdatURLCodec.h2PeerConfig(from: blob)
        VKCredsPreferences.applyDerivedH2PeerConfig(derived)
        vkDerivedPeerAddr = derived?.server ?? ""
        vkDerivedPasswordConfigured = derived?.shortID.isEmpty == false
        return derived
    }

    /// Silent persist + debounced refresh. Called from the hash TextField's
    /// `onChange`. Normalises hash, mirrors H2 URI authority+shortid
    /// into the App Group keys consumed by the Network Extension, then
    /// schedules a single forceRefresh 1 second after the last edit settles.
    /// Empty hash or missing H2 URI doesn't trip refresh — we just save the
    /// partial state so the user can come back and complete it later.
    ///
    /// Doesn't touch EndpointTurnMode any more — the Whitelist-mode
    /// picker (H2 / TURN) is the single source of truth.
    private func persistAndMaybeRefresh() {
        let derived = syncVKDerivedH2Config()

        let hash = Self.normalizeVKHash(vkCallHashDraft)
        VKCredsPreferences.primaryCallHash = hash

        // Re-sync drafts if normalisation changed them — but only when
        // the user has paused typing, otherwise we fight against their
        // edit position. Detect "paused" by deferring the rewrite to
        // after the debounce timer fires.

        // Cancel any pending debounce.
        vkRefreshDebounceTask?.cancel()
        vkCallHashFeedback = ""

        // Only fire the refresh once hash and derived H2 peer config exist.
        let ready = !hash.isEmpty && derived != nil
        guard ready else {
            return
        }

        vkRefreshDebounceTask = Task { @MainActor in
            try? await Task.sleep(nanoseconds: 1_000_000_000)
            if Task.isCancelled { return }
            // Snap normalised forms back into the drafts now that the
            // user has paused typing.
            if vkCallHashDraft != hash {
                vkCallHashDraft = hash
            }
            if vkDerivedPeerAddr != (derived?.server ?? "") {
                vkDerivedPeerAddr = derived?.server ?? ""
            }
            vkDerivedPasswordConfigured = derived?.shortID.isEmpty == false
            vkCallHashFeedback = "Автообновление..."
            TURNCredsRefresher.shared.forceRefresh()
        }
    }

    private func clearVKHash() {
        vkRefreshDebounceTask?.cancel()
        VKCredsPreferences.primaryCallHash = ""
        vkCallHashDraft = ""
        vkCallHashFeedback = "Очищено"
        TURNCredsStore.shared.clear()
    }

    private func resetRefreshState() {
        TURNCredsRefresher.shared.resetRefreshState()
        vkCallHashFeedback = "Состояние refresh сброшено"
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

                // Phase 2G: pick how the "whitelist" endpoint actually
                // works. H2 = legacy backup URI. TURN = VK TURN relay.
                // Switching this does NOT clear the existing backup URI,
                // so the operator can flip back without re-pasting.
                Text("Whitelist mode")
                    .font(.geist(.medium, size: 12))
                    .foregroundStyle(theme.textMuted)
                Picker("", selection: $whitelistMode) {
                    ForEach(WhitelistMode.allCases) { mode in
                        Text(mode.label).tag(mode)
                    }
                }
                .pickerStyle(.segmented)
                .onChange(of: whitelistMode) { _, newValue in
                    WhitelistMode.current = newValue
                    // EndpointTurnMode mirror REMOVED on the autonomous-
                    // refresh pass — `WhitelistMode` is now the single
                    // source of truth and the extension reads it
                    // directly in attachVKTurnUpstream.
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
                .onChange(of: wlSuccessesDraft) { _, newValue in
                    WhitelistProbePreferences.successesNeeded = newValue
                }

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
                .onChange(of: wlIntervalDraft) { _, newValue in
                    WhitelistProbePreferences.probeInterval = newValue
                }

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
