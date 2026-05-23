import SwiftUI

/// IPA-D22: Endpoints management screen (Main + Whitelist tamizdat://
/// URLs). Replaces the legacy `ConfigPasteView` 2-TextEditor sheet.
///
/// Two cards stacked: Main (mint accent) + Whitelist (blue accent).
/// Each renders the URL as a parsed code-block and offers
/// Paste / Scan (QR camera) / Clear chip actions. Clear opens an
/// inline confirmation strip (no native alert) so the surrounding
/// context stays visible.
///
/// Persistence: still goes through `ConfigStore` (Keychain) +
/// `SamizdatURLCodec.compose / split` so the Network Extension reads
/// the same blob shape it already understands.
struct EndpointsView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(\.themeTokens) private var theme

    /// Called on dismiss with `true` if at least Main is stored, `false`
    /// otherwise. Parent uses this to refresh hasConfig + hasBackup.
    var onClose: (Bool) -> Void

    @State private var primaryURL: String
    @State private var backupURL: String
    @State private var confirming: ConfirmingCard? = nil
    @State private var scanning: ScanTarget? = nil
    @State private var pasteError: String?

    // IPA-D24: per-card inline edit state. `editing` toggles the
    // CodeBlock into a TextEditor; `editBufferMain/Backup` hold the
    // mutable draft so Cancel can revert.
    @State private var editing: ConfirmingCard? = nil
    @State private var editBufferMain: String = ""
    @State private var editBufferBackup: String = ""

    private enum ConfirmingCard { case main, backup }
    private enum ScanTarget: Identifiable {
        case main, backup
        var id: String {
            switch self {
            case .main: return "main"
            case .backup: return "backup"
            }
        }
    }

    init(onClose: @escaping (Bool) -> Void) {
        self.onClose = onClose
        let stored = ConfigStore.shared.load() ?? ""
        let split = SamizdatURLCodec.split(stored)
        _primaryURL = State(initialValue: split.primary)
        _backupURL  = State(initialValue: split.backup ?? "")
    }

    var body: some View {
        ZStack {
            ThemeBackground(theme: theme)

            VStack(spacing: 0) {
                // ── Header ────────────────────────────────────────
                HStack {
                    Chip(label: "Done") { closeAndPersist() }
                    Spacer()
                    Text("Proxies")
                        .font(.geist(.semibold, size: 16))
                        .foregroundStyle(theme.text)
                    Spacer()
                    // Balance the Done chip
                    Color.clear.frame(width: 56, height: 1)
                }
                .padding(.horizontal, 20)
                .padding(.top, 8)
                .padding(.bottom, 6)

                // ── Large title ───────────────────────────────────
                Text("Proxies")
                    .font(.geist(.bold, size: 32))
                    .tracking(-0.96)
                    .foregroundStyle(theme.text)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 20)
                    .padding(.bottom, 18)

                // ── Cards ─────────────────────────────────────────
                ScrollView {
                    VStack(spacing: 12) {
                        EndpointCard(
                            label: "Main",
                            labelBg: theme.mintDim,
                            labelFg: theme.mint,
                            accent: theme.mint,
                            url: primaryURL,
                            isConfirming: confirming == .main,
                            isEditing: editing == .main,
                            editBuffer: $editBufferMain,
                            onPaste: pasteMain,
                            onScan: { scanning = .main },
                            onClearRequest: { confirming = .main },
                            onClearCancel:  { confirming = nil },
                            onClearConfirm: clearMain,
                            onEditStart: {
                                editBufferMain = primaryURL
                                editing = .main
                                pasteError = nil
                            },
                            onEditCancel: { editing = nil; pasteError = nil },
                            onEditSave: { saveEditedMain() }
                        )

                        EndpointCard(
                            label: "Whitelist",
                            labelBg: theme.blueDim,
                            labelFg: theme.blue,
                            accent: theme.blue,
                            url: backupURL,
                            isConfirming: confirming == .backup,
                            isEditing: editing == .backup,
                            editBuffer: $editBufferBackup,
                            onPaste: pasteBackup,
                            onScan: { scanning = .backup },
                            onClearRequest: { confirming = .backup },
                            onClearCancel:  { confirming = nil },
                            onClearConfirm: clearBackup,
                            onEditStart: {
                                editBufferBackup = backupURL
                                editing = .backup
                                pasteError = nil
                            },
                            onEditCancel: { editing = nil; pasteError = nil },
                            onEditSave: { saveEditedBackup() }
                        )

                        if let err = pasteError {
                            HStack(spacing: 8) {
                                Image(systemName: "exclamationmark.triangle.fill")
                                    .foregroundStyle(theme.red)
                                Text(err)
                                    .font(.geist(.medium, size: 13))
                                    .foregroundStyle(theme.text)
                                Spacer()
                            }
                            .padding(12)
                            .background(theme.redDim)
                            .clipShape(RoundedRectangle(cornerRadius: 12))
                        }
                    }
                    .padding(.horizontal, 16)
                    .padding(.bottom, 24)
                }
            }
        }
        .preferredColorScheme(theme.isDark ? .dark : .light)
        .sheet(item: $scanning) { target in
            QRScannerSheet { code in
                applyScanned(code, to: target)
            }
            .environment(\.themeTokens, theme)
        }
    }

    // MARK: – Actions

    private func pasteMain() {
        guard let pasted = UIPasteboard.general.string?
            .trimmingCharacters(in: .whitespacesAndNewlines), !pasted.isEmpty else { return }
        applyPasted(pasted, toBackup: false)
    }

    private func pasteBackup() {
        guard let pasted = UIPasteboard.general.string?
            .trimmingCharacters(in: .whitespacesAndNewlines), !pasted.isEmpty else { return }
        applyPasted(pasted, toBackup: true)
    }

    private func applyPasted(_ s: String, toBackup: Bool) {
        guard validateAndApply(s, toBackup: toBackup) else { return }
        pasteError = nil
        persistImmediately()
    }

    private func applyScanned(_ s: String, to target: ScanTarget) {
        let toBackup = target == .backup
        guard validateAndApply(s, toBackup: toBackup) else { return }
        pasteError = nil
        persistImmediately()
    }

    /// Validates the URL, updates the corresponding @State field,
    /// returns true on success. Sets pasteError on failure.
    private func validateAndApply(_ s: String, toBackup: Bool) -> Bool {
        let scheme = toBackup ? "Whitelist" : "Main"
        if let err = SamizdatBridge.validate(s) {
            pasteError = "\(scheme): \(err)"
            return false
        }
        if toBackup {
            backupURL = s
        } else {
            primaryURL = s
        }
        return true
    }

    /// IPA-D24: commit the inline-edited Main URL. Empty buffer is treated
    /// as "clear" (skip URL validation, just persist the empty state).
    private func saveEditedMain() {
        let s = editBufferMain.trimmingCharacters(in: .whitespacesAndNewlines)
        if s.isEmpty {
            primaryURL = ""
            editing = nil
            pasteError = nil
            persistImmediately()
            return
        }
        if validateAndApply(s, toBackup: false) {
            editing = nil
            pasteError = nil
            persistImmediately()
        }
    }

    /// IPA-D24: commit the inline-edited Whitelist URL.
    private func saveEditedBackup() {
        let s = editBufferBackup.trimmingCharacters(in: .whitespacesAndNewlines)
        if s.isEmpty {
            backupURL = ""
            editing = nil
            pasteError = nil
            persistImmediately()
            return
        }
        if validateAndApply(s, toBackup: true) {
            editing = nil
            pasteError = nil
            persistImmediately()
        }
    }

    private func clearMain() {
        primaryURL = ""
        confirming = nil
        persistImmediately()
    }

    private func clearBackup() {
        backupURL = ""
        confirming = nil
        persistImmediately()
    }

    /// IPA-D22: design says "changes apply immediately" (no Save
    /// button). We compose primary+backup into the combined blob and
    /// write Keychain on every successful change.
    private func persistImmediately() {
        let p = primaryURL.trimmingCharacters(in: .whitespacesAndNewlines)
        let b = backupURL.trimmingCharacters(in: .whitespacesAndNewlines)
        if p.isEmpty && b.isEmpty {
            ConfigStore.shared.delete()
            return
        }
        let combined = SamizdatURLCodec.compose(primary: p, backup: b.isEmpty ? nil : b)
        ConfigStore.shared.save(combined)
    }

    private func closeAndPersist() {
        persistImmediately()
        let stored = ConfigStore.shared.load() ?? ""
        onClose(!stored.isEmpty)
        dismiss()
    }
}

// MARK: – Endpoint card (per-side)

private struct EndpointCard: View {
    @Environment(\.themeTokens) private var theme

    let label: String
    let labelBg: Color
    let labelFg: Color
    let accent: Color
    let url: String

    let isConfirming: Bool
    // IPA-D24: inline edit state, owned by the parent EndpointsView.
    let isEditing: Bool
    @Binding var editBuffer: String

    let onPaste: () -> Void
    let onScan: () -> Void
    let onClearRequest: () -> Void
    let onClearCancel: () -> Void
    let onClearConfirm: () -> Void
    let onEditStart: () -> Void
    let onEditCancel: () -> Void
    let onEditSave: () -> Void

    var body: some View {
        CardContainer(padding: 16) {
            VStack(alignment: .leading, spacing: 12) {
                // Label badge + parsed host
                HStack {
                    Text(label.uppercased())
                        .font(.geist(.bold, size: 10.5))
                        .tracking(0.84) // 0.08em at 10.5pt
                        .padding(.horizontal, 8)
                        .padding(.vertical, 3)
                        .background(Capsule().fill(labelBg))
                        .foregroundStyle(labelFg)
                    Spacer()
                    if let host = parseHost(url) {
                        Text(host)
                            .font(.geistMono(.regular, size: 12))
                            .foregroundStyle(theme.textMuted)
                    }
                }

                if isEditing {
                    // IPA-D24: TextEditor for manual URL editing. Mono
                    // font matches the read-only CodeBlock style.
                    TextEditor(text: $editBuffer)
                        .font(.geistMono(.regular, size: 12))
                        .foregroundStyle(theme.text)
                        .scrollContentBackground(.hidden)
                        .frame(minHeight: 100, maxHeight: 220)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 6)
                        .background(theme.chip)
                        .clipShape(RoundedRectangle(cornerRadius: 14))
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .keyboardType(.URL)
                } else if url.isEmpty {
                    // Empty state — same code-block frame, dim placeholder
                    CodeBlock {
                        Text("Not configured — paste, scan or edit a tamizdat:// link to set up the \(label.lowercased()) endpoint.")
                            .foregroundStyle(theme.textMuted)
                    }
                } else {
                    CodeBlock {
                        URLBreakdownView(url: url, accent: accent)
                    }
                }

                // Actions row OR inline confirmation strip OR edit Save/Cancel
                if isEditing {
                    HStack(spacing: 6) {
                        ActionChip(systemName: "xmark",
                                   label: "Cancel",
                                   tint: theme.textDim,
                                   action: onEditCancel)
                        ActionChip(systemName: "checkmark",
                                   label: "Done",
                                   tint: theme.mint,
                                   labelColor: theme.mint,
                                   action: onEditSave)
                    }
                } else if isConfirming {
                    HStack(spacing: 10) {
                        Text("Clear this endpoint?")
                            .font(.geist(.medium, size: 12.5))
                            .foregroundStyle(theme.text)
                        Spacer()
                        Button(action: onClearCancel) {
                            Text("Cancel")
                                .font(.geist(.semibold, size: 12.5))
                                .padding(.horizontal, 12).padding(.vertical, 6)
                                .background(Capsule().fill(theme.chip))
                                .foregroundStyle(theme.text)
                        }
                        .buttonStyle(.plain)
                        Button(action: onClearConfirm) {
                            Text("Clear")
                                .font(.geist(.bold, size: 12.5))
                                .padding(.horizontal, 12).padding(.vertical, 6)
                                .background(Capsule().fill(theme.red))
                                .foregroundStyle(Color.white)
                        }
                        .buttonStyle(.plain)
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 10)
                    .background(theme.redDim)
                    .overlay(
                        RoundedRectangle(cornerRadius: 12)
                            .strokeBorder(theme.red, lineWidth: 0.5)
                    )
                    .clipShape(RoundedRectangle(cornerRadius: 12))
                } else {
                    HStack(spacing: 6) {
                        ActionChip(systemName: "pencil",
                                   label: "Edit",
                                   tint: theme.blue,
                                   action: onEditStart)
                        ActionChip(systemName: "doc.on.clipboard",
                                   label: "Paste",
                                   tint: theme.blue,
                                   action: onPaste)
                        ActionChip(systemName: "qrcode.viewfinder",
                                   label: "Scan",
                                   tint: theme.blue,
                                   action: onScan)
                        ActionChip(systemName: "trash",
                                   label: "Clear",
                                   tint: theme.red,
                                   labelColor: theme.red,
                                   action: url.isEmpty ? {} : onClearRequest)
                        .opacity(url.isEmpty ? 0.4 : 1.0)
                        .disabled(url.isEmpty)
                    }
                }
            }
        }
    }

    /// Best-effort: parse the URL into a host:port to render on the
    /// right of the label. Falls back to nil when unparseable.
    private func parseHost(_ s: String) -> String? {
        guard !s.isEmpty else { return nil }
        // Replace scheme so URLComponents can parse — `tamizdat://` is
        // unknown to URLComponents and may produce nil host on iOS 17.
        let probe = s
            .replacingOccurrences(of: "tamizdat://", with: "https://")
            .replacingOccurrences(of: "samizdat://", with: "https://")
        guard let u = URL(string: probe), let host = u.host else { return nil }
        if let port = u.port { return "\(host):\(port)" }
        return host
    }
}

private struct ActionChip: View {
    @Environment(\.themeTokens) private var theme
    let systemName: String
    let label: String
    let tint: Color
    var labelColor: Color? = nil
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 6) {
                Image(systemName: systemName)
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(tint)
                Text(label)
                    .font(.geist(.semibold, size: 13))
                    .foregroundStyle(labelColor ?? theme.text)
            }
            .frame(maxWidth: .infinity)
            .frame(height: 38)
            .background(theme.chip)
            .clipShape(RoundedRectangle(cornerRadius: 10))
        }
        .buttonStyle(.plain)
    }
}

// MARK: – URL breakdown (key=value param dimming)

/// Renders a tamizdat:// URL with the scheme + host in normal text and
/// each query-parameter key in `theme.textDim`. Designed to break
/// naturally across 3-4 lines via word-wrap on `&` boundaries.
private struct URLBreakdownView: View {
    @Environment(\.themeTokens) private var theme
    let url: String
    let accent: Color

    var body: some View {
        if let parts = parseParts(url) {
            // Build a single AttributedString so wrapping behaves like
            // a single Text. Each "&key=" segment colour-tints the key.
            Text(buildAttributed(parts))
                .frame(maxWidth: .infinity, alignment: .leading)
        } else {
            // Fall back to plain
            Text(url)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private struct Parts {
        let scheme: String       // "tamizdat://"
        let hostPort: String     // "sync.ai-archive.ru:443/"
        let pairs: [(String, String)]  // [(sni, ya.ru), (pubkey, ...), ...]
    }

    private func parseParts(_ s: String) -> Parts? {
        guard let qIdx = s.firstIndex(of: "?") else { return nil }
        let scheme: String
        var afterScheme: String
        if s.hasPrefix("tamizdat://") {
            scheme = "tamizdat://"
            afterScheme = String(s.dropFirst("tamizdat://".count))
        } else if s.hasPrefix("samizdat://") {
            scheme = "samizdat://"
            afterScheme = String(s.dropFirst("samizdat://".count))
        } else {
            scheme = ""
            afterScheme = s
        }
        // Split host/port from query
        let _ = qIdx // silence
        let beforeQuery = String(s[..<qIdx])
        let queryStr = String(s[s.index(after: qIdx)...])
        let host: String
        if scheme.isEmpty {
            host = beforeQuery
        } else {
            host = String(beforeQuery.dropFirst(scheme.count))
        }
        let _ = afterScheme

        var pairs: [(String, String)] = []
        for chunk in queryStr.split(separator: "&", omittingEmptySubsequences: true) {
            let parts = chunk.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            if parts.count == 2 {
                pairs.append((String(parts[0]), String(parts[1])))
            } else {
                pairs.append((String(parts[0]), ""))
            }
        }
        return Parts(scheme: scheme, hostPort: host + "/?", pairs: pairs)
    }

    private func buildAttributed(_ parts: Parts) -> AttributedString {
        var out = AttributedString()

        // scheme
        var schemeStr = AttributedString(parts.scheme)
        schemeStr.foregroundColor = accent
        out.append(schemeStr)

        // host
        var hostStr = AttributedString(parts.hostPort)
        hostStr.foregroundColor = theme.text
        out.append(hostStr)

        for (i, pair) in parts.pairs.enumerated() {
            let key = pair.0
            let value = pair.1
            // Special-case: `backup=…b64…` — render as one dim line so
            // the long base64 chunk is visually grouped.
            var keyPart = AttributedString("\(key)=")
            keyPart.foregroundColor = theme.textDim
            var valuePart = AttributedString(elidedValue(key: key, value: value))
            valuePart.foregroundColor = theme.text
            out.append(keyPart)
            out.append(valuePart)
            if i != parts.pairs.count - 1 {
                var amp = AttributedString("&")
                amp.foregroundColor = theme.textDim
                out.append(amp)
            }
        }
        return out
    }

    /// Truncate visually-long values (pubkey, backup, …) with an ellipsis
    /// in the middle so the code-block stays a digestible 3-4 lines tall.
    private func elidedValue(key: String, value: String) -> String {
        let collapsable: Set<String> = ["pubkey", "backup"]
        guard collapsable.contains(key.lowercased()), value.count > 26 else {
            return value
        }
        let head = value.prefix(10)
        let tail = value.suffix(10)
        return "\(head)…\(tail)"
    }
}
