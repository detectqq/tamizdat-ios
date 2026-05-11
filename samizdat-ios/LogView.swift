import SwiftUI
import SamizdatClient // SocksstubWriteHeapProfile (heap dump button via TelegramReporter)

/// IPA-D22: redesigned Logs screen — filter pills (All / Info / Warn /
/// Error / Crit with count badges), monospaced stream card, sticky
/// bottom action bar.
///
/// The legacy `LogView` took a `bridge` parameter so it could read
/// `bridge.logs`. We now create our own `SamizdatBridge` instance if
/// none is injected, which keeps the call site simpler (Logs can be
/// opened from Settings without a bridge handle).
struct LogView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(\.themeTokens) private var theme

    /// Optional injected bridge. When nil we spin up our own.
    var injectedBridge: SamizdatBridge? = nil

    @StateObject private var ownBridge = SamizdatBridge()

    private var bridge: SamizdatBridge { injectedBridge ?? ownBridge }

    @State private var visibleLevels: Set<LogLevel> = Set(LogLevel.allCases)
    @State private var autoScroll: Bool = true
    @State private var showClearConfirm: Bool = false
    @State private var copiedFlash: Bool = false
    @State private var critFlash: SendStatus = .idle
    @State private var showShareSheet: Bool = false
    @State private var shareText: String = ""

    // Init form needed by some call sites; the default-init is fine
    // when injectedBridge is nil.
    init(injectedBridge: SamizdatBridge? = nil) {
        self.injectedBridge = injectedBridge
    }

    enum LogLevel: String, CaseIterable, Identifiable {
        case info, warn, error, crit
        var id: String { rawValue }
        var label: String {
            switch self {
            case .info:  return "Info"
            case .warn:  return "Warn"
            case .error: return "Error"
            case .crit:  return "Crit"
            }
        }
        func dotColor(theme: ThemeTokens) -> Color {
            switch self {
            case .info:  return theme.blue
            case .warn:  return theme.amber
            case .error: return theme.red
            case .crit:  return theme.red
            }
        }
        func bgColor(theme: ThemeTokens) -> Color {
            switch self {
            case .info:  return theme.blueDim
            case .warn:  return theme.amberDim
            case .error: return theme.redDim
            case .crit:  return theme.redDim
            }
        }
    }

    enum SendStatus: Equatable {
        case idle, sending
        case sent
        case failed(String)
    }

    // Parsed lines computed from bridge.logs
    private var parsedLines: [ParsedLogLine] {
        bridge.logs.map { ParsedLogLine.from($0) }
    }

    private var levelCounts: [LogLevel: Int] {
        var counts: [LogLevel: Int] = [:]
        for line in parsedLines {
            counts[line.level, default: 0] += 1
        }
        return counts
    }

    private var filteredLines: [ParsedLogLine] {
        if visibleLevels.count == LogLevel.allCases.count { return parsedLines }
        return parsedLines.filter { visibleLevels.contains($0.level) }
    }

    var body: some View {
        ZStack {
            ThemeBackground(theme: theme)

            VStack(spacing: 0) {
                // ── Header ────────────────────────────────────────
                HStack {
                    Chip(label: "Close") { dismiss() }
                    Spacer()
                    Text("Logs")
                        .font(.geist(.semibold, size: 16))
                        .foregroundStyle(theme.text)
                    Spacer()
                    Button {
                        shareText = filteredLines.map { $0.raw }.joined(separator: "\n")
                        showShareSheet = true
                    } label: {
                        ZStack {
                            Circle().fill(theme.chip).frame(width: 34, height: 34)
                            Image(systemName: "square.and.arrow.up")
                                .font(.system(size: 14, weight: .semibold))
                                .foregroundStyle(theme.textDim)
                        }
                    }
                    .buttonStyle(.plain)
                }
                .padding(.horizontal, 20)
                .padding(.top, 8)
                .padding(.bottom, 6)

                Text("Live logs")
                    .font(.geist(.bold, size: 32))
                    .tracking(-0.96)
                    .foregroundStyle(theme.text)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 20)
                    .padding(.top, 4)

                // Streaming status line
                HStack(spacing: 8) {
                    PulsingDot(color: theme.mint)
                    Text("streaming · \(parsedLines.count) lines · \(autoScroll ? "auto-scroll" : "manual")")
                        .font(.geistMono(.regular, size: 12.5))
                        .foregroundStyle(theme.textDim)
                }
                .padding(.horizontal, 20)
                .padding(.top, 4)
                .padding(.bottom, 6)
                .frame(maxWidth: .infinity, alignment: .leading)

                // ── Filter pills ─────────────────────────────────
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 6) {
                        Pill(label: "All",
                             count: parsedLines.count,
                             dotColor: nil,
                             isActive: visibleLevels.count == LogLevel.allCases.count,
                             action: {
                                visibleLevels = Set(LogLevel.allCases)
                             })
                        ForEach(LogLevel.allCases) { level in
                            Pill(label: level.label,
                                 count: levelCounts[level] ?? 0,
                                 dotColor: level.dotColor(theme: theme),
                                 isActive: visibleLevels == [level],
                                 action: {
                                    visibleLevels = [level]
                                 })
                        }
                    }
                    .padding(.horizontal, 16)
                }
                .padding(.vertical, 10)

                // ── Stream card ───────────────────────────────────
                streamCard
                    .padding(.horizontal, 16)
                    .padding(.bottom, 12)

                // ── Sticky bottom action bar ─────────────────────
                actionBar
                    .padding(.horizontal, 16)
                    .padding(.bottom, 18)
            }
        }
        .preferredColorScheme(theme.isDark ? .dark : .light)
        .sheet(isPresented: $showShareSheet) {
            ShareSheet(activityItems: [shareText])
        }
    }

    private var streamCard: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(Array(filteredLines.enumerated()), id: \.offset) { idx, line in
                        logRow(line: line, isLast: idx == filteredLines.count - 1)
                            .id(idx)
                    }
                }
                .padding(.vertical, 10)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(theme.cardSolid)
            .clipShape(RoundedRectangle(cornerRadius: 18))
            .overlay(
                RoundedRectangle(cornerRadius: 18)
                    .strokeBorder(theme.cardBorder, lineWidth: 0.5)
            )
            .onChange(of: filteredLines.count) {
                guard autoScroll, !filteredLines.isEmpty else { return }
                withAnimation { proxy.scrollTo(filteredLines.count - 1, anchor: .bottom) }
            }
            .onAppear {
                guard !filteredLines.isEmpty else { return }
                proxy.scrollTo(filteredLines.count - 1, anchor: .bottom)
            }
        }
    }

    private func logRow(line: ParsedLogLine, isLast: Bool) -> some View {
        VStack(spacing: 0) {
            HStack(alignment: .top, spacing: 8) {
                Text(line.time)
                    .font(.geistMono(.regular, size: 11.5))
                    .foregroundStyle(theme.textMuted)
                    .lineLimit(1)
                Text(line.level.rawValue.uppercased())
                    .font(.geistMono(.bold, size: 10))
                    .tracking(0.4)
                    .padding(.horizontal, 6)
                    .frame(minHeight: 16)
                    .background(line.level.bgColor(theme: theme))
                    .foregroundStyle(line.level.dotColor(theme: theme))
                    .clipShape(RoundedRectangle(cornerRadius: 4))
                Text(line.tag)
                    .font(.geistMono(.regular, size: 11.5))
                    .foregroundStyle(theme.textDim)
                    .lineLimit(1)
                Text(line.message)
                    .font(.geistMono(.regular, size: 11.5))
                    .lineSpacing(2)
                    .foregroundStyle(theme.text)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 6)

            if !isLast {
                Rectangle()
                    .fill(theme.rowBorder)
                    .frame(height: 0.5)
            }
        }
    }

    private var actionBar: some View {
        HStack(spacing: 4) {
            ActionTile(icon: autoScroll ? "arrow.down.to.line" : "arrow.up.and.down",
                       label: "Auto",
                       tint: theme.text,
                       isActive: autoScroll) {
                autoScroll.toggle()
            }
            ActionTile(icon: copiedFlash ? "checkmark" : "doc.on.doc",
                       label: copiedFlash ? "Copied" : "Copy",
                       tint: theme.textDim,
                       isActive: false) {
                UIPasteboard.general.string = filteredLines.map { $0.raw }.joined(separator: "\n")
                copiedFlash = true
                DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) { copiedFlash = false }
            }
            ActionTile(icon: "paperplane",
                       label: "Share",
                       tint: theme.textDim,
                       isActive: false) {
                shareText = filteredLines.map { $0.raw }.joined(separator: "\n")
                showShareSheet = true
            }
            ActionTile(icon: "exclamationmark.triangle",
                       label: critFlashLabel,
                       tint: theme.amber,
                       isActive: false) {
                sendLatestAutoDumpToTelegram()
            }
            ActionTile(icon: "trash",
                       label: showClearConfirm ? "Confirm" : "Clear",
                       tint: theme.red,
                       isActive: showClearConfirm) {
                if showClearConfirm {
                    bridge.clearLogs()
                    showClearConfirm = false
                } else {
                    showClearConfirm = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 3.0) {
                        showClearConfirm = false
                    }
                }
            }
        }
        .padding(6)
        .background(theme.cardSolid)
        .clipShape(RoundedRectangle(cornerRadius: 18))
        .overlay(
            RoundedRectangle(cornerRadius: 18)
                .strokeBorder(theme.cardBorder, lineWidth: 0.5)
        )
    }

    private var critFlashLabel: String {
        switch critFlash {
        case .idle: return "Crit"
        case .sending: return "Sending…"
        case .sent: return "Sent"
        case .failed: return "Failed"
        }
    }

    // MARK: – Crit (heap-dump upload to telegram, preserved from D11)

    private func sendLatestAutoDumpToTelegram() {
        guard TelegramReporter.isConfigured else {
            critFlash = .failed("Configure bot token first")
            return
        }
        guard let containerURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: SamizdatBridge.appGroupID
        ) else {
            critFlash = .failed("App Group container unavailable")
            return
        }
        let fm = FileManager.default
        guard let entries = try? fm.contentsOfDirectory(
            at: containerURL,
            includingPropertiesForKeys: [.contentModificationDateKey],
            options: [.skipsHiddenFiles]
        ) else {
            critFlash = .failed("Cannot read app group")
            return
        }
        let heapFiles = entries
            .filter { $0.lastPathComponent.hasPrefix("heap-") &&
                      $0.lastPathComponent.hasSuffix(".pb.gz") }
            .compactMap { url -> (URL, Date)? in
                let date = (try? url.resourceValues(forKeys: [.contentModificationDateKey])
                    .contentModificationDate) ?? .distantPast
                return (url, date)
            }
            .sorted { $0.1 > $1.1 }

        guard let latest = heapFiles.first?.0 else {
            critFlash = .failed("No auto-dump available")
            return
        }
        guard let data = try? Data(contentsOf: latest) else {
            critFlash = .failed("Cannot read \(latest.lastPathComponent)")
            return
        }
        critFlash = .sending
        let caption = TelegramReporter.defaultCaption(extra: "auto-dump (\(latest.lastPathComponent))")
        TelegramReporter.sendFile(
            data: data,
            filename: latest.lastPathComponent,
            mimeType: "application/gzip",
            caption: caption
        ) { result in
            switch result {
            case .success:
                critFlash = .sent
                DispatchQueue.main.asyncAfter(deadline: .now() + 3.0) {
                    if case .sent = critFlash { critFlash = .idle }
                }
            case .failure(let err):
                critFlash = .failed(err.errorDescription ?? "unknown")
            }
        }
    }
}

// MARK: – Bottom action-bar tile

private struct ActionTile: View {
    @Environment(\.themeTokens) private var theme
    let icon: String
    let label: String
    let tint: Color
    let isActive: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            VStack(spacing: 4) {
                Image(systemName: icon)
                    .font(.system(size: 16, weight: .semibold))
                    .foregroundStyle(tint)
                Text(label)
                    .font(.geist(.semibold, size: 10.5))
                    .foregroundStyle(isActive ? theme.text : theme.textDim)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 8)
            .background(isActive ? theme.chip : Color.clear)
            .clipShape(RoundedRectangle(cornerRadius: 12))
        }
        .buttonStyle(.plain)
    }
}

// MARK: – Pulsing mint dot for the streaming indicator

private struct PulsingDot: View {
    let color: Color
    @State private var animate = false

    var body: some View {
        Circle()
            .fill(color)
            .frame(width: 6, height: 6)
            .scaleEffect(animate ? 1.4 : 1.0)
            .opacity(animate ? 0.5 : 1.0)
            .onAppear {
                withAnimation(.easeInOut(duration: 1.6).repeatForever(autoreverses: true)) {
                    animate = true
                }
            }
    }
}

// MARK: – Parsed log line

struct ParsedLogLine: Identifiable, Equatable {
    let id = UUID()
    let raw: String
    let time: String
    let level: LogView.LogLevel
    let tag: String
    let message: String

    static func from(_ raw: String) -> ParsedLogLine {
        // Typical shape produced by the extension / Go side:
        //   "12:57:07.847 info: bridge: status connecting → connected"
        //   "13:00:10.598 info: detector cycle outcome=internetOK"
        //   "12:57:15.681 warn: bridge: log file stale 4s"
        //
        // Bridge events use the explicit `bridge:` prefix; Go side
        // uses `<tag>:` (e.g. `detector:`). We parse:
        //   time = up to first space
        //   level = up to first `:`
        //   then strip the `<tag>:` prefix if present and surface
        //         the tag separately.
        let trimmed = raw
        var time = ""
        var levelStr = "info"
        var rest = trimmed

        if let spaceIdx = trimmed.firstIndex(of: " ") {
            time = String(trimmed[..<spaceIdx])
            rest = String(trimmed[trimmed.index(after: spaceIdx)...])
        }
        if let colonIdx = rest.firstIndex(of: ":") {
            let prefix = String(rest[..<colonIdx]).lowercased()
            switch prefix {
            case "info", "warn", "error", "crit":
                levelStr = prefix
                rest = String(rest[rest.index(after: colonIdx)...])
                    .trimmingCharacters(in: .whitespaces)
            default: break
            }
        }
        // Try to split off `<tag>: rest`
        var tag = ""
        var message = rest
        if let colonIdx = rest.firstIndex(of: ":") {
            let candidateTag = String(rest[..<colonIdx])
            // Tag heuristic: short, no spaces.
            if !candidateTag.contains(" ") && candidateTag.count < 24 {
                tag = candidateTag
                message = String(rest[rest.index(after: colonIdx)...])
                    .trimmingCharacters(in: .whitespaces)
            }
        }
        let level = LogView.LogLevel(rawValue: levelStr) ?? .info
        return ParsedLogLine(raw: raw, time: time, level: level, tag: tag, message: message)
    }
}

// MARK: – UIActivityViewController bridge for Share

private struct ShareSheet: UIViewControllerRepresentable {
    let activityItems: [Any]
    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: activityItems, applicationActivities: nil)
    }
    func updateUIViewController(_ vc: UIActivityViewController, context: Context) {}
}
