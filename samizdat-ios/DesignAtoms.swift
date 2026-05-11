import SwiftUI

/// IPA-D22: reusable atoms ported from
/// `design_handoff_samizdat_vpn_2026/samizdat-ui.jsx`.
///
/// All atoms read the active theme from `@Environment(\.themeTokens)`.

// MARK: – Card container (22-radius surface)

/// Large card surface (Settings sections, Endpoint cards, etc.) — 22 px
/// corner radius, 0.5 px border, solid card background. Padding defaults
/// to 18 like the JSX `Card`.
struct CardContainer<Content: View>: View {
    @Environment(\.themeTokens) private var theme
    var padding: CGFloat = 18
    @ViewBuilder var content: () -> Content

    var body: some View {
        content()
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(theme.cardSolid)
            .clipShape(RoundedRectangle(cornerRadius: 22))
            .overlay(
                RoundedRectangle(cornerRadius: 22)
                    .strokeBorder(theme.cardBorder, lineWidth: 0.5)
            )
    }
}

// MARK: – Small-caps section header

/// 11 pt / 600 / 0.14 em / UPPERCASE / muted. Standard for "Notifications",
/// "Configuration", etc. headings.
struct SectionLabel: View {
    @Environment(\.themeTokens) private var theme
    let text: String

    var body: some View {
        Text(text.uppercased())
            .font(.geist(.semibold, size: 11))
            .tracking(1.54) // 0.14em ≈ 1.54 at 11pt
            .foregroundStyle(theme.textMuted)
            .padding(.horizontal, 24)
            .padding(.bottom, 8)
            .frame(maxWidth: .infinity, alignment: .leading)
    }
}

// MARK: – Stat tile (Mode / Uptime / Data)

struct StatTile: View {
    @Environment(\.themeTokens) private var theme
    let label: String
    let value: String
    var unit: String? = nil
    var accent: Color? = nil

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(label.uppercased())
                .font(.geist(.semibold, size: 10.5))
                .tracking(1.05) // 0.1em at 10.5pt
                .foregroundStyle(theme.textMuted)

            HStack(alignment: .firstTextBaseline, spacing: 3) {
                Text(value)
                    .font(.geistMono(.semibold, size: 20))
                    .tracking(-0.4)
                    .foregroundStyle(accent ?? theme.text)
                if let unit {
                    Text(unit)
                        .font(.geistMono(.regular, size: 11))
                        .foregroundStyle(theme.textDim)
                }
            }
        }
        .padding(.horizontal, 14)
        .padding(.top, 14)
        .padding(.bottom, 12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(theme.cardSolid)
        .clipShape(RoundedRectangle(cornerRadius: 18))
        .overlay(
            RoundedRectangle(cornerRadius: 18)
                .strokeBorder(theme.cardBorder, lineWidth: 0.5)
        )
    }
}

// MARK: – Tinted icon card (the 34x34 SF Symbol bg-tinted square)

struct IconCard: View {
    let systemName: String
    let bg: Color
    let fg: Color
    var size: CGFloat = 34
    var radius: CGFloat = 9
    var iconSize: CGFloat = 18

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: radius)
                .fill(bg)
            Image(systemName: systemName)
                .font(.system(size: iconSize, weight: .semibold))
                .foregroundStyle(fg)
        }
        .frame(width: size, height: size)
    }
}

// MARK: – Pill (log filter: All / Info / Warn / Error / Crit + count)

struct Pill: View {
    @Environment(\.themeTokens) private var theme
    let label: String
    var count: Int? = nil
    var dotColor: Color? = nil
    let isActive: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 6) {
                if let dot = dotColor {
                    Circle()
                        .fill(dot)
                        .frame(width: 6, height: 6)
                }
                Text(label)
                    .font(.geist(.semibold, size: 13))
                if let count {
                    Text("\(count)")
                        .font(.geistMono(.regular, size: 11))
                        .opacity(0.6)
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 7)
            .background(
                Capsule()
                    .fill(isActive ? theme.chipActive : theme.chip)
            )
            .foregroundStyle(isActive ? theme.chipActiveText : theme.textDim)
        }
        .buttonStyle(.plain)
    }
}

// MARK: – Chip ("Done" / "Cancel" header chip + segmented entries)

struct Chip: View {
    @Environment(\.themeTokens) private var theme
    let label: String
    var isActive: Bool = false
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(label)
                .font(.geist(.medium, size: 14))
                .padding(.horizontal, 12)
                .padding(.vertical, 6)
                .background(
                    Capsule()
                        .fill(isActive ? theme.chipActive : theme.chip)
                )
                .foregroundStyle(isActive ? theme.chipActiveText : theme.text)
        }
        .buttonStyle(.plain)
    }
}

// MARK: – Code-block (mono URL display, 14-radius chip background)

struct CodeBlock<Content: View>: View {
    @Environment(\.themeTokens) private var theme
    @ViewBuilder var content: () -> Content

    var body: some View {
        content()
            .font(.geistMono(.regular, size: 12))
            .foregroundStyle(theme.text)
            .lineSpacing(4)
            .padding(.horizontal, 12)
            .padding(.vertical, 11)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(theme.chip)
            .clipShape(RoundedRectangle(cornerRadius: 14))
            .textSelection(.enabled)
    }
}

// MARK: – Ping chip (mint pill under the hero status label)

/// Mint pill rendered under the status label when connected. Format:
///   • Ping NN ms · ↓ X.X MB/s
/// Falls back gracefully when no ping sample yet (renders `Ping —`) or
/// no data sample yet (drops the rate segment).
struct PingChip: View {
    @Environment(\.themeTokens) private var theme
    let pingMs: Int?
    let dataRateText: String?  // e.g. "1.2 MB/s" or "850 KB/s"; nil = hide

    var body: some View {
        HStack(spacing: 8) {
            Circle()
                .fill(theme.mint)
                .frame(width: 6, height: 6)
            Text("Ping")
                .font(.geistMono(.semibold, size: 12.5))
                .foregroundStyle(theme.mint)
            Text(pingDisplay)
                .font(.geistMono(.semibold, size: 12.5))
                .foregroundStyle(theme.text.opacity(theme.isDark ? 0.95 : 0.85))
            if let rate = dataRateText, !rate.isEmpty {
                Text("·")
                    .font(.geistMono(.regular, size: 12.5))
                    .foregroundStyle(theme.mint.opacity(0.5))
                Text("↓ \(rate)")
                    .font(.geistMono(.semibold, size: 12.5))
                    .foregroundStyle(theme.mint)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
        .background(
            Capsule()
                .fill(theme.mintDim)
        )
    }

    private var pingDisplay: String {
        if let ms = pingMs, ms >= 0 {
            return "\(ms) ms"
        }
        return "—"
    }
}

// MARK: – Row (inside CardContainer, with optional bottom separator)

struct DesignRow<Trailing: View>: View {
    @Environment(\.themeTokens) private var theme
    let icon: AnyView?
    let title: String
    var sub: String? = nil
    let isLast: Bool
    @ViewBuilder var trailing: () -> Trailing

    init<I: View>(icon: I,
                  title: String,
                  sub: String? = nil,
                  isLast: Bool = true,
                  @ViewBuilder trailing: @escaping () -> Trailing) {
        self.icon = AnyView(icon)
        self.title = title
        self.sub = sub
        self.isLast = isLast
        self.trailing = trailing
    }

    init(title: String,
         sub: String? = nil,
         isLast: Bool = true,
         @ViewBuilder trailing: @escaping () -> Trailing) {
        self.icon = nil
        self.title = title
        self.sub = sub
        self.isLast = isLast
        self.trailing = trailing
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 14) {
                if let icon { icon }
                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .font(.geist(.medium, size: 16))
                        .tracking(-0.16)
                        .foregroundStyle(theme.text)
                    if let sub, !sub.isEmpty {
                        Text(sub)
                            .font(.geist(.regular, size: 12.5))
                            .foregroundStyle(theme.textDim)
                            .lineSpacing(2)
                    }
                }
                Spacer(minLength: 8)
                trailing()
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 14)
            if !isLast {
                Rectangle()
                    .fill(theme.rowBorder)
                    .frame(height: 0.5)
                    .padding(.leading, 16)
            }
        }
    }
}
