import SwiftUI

/// IPA-D22: design tokens for the 2026 redesign (cream + dark themes).
/// Ports `TOK.dark` / `TOK.cream` from `samizdat-ui.jsx`. Values are
/// canonical — do not invent new tints; reuse these so the four screens
/// stay coherent.
///
/// Access pattern: `@Environment(\.themeTokens) private var tokens`.
/// The root view sets `.environment(\.themeTokens, ThemeTokens.cream)`
/// (or `.dark`) based on the user pick in `ThemePreferences.current`.
struct ThemeTokens {
    let name: String
    let isDark: Bool

    // Backgrounds
    let bg: Color
    let bgGradTop: Color
    let bgGradMid: Color
    let bgGradBot: Color

    // Cards
    let cardSolid: Color
    let cardBorder: Color
    let rowBorder: Color

    // Text
    let text: Color
    let textDim: Color
    let textMuted: Color

    // Chips
    let chip: Color
    let chipActive: Color
    let chipActiveText: Color

    // Mint (primary accent)
    let mint: Color
    let mintInk: Color
    let mintDim: Color
    let mintRing: Color

    // Red (off / destructive)
    let red: Color
    let redDim: Color

    // Amber (warn / reconnecting)
    let amber: Color
    let amberDim: Color

    // Blue (whitelist / info)
    let blue: Color
    let blueDim: Color

    static let dark = ThemeTokens(
        name: "dark",
        isDark: true,
        bg: Color(hex: 0x050507),
        bgGradTop: Color(hex: 0x0E1410),
        bgGradMid: Color(hex: 0x050507),
        bgGradBot: .black,
        cardSolid: Color(hex: 0x15151A),
        cardBorder: Color.white.opacity(0.06),
        rowBorder: Color.white.opacity(0.05),
        text: .white,
        textDim: Color(red: 235/255, green: 235/255, blue: 245/255).opacity(0.65),
        textMuted: Color(red: 235/255, green: 235/255, blue: 245/255).opacity(0.35),
        chip: Color.white.opacity(0.08),
        chipActive: Color.white.opacity(0.96),
        chipActiveText: Color(hex: 0x0A0A0C),
        mint: Color(hex: 0x7BF1A8),
        mintInk: Color(hex: 0x0A2316),
        mintDim: Color(red: 123/255, green: 241/255, blue: 168/255).opacity(0.14),
        mintRing: Color(red: 123/255, green: 241/255, blue: 168/255).opacity(0.35),
        red: Color(hex: 0xFF6B6B),
        redDim: Color(red: 255/255, green: 107/255, blue: 107/255).opacity(0.14),
        amber: Color(hex: 0xFFB845),
        amberDim: Color(red: 255/255, green: 184/255, blue: 69/255).opacity(0.14),
        blue: Color(hex: 0x6FA8FF),
        blueDim: Color(red: 111/255, green: 168/255, blue: 255/255).opacity(0.16)
    )

    static let cream = ThemeTokens(
        name: "cream",
        isDark: false,
        bg: Color(hex: 0xF4F1EA),
        bgGradTop: Color(hex: 0xFBF8F1),
        bgGradMid: Color(hex: 0xF4F1EA),
        bgGradBot: Color(hex: 0xECE7DA),
        cardSolid: .white,
        cardBorder: Color(red: 20/255, green: 15/255, blue: 10/255).opacity(0.06),
        rowBorder: Color(red: 20/255, green: 15/255, blue: 10/255).opacity(0.08),
        text: Color(hex: 0x13110D),
        textDim: Color(red: 35/255, green: 30/255, blue: 22/255).opacity(0.62),
        textMuted: Color(red: 35/255, green: 30/255, blue: 22/255).opacity(0.38),
        chip: Color(red: 20/255, green: 15/255, blue: 10/255).opacity(0.06),
        chipActive: Color(hex: 0x13110D),
        chipActiveText: Color(hex: 0xF4F1EA),
        mint: Color(hex: 0x0D8C5A),
        mintInk: Color(hex: 0x0A2316),
        mintDim: Color(red: 13/255, green: 140/255, blue: 90/255).opacity(0.12),
        mintRing: Color(red: 13/255, green: 140/255, blue: 90/255).opacity(0.32),
        red: Color(hex: 0xD14545),
        redDim: Color(red: 209/255, green: 69/255, blue: 69/255).opacity(0.10),
        amber: Color(hex: 0xB8821F),
        amberDim: Color(red: 184/255, green: 130/255, blue: 31/255).opacity(0.12),
        blue: Color(hex: 0x2E62D9),
        blueDim: Color(red: 46/255, green: 98/255, blue: 217/255).opacity(0.10)
    )
}

extension Color {
    /// Convenience initializer for hex literals like `Color(hex: 0xFF6B6B)`.
    init(hex: UInt32, alpha: Double = 1.0) {
        let r = Double((hex >> 16) & 0xFF) / 255.0
        let g = Double((hex >> 8) & 0xFF) / 255.0
        let b = Double(hex & 0xFF) / 255.0
        self.init(.sRGB, red: r, green: g, blue: b, opacity: alpha)
    }
}

/// EnvironmentKey for the active theme. Defaults to `.cream` (operator
/// decision in D22 — see CLAUDE.md). The root view overrides this with
/// `.environment(\.themeTokens, ThemeTokens.cream/.dark)` based on
/// `ThemePreferences.current`.
private struct ThemeTokensKey: EnvironmentKey {
    static let defaultValue: ThemeTokens = .cream
}

extension EnvironmentValues {
    var themeTokens: ThemeTokens {
        get { self[ThemeTokensKey.self] }
        set { self[ThemeTokensKey.self] = newValue }
    }
}

/// Background gradient view that paints `theme.bgGrad` across the screen.
/// Used as the root of every redesigned screen.
struct ThemeBackground: View {
    let theme: ThemeTokens

    var body: some View {
        // Radial gradient approximated from CSS:
        //   radial-gradient(120% 80% at 50% -10%, top 0%, mid 55-60%, bot 100%)
        RadialGradient(
            gradient: Gradient(stops: [
                .init(color: theme.bgGradTop, location: 0.0),
                .init(color: theme.bgGradMid, location: theme.isDark ? 0.55 : 0.60),
                .init(color: theme.bgGradBot, location: 1.0),
            ]),
            center: UnitPoint(x: 0.5, y: -0.10),
            startRadius: 0,
            endRadius: 600
        )
        .ignoresSafeArea()
    }
}
