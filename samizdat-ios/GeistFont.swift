import SwiftUI
import CoreText

/// IPA-D22: Geist font registration + helpers.
///
/// The .ttf files live in `samizdat-ios/Resources/Fonts/` and are copied
/// into the app bundle as plain resources. We also list them in
/// `Info.plist → UIAppFonts` so iOS auto-registers them at launch. The
/// belt-and-braces `register()` call below is a fallback: if for some
/// reason the Info.plist entry didn't propagate (xcodegen quirks, weird
/// build cache), we register at app launch via CTFontManager.
///
/// Usage: `Text("hi").font(.geist(.bold, size: 38))` — falls back to
/// `Font.system(...)` if the named font is unavailable, so the UI
/// degrades gracefully rather than rendering as Times.
enum GeistFont {
    enum Weight {
        case regular, medium, semibold, bold

        fileprivate var sansName: String {
            switch self {
            case .regular:  return "Geist-Regular"
            case .medium:   return "Geist-Medium"
            case .semibold: return "Geist-SemiBold"
            case .bold:     return "Geist-Bold"
            }
        }

        fileprivate var monoName: String {
            switch self {
            case .regular:  return "GeistMono-Regular"
            case .medium:   return "GeistMono-Medium"
            case .semibold: return "GeistMono-SemiBold"
            case .bold:     return "GeistMono-Bold"
            }
        }

        fileprivate var systemFallback: Font.Weight {
            switch self {
            case .regular:  return .regular
            case .medium:   return .medium
            case .semibold: return .semibold
            case .bold:     return .bold
            }
        }
    }

    /// One-shot registration. Idempotent. Called from `App.init()`.
    /// Most builds will see the fonts already registered via Info.plist's
    /// `UIAppFonts`; this is the safety net.
    static func register() {
        for name in ["Geist-Regular", "Geist-Medium", "Geist-SemiBold", "Geist-Bold",
                     "GeistMono-Regular", "GeistMono-Medium", "GeistMono-SemiBold", "GeistMono-Bold"] {
            // Skip if already registered (UIAppFonts already loaded it).
            if UIFont(name: name, size: 12) != nil { continue }
            guard let url = Bundle.main.url(forResource: name, withExtension: "ttf") else {
                continue
            }
            var error: Unmanaged<CFError>?
            _ = CTFontManagerRegisterFontsForURL(url as CFURL, .process, &error)
        }
    }

    /// Returns the sans-serif Geist font at the given weight + size, or a
    /// matching system fallback if Geist failed to load.
    static func sans(_ weight: Weight, size: CGFloat) -> Font {
        if UIFont(name: weight.sansName, size: size) != nil {
            return Font.custom(weight.sansName, size: size)
        }
        return Font.system(size: size, weight: weight.systemFallback, design: .default)
    }

    /// Returns the monospaced Geist Mono font at the given weight + size,
    /// or a matching system fallback if Geist Mono failed to load.
    static func mono(_ weight: Weight, size: CGFloat) -> Font {
        if UIFont(name: weight.monoName, size: size) != nil {
            return Font.custom(weight.monoName, size: size)
        }
        return Font.system(size: size, weight: weight.systemFallback, design: .monospaced)
    }
}

extension Font {
    /// Sugar: `.geist(.bold, size: 38)`.
    static func geist(_ weight: GeistFont.Weight, size: CGFloat) -> Font {
        GeistFont.sans(weight, size: size)
    }

    /// Sugar: `.geistMono(.regular, size: 12)`.
    static func geistMono(_ weight: GeistFont.Weight, size: CGFloat) -> Font {
        GeistFont.mono(weight, size: size)
    }
}
