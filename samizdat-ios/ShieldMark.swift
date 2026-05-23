import SwiftUI

/// IPA-D22: SZ-tower shield mark, ported from
/// `design_handoff_samizdat_vpn_2026/samizdat-ui.jsx → ShieldMark`.
///
/// Original SVG viewBox 0 0 96 96. We re-create the same paths as
/// SwiftUI `Path` instances and scale them. The shield body is filled
/// with a vertical gradient (color → color at 0.75 opacity); the tower
/// negative cut + battlements are filled with `dim` (the darker
/// counterpart, typically `mintInk` so the cut reads as a dark window
/// in the mint shield).
///
/// No surrounding pulse ring — handoff explicitly says the shipping
/// hero is the simple oversized ShieldMark, no pulse / disc.
struct ShieldMark: View {
    var size: CGFloat = 220
    var color: Color
    var dim: Color

    var body: some View {
        let scale = size / 96.0

        ZStack {
            // Shield body — original path "M48 6 L78 16 V46 C78 64 64 78 48 88 C32 78 18 64 18 46 V16 Z"
            shieldBody(scale: scale)
                .fill(
                    LinearGradient(
                        gradient: Gradient(stops: [
                            .init(color: color.opacity(0.95), location: 0),
                            .init(color: color.opacity(0.75), location: 1),
                        ]),
                        startPoint: .top,
                        endPoint: .bottom
                    )
                )

            // Tower negative-cut: outer outline + two horizontal slits.
            // Use even-odd fill so the slits cut visible windows into
            // the tower body, which reads better than the original
            // SVG's degenerate "same colour on top of same colour".
            towerCut(scale: scale)
                .fill(dim, style: FillStyle(eoFill: true))

            // Battlements at the top of the tower
            battlements(scale: scale)
                .fill(dim.opacity(0.95))
        }
        .frame(width: size, height: size)
    }

    private func shieldBody(scale: CGFloat) -> Path {
        Path { p in
            // M48 6 L78 16 V46 C78 64 64 78 48 88 C32 78 18 64 18 46 V16 Z
            p.move(to: CGPoint(x: 48 * scale, y: 6 * scale))
            p.addLine(to: CGPoint(x: 78 * scale, y: 16 * scale))
            p.addLine(to: CGPoint(x: 78 * scale, y: 46 * scale))
            p.addCurve(
                to: CGPoint(x: 48 * scale, y: 88 * scale),
                control1: CGPoint(x: 78 * scale, y: 64 * scale),
                control2: CGPoint(x: 64 * scale, y: 78 * scale)
            )
            p.addCurve(
                to: CGPoint(x: 18 * scale, y: 46 * scale),
                control1: CGPoint(x: 32 * scale, y: 78 * scale),
                control2: CGPoint(x: 18 * scale, y: 64 * scale)
            )
            p.addLine(to: CGPoint(x: 18 * scale, y: 16 * scale))
            p.closeSubpath()
        }
    }

    private func towerCut(scale: CGFloat) -> Path {
        Path { p in
            // M40 30 H44 V26 H52 V30 H56 V70 H40 Z  — outer tower shape
            p.move(to: CGPoint(x: 40 * scale, y: 30 * scale))
            p.addLine(to: CGPoint(x: 44 * scale, y: 30 * scale))
            p.addLine(to: CGPoint(x: 44 * scale, y: 26 * scale))
            p.addLine(to: CGPoint(x: 52 * scale, y: 26 * scale))
            p.addLine(to: CGPoint(x: 52 * scale, y: 30 * scale))
            p.addLine(to: CGPoint(x: 56 * scale, y: 30 * scale))
            p.addLine(to: CGPoint(x: 56 * scale, y: 70 * scale))
            p.addLine(to: CGPoint(x: 40 * scale, y: 70 * scale))
            p.closeSubpath()

            // M44 36 V42 H52 V36 Z — upper slit
            p.move(to: CGPoint(x: 44 * scale, y: 36 * scale))
            p.addLine(to: CGPoint(x: 44 * scale, y: 42 * scale))
            p.addLine(to: CGPoint(x: 52 * scale, y: 42 * scale))
            p.addLine(to: CGPoint(x: 52 * scale, y: 36 * scale))
            p.closeSubpath()

            // M44 50 V58 H52 V50 Z — lower slit
            p.move(to: CGPoint(x: 44 * scale, y: 50 * scale))
            p.addLine(to: CGPoint(x: 44 * scale, y: 58 * scale))
            p.addLine(to: CGPoint(x: 52 * scale, y: 58 * scale))
            p.addLine(to: CGPoint(x: 52 * scale, y: 50 * scale))
            p.closeSubpath()
        }
    }

    private func battlements(scale: CGFloat) -> Path {
        Path { p in
            // M40 26 H42 V22 H46 V26 H50 V22 H54 V26 H56 V30 H40 Z
            p.move(to: CGPoint(x: 40 * scale, y: 26 * scale))
            p.addLine(to: CGPoint(x: 42 * scale, y: 26 * scale))
            p.addLine(to: CGPoint(x: 42 * scale, y: 22 * scale))
            p.addLine(to: CGPoint(x: 46 * scale, y: 22 * scale))
            p.addLine(to: CGPoint(x: 46 * scale, y: 26 * scale))
            p.addLine(to: CGPoint(x: 50 * scale, y: 26 * scale))
            p.addLine(to: CGPoint(x: 50 * scale, y: 22 * scale))
            p.addLine(to: CGPoint(x: 54 * scale, y: 22 * scale))
            p.addLine(to: CGPoint(x: 54 * scale, y: 26 * scale))
            p.addLine(to: CGPoint(x: 56 * scale, y: 26 * scale))
            p.addLine(to: CGPoint(x: 56 * scale, y: 30 * scale))
            p.addLine(to: CGPoint(x: 40 * scale, y: 30 * scale))
            p.closeSubpath()
        }
    }
}

#Preview("ShieldMark dark mint") {
    ZStack {
        Color(hex: 0x050507).ignoresSafeArea()
        ShieldMark(size: 220, color: Color(hex: 0x7BF1A8), dim: Color(hex: 0x0A2316))
    }
}

#Preview("ShieldMark cream mint") {
    ZStack {
        Color(hex: 0xF4F1EA).ignoresSafeArea()
        ShieldMark(size: 220, color: Color(hex: 0x0D8C5A), dim: Color(hex: 0x0A2316))
    }
}

#Preview("ShieldMark cream off-red") {
    ZStack {
        Color(hex: 0xF4F1EA).ignoresSafeArea()
        ShieldMark(size: 220, color: Color(hex: 0xD14545), dim: Color.black.opacity(0.18))
    }
}
