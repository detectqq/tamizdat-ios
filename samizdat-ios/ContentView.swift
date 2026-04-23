import SwiftUI

struct ContentView: View {
    @State private var tapCount = 0

    var body: some View {
        VStack(spacing: 24) {
            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: 72))
                .foregroundStyle(.tint)

            Text("Samizdat iOS")
                .font(.largeTitle)
                .bold()

            Text("Build pipeline check")
                .font(.headline)
                .foregroundStyle(.secondary)

            Button {
                tapCount += 1
            } label: {
                Text("Taps: \(tapCount)")
                    .font(.title2)
                    .padding(.horizontal, 32)
                    .padding(.vertical, 12)
            }
            .buttonStyle(.borderedProminent)
        }
        .padding()
    }
}

#Preview {
    ContentView()
}
