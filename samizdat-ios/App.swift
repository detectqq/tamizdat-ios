import SwiftUI
import SamizdatClient

@main
struct SamizdatTestApp: App {

    /// Path 3: the SOCKS5 listener that hev-socks5-tunnel inside the
    /// extension forwards to. Lives in this main-app process where there
    /// is no jetsam memory cap. Started once at app launch; on iOS the
    /// app may be suspended after ~30 s of background, in which case the
    /// listener also stops accepting — that is the known V2Box-style
    /// trade-off. Bringing the app to foreground re-arms it via the
    /// scenePhase observer below.
    init() {
        // Mirror SocksStub logs into the App Group file so SamizdatBridge
        // sees them merged with extension-side logs.
        if let containerURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: "group.com.anarki.samizdat-test"
        ) {
            let logURL = containerURL.appendingPathComponent("extension-log.txt")
            SocksstubSetLogSink(logURL.path)
        }
        // gomobile-generated signature for Go funcs returning `error` is
        // (arg, NSError**). Idempotent — second call's "already listening"
        // gets surfaced as nsError, ignored.
        var nsError: NSError?
        SocksstubStart("127.0.0.1:18443", &nsError)
    }

    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            ContentView()
        }
        .onChange(of: scenePhase) { _, newPhase in
            if newPhase == .active {
                var err: NSError?
                SocksstubStart("127.0.0.1:18443", &err)
            }
        }
    }
}
