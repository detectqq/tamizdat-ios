import NetworkExtension
import OSLog

/// Iteration 1 stub. Apple requires the extension target exist with the
/// Network Extensions entitlement before the App ID's provisioning profile
/// is wired up correctly; we add the target now so signing+sideload+install
/// all work end-to-end on the right App ID structure.
///
/// Iteration 2 will move samizdat client + a tun2socks layer here so that
/// every packet on the device flows through the tunnel.
final class PacketTunnelProvider: NEPacketTunnelProvider {

    private let log = Logger(subsystem: "com.anarki.samizdat-test.tunnel", category: "extension")

    override func startTunnel(options: [String: NSObject]?,
                              completionHandler: @escaping (Error?) -> Void) {
        log.info("startTunnel called (stub iteration 1; not actually tunneling)")

        // We intentionally do not establish a real tunnel yet. Returning a
        // generic "not yet implemented" error keeps iOS from putting the
        // VPN UI in a misleading "Connected" state.
        let err = NSError(
            domain: "com.anarki.samizdat-test.tunnel",
            code: -1,
            userInfo: [NSLocalizedDescriptionKey: "iter1 stub: tunnel not implemented yet — use the in-app SOCKS5 listener for now"]
        )
        completionHandler(err)
    }

    override func stopTunnel(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        log.info("stopTunnel reason=\(reason.rawValue, privacy: .public)")
        completionHandler()
    }

    override func handleAppMessage(_ messageData: Data,
                                   completionHandler: ((Data?) -> Void)?) {
        // App↔extension RPC will be wired in iteration 2 (status/log forwarding).
        completionHandler?(nil)
    }
}
