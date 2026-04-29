import Foundation
import NetworkExtension
import OSLog
import os
import SamizdatClient

final class PacketTunnelProvider: NEPacketTunnelProvider {

    private let log = Logger(subsystem: "com.anarki.samizdat-test.tunnel", category: "extension")
    private let pumpQueue = DispatchQueue(label: "com.anarki.samizdat-test.packet-writer")

    /// Lifecycle flag read from three different queues (NE callback queue
    /// for packetFlow.readPackets, our pumpQueue for the write loop, and
    /// stopTunnel from yet another queue). Plain `Bool` had a torn-write
    /// race; on Swift 6 it would be a compile error. OSAllocatedUnfairLock
    /// keeps writes/reads atomic without the cost of a serial queue.
    private let runningState = OSAllocatedUnfairLock<Bool>(initialState: false)
    private var isRunning: Bool {
        get { runningState.withLock { $0 } }
        set { runningState.withLock { $0 = newValue } }
    }

    private static let appGroupID = "group.com.anarki.samizdat-test"
    private static let logFileName = "extension-log.txt"

    override func startTunnel(options: [String: NSObject]?,
                              completionHandler: @escaping (Error?) -> Void) {
        guard let proto = protocolConfiguration as? NETunnelProviderProtocol,
              let configBlob = proto.providerConfiguration?["configBlob"] as? String else {
            completionHandler(makeError("missing samizdat config"))
            return
        }

        // Point the Go shim's log sink at the App Group container BEFORE
        // anything else, so even early-startup messages land in the file
        // the main app reads. The file survives extension death — it's
        // our "last words" trail for diagnosing iOS reaps.
        if let containerURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: Self.appGroupID
        ) {
            let logURL = containerURL.appendingPathComponent(Self.logFileName)
            SamizdatSetLogSink(logURL.path)
        }

        SamizdatAddLog("info: PacketTunnelProvider startTunnel")
        let engineConfigBlob = proto.providerConfiguration?["engineConfigBlob"] as? String ?? configBlob
        let serverIP = proto.providerConfiguration?["serverIP"] as? String
        if serverIP != nil {
            SamizdatAddLog("info: using pre-resolved server IPv4")
        } else {
            SamizdatAddLog("warn: no pre-resolved server IPv4 in provider configuration")
        }

        let settings = makeNetworkSettings(configBlob: configBlob, serverIP: serverIP)
        SamizdatAddLog("info: applying packet tunnel network settings")
        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self else { return }
            if let error {
                SamizdatAddLog("error: setTunnelNetworkSettings: \(error.localizedDescription)")
                completionHandler(error)
                return
            }

            var nsError: NSError?
            SamizdatTunnelStart(engineConfigBlob, &nsError)
            if let nsError {
                SamizdatAddLog("error: SamizdatTunnelStart: \(nsError.localizedDescription)")
                completionHandler(nsError)
                return
            }

            self.isRunning = true
            self.startPacketReadLoop()
            self.startPacketWriteLoop()
            self.log.info("packet tunnel started")
            SamizdatAddLog("info: packet tunnel started")
            completionHandler(nil)
        }
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        SamizdatAddLog("warn: PacketTunnelProvider sleep() — iOS suspending extension")
        completionHandler()
    }

    override func wake() {
        SamizdatAddLog("info: PacketTunnelProvider wake() — iOS resumed extension")
    }

    override func stopTunnel(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        log.info("stopTunnel reason=\(reason.rawValue, privacy: .public)")
        isRunning = false
        SamizdatAddLog("info: PacketTunnelProvider stopTunnel reason=\(reason.rawValue)")
        SamizdatTunnelStop()
        // Detach the log sink so the next startTunnel reopens it. Keep the
        // file content though — main app may still want to read it.
        SamizdatSetLogSink("")
        completionHandler()
    }

    override func handleAppMessage(_ messageData: Data,
                                   completionHandler: ((Data?) -> Void)?) {
        let command = String(data: messageData, encoding: .utf8) ?? "logs"
        switch command {
        case "clearLogs":
            SamizdatClearLogs()
            completionHandler?(Data())
        case "status":
            let payload = [
                "status=\(SamizdatStatus())",
                "lastError=\(SamizdatLastError())",
                SamizdatLogs(0)
            ].filter { !$0.isEmpty }.joined(separator: "\n")
            completionHandler?(payload.data(using: .utf8))
        default:
            completionHandler?(SamizdatLogs(0).data(using: .utf8))
        }
    }

    private func makeNetworkSettings(configBlob: String, serverIP: String?) -> NEPacketTunnelNetworkSettings {
        let remoteAddress = serverIP ?? "127.0.0.1"
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remoteAddress)
        // 1280 is the IPv6 minimum and gives plenty of headroom for our
        // outer overhead: TLS + H2 frame header + inner TCP/UDP. The old
        // 1500 left only ~1391 effective bytes after overhead, which iOS
        // would split with PMTU-sized writePackets calls under load.
        settings.mtu = 1280

        let ipv4 = NEIPv4Settings(addresses: ["198.18.0.1"], subnetMasks: ["255.255.255.0"])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        if let serverIP {
            ipv4.excludedRoutes = [NEIPv4Route(destinationAddress: serverIP, subnetMask: "255.255.255.255")]
        }
        settings.ipv4Settings = ipv4

        // No IPv6 default route — the upstream samizdat server has no IPv6
        // egress so any v6 destination would just cost us a CONNECT
        // round-trip and a 502. Without an included v6 route iOS won't
        // send v6 packets to us at all; apps fall back to IPv4 via Happy
        // Eyeballs in <300ms. We still set a placeholder v6 address so
        // iOS doesn't reject the settings.
        let ipv6 = NEIPv6Settings(addresses: ["fd00:7361:6d69::1"], networkPrefixLengths: [64])
        // includedRoutes deliberately empty.
        settings.ipv6Settings = ipv6

        let dns = NEDNSSettings(servers: ["1.1.1.1", "8.8.8.8"])
        dns.matchDomains = [""]
        settings.dnsSettings = dns

        return settings
    }

    private func startPacketReadLoop() {
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self, self.isRunning else { return }

            for packet in packets {
                var nsError: NSError?
                SamizdatTunnelInjectPacket(packet, &nsError)
                if let nsError {
                    self.log.error("inject packet failed: \(nsError.localizedDescription, privacy: .public)")
                }
            }
            self.startPacketReadLoop()
        }
    }

    private func startPacketWriteLoop() {
        pumpQueue.async { [weak self] in
            guard let self else { return }
            while self.isRunning {
                guard let packet = SamizdatTunnelReadPacket(), !packet.isEmpty else {
                    // Empty packet means the Go side returned (ctx done /
                    // stack closed). Don't spin — yield briefly so we
                    // don't pin the CPU if Go is in shutdown.
                    Thread.sleep(forTimeInterval: 0.05)
                    continue
                }
                self.packetFlow.writePackets([packet], withProtocols: [NSNumber(value: self.protocolFamily(for: packet))])
            }
        }
    }

    private func protocolFamily(for packet: Data) -> Int32 {
        guard let first = packet.first else { return AF_INET }
        return (first >> 4) == 6 ? AF_INET6 : AF_INET
    }

    private func makeError(_ message: String) -> NSError {
        NSError(
            domain: "com.anarki.samizdat-test.tunnel",
            code: -1,
            userInfo: [NSLocalizedDescriptionKey: message]
        )
    }
}
