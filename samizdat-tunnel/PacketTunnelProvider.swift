import Foundation
import NetworkExtension
import OSLog
import SamizdatClient

final class PacketTunnelProvider: NEPacketTunnelProvider {

    private let log = Logger(subsystem: "com.anarki.samizdat-test.tunnel", category: "extension")
    private let pumpQueue = DispatchQueue(label: "com.anarki.samizdat-test.packet-writer")
    private var isRunning = false

    override func startTunnel(options: [String: NSObject]?,
                              completionHandler: @escaping (Error?) -> Void) {
        guard let proto = protocolConfiguration as? NETunnelProviderProtocol,
              let configBlob = proto.providerConfiguration?["configBlob"] as? String else {
            completionHandler(makeError("missing samizdat config"))
            return
        }

        SamizdatAddLog("info: PacketTunnelProvider startTunnel")
        let serverIP = resolvedIPv4Address(from: configBlob)
        if let serverIP {
            SamizdatAddLog("info: resolved server IPv4 \(serverIP)")
        } else {
            SamizdatAddLog("warn: could not resolve server IPv4 before routing")
        }

        let engineConfigBlob = configBlobWithHost(serverIP, in: configBlob) ?? configBlob
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

    override func stopTunnel(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        log.info("stopTunnel reason=\(reason.rawValue, privacy: .public)")
        isRunning = false
        SamizdatAddLog("info: PacketTunnelProvider stopTunnel reason=\(reason.rawValue)")
        SamizdatTunnelStop()
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
        let remoteAddress = URL(string: configBlob)?.host ?? "Samizdat"
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remoteAddress)
        settings.mtu = 1500

        let ipv4 = NEIPv4Settings(addresses: ["198.18.0.1"], subnetMasks: ["255.255.255.0"])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        if let serverIP {
            ipv4.excludedRoutes = [NEIPv4Route(destinationAddress: serverIP, subnetMask: "255.255.255.255")]
        }
        settings.ipv4Settings = ipv4

        let ipv6 = NEIPv6Settings(addresses: ["fd00:7361:6d69::1"], networkPrefixLengths: [64])
        ipv6.includedRoutes = [NEIPv6Route.default()]
        settings.ipv6Settings = ipv6

        let dns = NEDNSSettings(servers: ["1.1.1.1", "8.8.8.8"])
        dns.matchDomains = [""]
        settings.dnsSettings = dns

        return settings
    }

    private func configBlobWithHost(_ host: String?, in configBlob: String) -> String? {
        guard let host, var components = URLComponents(string: configBlob) else { return nil }
        components.host = host
        return components.string
    }

    private func resolvedIPv4Address(from configBlob: String) -> String? {
        guard let host = URL(string: configBlob)?.host else { return nil }
        var parsed = in_addr()
        if inet_pton(AF_INET, host, &parsed) == 1 { return host }

        var hints = addrinfo()
        hints.ai_family = AF_INET
        hints.ai_socktype = SOCK_STREAM
        hints.ai_protocol = IPPROTO_TCP
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &result) == 0, let result else { return nil }
        defer { freeaddrinfo(result) }

        var addr = result.pointee.ai_addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr }
        var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        guard inet_ntop(AF_INET, &addr, &buffer, socklen_t(INET_ADDRSTRLEN)) != nil else {
            return nil
        }
        return String(cString: buffer)
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
